#!/usr/bin/env python3
"""Drift corpus v0: fetch registry metadata only (never package contents, never servers).

Stages (run in order; each saves raw responses under bench/drift/raw/ and records
url / fetchedAt / sha256 in bench/drift/raw/MANIFEST.json):

  registry   official MCP registry, latest version of every server (paginated)
  rank-retry re-fetch failed download pages with backoff
  rank       npm last-month download counts for npm-backed entries (selection only)
  packages   npm packuments / PyPI JSON for the selected entries (version history)
  compress   gzip large saved responses (manifest keeps compressed and uncompressed sha256)
  surfaces   for the selected entries' GitHub repos: tag list (git ls-remote) and
             machine-readable tool-definition files, if any, at HEAD

Network use is limited to: registry.modelcontextprotocol.io, registry.npmjs.org,
api.npmjs.org, pypi.org (JSON API), github.com (git ls-remote) and
raw.githubusercontent.com. Only GET requests with package names / paths are made.

Redistribution: npm packuments embed README text; the `readme` fields are removed
before saving (the original response's sha256 is kept in the manifest). Tool
definition files found in repositories are not stored; only their sha256 and the
tool-name list are kept.

    python bench/drift/fetch.py registry|rank|packages|surfaces
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DRIFT = Path(__file__).resolve().parent
RAW = DRIFT / "raw"
MANIFEST = RAW / "MANIFEST.json"
REGISTRY = "https://registry.modelcontextprotocol.io/v0.1/servers"
UA = "caplock-bench-drift/0.1 (metadata survey; contact via repository)"
TOP_N_NPM = 30
PYPI_SAMPLE = 10  # random sample (seed 0): PyPI has no first-party download statistics
SEARCH_PAGES = 8  # npm search results 0..1999 for "mcp"
SELECTION = DRIFT / "selection.json"
DEF_FILES = ("manifest.json", "tools.json", "mcp.json", "server.json", ".well-known/mcp.json")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def manifest() -> dict:
    return json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {"entries": []}


def record(entry: dict) -> None:
    m = manifest()
    m["entries"] = [e for e in m["entries"] if e["path"] != entry["path"]] + [entry]
    m["entries"].sort(key=lambda e: e["path"])
    RAW.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


def get(url: str, timeout: float = 30.0, retries: int = 4) -> tuple[int, bytes]:
    """GET with backoff on HTTP 429 / 5xx (5, 10, 20, 40 s)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == retries:
                return e.code, b""
            time.sleep(5 * 2 ** attempt)
    return 0, b""


def save(rel: str, url: str, status: int, body: bytes, transform=None, note: str | None = None) -> bytes:
    stored = transform(body) if (transform and body) else body
    p = RAW / rel
    stale = p.with_name(p.name + ".gz")  # an older compressed copy of the same response
    if stale.exists():
        stale.unlink()
        m = manifest()
        m["entries"] = [e for e in m["entries"] if e["path"] != rel + ".gz"]
        MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(stored)
    entry = {"path": rel, "url": url, "status": status, "fetchedAt": now(),
             "sha256": "sha256:" + hashlib.sha256(stored).hexdigest(), "bytes": len(stored)}
    if transform and body:
        entry["originalSha256"] = "sha256:" + hashlib.sha256(body).hexdigest()
    if note:
        entry["note"] = note
    record(entry)
    return stored


def safe(name: str) -> str:
    return urllib.parse.quote(name, safe="").replace("%", "_")


# --------------------------------------------------------------------------- stages


def stage_registry() -> None:
    cursor, page = None, 0
    while True:
        q = {"limit": "100", "version": "latest"}
        if cursor:
            q["cursor"] = cursor
        url = f"{REGISTRY}?{urllib.parse.urlencode(q)}"
        status, body = get(url)
        if status != 200:
            raise SystemExit(f"registry page {page}: HTTP {status}")
        save(f"registry/page-{page:04d}.json", url, status, body)
        cursor = json.loads(body).get("metadata", {}).get("nextCursor")
        page += 1
        if not cursor:
            break
        time.sleep(0.2)
    print(f"registry: {page} pages")


def read_raw(p: Path) -> dict:
    """A saved response, plain or gzip-compressed by the compress stage ({} for a failed fetch)."""
    gz = p.with_name(p.name + ".gz")
    data = gzip.decompress(gz.read_bytes()) if gz.exists() else p.read_bytes()
    return json.loads(data) if data else {}


def raw_paths(sub: str, pattern: str) -> list[Path]:
    return sorted({RAW / sub / p.name.removesuffix(".gz") for p in (RAW / sub).glob(pattern + "*")})


def registry_entries() -> list[dict]:
    out = []
    for p in raw_paths("registry", "page-*.json"):
        out += [s for s in read_raw(p)["servers"]]
    return out


def package_candidates() -> list[dict]:
    """Registry entries (latest, active) with exactly one npm or PyPI package."""
    out = []
    for e in registry_entries():
        s, meta = e["server"], e.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
        pkgs = [p for p in s.get("packages") or [] if p.get("registryType") in ("npm", "pypi")]
        if len(pkgs) != 1 or meta.get("status", "active") != "active":
            continue
        p = pkgs[0]
        out.append({"server": s["name"], "registryVersion": s.get("version"), "ecosystem": p["registryType"],
                    "package": p["identifier"], "packageVersion": p.get("version"),
                    "packageFields": sorted(p), "repository": (s.get("repository") or {}).get("url"),
                    "publishedAt": meta.get("publishedAt")})
    return out


def stage_rank_retry() -> None:
    """Re-fetch bulk download pages that failed (e.g. HTTP 429) with backoff."""
    for e in [e for e in manifest()["entries"] if e["path"].startswith("npm-downloads/") and e["status"] != 200]:
        status, body = get(e["url"])
        save(e["path"], e["url"], status, body, note="re-fetched after HTTP " + str(e["status"]))
        print(e["path"], status)
        time.sleep(2)


def stage_rank() -> None:
    """Last-month npm downloads: bulk API for unscoped names; for scoped names (no bulk API), the
    monthly count reported by npm search for the first SEARCH_PAGES pages of `text=mcp`."""
    cands = package_candidates()
    npm = sorted({c["package"] for c in cands if c["ecosystem"] == "npm"})
    unscoped = [n for n in npm if not n.startswith("@")]
    for i in range(0, len(unscoped), 100):
        chunk = unscoped[i:i + 100]
        url = "https://api.npmjs.org/downloads/point/last-month/" + ",".join(chunk)
        status, body = get(url)
        save(f"npm-downloads/bulk-{i // 100:03d}.json", url, status, body)
        time.sleep(0.3)
    for page in range(SEARCH_PAGES):
        url = f"https://registry.npmjs.org/-/v1/search?text=mcp&size=250&from={page * 250}"
        status, body = get(url)
        save(f"npm-search/page-{page:02d}.json", url, status, body, transform=slim_search,
             note="only name + downloads kept per result")
        time.sleep(0.5)
    print(f"rank: {len(unscoped)} unscoped via bulk downloads; scoped via {SEARCH_PAGES} npm search pages")


def slim_search(body: bytes) -> bytes:
    doc = json.loads(body)
    out = {"total": doc.get("total"), "objects": [{"name": o["package"]["name"], "downloads": o.get("downloads")}
                                                   for o in doc.get("objects", [])]}
    return (json.dumps(out, sort_keys=True) + "\n").encode()


def downloads() -> dict[str, int]:
    """name -> last-month downloads (bulk API first; npm search monthly only for names it lacks)."""
    d: dict[str, int] = {}
    for p in raw_paths("npm-downloads", "bulk-*.json"):
        if read_raw(p):
            for name, v in read_raw(p).items():
                if isinstance(v, dict) and "downloads" in v:
                    d[name] = v["downloads"]
    for p in raw_paths("npm-search", "page-*.json"):
        for o in read_raw(p)["objects"]:
            if o["name"] not in d and (o.get("downloads") or {}).get("monthly") is not None:
                d[o["name"]] = o["downloads"]["monthly"]
    return d


def select() -> list[dict]:
    cands = package_candidates()
    dl = downloads()
    npm = [c | {"npmDownloadsLastMonth": dl.get(c["package"])} for c in cands if c["ecosystem"] == "npm"]
    npm.sort(key=lambda c: (-(c["npmDownloadsLastMonth"] or -1), c["server"]))
    seen, top_npm = set(), []
    for c in npm:  # one registry entry per package
        if c["package"] not in seen:
            seen.add(c["package"])
            top_npm.append(c)
        if len(top_npm) == TOP_N_NPM:
            break
    pypi = sorted({c["package"].lower(): c for c in cands if c["ecosystem"] == "pypi"}.values(),
                  key=lambda c: c["package"].lower())
    return top_npm, random.Random(0).sample(pypi, min(PYPI_SAMPLE, len(pypi)))


def stage_packages() -> None:
    top_npm, pypi = select()
    for c in top_npm:
        url = "https://registry.npmjs.org/" + urllib.parse.quote(c["package"], safe="@")
        status, body = get(url, timeout=60)
        save(f"npm/{safe(c['package'])}.json", url, status, body, transform=strip_readme,
             note="readme fields removed before saving")
        time.sleep(0.3)
    for c in pypi:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(c['package'])}/json"
        status, body = get(url, timeout=60)
        save(f"pypi/{safe(c['package'])}.json", url, status, body, transform=strip_pypi_description,
             note="info.description removed before saving")
        time.sleep(0.3)
    sel = {"selectedAt": now(), "rule": {
        "npm": f"top {TOP_N_NPM} distinct npm packages by last-month downloads among active latest registry "
               "entries with exactly one npm/PyPI package. Unscoped: api.npmjs.org bulk downloads. Scoped (no bulk "
               "API): the monthly count npm search reports for its first 2000 results of text=mcp; scoped packages "
               "outside that window have no count and rank last.",
        "pypi": f"random sample of {PYPI_SAMPLE} distinct PyPI packages (random.Random(0), sorted by name) among "
                "the same registry entries; not a top list, because PyPI has no first-party download statistics"},
        "npm": top_npm, "pypi": pypi}
    SELECTION.write_text(json.dumps(sel, indent=2, sort_keys=True) + "\n")
    print(f"packages: {len(top_npm)} npm (top by downloads), {len(pypi)} pypi (random sample)")


def strip_readme(body: bytes) -> bytes:
    doc = json.loads(body)
    doc.pop("readme", None)
    for v in (doc.get("versions") or {}).values():
        v.pop("readme", None)
    return (json.dumps(doc, sort_keys=True) + "\n").encode()


def strip_pypi_description(body: bytes) -> bytes:
    doc = json.loads(body)
    (doc.get("info") or {}).pop("description", None)
    return (json.dumps(doc, sort_keys=True) + "\n").encode()


def github_repo(url: str | None) -> str | None:
    if not url:
        return None
    u = urllib.parse.urlsplit(url)
    if u.hostname != "github.com":
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1].removesuffix('.git')}"


def stage_surfaces() -> None:
    sel = json.loads(SELECTION.read_text())
    results = []
    for c in sel["npm"] + sel["pypi"]:
        repo = github_repo(c.get("repository")) or github_repo(npm_repo(c))
        item = {"server": c["server"], "package": c["package"], "ecosystem": c["ecosystem"], "repo": repo,
                "checkedAt": now(), "tags": None, "definitionFiles": []}
        if repo:
            r = subprocess.run(["git", "ls-remote", "--tags", "--refs", f"https://github.com/{repo}.git"],
                               capture_output=True, text=True, timeout=60,
                               env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin"})
            tags = [line.split("refs/tags/", 1)[1] for line in r.stdout.splitlines() if "refs/tags/" in line]
            item["tags"] = len(tags) if r.returncode == 0 else None
            item["tagSample"] = sorted(tags)[-5:]
            for f in DEF_FILES:
                url = f"https://raw.githubusercontent.com/{repo}/HEAD/{f}"
                status, body = get(url)
                if status == 200 and body:
                    item["definitionFiles"].append(describe_def(f, url, body))
                time.sleep(0.1)
        results.append(item)
    out = {"checkedAt": now(), "files": list(DEF_FILES), "items": results}
    p = RAW / "surfaces" / "survey.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(out, indent=2, sort_keys=True) + "\n").encode()
    p.write_bytes(data)
    record({"path": "surfaces/survey.json", "url": "git ls-remote + raw.githubusercontent.com (see items)",
            "status": 200, "fetchedAt": now(), "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "note": "derived summary; definition file bodies are not stored"})
    print(f"surfaces: {len(results)} items, "
          f"{sum(bool(i['definitionFiles']) for i in results)} with a candidate definition file")


def npm_repo(c: dict) -> str | None:
    p = RAW / "npm" / f"{safe(c['package'])}.json"
    if c["ecosystem"] != "npm" or not (p.exists() or p.with_name(p.name + ".gz").exists()):
        return None
    repo = read_raw(p).get("repository")
    url = repo.get("url") if isinstance(repo, dict) else repo
    if isinstance(url, str):
        url = url.removeprefix("git+").replace("git://", "https://").replace("ssh://git@", "https://")
    return url


def describe_def(name: str, url: str, body: bytes) -> dict:
    """Is this a machine-readable tool list? Keep only names, counts and a hash."""
    d = {"file": name, "url": url, "sha256": "sha256:" + hashlib.sha256(body).hexdigest(), "hasTools": False}
    try:
        doc = json.loads(body)
    except ValueError:
        d["json"] = False
        return d
    tools = doc.get("tools") if isinstance(doc, dict) else None
    if isinstance(tools, list) and tools and all(isinstance(t, dict) and "name" in t for t in tools):
        d.update(hasTools=True, toolCount=len(tools), toolNames=sorted(str(t["name"]) for t in tools),
                 withDescription=sum("description" in t for t in tools),
                 withInputSchema=sum("inputSchema" in t or "input_schema" in t for t in tools))
    return d


def stage_compress() -> None:
    """gzip saved responses over 64 KiB (deterministic: mtime 0); the manifest keeps both digests."""
    m = manifest()
    for e in m["entries"]:
        p = RAW / e["path"]
        if e["path"].endswith(".gz") or not p.exists() or p.stat().st_size <= 65536:
            continue
        data = p.read_bytes()
        gz = gzip.compress(data, compresslevel=9, mtime=0)
        p.with_name(p.name + ".gz").write_bytes(gz)
        p.unlink()
        e.update(path=e["path"] + ".gz", uncompressedSha256=e["sha256"], uncompressedBytes=len(data),
                 sha256="sha256:" + hashlib.sha256(gz).hexdigest(), bytes=len(gz))
    MANIFEST.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else ""
    {"registry": stage_registry, "rank": stage_rank, "rank-retry": stage_rank_retry, "packages": stage_packages,
     "surfaces": stage_surfaces, "compress": stage_compress}.get(stage, lambda: sys.exit(__doc__))()
