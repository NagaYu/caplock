#!/usr/bin/env python3
"""Summarize the drift survey from bench/drift/raw/ (offline): writes summary.json and DRIFT.md.

Inputs are only the saved registry metadata (see fetch.py and raw/MANIFEST.json).
"""

from __future__ import annotations

import gzip
import json
import statistics
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

DRIFT = Path(__file__).resolve().parent
RAW = DRIFT / "raw"
KILL_THRESHOLD = 0.10  # surface drift is out of v0 if comparable targets < 10% of the top 30


def load(rel: str):
    p = RAW / rel
    if p.with_suffix(p.suffix + ".gz").exists():
        return json.loads(gzip.decompress(p.with_suffix(p.suffix + ".gz").read_bytes()))
    return json.loads(p.read_text(encoding="utf-8"))


def raw_files(sub: str) -> list[str]:
    return sorted(str(p.relative_to(RAW)).removesuffix(".gz") for p in (RAW / sub).glob("*.json*"))


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def safe(name: str) -> str:
    import urllib.parse
    return urllib.parse.quote(name, safe="").replace("%", "_")


# --------------------------------------------------------------------------- registry-wide


def registry_stats() -> dict:
    entries = [s for rel in raw_files("registry") for s in load(rel)["servers"]]
    kinds, versions, hash_fields, pkg_entries = Counter(), Counter(), Counter(), 0
    remote_only = 0
    for e in entries:
        s = e["server"]
        pkgs = s.get("packages") or []
        if not pkgs and s.get("remotes"):
            remote_only += 1
        kinds[tuple(sorted({p.get("registryType") for p in pkgs})) or ("none",)] += 1
        for p in pkgs:
            pkg_entries += 1
            rt = p.get("registryType")
            hashed = [k for k in p if k.lower() in ("filesha256", "integrity", "sha256", "digest")]
            hash_fields[(rt, bool(hashed))] += 1
            v = str(p.get("version") or "")
            versions[(rt, "exact" if v and v[0].isdigit() and not any(c in v for c in "^~*><x ")
                      else ("missing" if not v else "non-exact"))] += 1
    by_type = {}
    for (rt, hashed), n in hash_fields.items():
        d = by_type.setdefault(rt or "unknown", {"packageEntries": 0, "withHashField": 0})
        d["packageEntries"] += n
        d["withHashField"] += n if hashed else 0
    npm_pypi = [v for k, v in by_type.items() if k in ("npm", "pypi")]
    np_total = sum(d["packageEntries"] for d in npm_pypi)
    np_hashed = sum(d["withHashField"] for d in npm_pypi)
    return {
        "latestEntries": len(entries),
        "remoteOnlyEntries": remote_only,
        "packageEntries": pkg_entries,
        "byRegistryType": dict(sorted(by_type.items())),
        "npmPypiHashFieldShare": {"entries": np_total, "withHashField": np_hashed,
                                  "rate": round(np_hashed / np_total, 4) if np_total else None},
        "versionSpec": {f"{rt}:{k}": n for (rt, k), n in sorted(versions.items(), key=lambda x: (str(x[0][0]), x[0][1]))
                        if rt in ("npm", "pypi")},
        "topCombinations": [{"registryTypes": list(k), "entries": n} for k, n in kinds.most_common(8)],
    }


# --------------------------------------------------------------------------- npm


def npm_stats(sel: list[dict], ref: datetime) -> list[dict]:
    out = []
    for c in sel:
        doc = load(f"npm/{safe(c['package'])}.json")
        versions = doc.get("versions") or {}
        times = {k: v for k, v in (doc.get("time") or {}).items() if k not in ("created", "modified")}
        published = sorted(ts(t) for v, t in times.items() if v in versions)
        last_year = [t for t in published if t >= ref - timedelta(days=365)]
        gaps = [(b - a).total_seconds() / 86400 for a, b in zip(last_year, last_year[1:])]
        latest = (doc.get("dist-tags") or {}).get("latest")
        ordered = sorted(versions, key=lambda v: times.get(v, ""))
        reg_v = c.get("packageVersion")
        out.append({
            "package": c["package"], "server": c["server"], "downloadsLastMonth": c.get("npmDownloadsLastMonth"),
            "versions": len(versions),
            "withIntegritySha512": sum(str((v.get("dist") or {}).get("integrity", "")).startswith("sha512-")
                                       for v in versions.values()),
            "shasumOnly": sum(not (v.get("dist") or {}).get("integrity") and bool((v.get("dist") or {}).get("shasum"))
                              for v in versions.values()),
            "noHash": sum(not (v.get("dist") or {}).get("integrity") and not (v.get("dist") or {}).get("shasum")
                          for v in versions.values()),
            "withRegistrySignature": sum(bool((v.get("dist") or {}).get("signatures")) for v in versions.values()),
            "withProvenance": sum(bool((v.get("dist") or {}).get("attestations")) for v in versions.values()),
            "latestHasProvenance": bool(((versions.get(latest) or {}).get("dist") or {}).get("attestations")),
            "deprecated": sum(bool(v.get("deprecated")) for v in versions.values()),
            "unpublishedVersions": sorted(v for v in times if v not in versions),
            "firstPublished": published[0].isoformat() if published else None,
            "lastPublished": published[-1].isoformat() if published else None,
            "releasesLast90Days": sum(t >= ref - timedelta(days=90) for t in published),
            "releasesLast365Days": len(last_year),
            "medianDaysBetweenReleasesLastYear": round(statistics.median(gaps), 2) if gaps else None,
            "registryVersion": reg_v,
            "registryVersionOnNpm": reg_v in versions,
            "npmLatest": latest,
            "registryBehindLatestBy": (len(ordered) - 1 - ordered.index(reg_v)) if reg_v in ordered and latest in ordered else None,
        })
    return out


# --------------------------------------------------------------------------- PyPI


def pypi_stats(sel: list[dict], ref: datetime) -> list[dict]:
    out = []
    for c in sel:
        try:
            doc = load(f"pypi/{safe(c['package'])}.json")
        except (FileNotFoundError, ValueError):
            out.append({"package": c["package"], "server": c["server"], "fetched": False})
            continue
        rel = doc.get("releases") or {}
        late, empty, yanked, files_total, no_sha = [], 0, 0, 0, 0
        first_upload = []
        for v, files in rel.items():
            if not files:
                empty += 1
                continue
            up = sorted(ts(f["upload_time_iso_8601"]) for f in files if f.get("upload_time_iso_8601"))
            files_total += len(files)
            no_sha += sum(not (f.get("digests") or {}).get("sha256") for f in files)
            yanked += any(f.get("yanked") for f in files)
            if up:
                first_upload.append(up[0])
                if (up[-1] - up[0]) > timedelta(hours=24):
                    late.append({"version": v, "files": len(files), "spanHours": round((up[-1] - up[0]).total_seconds() / 3600, 1)})
        first_upload.sort()
        reg_v = c.get("packageVersion")
        out.append({
            "package": c["package"], "server": c["server"], "fetched": True,
            "releases": len(rel), "releasesWithoutFiles": empty, "files": files_total,
            "filesWithoutSha256": no_sha, "releasesWithYankedFiles": yanked,
            "releasesWithFilesAddedOver24hLater": late,
            "releasesLast90Days": sum(t >= ref - timedelta(days=90) for t in first_upload),
            "registryVersion": reg_v, "registryVersionOnPypi": reg_v in rel,
            "pypiLatest": (doc.get("info") or {}).get("version"),
        })
    return out


# --------------------------------------------------------------------------- surfaces


def surface_stats(sel: dict) -> dict:
    survey = load("surfaces/survey.json")
    items = survey["items"]
    top = [i for i in items if i["ecosystem"] == "npm"]
    sample = [i for i in items if i["ecosystem"] == "pypi"]

    def with_tools(rows):
        return [i for i in rows if any(d.get("hasTools") for d in i["definitionFiles"])]

    def with_schema(rows):
        return [i for i in rows if any(d.get("hasTools") and d.get("withInputSchema") for d in i["definitionFiles"])]

    files = Counter(d["file"] for i in items for d in i["definitionFiles"])
    comparable = with_tools(top)  # a tool list at HEAD is the precondition for any version-to-version comparison
    rate = len(comparable) / len(top) if top else 0.0
    return {
        "checkedAt": survey["checkedAt"],
        "method": "git ls-remote --tags and GET raw.githubusercontent.com/<repo>/HEAD/<file> for "
                  + ", ".join(survey["files"]) + "; a file counts only if it is JSON with a tools[] list of named tools",
        "top30": {"items": len(top), "withRepo": sum(bool(i["repo"]) for i in top),
                  "withAnyCandidateFile": sum(bool(i["definitionFiles"]) for i in top),
                  "withToolList": len(comparable), "withToolListAndInputSchema": len(with_schema(top))},
        "pypiSample": {"items": len(sample), "withToolList": len(with_tools(sample)),
                       "withToolListAndInputSchema": len(with_schema(sample)),
                       "packagesWithToolList": [i["package"] for i in with_tools(sample)]},
        "candidateFilesFound": dict(sorted(files.items())),
        "coverage": round(rate, 4),
        "killThreshold": KILL_THRESHOLD,
        "decision": ("surface drift OUT OF SCOPE for v0 (coverage below the kill threshold); package drift only"
                     if rate < KILL_THRESHOLD else "surface drift in scope"),
    }


# --------------------------------------------------------------------------- main


def main() -> int:
    sel = json.loads((DRIFT / "selection.json").read_text())
    man = json.loads((RAW / "MANIFEST.json").read_text())
    fetched = sorted(e["fetchedAt"] for e in man["entries"])
    ref = ts(max(fetched))
    reg = registry_stats()
    npm = npm_stats(sel["npm"], ref)
    pypi = pypi_stats(sel["pypi"], ref)
    surf = surface_stats(sel)
    pf = [p for p in pypi if p.get("fetched")]
    summary = {
        "fetchWindow": {"first": fetched[0], "last": fetched[-1]},
        "selection": sel["rule"],
        "sources": ["https://registry.modelcontextprotocol.io/v0.1/servers?version=latest",
                    "https://api.npmjs.org/downloads/point/last-month/…", "https://registry.npmjs.org/-/v1/search?text=mcp",
                    "https://registry.npmjs.org/<package>", "https://pypi.org/pypi/<package>/json",
                    "git ls-remote https://github.com/<repo>.git", "https://raw.githubusercontent.com/<repo>/HEAD/<file>"],
        "registry": reg,
        "surfaces": surf,
        "npmTop30": {
            "packages": len(npm),
            "versionsTotal": sum(p["versions"] for p in npm),
            "versionsWithIntegritySha512": sum(p["withIntegritySha512"] for p in npm),
            "versionsShasumOnly": sum(p["shasumOnly"] for p in npm),
            "versionsNoHash": sum(p["noHash"] for p in npm),
            "packagesWithShasumOnlyVersions": sum(p["shasumOnly"] > 0 for p in npm),
            "latestWithProvenance": sum(p["latestHasProvenance"] for p in npm),
            "packagesWithUnpublishedVersions": sum(bool(p["unpublishedVersions"]) for p in npm),
            "unpublishedVersionsTotal": sum(len(p["unpublishedVersions"]) for p in npm),
            "releasesLast90Days": {"total": sum(p["releasesLast90Days"] for p in npm),
                                   "median": statistics.median(p["releasesLast90Days"] for p in npm),
                                   "packagesWithAtLeastOne": sum(p["releasesLast90Days"] > 0 for p in npm)},
            "medianOfMedianDaysBetweenReleases": statistics.median(
                [p["medianDaysBetweenReleasesLastYear"] for p in npm if p["medianDaysBetweenReleasesLastYear"] is not None]),
            "registryVersionNotOnNpm": sum(not p["registryVersionOnNpm"] for p in npm),
            "registryBehindNpmLatest": sum((p["registryBehindLatestBy"] or 0) > 0 for p in npm),
            "perPackage": npm,
        },
        "pypiSample": {
            "packages": len(pypi), "fetched": len(pf),
            "releasesTotal": sum(p["releases"] for p in pf),
            "filesWithoutSha256": sum(p["filesWithoutSha256"] for p in pf),
            "releasesWithFilesAddedOver24hLater": sum(len(p["releasesWithFilesAddedOver24hLater"]) for p in pf),
            "releasesWithYankedFiles": sum(p["releasesWithYankedFiles"] for p in pf),
            "registryVersionNotOnPypi": sum(not p["registryVersionOnPypi"] for p in pf),
            "perPackage": pypi,
        },
        "notMeasured": [
            "Tool-surface drift between versions (coverage below the kill threshold; see surfaces).",
            "Whether package contents changed under an unchanged version: npm forbids republishing a version, so "
            "registry metadata can only show unpublished versions and late-added PyPI files, not silent rewrites.",
            "Anything about runtime behavior; no package was downloaded and no server was run.",
        ],
    }
    t = summary["npmTop30"]
    summary["headline"] = (
        f"Drift survey ({fetched[-1][:10]}, registry metadata only): of the 30 most-downloaded npm-backed entries in the "
        f"official MCP registry, {surf['top30']['withToolList']} publish a machine-readable tool list without running "
        f"the server, so surface drift could not be measured; their packages shipped "
        f"{t['releasesLast90Days']['total']} versions in the last 90 days "
        f"({t['releasesLast90Days']['packagesWithAtLeastOne']}/30 packages), and "
        f"{reg['npmPypiHashFieldShare']['withHashField']}/{reg['npmPypiHashFieldShare']['entries']} npm/PyPI package "
        f"entries in the registry carry a content hash.")
    summary["citeVersionCadence"] = (f"npmTop30.releasesLast90Days.total = {t['releasesLast90Days']['total']} "
                                     f"({t['releasesLast90Days']['packagesWithAtLeastOne']}/30 packages)")
    summary["citeRegistryHashes"] = (f"registry.npmPypiHashFieldShare = {reg['npmPypiHashFieldShare']['withHashField']}/"
                                     f"{reg['npmPypiHashFieldShare']['entries']}")
    summary["citeSurfaceCoverage"] = f"surfaces.coverage = {surf['top30']['withToolList']}/{surf['top30']['items']}"
    (DRIFT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    (DRIFT / "DRIFT.md").write_text(render(summary), encoding="utf-8")
    print(summary["headline"])
    return 0


def render(s: dict) -> str:
    r, su, n, p = s["registry"], s["surfaces"], s["npmTop30"], s["pypiSample"]
    L = ["# Drift corpus v0 — feasibility survey and package drift", "",
         f"Fetched {s['fetchWindow']['first']} – {s['fetchWindow']['last']} (UTC). Registry metadata only: no package "
         "contents were downloaded and no server was run. Raw responses and their sha256 are in `raw/` "
         "(`raw/MANIFEST.json`).", "",
         "## 1. Coverage first (decides the scope)", "",
         f"- Method: {su['method']}.",
         f"- Top 30 npm-backed entries: {su['top30']['withRepo']}/30 have a GitHub repository; "
         f"{su['top30']['withAnyCandidateFile']}/30 have one of the candidate files at HEAD, but "
         f"**{su['top30']['withToolList']}/30 contain a tool list** (mostly `server.json`, which is registry metadata "
         f"without tools; a manual check of the MCPB `manifest.json` files found no `tools` list, one declaring \
`tools_generated: true`).",
         f"- PyPI random sample: {su['pypiSample']['withToolList']}/{su['pypiSample']['items']} with a tool list "
         f"({', '.join(su['pypiSample']['packagesWithToolList']) or 'none'}; names and descriptions only, "
         f"{su['pypiSample']['withToolListAndInputSchema']} with inputSchema).",
         f"- Coverage {su['coverage'] * 100:.0f}% vs kill threshold {su['killThreshold'] * 100:.0f}% → "
         f"**{su['decision']}**. Human-readable tool lists in READMEs and docs exist for many servers but were not "
         "treated as definitions (no schema, not versioned with the package).", "",
         "## 2. Selection", "",
         f"- npm: {s['selection']['npm']}", f"- PyPI: {s['selection']['pypi']}", "",
         "## 3. Registry-wide metadata", "",
         f"- Latest entries: {r['latestEntries']}; remote-only (no package, CapLock: always unverifiable): "
         f"{r['remoteOnlyEntries']}.",
         f"- npm/PyPI package entries carrying any content-hash field: "
         f"{r['npmPypiHashFieldShare']['withHashField']}/{r['npmPypiHashFieldShare']['entries']}.",
         "- Package entries with a hash field, by registry type: " + ", ".join(
             f"{k} {v['withHashField']}/{v['packageEntries']}" for k, v in r["byRegistryType"].items()) + ".",
         "- Version spec of npm/PyPI package entries: " + ", ".join(f"{k} {v}" for k, v in r["versionSpec"].items()) + ".",
         "", "## 4. Package drift — npm top 30", "",
         f"- Versions: {n['versionsTotal']} in total; with sha512 integrity {n['versionsWithIntegritySha512']}, "
         f"shasum (sha1) only {n['versionsShasumOnly']} (in {n['packagesWithShasumOnlyVersions']} packages), "
         f"no hash {n['versionsNoHash']}.",
         f"- Releases in the last 90 days: {n['releasesLast90Days']['total']} "
         f"({n['releasesLast90Days']['packagesWithAtLeastOne']}/30 packages released at least once; median "
         f"{n['releasesLast90Days']['median']} per package). Median of per-package median days between releases "
         f"(last year): {n['medianOfMedianDaysBetweenReleases']}.",
         f"- Latest version with an npm provenance attestation: {n['latestWithProvenance']}/30.",
         f"- Unpublished versions (listed in `time`, gone from `versions`): {n['unpublishedVersionsTotal']} in "
         f"{n['packagesWithUnpublishedVersions']} packages. A lockfile pinned to one of them can no longer be re-verified.",
         f"- Registry entry's version not on npm: {n['registryVersionNotOnNpm']}/30; registry version older than npm "
         f"`latest`: {n['registryBehindNpmLatest']}/30.", "",
         "| package | versions | 90d releases | median days between | shasum-only | unpublished | latest provenance |",
         "|---|---|---|---|---|---|---|"]
    for x in n["perPackage"]:
        L.append(f"| `{x['package']}` | {x['versions']} | {x['releasesLast90Days']} | "
                 f"{x['medianDaysBetweenReleasesLastYear']} | {x['shasumOnly']} | {len(x['unpublishedVersions'])} | "
                 f"{'yes' if x['latestHasProvenance'] else 'no'} |")
    L += ["", "## 5. Package drift — PyPI random sample", "",
          f"- {p['fetched']}/{p['packages']} fetched; {p['releasesTotal']} releases; files without sha256: "
          f"{p['filesWithoutSha256']}.",
          f"- Releases whose file set grew more than 24 h after the first upload (the same version number with "
          f"different content over time; CapLock's integritySet reports this as integrity_mismatch): "
          f"{p['releasesWithFilesAddedOver24hLater']}.",
          f"- Releases with yanked files: {p['releasesWithYankedFiles']}; registry version not on PyPI: "
          f"{p['registryVersionNotOnPypi']}.", "",
          "## Not measured", ""] + [f"- {x}" for x in s["notMeasured"]] + [
          "", "## Redistribution", "",
          "`raw/` holds registry API responses with README / long-description fields removed (the original "
          "response's sha256 is kept). Tool-definition file bodies were not stored. Review the registries' terms "
          "before redistributing `raw/`; it is excluded from the publication packet."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
