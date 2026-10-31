"""Evidence pack: ``caplock evidence`` and ``caplock evidence --verify``.

A pack bundles, for one workspace:

  mcp-lock.json      byte-for-byte copy of the lockfile
  verify.sarif       the verify result (SARIF 2.1.0), as produced
  verify.md          the verify result (PR Markdown), as produced
  approval.json      the lockfile's approval block + the lockfile's sha256
  rule-catalog.json  the versioned rule catalog the finding codes refer to
  EVIDENCE.md        human-readable summary and limits
  manifest.json      sha256 + size of every file above, generation time, CapLock
                     version, rule catalog version, config file list (paths and
                     formats only; no secret values, no raw config content)

``--verify`` recomputes every sha256 and compares it with the manifest. This is
tamper detection *after the pack was made*. The pack is not signed: whoever can
rewrite a file and manifest.json together is not detected, and nothing here
proves who made the pack. The format is a CapLock format for pre-approval
evidence (the kind of material an Agent 365-style review asks for); it is not
an official Microsoft certification format and was not checked against any
official requirement.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from caplock import LIMITATION_NOTICE, __version__
from caplock.config_discovery import discover
from caplock.sarif import rule_catalog

PACK_FORMAT = "caplock-evidence/v1"
MANIFEST = "manifest.json"
LOCK_NAME = "mcp-lock.json"
SARIF_NAME = "verify.sarif"
MARKDOWN_NAME = "verify.md"
APPROVAL_NAME = "approval.json"
CATALOG_NAME = "rule-catalog.json"
SUMMARY_NAME = "EVIDENCE.md"

INTEGRITY_NOTICE = (
    "Tamper detection only: evidence --verify checks that the files still match manifest.json. "
    "The pack is unsigned, so it does not prove who produced it, and a change to both a file and "
    "manifest.json is not detected. Record the manifest digest somewhere you trust to close that gap."
)
POSITIONING_NOTICE = (
    "CapLock evidence format for pre-approval review. Not an official Microsoft (or Agent 365) "
    "certification format; it has not been checked against any official requirement."
)

ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class EvidenceError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json_bytes(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def _now(now: str | None) -> str:
    if now:
        return now
    epoch = os.environ.get("SOURCE_DATE_EPOCH")  # reproducible packs
    t = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch and epoch.isdigit() else datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- build


def sarif_summary(sarif_text: str) -> dict:
    """exitCode / verdict / failOn / per-severity counts from a CapLock SARIF log."""
    try:
        run = json.loads(sarif_text)["runs"][0]
        props = run["properties"]
        if run["tool"]["driver"]["name"] != "CapLock":
            raise KeyError("driver")
        counts: dict[str, int] = {}
        for r in run.get("results", []):
            sev = r.get("properties", {}).get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return {"exitCode": props["exitCode"], "verdict": props["verdict"], "failOn": props["failOn"],
                "findingCounts": dict(sorted(counts.items())),
                "ruleCatalogVersion": run["tool"]["driver"].get("properties", {}).get("ruleCatalogVersion")}
    except (ValueError, KeyError, IndexError, TypeError) as e:
        raise EvidenceError(f"not a CapLock SARIF log ({e})") from None


def build_files(*, workspace: Path, configs: list[Path], lockfile_path: Path, sarif_text: str,
                markdown_text: str, source: str, now: str | None = None) -> dict[str, bytes]:
    """All pack files (name -> bytes), manifest.json included."""
    lock_bytes = Path(lockfile_path).read_bytes()
    try:
        lock = json.loads(lock_bytes)
        approval = {"generatedAt": lock["approval"]["generatedAt"],
                    "caplockVersion": lock["approval"]["caplockVersion"]}
        servers = lock["servers"]
    except (ValueError, KeyError, TypeError) as e:
        raise EvidenceError(f"{lockfile_path}: not a CapLock lockfile ({e})") from None
    verify_info = {"source": source, **sarif_summary(sarif_text)}
    catalog = rule_catalog()
    disc = discover(Path(workspace), configs)

    files: dict[str, bytes] = {
        LOCK_NAME: lock_bytes,
        SARIF_NAME: sarif_text.encode("utf-8"),
        MARKDOWN_NAME: markdown_text.encode("utf-8"),
        APPROVAL_NAME: _json_bytes({**approval, "lockfileSha256": sha256_bytes(lock_bytes),
                                    "meaning": "When and with which CapLock version mcp-lock.json was written. "
                                               "Who approved it is recorded by your review system, not here."}),
        CATALOG_NAME: _json_bytes(catalog),
    }
    manifest = {
        "format": PACK_FORMAT,
        "generatedAt": _now(now),
        "caplockVersion": __version__,
        "ruleCatalog": {k: catalog[k] for k in ("version", "digest", "ruleCount")},
        "approval": {**approval, "lockfileSha256": sha256_bytes(lock_bytes)},
        "verify": verify_info,
        "workspace": {
            # paths and formats only: no config content, no env/header values
            "configFiles": [s.to_dict() for s in disc.sources],
            "servers": [{"name": n, "configHash": s.get("configHash"),
                         "sources": [x.get("path") for x in s.get("sources", [])]}
                        for n, s in sorted(servers.items())],
        },
        "notices": {"limitation": LIMITATION_NOTICE, "integrity": INTEGRITY_NOTICE,
                    "positioning": POSITIONING_NOTICE},
    }
    files[SUMMARY_NAME] = _summary(manifest).encode("utf-8")
    manifest["files"] = [{"path": name, "sha256": sha256_bytes(data), "bytes": len(data)}
                         for name, data in sorted(files.items())]
    files[MANIFEST] = _json_bytes(manifest)
    return files


def _summary(m: dict) -> str:
    v = m["verify"]
    counts = ", ".join(f"{k} {n}" for k, n in v["findingCounts"].items()) or "none"
    cfgs = "\n".join(f"- `{c['path']}` ({c['format']})" for c in m["workspace"]["configFiles"]) or "- (none found)"
    return "\n".join([
        "# CapLock evidence pack",
        "",
        f"- Generated: {m['generatedAt']} with CapLock {m['caplockVersion']}",
        f"- Verify verdict: **{v['verdict']}** (exit {v['exitCode']}, --fail-on {v['failOn']}, "
        f"result {'re-run for this pack' if v['source'] == 'run' else 'supplied as produced'})",
        f"- Findings by severity: {counts}",
        f"- Lockfile approval: written {m['approval']['generatedAt']} by CapLock {m['approval']['caplockVersion']}",
        f"- Rule catalog: version {m['ruleCatalog']['version']} ({m['ruleCatalog']['ruleCount']} rules)",
        "",
        "## Configuration files (paths only)",
        "",
        cfgs,
        "",
        "## What this pack shows, and what it does not",
        "",
        f"- {m['notices']['limitation']}",
        f"- {m['notices']['integrity']}",
        f"- {m['notices']['positioning']}",
        "",
        "Check the pack with: `caplock evidence --verify <this directory or zip>`",
        "",
    ])


def write_pack(files: dict[str, bytes], out: Path, as_zip: bool) -> Path:
    out = Path(out)
    if as_zip:
        if out.suffix != ".zip":
            out = out.with_name(out.name + ".zip")
        if out.exists():
            raise EvidenceError(f"{out} already exists")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for name in sorted(files):
                info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
                info.external_attr = 0o644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, files[name])
        out.write_bytes(buf.getvalue())
        return out
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise EvidenceError(f"{out} exists and is not an empty directory")
    out.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (out / name).write_bytes(data)
    return out


# --------------------------------------------------------------------------- verify


@dataclass
class PackCheck:
    status: str  # "intact" | "tampered" | "unverifiable"
    problems: list[str] = field(default_factory=list)
    checked: int = 0
    manifest_digest: str | None = None
    manifest: dict | None = None

    @property
    def exit_code(self) -> int:
        return {"intact": 0, "tampered": 1}.get(self.status, 2)


def _safe_name(name: str) -> bool:
    p = PurePosixPath(name)
    return bool(name) and "\\" not in name and not p.is_absolute() and ".." not in p.parts and len(p.parts) == 1


def _read_pack(path: Path) -> dict[str, bytes]:
    path = Path(path)
    if path.is_dir():  # sub-directories are listed as "name/" so they show up as unlisted entries
        return {(p.name if p.is_file() else p.name + "/"): (p.read_bytes() if p.is_file() else b"")
                for p in sorted(path.iterdir())}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:  # read in memory; nothing is extracted to disk
            return {i.filename: (b"" if i.is_dir() else z.read(i)) for i in z.infolist()}
    raise EvidenceError(f"{path}: not a directory or zip file")


def verify_pack(path: Path) -> PackCheck:
    try:
        files = _read_pack(path)
    except (OSError, EvidenceError, zipfile.BadZipFile) as e:
        return PackCheck("unverifiable", [str(e)])
    if MANIFEST not in files:
        return PackCheck("unverifiable", [f"{MANIFEST} is missing; nothing to compare against"])
    raw = files[MANIFEST]
    digest = sha256_bytes(raw)
    try:
        manifest = json.loads(raw)
        if manifest.get("format") != PACK_FORMAT:
            raise ValueError(f"format is {manifest.get('format')!r}, expected {PACK_FORMAT!r}")
        entries = manifest["files"]
        if not isinstance(entries, list) or not all(
                isinstance(e, dict) and isinstance(e.get("path"), str) and isinstance(e.get("sha256"), str)
                for e in entries):
            raise ValueError("files must be a list of {path, sha256, bytes}")
    except (ValueError, KeyError, AttributeError) as e:
        return PackCheck("unverifiable", [f"{MANIFEST} is not a valid manifest ({e})"], manifest_digest=digest)

    problems: list[str] = []
    listed = set()
    for e in entries:
        name = e["path"]
        if not _safe_name(name):
            problems.append(f"{name!r}: unsafe path in manifest")
            continue
        listed.add(name)
        if name not in files:
            problems.append(f"{name}: missing")
        elif sha256_bytes(files[name]) != e["sha256"]:
            problems.append(f"{name}: modified (sha256 now {sha256_bytes(files[name])[7:19]}…, "
                            f"manifest says {e['sha256'][7:19]}…)")
        elif e.get("bytes") is not None and e["bytes"] != len(files[name]):
            problems.append(f"{name}: size differs from manifest")
    for name in sorted(set(files) - listed - {MANIFEST}):
        problems.append(f"{name}: not listed in the manifest")
    # cross-references inside the pack (catch an edited manifest that forgot its own summary fields)
    lock = files.get(LOCK_NAME)
    if lock is not None and manifest.get("approval", {}).get("lockfileSha256") not in (None, sha256_bytes(lock)):
        problems.append(f"manifest approval.lockfileSha256 does not match {LOCK_NAME}")
    status = "tampered" if problems else "intact"
    return PackCheck(status, problems, checked=len(listed), manifest_digest=digest, manifest=manifest)
