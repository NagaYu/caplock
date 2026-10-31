"""mcp-lock.json: building, serialization, loading and schema validation.

The lockfile binds, per server:
  config (normalized, no secret values) → package (version + integrity)
  → surface (server-level hash) → tools (normalized definition, hash, capability).

Serialization is deterministic (sorted keys, 2-space indent, trailing
newline). Invisible characters inside strings are written as ``\\uXXXX``
escapes so they stay visible in code review.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from caplock import LIMITATION_NOTICE, __version__
from caplock.canonical import canonical_tool, escape_invisible, find_invisible_chars, sha256_of, surface_hash
from caplock.capability import classify
from caplock.config_discovery import ServerEntry
from caplock.diff import find_instruction_patterns
from caplock.enumerate import Surface
from caplock.resolve import ResolvedPackage

LOCKFILE_NAME = "mcp-lock.json"
LOCKFILE_VERSION = 1

SURFACE_STATUSES = {"enumerated", "failed", "not_enumerated"}
PACKAGE_STATUSES = {"resolved", "floating", "unrecorded", "manual", "remote"}


class LockfileError(ValueError):
    pass


def tool_record(tool: dict) -> dict:
    definition = canonical_tool(tool)
    rec = {
        "definition": definition,
        "hash": sha256_of(definition),
        "capability": classify(definition).to_dict(),
    }
    flags = []
    for f in find_invisible_chars(definition):
        flags.append({"kind": "invisible_chars", "path": f["path"], "detail": f"{f['codepoint']} {f['name']}"})
    for f in find_instruction_patterns(definition):
        flags.append({"kind": "instruction_pattern", "path": f["path"], "detail": f["pattern"]})
    if flags:
        rec["flags"] = flags
    return rec


def surface_record(surface: Surface | None, method: str | None, error: str | None) -> tuple[dict, dict]:
    if surface is None:
        status = "failed" if error else "not_enumerated"
        rec = {"status": status, "method": method, "hash": None, "toolCount": None}
        if error:
            rec["error"] = error
        return {k: v for k, v in rec.items() if v is not None or k == "hash"}, {}
    tools = {t["name"]: tool_record(t) for t in surface.tools}
    hashes = {name: r["hash"] for name, r in tools.items()}
    rec = {
        "status": "enumerated",
        "method": method,
        "protocolVersion": surface.protocol_version,
        "hash": surface_hash(hashes),
        "toolCount": len(tools),
        "resourcesHash": sha256_of(surface.resources) if surface.resources is not None else None,
        "promptsHash": sha256_of(surface.prompts) if surface.prompts is not None else None,
        "instructionsHash": sha256_of(surface.instructions) if surface.instructions is not None else None,
    }
    return {k: v for k, v in rec.items() if v is not None or k == "hash"}, tools


def server_record(
    entry: ServerEntry,
    occurrences: list[ServerEntry],
    package: ResolvedPackage,
    surface: Surface | None,
    method: str | None,
    error: str | None,
) -> dict:
    surf, tools = surface_record(surface, method, error)
    rec = {
        "config": entry.canonical(),
        "configHash": entry.config_hash(),
        "sources": [e.source.to_dict() for e in occurrences if e.source],
        "package": package.to_dict(),
        "surface": surf,
        "tools": tools,
    }
    hashes = {e.config_hash() for e in occurrences}
    if len(hashes) > 1:
        rec["configDrift"] = [
            {**e.source.to_dict(), "configHash": e.config_hash()} for e in occurrences if e.source
        ]
    return rec


def build_lock(servers: dict[str, dict], generated_at: str | None = None) -> dict:
    return {
        "lockfileVersion": LOCKFILE_VERSION,
        "notice": LIMITATION_NOTICE,
        "approval": {
            "generatedAt": generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "caplockVersion": __version__,
        },
        "servers": {name: servers[name] for name in sorted(servers)},
    }


def content_of(lock: dict) -> dict:
    """The lock without approval metadata (used to decide whether anything changed)."""
    return {k: v for k, v in lock.items() if k != "approval"}


def dumps(lock: dict) -> str:
    text = json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return escape_invisible(text) + "\n"


def write(path: Path, lock: dict) -> None:
    validate(lock)
    Path(path).write_text(dumps(lock), encoding="utf-8")


def load(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise LockfileError(f"{path}: not readable JSON ({e})") from None
    validate(data)
    return data


# --------------------------------------------------------------------------- validation


def _req(obj: dict, key: str, types, where: str):
    if not isinstance(obj, dict) or key not in obj:
        raise LockfileError(f"{where}: missing '{key}'")
    if not isinstance(obj[key], types):
        raise LockfileError(f"{where}.{key}: wrong type")
    return obj[key]


def validate(lock: dict) -> None:
    if not isinstance(lock, dict):
        raise LockfileError("lockfile: top level must be an object")
    version = _req(lock, "lockfileVersion", int, "lockfile")
    if version != LOCKFILE_VERSION:
        raise LockfileError(f"lockfile: unsupported lockfileVersion {version} (expected {LOCKFILE_VERSION})")
    approval = _req(lock, "approval", dict, "lockfile")
    _req(approval, "generatedAt", str, "approval")
    _req(approval, "caplockVersion", str, "approval")
    servers = _req(lock, "servers", dict, "lockfile")
    for name, s in servers.items():
        w = f"servers.{name}"
        if not isinstance(s, dict):
            raise LockfileError(f"{w}: must be an object")
        cfg = _req(s, "config", dict, w)
        if _req(cfg, "transport", str, f"{w}.config") not in ("stdio", "http"):
            raise LockfileError(f"{w}.config.transport: invalid")
        h = _req(s, "configHash", str, w)
        if not h.startswith("sha256:"):
            raise LockfileError(f"{w}.configHash: invalid")
        _req(s, "sources", list, w)
        pkg = _req(s, "package", dict, w)
        if _req(pkg, "status", str, f"{w}.package") not in PACKAGE_STATUSES:
            raise LockfileError(f"{w}.package.status: invalid")
        _req(pkg, "ecosystem", str, f"{w}.package")
        if pkg["status"] == "resolved":
            _req(pkg, "integrity", str, f"{w}.package")
            if pkg["ecosystem"] == "pypi":
                iset = _req(pkg, "integritySet", list, f"{w}.package")
                files = [e.get("file") if isinstance(e, dict) else None for e in iset]
                if not iset or not all(isinstance(e, dict) and isinstance(e.get("file"), str)
                                       and isinstance(e.get("sha256"), str) for e in iset):
                    raise LockfileError(f"{w}.package.integritySet: entries must be {{file, sha256}}")
                if files != sorted(files) or len(set(files)) != len(files):
                    raise LockfileError(f"{w}.package.integritySet: must be sorted by file without duplicates")
                if sha256_of(iset) != pkg["integrity"]:
                    raise LockfileError(f"{w}.package.integrity: does not match integritySet")
        surf = _req(s, "surface", dict, w)
        if _req(surf, "status", str, f"{w}.surface") not in SURFACE_STATUSES:
            raise LockfileError(f"{w}.surface.status: invalid")
        tools = _req(s, "tools", dict, w)
        if surf["status"] == "enumerated":
            _req(surf, "hash", str, f"{w}.surface")
        for tname, t in tools.items():
            tw = f"{w}.tools.{tname}"
            d = _req(t, "definition", dict, tw)
            th = _req(t, "hash", str, tw)
            if sha256_of(d) != th:
                raise LockfileError(f"{tw}.hash: does not match the recorded definition")
            if d.get("name") != tname:
                raise LockfileError(f"{tw}: definition name mismatch")
            cap = _req(t, "capability", dict, tw)
            _req(cap, "capabilities", list, f"{tw}.capability")
            _req(cap, "evidence", list, f"{tw}.capability")
        if surf["status"] == "enumerated" and surface_hash({n: t["hash"] for n, t in tools.items()}) != surf["hash"]:
            raise LockfileError(f"{w}.surface.hash: does not match the recorded tools")
