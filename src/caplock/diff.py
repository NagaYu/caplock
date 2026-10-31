"""Semantic diff (first version) between a lockfile and the current state.

Both sides are lock-shaped dicts (``lockfile.server_record`` output), so the
same code compares "old lockfile vs re-locked state" (``caplock lock``) and
"lockfile vs reconstructed state" (``caplock verify`` / ``caplock diff``).

Severities: ``critical`` > ``high`` > ``medium`` > ``info``, plus
``unverifiable`` for anything that could not be checked. Formatting / key
order only changes never produce findings (hashes are over canonical forms).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from caplock.canonical import find_invisible_chars
from caplock.config_discovery import url_host

SEVERITIES = ("critical", "high", "medium", "info")
RANK = {"unverifiable": 0, "critical": 1, "high": 2, "medium": 3, "info": 4}
ESCALATING_CAPS = ("write", "destructive", "exec", "network")

# Known, simple instruction-injection shapes only (kept narrow to avoid false positives).
INSTRUCTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("hidden-instruction-tag",
     re.compile(r"<\s*/?\s*(?:important|system|instructions?|secret|hidden)\s*>", re.I)),
    ("ignore-previous-instructions",
     re.compile(r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+"
                r"(?:instructions|prompts?|rules)\b", re.I)),
    ("conceal-from-user",
     re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|notify)\b[^.]{0,40}\buser\b|"
                r"\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+user\b", re.I)),
    ("sensitive-file-reference",
     re.compile(r"~/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|~/\.aws/credentials|/etc/(?:passwd|shadow)\b|"
                r"\bmcp\.json\b|~/\.cursor/|\bclaude_desktop_config\.json\b", re.I)),
]


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    server: str | None = None
    tool: str | None = None
    field: str | None = None
    before: Any = None
    after: Any = None

    @property
    def unverifiable(self) -> bool:
        return self.severity == "unverifiable"

    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (RANK[f.severity], f.server or "", f.tool or "", f.code))


FAIL_ON = ("info", "medium", "high", "critical", "never")


def exit_code(findings: list[Finding], fail_on: str = "high") -> int:
    """2 if anything is unverifiable (always, whatever ``fail_on`` says), else 1 if any
    finding is at or above the ``fail_on`` threshold, else 0."""
    if fail_on not in FAIL_ON:
        raise ValueError(f"fail_on must be one of {FAIL_ON}")
    if any(f.unverifiable for f in findings):
        return 2
    if fail_on != "never" and any(RANK[f.severity] <= RANK[fail_on] for f in findings):
        return 1
    return 0


# --------------------------------------------------------------------------- content scans


def _strings(value: Any, path: str = ""):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}" if path else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")


def find_instruction_patterns(definition: dict) -> list[dict]:
    out = []
    for path, text in _strings(definition):
        if path == "name":
            continue
        for label, pat in INSTRUCTION_PATTERNS:
            m = pat.search(text)
            if m:
                out.append({"path": path, "pattern": label, "match": m.group(0)})
    return out


# --------------------------------------------------------------------------- assess (state only)


def assess(servers: dict[str, dict], *, content_flags: bool) -> list[Finding]:
    """Findings that depend only on one state: what cannot be verified, plus
    (when ``content_flags``) suspicious content in the whole surface."""
    out: list[Finding] = []
    for name, s in servers.items():
        pkg = s["package"]
        st = pkg["status"]
        if st == "floating":
            out.append(Finding("floating_version", "unverifiable", server=name, field="package",
                               after=pkg.get("requested"),
                               message=f"{pkg.get('name')} is not pinned ({pkg.get('floatingReason')}); "
                                       "the code that runs can change at any launch"))
        elif st == "manual":
            out.append(Finding("package_unresolvable", "unverifiable", server=name, field="package",
                               message=f"package cannot be identified: {pkg.get('detail')}"))
        elif st == "unrecorded":
            out.append(Finding("integrity_unrecorded", "unverifiable", server=name, field="package.integrity",
                               message=f"integrity of {pkg.get('name')}@{pkg.get('version')} is not recorded: "
                                       f"{pkg.get('detail')}"))
        elif st == "remote":
            out.append(Finding("remote_entity_unverifiable", "unverifiable", server=name, field="package",
                               message="remote (http) server: the code behind the URL cannot be pinned; "
                                       "only its recorded surface is compared"))
        surf = s["surface"]
        if surf["status"] == "failed":
            out.append(Finding("enumeration_failed", "unverifiable", server=name, field="surface",
                               message=f"surface could not be enumerated: {surf.get('error')}"))
        elif surf["status"] == "not_enumerated":
            out.append(Finding("surface_not_enumerated", "unverifiable", server=name, field="surface",
                               message="no surface source (use --launch, --allow-launch or --surface)"))
        if s["config"].get("requiresInteractiveInput"):
            out.append(Finding("interactive_input_required", "info", server=name, field="config",
                               after=s["config"].get("interactiveInputs"),
                               message="config uses ${input:...} values that are left unresolved"))
        if s.get("configDrift"):
            out.append(Finding("config_drift", "medium", server=name, field="config",
                               after=[f"{d['path']} ({d['configHash'][:15]}…)" for d in s["configDrift"]],
                               message="server is defined differently in several config files; "
                                       f"the first ({s['sources'][0]['path']}) is used"))
        if content_flags:
            for tname, t in s.get("tools", {}).items():
                for fl in t.get("flags", []):
                    code = "invisible_chars" if fl["kind"] == "invisible_chars" else "instruction_injection"
                    out.append(Finding(code, "high", server=name, tool=tname, field=fl["path"],
                                       after=fl["detail"],
                                       message=f"{fl['kind'].replace('_', ' ')} in tool definition: {fl['detail']}"))
    return out


# --------------------------------------------------------------------------- diff (old vs new)


def diff_states(old: dict[str, dict], new: dict[str, dict]) -> list[Finding]:
    out: list[Finding] = []
    for name in sorted(set(old) - set(new)):
        out.append(Finding("server_removed", "medium", server=name,
                           message="server is no longer configured"))
    for name in sorted(set(new) - set(old)):
        tools = new[name].get("tools", {})
        caps = sorted({c for t in tools.values() for c in t["capability"]["capabilities"]})
        out.append(Finding("server_added", "high", server=name, after=sorted(tools),
                           message=f"new server with {len(tools)} tool(s), capabilities: {', '.join(caps) or 'none'}"))
    for name in sorted(set(old) & set(new)):
        out.extend(diff_server(name, old[name], new[name]))
    return out


def diff_server(name: str, o: dict, n: dict) -> list[Finding]:
    from caplock.resolve import args_without_version

    out: list[Finding] = []
    oc, nc = o["config"], n["config"]

    # ---- config
    if oc.get("transport") != nc.get("transport"):
        out.append(Finding("config_changed", "high", server=name, field="config.transport",
                           before=oc.get("transport"), after=nc.get("transport"),
                           message="transport changed"))
    oh, nh = url_host(oc.get("url")), url_host(nc.get("url"))
    if oh != nh and (oh or nh):
        out.append(Finding("remote_host_changed", "critical", server=name, field="config.url",
                           before=oh, after=nh, message=f"connection host changed: {oh} → {nh}"))
    elif oc.get("url") != nc.get("url"):
        out.append(Finding("config_changed", "medium", server=name, field="config.url",
                           before=oc.get("url"), after=nc.get("url"), message="URL path or query keys changed"))
    if oc.get("command") != nc.get("command"):
        out.append(Finding("config_changed", "high", server=name, field="config.command",
                           before=oc.get("command"), after=nc.get("command"), message="launch command changed"))
    elif args_without_version(oc.get("command"), oc.get("args", [])) != args_without_version(
        nc.get("command"), nc.get("args", [])
    ):
        out.append(Finding("config_changed", "medium", server=name, field="config.args",
                           before=oc.get("args"), after=nc.get("args"), message="launch arguments changed"))
    for key, label in (("envKeys", "environment variable"), ("headerKeys", "header")):
        added = sorted(set(nc.get(key, [])) - set(oc.get(key, [])))
        removed = sorted(set(oc.get(key, [])) - set(nc.get(key, [])))
        if added:
            out.append(Finding("config_changed", "medium", server=name, field=f"config.{key}", after=added,
                               message=f"{label} key(s) added: {', '.join(added)}"))
        if removed:
            out.append(Finding("config_changed", "info", server=name, field=f"config.{key}", before=removed,
                               message=f"{label} key(s) removed: {', '.join(removed)}"))
    if oc.get("envFile") != nc.get("envFile"):
        out.append(Finding("config_changed", "medium", server=name, field="config.envFile",
                           before=oc.get("envFile"), after=nc.get("envFile"), message="envFile changed"))

    # ---- package
    op, np_ = o["package"], n["package"]
    if op["status"] not in ("resolved", "remote"):
        if np_["status"] in ("resolved", "remote"):  # otherwise assess() already reports it
            out.append(Finding("lock_incomplete", "unverifiable", server=name, field="package",
                               message=f"lockfile has no pinned integrity for this server (locked as "
                                       f"'{op['status']}'); re-run caplock lock to record it"))
    elif (op.get("ecosystem"), op.get("name")) != (np_.get("ecosystem"), np_.get("name")) and np_["status"] != "manual":
        out.append(Finding("package_changed", "critical", server=name, field="package.name",
                           before=f"{op.get('ecosystem')}:{op.get('name')}",
                           after=f"{np_.get('ecosystem')}:{np_.get('name')}",
                           message="a different package is now launched"))
    elif np_["status"] == "resolved" and op["status"] == "resolved":
        if op.get("version") == np_.get("version"):
            if op.get("integrity") != np_.get("integrity"):
                before, after = op.get("integrity"), np_.get("integrity")
                detail = ""
                if "integritySet" in op and "integritySet" in np_:
                    before, after, detail = _integrity_set_delta(op["integritySet"], np_["integritySet"])
                out.append(Finding("integrity_mismatch", "critical", server=name, field="package.integrity",
                                   before=before, after=after,
                                   message=f"{np_.get('name')}@{np_.get('version')} now resolves to different "
                                           f"content although the version is unchanged{detail}"))
        else:
            same_surface = o["surface"].get("hash") == n["surface"].get("hash") and n["surface"]["status"] == "enumerated"
            out.append(Finding("version_changed", "info", server=name, field="package.version",
                               before=op.get("version"), after=np_.get("version"),
                               message=f"version {op.get('version')} → {np_.get('version')}"
                                       + (" (tool surface unchanged)" if same_surface else "")))

    # ---- surface
    os_, ns = o["surface"], n["surface"]
    if os_["status"] != "enumerated":
        if ns["status"] == "enumerated":  # otherwise assess() already reports it
            out.append(Finding("lock_incomplete", "unverifiable", server=name, field="surface",
                               message=f"lockfile has no recorded surface (locked as '{os_['status']}'); "
                                       "re-run caplock lock to record it"))
        return out
    if ns["status"] != "enumerated":
        return out  # reported by assess()
    if os_.get("method") != ns.get("method"):
        out.append(Finding("surface_source_changed", "info", server=name, field="surface.method",
                           before=os_.get("method"), after=ns.get("method"),
                           message="surface was obtained differently than at lock time"))
    for key, label in (("resourcesHash", "resources/list content"), ("promptsHash", "prompts/list content"),
                       ("instructionsHash", "server instructions")):
        if os_.get(key) != ns.get(key):
            state = "appeared" if key not in os_ else "disappeared" if key not in ns else "changed"
            out.append(Finding("auxiliary_changed", "medium", server=name, field=f"surface.{key}",
                               message=f"{label} {state}"))
    if os_.get("hash") == ns.get("hash"):
        return out
    ot, nt = o.get("tools", {}), n.get("tools", {})
    for tname in sorted(set(nt) - set(ot)):
        rec = nt[tname]
        caps = rec["capability"]["capabilities"]
        out.append(Finding("tool_added", "high", server=name, tool=tname, after=caps,
                           message=f"new tool (capabilities: {', '.join(caps)})"))
        out.extend(_content_findings(name, tname, {}, rec["definition"]))
    for tname in sorted(set(ot) - set(nt)):
        out.append(Finding("tool_removed", "medium", server=name, tool=tname,
                           before=ot[tname]["capability"]["capabilities"], message="tool was removed"))
    for tname in sorted(set(ot) & set(nt)):
        if ot[tname]["hash"] != nt[tname]["hash"]:
            out.extend(diff_tool(name, tname, ot[tname], nt[tname]))
    return out


def _integrity_set_delta(old: list[dict], new: list[dict]) -> tuple[list, list, str]:
    """Only the per-file entries that differ, plus a short summary for the message."""
    o = {e["file"]: e["sha256"] for e in old}
    n = {e["file"]: e["sha256"] for e in new}
    changed = sorted(f for f in o.keys() & n.keys() if o[f] != n[f])
    removed = sorted(o.keys() - n.keys())
    added = sorted(n.keys() - o.keys())
    parts = [f"{label}: {', '.join(files)}" for label, files in
             (("changed", changed), ("added", added), ("removed", removed)) if files]
    before = [{"file": f, "sha256": o[f]} for f in sorted(set(changed) | set(removed))]
    after = [{"file": f, "sha256": n[f]} for f in sorted(set(changed) | set(added))]
    return before, after, (" (" + "; ".join(parts) + ")") if parts else ""


def _content_findings(server: str, tool: str, before: dict, after: dict) -> list[Finding]:
    out = []
    old_pat = {(p["path"], p["pattern"]) for p in find_instruction_patterns(before)}
    for p in find_instruction_patterns(after):
        if (p["path"], p["pattern"]) not in old_pat:
            out.append(Finding("instruction_injection", "high", server=server, tool=tool, field=p["path"],
                               after=p["match"],
                               message=f"instruction-like text appeared ({p['pattern']}): {p['match']!r}"))
    old_inv = Counter((f["path"], f["codepoint"]) for f in find_invisible_chars(before))
    new_inv = Counter((f["path"], f["codepoint"]) for f in find_invisible_chars(after))
    for (path, cp), cnt in sorted((new_inv - old_inv).items()):
        out.append(Finding("invisible_chars", "high", server=server, tool=tool, field=path, after=cp,
                           message=f"invisible character {cp} appeared (x{cnt})"))
    return out


def _schema_parts(d: dict) -> tuple[dict, set, dict]:
    s = d.get("inputSchema") if isinstance(d.get("inputSchema"), dict) else {}
    props = s.get("properties") if isinstance(s.get("properties"), dict) else {}
    req = set(s.get("required") or []) if isinstance(s.get("required"), list) else set()
    rest = {k: v for k, v in s.items() if k not in ("properties", "required")}
    return props, req, rest


def diff_tool(server: str, tool: str, o: dict, n: dict) -> list[Finding]:
    out: list[Finding] = []
    od, nd = o["definition"], n["definition"]

    def F(code, sev, msg, field=None, before=None, after=None):
        out.append(Finding(code, sev, msg, server=server, tool=tool, field=field, before=before, after=after))

    out.extend(_content_findings(server, tool, od, nd))

    if od.get("title") != nd.get("title"):
        F("title_changed", "medium", "title changed", "title", od.get("title"), nd.get("title"))
    if od.get("description") != nd.get("description"):
        F("description_changed", "medium", "description changed", "description",
          od.get("description"), nd.get("description"))

    # ---- inputSchema
    op, oreq, orest = _schema_parts(od)
    np_, nreq, nrest = _schema_parts(nd)
    for p in sorted(set(np_) - set(op)):
        if p in nreq:
            F("required_param_added", "high", f"new required parameter '{p}'", f"inputSchema.properties.{p}",
              after=np_[p])
        else:
            F("optional_param_added", "medium", f"new optional parameter '{p}'", f"inputSchema.properties.{p}",
              after=np_[p])
    for p in sorted(set(op) - set(np_)):
        F("param_removed", "medium", f"parameter '{p}' removed", f"inputSchema.properties.{p}", before=op[p])
    for p in sorted(set(op) & set(np_)):
        if p in nreq and p not in oreq:
            F("required_param_added", "high", f"parameter '{p}' is now required", "inputSchema.required",
              before=sorted(oreq), after=sorted(nreq))
        elif p in oreq and p not in nreq:
            F("schema_changed", "medium", f"parameter '{p}' is no longer required", "inputSchema.required",
              before=sorted(oreq), after=sorted(nreq))
        if op[p] != np_[p]:
            F("schema_changed", "medium", f"definition of parameter '{p}' changed",
              f"inputSchema.properties.{p}", op[p], np_[p])
    for k in sorted(set(orest) | set(nrest)):
        if orest.get(k) != nrest.get(k):
            F("schema_changed", "medium", f"inputSchema.{k} changed", f"inputSchema.{k}", orest.get(k), nrest.get(k))
    if od.get("outputSchema") != nd.get("outputSchema"):
        F("output_schema_changed", "medium", "outputSchema changed", "outputSchema",
          od.get("outputSchema"), nd.get("outputSchema"))

    # ---- annotations
    oa = od.get("annotations") if isinstance(od.get("annotations"), dict) else {}
    na = nd.get("annotations") if isinstance(nd.get("annotations"), dict) else {}
    handled = set()
    if oa.get("readOnlyHint") is True and na.get("readOnlyHint") is not True:
        F("annotation_readonly_revoked", "critical", "readOnlyHint true → "
          + ("false" if na.get("readOnlyHint") is False else "absent (defaults to false)"),
          "annotations.readOnlyHint", True, na.get("readOnlyHint"))
        handled.add("readOnlyHint")
    if na.get("destructiveHint") is True and oa.get("destructiveHint") is not True:
        F("annotation_destructive_added", "critical", "destructiveHint is now true",
          "annotations.destructiveHint", oa.get("destructiveHint"), True)
        handled.add("destructiveHint")
    for k in sorted((set(oa) | set(na)) - handled):
        if oa.get(k) != na.get(k):
            F("annotation_changed", "medium", f"annotations.{k} changed", f"annotations.{k}", oa.get(k), na.get(k))

    # ---- capability
    oc, nc = o["capability"], n["capability"]
    ocs, ncs = set(oc["capabilities"]), set(nc["capabilities"])
    added = ncs - ocs - {"unknown"}
    for cap in sorted(added, key=lambda c: ESCALATING_CAPS.index(c) if c in ESCALATING_CAPS else -1):
        if cap in ESCALATING_CAPS:
            ev = [e["source"] for e in nc["evidence"] if e["capability"] == cap]
            F("capability_expanded", "critical", f"capability '{cap}' added (evidence: {', '.join(ev)})",
              "capability", sorted(ocs), sorted(ncs))
        else:
            F("capability_changed", "info", f"capability '{cap}' added", "capability", sorted(ocs), sorted(ncs))
    if ncs == {"unknown"} and ocs != {"unknown"}:
        F("capability_unknown", "high", "classification evidence disappeared; capability is now unknown",
          "capability", sorted(ocs), sorted(ncs))
    removed = ocs - ncs - {"unknown"}
    if removed:
        F("capability_reduced", "info", f"capability removed: {', '.join(sorted(removed))}", "capability",
          sorted(ocs), sorted(ncs))
    oh, nh = set(oc.get("networkHosts", [])), set(nc.get("networkHosts", []))
    if nh - oh:
        F("network_host_added", "critical", f"new network target host(s): {', '.join(sorted(nh - oh))}",
          "capability.networkHosts", sorted(oh), sorted(nh))
    if oh - nh:
        F("network_host_removed", "info", f"network target host(s) removed: {', '.join(sorted(oh - nh))}",
          "capability.networkHosts", sorted(oh), sorted(nh))
    return out
