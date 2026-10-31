"""Deterministic capability classification of tools.

A tool's capability set is the unit of approval. It is derived from fixed
rules over four inputs, and every rule that fires is recorded as evidence:

1. ``annotations`` – only *explicitly present* hints count (MCP defaults such
   as ``destructiveHint: true`` are not assumed, and hints are self-declared
   by the server):
     readOnlyHint=true → read, readOnlyHint=false → write,
     destructiveHint=true (and readOnlyHint not true) → destructive,
     openWorldHint=true → network.
2. Tool name tokens (snake/camel/kebab split) against fixed verb tables.
3. ``inputSchema`` property names / ``format`` (destination-like → network,
   command-like → exec).
4. Description: the leading verb, a few fixed phrases, and literal URLs
   (whose hosts are recorded as network targets).

Rules only add capabilities; nothing is removed or "upgraded" by inference.
When no rule fires the result is ``unknown``. Contradictions (e.g.
readOnlyHint=true with a destructive verb) are kept in ``conflicts``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ORDER = ("read", "write", "destructive", "exec", "network", "unknown")

NAME_VERBS: dict[str, set[str]] = {
    "read": {"get", "list", "read", "search", "find", "query", "show", "view", "describe",
             "lookup", "retrieve", "count", "inspect", "stat", "check", "cat", "head", "tail"},
    "write": {"create", "write", "update", "set", "add", "put", "edit", "modify", "save",
              "insert", "upload", "append", "rename", "move", "patch", "upsert", "commit",
              "send", "publish", "post", "push", "merge", "replace", "submit", "reply", "comment"},
    "destructive": {"delete", "remove", "drop", "destroy", "purge", "erase", "truncate", "wipe",
                    "rm", "unlink", "kill", "terminate", "revoke", "overwrite", "format"},
    "exec": {"exec", "execute", "eval", "shell", "bash", "spawn", "subprocess", "terminal",
             "cmd", "command", "sh", "powershell", "zsh", "repl"},
    "network": {"fetch", "http", "https", "url", "download", "upload", "webhook", "curl", "wget",
                "browse", "scrape", "crawl", "email", "mail", "smtp", "send", "slack", "tweet",
                "request", "api"},
}

NETWORK_PROPS = {"url", "uri", "urls", "endpoint", "host", "hostname", "webhook", "callback",
                 "recipient", "recipients", "email", "emails", "cc", "bcc", "forward", "domain"}
NETWORK_FORMATS = {"uri", "url", "iri", "email", "idn-email", "hostname", "idn-hostname", "uri-reference"}
EXEC_PROPS = {"command", "cmd", "script", "shell", "argv"}

DESC_PHRASES: list[tuple[str, re.Pattern]] = [
    ("exec", re.compile(r"\b(?:shell|terminal|system) commands?\b|\bexecut\w* (?:a |an |the |arbitrary )?"
                        r"(?:shell )?(?:command|code|script|program)s?\b|\bruns? (?:a |an |the |arbitrary )?"
                        r"(?:shell )?(?:command|script)s?\b")),
    ("destructive", re.compile(r"\b(?:permanently|irreversibl[ey]|cannot be undone)\b")),
    ("network", re.compile(r"\bsends? (?:an? )?(?:e-?mail|message|request|webhook)s?\b|\bhttp requests?\b")),
    ("read", re.compile(r"\bread[- ]only\b|\bdoes not (?:modify|change|write)\b")),
]

_URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE)


def name_tokens(name: str) -> list[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [t for t in re.split(r"[^A-Za-z0-9]+", s.lower()) if t]


def _hosts_in(text: str) -> list[str]:
    out = []
    for m in _URL.finditer(text):
        try:
            h = urlsplit(m.group(0).rstrip(".,;:")).hostname
        except ValueError:
            h = None
        if h:
            out.append(h)
    return out


@dataclass
class CapabilityResult:
    capabilities: list[str]
    network_hosts: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {"capabilities": self.capabilities, "evidence": self.evidence}
        if self.network_hosts:
            d["networkHosts"] = self.network_hosts
        if self.conflicts:
            d["conflicts"] = self.conflicts
        return d


def classify(tool: dict) -> CapabilityResult:
    caps: set[str] = set()
    evidence: list[dict] = []
    hosts: set[str] = set()

    def add(cap: str, source: str, detail: str) -> None:
        caps.add(cap)
        ev = {"capability": cap, "source": source, "detail": detail}
        if ev not in evidence:
            evidence.append(ev)

    # 1. annotations (explicit values only)
    ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    ro = ann.get("readOnlyHint")
    if ro is True:
        add("read", "annotations.readOnlyHint", "true")
    elif ro is False:
        add("write", "annotations.readOnlyHint", "false")
    if ann.get("destructiveHint") is True and ro is not True:
        add("destructive", "annotations.destructiveHint", "true")
    if ann.get("openWorldHint") is True:
        add("network", "annotations.openWorldHint", "true")

    # 2. tool name tokens
    for tok in name_tokens(str(tool.get("name", ""))):
        for cap in ORDER:
            if tok in NAME_VERBS.get(cap, ()):
                add(cap, "name", tok)

    # 3. inputSchema properties
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    for pname in sorted(props):
        pdef = props[pname] if isinstance(props[pname], dict) else {}
        toks = set(name_tokens(pname))
        if toks & NETWORK_PROPS:
            add("network", f"inputSchema.properties.{pname}", "destination-like name")
        fmt = pdef.get("format")
        if isinstance(fmt, str) and fmt in NETWORK_FORMATS:
            add("network", f"inputSchema.properties.{pname}.format", fmt)
        if toks & EXEC_PROPS:
            add("exec", f"inputSchema.properties.{pname}", "command-like name")
        for key in ("default", "const", "enum", "examples"):
            vals = pdef.get(key)
            for v in vals if isinstance(vals, list) else [vals]:
                if isinstance(v, str):
                    for h in _hosts_in(v):
                        hosts.add(h)
                        add("network", f"inputSchema.properties.{pname}.{key}", h)
        if isinstance(pdef.get("description"), str):
            for h in _hosts_in(pdef["description"]):
                hosts.add(h)
                add("network", f"inputSchema.properties.{pname}.description", h)

    # 4. description
    desc = tool.get("description") if isinstance(tool.get("description"), str) else ""
    first = name_tokens(desc.split(None, 1)[0]) if desc.strip() else []
    if first:
        for cap in ORDER:
            if first[0] in NAME_VERBS.get(cap, ()):
                add(cap, "description.leadingVerb", first[0])
    low = desc.lower()
    for cap, pat in DESC_PHRASES:
        m = pat.search(low)
        if m:
            add(cap, "description.phrase", m.group(0))
    for h in _hosts_in(desc):
        hosts.add(h)
        add("network", "description.url", h)

    conflicts = []
    if ro is True:
        for c in ("write", "destructive", "exec"):
            if c in caps:
                conflicts.append(f"annotations.readOnlyHint=true but '{c}' evidence exists")
    if ann.get("openWorldHint") is False and "network" in caps:
        conflicts.append("annotations.openWorldHint=false but 'network' evidence exists")

    if not caps:
        caps.add("unknown")
        evidence.append({"capability": "unknown", "source": "none", "detail": "no rule matched"})

    return CapabilityResult(
        capabilities=[c for c in ORDER if c in caps],
        network_hosts=sorted(hosts),
        evidence=evidence,
        conflicts=conflicts,
    )
