"""Discovery and normalization of MCP server configuration files.

Supported formats:

* ``vscode``   – ``.vscode/mcp.json`` with top-level ``servers`` (JSONC allowed).
* ``portable`` – ``.mcp.json`` or an explicitly given file with top-level
  ``mcpServers`` (Copilot portable / Claude Desktop / Cursor shape).

Secrets are never carried into the model: env and header *values* are
dropped (key names only), URL credentials and query values are redacted,
and argument values that look like secrets are replaced by ``<redacted>``.
VS Code ``${input:...}`` / ``${env:...}`` references are kept unresolved and
flagged as requiring interactive input.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlunsplit, quote

from caplock.canonical import sha256_of

REDACTED = "<redacted>"

VSCODE_PATH = Path(".vscode") / "mcp.json"
PORTABLE_PATH = Path(".mcp.json")

_INPUT_REF = re.compile(r"\$\{input:([^}]+)\}")
_ENV_REF = re.compile(r"\$\{env:([^}]+)\}")

# Flags whose following argument (or ``=value``) is treated as a secret.
_SECRET_FLAG = re.compile(
    r"^--?(?:[a-z0-9]+[-_])*(?:token|api[-_]?key|apikey|secret|password|passwd|pwd|auth|"
    r"authorization|credentials?|access[-_]?key|private[-_]?key|bearer|cookie|session)$",
    re.IGNORECASE,
)
# Well-known token shapes.
_SECRET_VALUE = re.compile(
    r"^(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_\-]{16,}|"
    r"xox[abposr]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30,}|"
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})$"
)
_HIGH_ENTROPY = re.compile(r"^[A-Za-z0-9_\-+=]{32,}$")
_DOCKER_ENV_FLAGS = {"-e", "--env"}


class ConfigError(ValueError):
    pass


@dataclass
class ConfigSource:
    path: str  # workspace-relative when possible, posix separators
    format: str  # "vscode" | "portable"

    def to_dict(self) -> dict:
        return {"path": self.path, "format": self.format}


@dataclass
class ServerEntry:
    name: str
    transport: str  # "stdio" | "http"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)
    env_file: str | None = None
    url: str | None = None
    header_keys: list[str] = field(default_factory=list)
    interactive_inputs: list[str] = field(default_factory=list)
    env_refs: list[str] = field(default_factory=list)
    source: ConfigSource | None = None
    raw_type: str | None = None

    @property
    def requires_interactive_input(self) -> bool:
        return bool(self.interactive_inputs)

    def canonical(self) -> dict:
        """Source-independent normalized representation (no secret values)."""
        d = {
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "envKeys": sorted(self.env_keys),
            "envFile": self.env_file,
            "url": self.url,
            "headerKeys": sorted(self.header_keys),
            "interactiveInputs": sorted(self.interactive_inputs),
            "requiresInteractiveInput": self.requires_interactive_input,
        }
        return {k: v for k, v in d.items() if v not in (None, [])}

    def config_hash(self) -> str:
        return sha256_of(self.canonical())


@dataclass
class Discovery:
    entries: dict[str, ServerEntry]  # winning entry per server name
    occurrences: dict[str, list[ServerEntry]]  # every occurrence, in discovery order
    sources: list[ConfigSource]
    errors: list[str]

    @property
    def drift(self) -> dict[str, list[ServerEntry]]:
        """Server names that appear in several files with differing content."""
        out = {}
        for name, occ in self.occurrences.items():
            if len({e.config_hash() for e in occ}) > 1:
                out[name] = occ
        return out


# --------------------------------------------------------------------------- JSONC


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside of strings."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    no_comments = "".join(out)
    # trailing commas: , followed by whitespace and } or ] (outside strings)
    result = []
    in_str = False
    i, n = 0, len(no_comments)
    while i < n:
        c = no_comments[i]
        if in_str:
            result.append(c)
            if c == "\\" and i + 1 < n:
                result.append(no_comments[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == ",":
            j = i + 1
            while j < n and no_comments[j] in " \t\r\n":
                j += 1
            if j < n and no_comments[j] in "}]":
                i += 1
                continue
        result.append(c)
        i += 1
    return "".join(result)


def load_jsonc(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(strip_jsonc(text))
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON ({e.msg} at line {e.lineno})") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be an object")
    return data


# --------------------------------------------------------------------------- redaction


def _refs(text: str) -> tuple[list[str], list[str]]:
    return _INPUT_REF.findall(text), _ENV_REF.findall(text)


def looks_secret(value: str) -> bool:
    if _INPUT_REF.search(value) or _ENV_REF.search(value):
        return False  # unresolved references are not secrets themselves
    if _SECRET_VALUE.match(value):
        return True
    if _HIGH_ENTROPY.match(value):
        has_digit = any(c.isdigit() for c in value)
        has_alpha = any(c.isalpha() for c in value)
        return has_digit and has_alpha
    return False


def redact_args(args: list[str]) -> list[str]:
    out: list[str] = []
    redact_next = False
    env_next = False
    for a in args:
        if redact_next:
            out.append(a if _is_ref_only(a) else REDACTED)
            redact_next = False
            continue
        if env_next:
            out.append(_redact_kv(a))
            env_next = False
            continue
        if a.startswith("-") and "=" in a:
            flag, _, val = a.partition("=")
            if _SECRET_FLAG.match(flag):
                out.append(f"{flag}={val if _is_ref_only(val) else REDACTED}")
                continue
            if flag in _DOCKER_ENV_FLAGS:
                out.append(f"{flag}={_redact_kv(val)}")
                continue
        if _SECRET_FLAG.match(a):
            out.append(a)
            redact_next = True
            continue
        if a in _DOCKER_ENV_FLAGS:
            out.append(a)
            env_next = True
            continue
        if re.match(r"^[A-Z_][A-Z0-9_]*=(?!=)", a):
            # KEY=value style positional (e.g. env assignments)
            out.append(_redact_kv(a))
            continue
        out.append(REDACTED if looks_secret(a) else a)
    return out


def _is_ref_only(v: str) -> bool:
    return bool(_INPUT_REF.fullmatch(v) or _ENV_REF.fullmatch(v))


def _redact_kv(a: str) -> str:
    if "=" not in a:
        return a  # `-e KEY` passes the variable through by name
    k, _, v = a.partition("=")
    return f"{k}={v if _is_ref_only(v) else REDACTED}"


def redact_url(url: str) -> str:
    """Keep scheme/host/port/path; drop credentials and fragment; redact query values
    and path segments that look like tokens."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    segs = [REDACTED if looks_secret(s) else s for s in parts.path.split("/")]
    path = "/".join(segs)
    query = ""
    if parts.query:
        keys = [k for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
        query = "&".join(f"{quote(k)}={REDACTED}" for k in keys)
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def url_host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if host and parts.port:
            return f"{host}:{parts.port}"
        return host
    except ValueError:
        return None


# --------------------------------------------------------------------------- parsing


def _transport(raw: dict) -> tuple[str, str | None]:
    t = raw.get("type")
    t_norm = t.lower() if isinstance(t, str) else None
    if t_norm in ("stdio", "local"):
        return "stdio", t
    if t_norm in ("http", "sse", "streamable-http", "streamablehttp", "remote"):
        return "http", t
    if "url" in raw or "serverUrl" in raw:
        return "http", t
    if "command" in raw:
        return "stdio", t
    raise ConfigError(f"cannot determine transport (type={t!r})")


def parse_server(name: str, raw: dict, source: ConfigSource) -> ServerEntry:
    if not isinstance(raw, dict):
        raise ConfigError(f"server {name!r}: entry must be an object")
    transport, raw_type = _transport(raw)
    entry = ServerEntry(name=name, transport=transport, source=source, raw_type=raw_type)
    inputs: list[str] = []
    env_refs: list[str] = []

    def collect(text: object) -> None:
        if isinstance(text, str):
            i, e = _refs(text)
            inputs.extend(i)
            env_refs.extend(e)

    if transport == "stdio":
        cmd = raw.get("command")
        if not isinstance(cmd, str) or not cmd:
            raise ConfigError(f"server {name!r}: stdio entry needs a command")
        args = raw.get("args") or []
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ConfigError(f"server {name!r}: args must be a list of strings")
        collect(cmd)
        for a in args:
            collect(a)
        entry.command = cmd
        entry.args = redact_args(args)
        env = raw.get("env") or {}
        if not isinstance(env, dict):
            raise ConfigError(f"server {name!r}: env must be an object")
        entry.env_keys = sorted(env.keys())
        for v in env.values():
            collect(v)
        env_file = raw.get("envFile")
        if isinstance(env_file, str):
            entry.env_file = env_file
    else:
        url = raw.get("url") or raw.get("serverUrl")
        if not isinstance(url, str) or not url:
            raise ConfigError(f"server {name!r}: http entry needs a url")
        collect(url)
        entry.url = redact_url(url)
        headers = raw.get("headers") or {}
        if not isinstance(headers, dict):
            raise ConfigError(f"server {name!r}: headers must be an object")
        entry.header_keys = sorted(headers.keys())
        for v in headers.values():
            collect(v)
    entry.interactive_inputs = sorted(set(inputs))
    entry.env_refs = sorted(set(env_refs))
    return entry


def detect_format(data: dict) -> str:
    if "servers" in data and isinstance(data["servers"], dict):
        return "vscode"
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        return "portable"
    raise ConfigError("no top-level 'servers' or 'mcpServers' object")


def parse_config_file(path: Path, rel: str, fmt: str | None = None) -> list[ServerEntry]:
    data = load_jsonc(path)
    fmt = fmt or detect_format(data)
    key = "servers" if fmt == "vscode" else "mcpServers"
    servers = data.get(key)
    if not isinstance(servers, dict):
        raise ConfigError(f"{rel}: expected top-level {key!r} object for {fmt} format")
    source = ConfigSource(path=rel, format=fmt)
    entries = []
    for name, raw in servers.items():
        try:
            entries.append(parse_server(name, raw, source))
        except ConfigError as e:
            raise ConfigError(f"{rel}: {e}") from None
    return entries


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def discover(workspace: Path, extra_configs: list[Path] | None = None) -> Discovery:
    """Find and normalize configs. Priority: .vscode/mcp.json, .mcp.json, extras."""
    workspace = Path(workspace)
    candidates: list[tuple[Path, str | None]] = []
    if (workspace / VSCODE_PATH).is_file():
        candidates.append((workspace / VSCODE_PATH, "vscode"))
    if (workspace / PORTABLE_PATH).is_file():
        candidates.append((workspace / PORTABLE_PATH, "portable"))
    for p in extra_configs or []:
        p = Path(p)
        if not p.is_absolute():
            p = workspace / p
        candidates.append((p, None))

    entries: dict[str, ServerEntry] = {}
    occurrences: dict[str, list[ServerEntry]] = {}
    sources: list[ConfigSource] = []
    errors: list[str] = []
    seen_paths: set[Path] = set()
    for path, fmt in candidates:
        rp = path.resolve()
        if rp in seen_paths:
            continue
        seen_paths.add(rp)
        rel = _rel(path, workspace)
        if not path.is_file():
            errors.append(f"{rel}: config file not found")
            continue
        try:
            parsed = parse_config_file(path, rel, fmt)
        except ConfigError as e:
            errors.append(str(e))
            continue
        if parsed:
            sources.append(parsed[0].source)  # type: ignore[arg-type]
        else:
            sources.append(ConfigSource(path=rel, format=fmt or "unknown"))
        for e in parsed:
            occurrences.setdefault(e.name, []).append(e)
            entries.setdefault(e.name, e)
    return Discovery(entries=entries, occurrences=occurrences, sources=sources, errors=errors)
