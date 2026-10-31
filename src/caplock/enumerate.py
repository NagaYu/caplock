"""Surface enumeration: a minimal stdio JSON-RPC 2.0 client for MCP.

The client is dual-era, following the MCP stdio backward-compatibility rules
(https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio#backward-compatibility):

* modern (2026-07-28, stateless): probe ``server/discover`` with per-request
  ``_meta``; every later request carries ``_meta`` as well.
* legacy (2025-11-25 and earlier): if the probe gets any error other than a
  recognized modern one, or no answer within the probe timeout, fall back to
  ``initialize`` (version negotiation) → ``notifications/initialized``.

Then ``tools/list`` (follows ``nextCursor``), and optionally
``resources/list`` / ``prompts/list`` (non-fatal).

Launching is only ever done for a command the user explicitly allowed
(``--launch`` / ``--allow-launch``). The child gets a minimal environment
(allow-list plus explicitly passed keys), a timeout per request, and its
stderr is discarded so that nothing it prints can leak into CapLock output.

HTTP servers are not contacted in Phase 1; a recorded ``tools/list``
response can be imported with ``load_recorded_surface``.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from caplock import __version__

# Newest first.
MODERN_PROTOCOL_VERSIONS = ("2026-07-28",)
LEGACY_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
SUPPORTED_PROTOCOL_VERSIONS = MODERN_PROTOCOL_VERSIONS + LEGACY_PROTOCOL_VERSIONS

# Modern JSON-RPC error codes (-32020..-32099 are reserved for the MCP specification).
MODERN_ERROR_CODES = {-32020, -32021, -32022}
UNSUPPORTED_PROTOCOL_VERSION = -32022
PROBE_TIMEOUT = 3.0

ENV_ALLOWLIST = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TEMP", "TMP",
    "SYSTEMROOT", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
)

MAX_PAGES = 100
MAX_LINE_BYTES = 16 * 1024 * 1024


class EnumerationError(Exception):
    pass


class RPCError(EnumerationError):
    def __init__(self, method: str, error: dict):
        self.code = error.get("code")
        self.data = error.get("data")
        super().__init__(f"{method}: JSON-RPC error {self.code}: {error.get('message')}")


class RPCTimeout(EnumerationError):
    pass


@dataclass
class Surface:
    tools: list[dict]
    resources: list[dict] | None = None
    prompts: list[dict] | None = None
    protocol_version: str | None = None
    server_info: dict | None = None
    instructions: str | None = None
    era: str | None = None  # "modern" | "legacy" (None for recorded surfaces)
    method: str = "launch"  # "launch" | "recorded"
    notes: list[str] = field(default_factory=list)


def minimal_env(pass_env: list[str] | tuple[str, ...] = ()) -> dict[str, str]:
    env = {}
    for k in (*ENV_ALLOWLIST, *pass_env):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


class StdioClient:
    def __init__(self, argv: list[str], *, env: dict[str, str], cwd: str | None, timeout: float):
        self.timeout = timeout
        self.notes: list[str] = []
        self._next_id = 0
        self._q: queue.Queue = queue.Queue()
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
                cwd=cwd,
            )
        except OSError as e:
            raise EnumerationError(f"failed to start server: {e.strerror or e}") from None
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            if len(raw) > MAX_LINE_BYTES:
                self._q.put(("oversize", None))
                continue
            self._q.put(("line", raw))
        self._q.put(("eof", None))

    def _write(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            raise EnumerationError("server closed its input (process exited?)") from None

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)

    def request(self, method: str, params: dict | None = None, *, timeout: float | None = None) -> dict:
        timeout = self.timeout if timeout is None else timeout
        self._next_id += 1
        rid = self._next_id
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RPCTimeout(f"{method}: timed out after {timeout:g}s")
            try:
                kind, raw = self._q.get(timeout=remaining)
            except queue.Empty:
                raise RPCTimeout(f"{method}: timed out after {timeout:g}s") from None
            if kind == "eof":
                code = self.proc.poll()
                raise EnumerationError(f"{method}: server exited (status {code}) before responding")
            if kind == "oversize":
                self.notes.append("oversized stdout line ignored")
                continue
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.notes.append("non-JSON output on stdout ignored")
                continue
            if not isinstance(data, dict):
                self.notes.append("non-object JSON-RPC message ignored")
                continue
            if "method" in data:
                self._handle_server_message(data)
                continue
            if data.get("id") != rid:
                self.notes.append("response with unexpected id ignored")
                continue
            if "error" in data:
                raise RPCError(method, data["error"] or {})
            result = data.get("result")
            if not isinstance(result, dict):
                raise EnumerationError(f"{method}: malformed result")
            # Absent resultType means "complete" (legacy servers); anything else is not a listing.
            if result.get("resultType", "complete") != "complete":
                raise EnumerationError(f"{method}: unexpected resultType {result.get('resultType')!r}")
            return result

    def _handle_server_message(self, data: dict) -> None:
        method = data.get("method")
        if "id" in data:  # server -> client request
            if method == "ping":
                self._write({"jsonrpc": "2.0", "id": data["id"], "result": {}})
            else:
                self._write({"jsonrpc": "2.0", "id": data["id"],
                             "error": {"code": -32601, "message": "Method not found"}})
            self.notes.append(f"server request '{method}' answered")
        elif method and method.endswith("/list_changed"):
            self.notes.append(f"server sent {method} during enumeration")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        for action in (None, self.proc.terminate, self.proc.kill):
            if action:
                try:
                    action()
                except OSError:
                    pass
            try:
                self.proc.wait(timeout=1.0)
                return
            except subprocess.TimeoutExpired:
                continue


def _paginate(client: StdioClient, method: str, key: str, meta: dict | None) -> list[dict]:
    items: list[dict] = []
    cursor = None
    seen: set[str] = set()
    for _ in range(MAX_PAGES):
        params: dict = {"cursor": cursor} if cursor else {}
        if meta is not None:
            params["_meta"] = meta
        result = client.request(method, params)
        page = result.get(key)
        if not isinstance(page, list):
            raise EnumerationError(f"{method}: result has no '{key}' array")
        items.extend(page)
        cursor = result.get("nextCursor")
        if not cursor:
            return items
        if not isinstance(cursor, str) or cursor in seen:
            raise EnumerationError(f"{method}: invalid or repeated nextCursor")
        seen.add(cursor)
    raise EnumerationError(f"{method}: more than {MAX_PAGES} pages")


def validate_tools(tools: list) -> list[dict]:
    names = set()
    for t in tools:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str) or not t["name"]:
            raise EnumerationError("tools/list: tool without a string name")
        if t["name"] in names:
            raise EnumerationError(f"tools/list: duplicate tool name '{t['name']}'")
        names.add(t["name"])
    return tools


def _modern_meta(version: str) -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "caplock", "version": __version__},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _probe_modern(client: StdioClient, probe_timeout: float) -> tuple[str, dict, dict] | None:
    """Return (version, capabilities, discover_result) for a modern server, None for legacy."""
    preferred = MODERN_PROTOCOL_VERSIONS[0]
    try:
        result = client.request("server/discover", {"_meta": _modern_meta(preferred)}, timeout=probe_timeout)
    except RPCTimeout:
        client.notes.append("server/discover unanswered: treated as legacy server")
        return None
    except RPCError as e:
        if e.code not in MODERN_ERROR_CODES:
            client.notes.append(f"server/discover rejected (code {e.code}): treated as legacy server")
            return None
        if e.code == UNSUPPORTED_PROTOCOL_VERSION:
            offered = (e.data or {}).get("supported") if isinstance(e.data, dict) else None
            common = [v for v in MODERN_PROTOCOL_VERSIONS if v in (offered or [])]
            if not common:
                raise EnumerationError(f"server/discover: no mutually supported protocol version "
                                       f"(server supports {offered!r})") from None
            result = client.request("server/discover", {"_meta": _modern_meta(common[0])})
        else:
            raise
    offered = result.get("supportedVersions")
    if not isinstance(offered, list):
        raise EnumerationError("server/discover: result has no supportedVersions")
    common = [v for v in MODERN_PROTOCOL_VERSIONS if v in offered]
    if not common:
        raise EnumerationError(f"server/discover: no mutually supported protocol version (server supports {offered!r})")
    caps = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else {}
    return common[0], caps, result


def _legacy_initialize(client: StdioClient) -> tuple[str, dict, dict]:
    init = client.request(
        "initialize",
        {
            "protocolVersion": LEGACY_PROTOCOL_VERSIONS[0],
            "capabilities": {},
            "clientInfo": {"name": "caplock", "version": __version__},
        },
    )
    version = init.get("protocolVersion")
    if version not in LEGACY_PROTOCOL_VERSIONS:
        raise EnumerationError(f"initialize: unsupported protocol version {version!r}")
    client.notify("notifications/initialized")
    caps = init.get("capabilities") if isinstance(init.get("capabilities"), dict) else {}
    return version, caps, init


def enumerate_stdio(
    argv: list[str],
    *,
    timeout: float = 10.0,
    pass_env: list[str] | tuple[str, ...] = (),
    cwd: str | None = None,
    probe_timeout: float | None = None,
) -> Surface:
    """Launch ``argv`` and enumerate its surface. Raises EnumerationError on any failure."""
    probe_timeout = min(timeout, PROBE_TIMEOUT) if probe_timeout is None else probe_timeout
    client = StdioClient(argv, env=minimal_env(pass_env), cwd=cwd, timeout=timeout)
    try:
        modern = _probe_modern(client, probe_timeout)
        if modern is not None:
            version, caps, head = modern
            meta: dict | None = _modern_meta(version)
            server_info = (head.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")
            era = "modern"
        else:
            version, caps, head = _legacy_initialize(client)
            meta = None
            server_info = head.get("serverInfo")
            era = "legacy"
        instructions = head.get("instructions") if isinstance(head.get("instructions"), str) else None
        surface = Surface(tools=[], protocol_version=version, server_info=server_info,
                          instructions=instructions, era=era)
        if "tools" in caps:
            surface.tools = validate_tools(_paginate(client, "tools/list", "tools", meta))
        else:
            client.notes.append("server does not advertise the tools capability")
        for method, key in (("resources/list", "resources"), ("prompts/list", "prompts")):
            if key not in caps:
                continue
            try:
                setattr(surface, key, _paginate(client, method, key, meta))
            except EnumerationError as e:
                client.notes.append(f"{method} skipped: {e}")
        surface.notes = client.notes
        return surface
    finally:
        client.close()


def load_recorded_surface(path: Path) -> Surface:
    """Import a recorded tools/list response.

    Accepted shapes: a JSON-RPC response ``{"result": {...}}``, a bare result
    ``{"tools": [...]}``, or a list of result pages (``nextCursor`` chained).
    ``resources`` / ``prompts`` / ``protocolVersion`` keys are used if present.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise EnumerationError(f"cannot read recorded surface {path}: {e}") from None
    pages = data if isinstance(data, list) else data.get("pages", [data]) if isinstance(data, dict) else None
    if not pages:
        raise EnumerationError(f"{path}: unrecognized recorded surface")
    tools: list[dict] = []
    resources = prompts = instructions = None
    version = None
    for p in pages:
        if isinstance(p, dict) and "result" in p:
            p = p["result"]
        if not isinstance(p, dict) or not isinstance(p.get("tools"), list):
            raise EnumerationError(f"{path}: page without a 'tools' array")
        tools.extend(p["tools"])
        resources = p.get("resources", resources)
        instructions = p.get("instructions", instructions)
        prompts = p.get("prompts", prompts)
        version = p.get("protocolVersion", version)
    return Surface(
        tools=validate_tools(tools),
        resources=resources,
        prompts=prompts,
        instructions=instructions if isinstance(instructions, str) else None,
        protocol_version=version,
        method="recorded",
        notes=[],
    )
