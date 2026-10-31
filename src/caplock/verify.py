"""Verification pipeline: config → resolve → enumerate → compare with the lockfile.

Anything that cannot be reconstructed (unpinned packages, unrecorded
integrity, remote servers, failed or missing enumeration, missing lockfile)
becomes an ``unverifiable`` finding and forces exit code 2. "Not verified"
is never reported as success.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path

from caplock import lockfile
from caplock.config_discovery import REDACTED, Discovery, ServerEntry, discover
from caplock.diff import Finding, assess, diff_states, exit_code, sort_findings
from caplock.enumerate import EnumerationError, Surface, enumerate_stdio, load_recorded_surface
from caplock.resolve import FixtureRegistry, NullRegistry, OnlineRegistry, RegistryBackend, resolve_entry


@dataclass
class Options:
    workspace: Path
    lockfile: Path | None = None
    configs: list[Path] = field(default_factory=list)
    registry_dirs: list[Path] = field(default_factory=list)
    online: bool = False
    launch: dict[str, str] = field(default_factory=dict)  # server -> explicit local command
    allow_launch: set[str] = field(default_factory=set)  # servers whose configured command may run
    surfaces: dict[str, Path] = field(default_factory=dict)  # server -> recorded tools/list
    pass_env: list[str] = field(default_factory=list)
    timeout: float = 10.0

    @property
    def lockfile_path(self) -> Path:
        return self.lockfile or (Path(self.workspace) / lockfile.LOCKFILE_NAME)


@dataclass
class State:
    discovery: Discovery
    servers: dict[str, dict]  # lock-shaped server records
    backend: str


@dataclass
class Report:
    findings: list[Finding]
    state: State | None
    lock: dict | None

    @property
    def exit_code(self) -> int:
        return exit_code(self.findings)


def make_backend(opts: Options) -> RegistryBackend:
    if opts.online:
        return OnlineRegistry(timeout=opts.timeout)
    if opts.registry_dirs:
        return FixtureRegistry(opts.registry_dirs)
    return NullRegistry()


def _enumerate(name: str, entry: ServerEntry, opts: Options) -> tuple[Surface | None, str | None, str | None]:
    """Return (surface, method, error)."""
    try:
        if name in opts.surfaces:
            return load_recorded_surface(opts.surfaces[name]), "recorded", None
        if name in opts.launch:
            argv = shlex.split(opts.launch[name])
            return _launch(argv, opts), "launch-override", None
        if name in opts.allow_launch:
            if entry.transport != "stdio":
                return None, "launch-config", "http servers are not contacted in Phase 1 (use --surface)"
            argv = [entry.command or "", *entry.args]
            if any(REDACTED in a or "${" in a for a in argv):
                return None, "launch-config", ("configured arguments contain redacted or unresolved values; "
                                               "use --launch with an explicit command")
            return _launch(argv, opts), "launch-config", None
    except EnumerationError as e:
        method = "recorded" if name in opts.surfaces else "launch-override" if name in opts.launch else "launch-config"
        return None, method, str(e)
    return None, None, None


def _launch(argv: list[str], opts: Options) -> Surface:
    return enumerate_stdio(argv, timeout=opts.timeout, pass_env=opts.pass_env, cwd=str(opts.workspace))


def build_state(opts: Options) -> State:
    disc = discover(Path(opts.workspace), opts.configs)
    backend = make_backend(opts)
    servers = {}
    for name, entry in disc.entries.items():
        package = resolve_entry(entry, backend)
        surface, method, error = _enumerate(name, entry, opts)
        servers[name] = lockfile.server_record(entry, disc.occurrences[name], package, surface, method, error)
    return State(discovery=disc, servers=servers, backend=backend.name)


def discovery_findings(state: State, opts: Options) -> list[Finding]:
    out = [Finding("config_error", "unverifiable", message=e) for e in state.discovery.errors]
    if not state.discovery.sources and not state.discovery.errors:
        out.append(Finding("no_config", "unverifiable",
                           message=f"no MCP configuration found in {opts.workspace}"))
    unknown = (set(opts.launch) | set(opts.surfaces) | opts.allow_launch) - set(state.servers)
    for name in sorted(unknown):
        out.append(Finding("unknown_server_option", "info", server=name,
                           message="a --launch/--surface/--allow-launch option names a server that is not configured"))
    return out


def verify(opts: Options) -> Report:
    path = opts.lockfile_path
    try:
        lock = lockfile.load(path)
    except FileNotFoundError:
        return Report([Finding("lockfile_missing", "unverifiable",
                               message=f"{path} not found; run caplock lock first")], None, None)
    except lockfile.LockfileError as e:
        return Report([Finding("lockfile_invalid", "unverifiable", message=str(e))], None, None)
    state = build_state(opts)
    findings = discovery_findings(state, opts)
    findings += assess(state.servers, content_flags=False)
    findings += diff_states(lock["servers"], state.servers)
    return Report(sort_findings(findings), state, lock)
