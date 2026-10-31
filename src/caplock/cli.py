"""Command line interface: ``caplock lock | verify | diff | evidence``.

argparse (standard library) is used rather than typer: CapLock's claim is
supply-chain hygiene, so the CLI has zero runtime dependencies.

Exit codes:
  0  no differences, or only findings below the --fail-on threshold
  1  at least one finding at or above --fail-on (default: high)
  2  something could not be verified (unpinned, unrecorded integrity, remote
     server, enumeration failure, missing/invalid lockfile, ...).
     Takes precedence over 1: an incomplete check is never reported as done.
  3  usage error or aborted by the user

``caplock evidence`` exits with the verify exit code of the result it packs
(the pack is written in every case except a missing/invalid lockfile).
``caplock evidence --verify`` exits 0 intact, 1 tampered, 2 cannot be checked.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from caplock import LIMITATION_NOTICE, __version__, evidence, lockfile
from caplock.diff import FAIL_ON, RANK, Finding, assess, diff_states, exit_code, sort_findings
from caplock.report import build_context, render_markdown
from caplock.sarif import to_sarif
from caplock.verify import Options, build_state, discovery_findings, verify

FORMATS = ("text", "json", "sarif", "markdown")

EXIT_USAGE = 3

LABEL = {"unverifiable": "UNVERIFIABLE", "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "info": "INFO"}


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse would use 2, which means "unverifiable" here
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _kv(text: str) -> tuple[str, str]:
    name, sep, value = text.partition("=")
    if not sep or not name or not value:
        raise argparse.ArgumentTypeError(f"expected NAME=VALUE, got {text!r}")
    return name, value


def _report_kv(text: str) -> tuple[str, Path]:
    fmt, path = _kv(text)
    if fmt not in FORMATS:
        raise argparse.ArgumentTypeError(f"unknown format {fmt!r} (choose from {', '.join(FORMATS)})")
    return fmt, Path(path)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="caplock", description="Pin MCP server surfaces and package identity in mcp-lock.json.")
    p.add_argument("--version", action="version", version=f"caplock {__version__}")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    common = _Parser(add_help=False)
    common.add_argument("-w", "--workspace", type=Path, default=Path("."), help="workspace root (default: .)")
    common.add_argument("--lockfile", type=Path, help="lockfile path (default: <workspace>/mcp-lock.json)")
    common.add_argument("--config", type=Path, action="append", default=[],
                        help="additional portable-format config file (repeatable)")
    common.add_argument("--registry", type=Path, action="append", default=[],
                        help="recorded registry metadata directory (repeatable; first match wins)")
    common.add_argument("--online", action="store_true",
                        help="query live npm/PyPI metadata (package names only; tool data is never sent)")
    common.add_argument("--launch", type=_kv, action="append", default=[], metavar="NAME=COMMAND",
                        help="enumerate server NAME by running this explicit local command")
    common.add_argument("--allow-launch", action="append", default=[], metavar="NAME",
                        help="allow running the configured command of server NAME to enumerate it")
    common.add_argument("--surface", type=_kv, action="append", default=[], metavar="NAME=FILE",
                        help="use a recorded tools/list response for server NAME (http servers)")
    common.add_argument("--pass-env", action="append", default=[], metavar="KEY",
                        help="pass this environment variable to launched servers (value never logged)")
    common.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")

    lk = sub.add_parser("lock", parents=[common], help="generate or update mcp-lock.json")
    lk.add_argument("--yes", action="store_true", help="overwrite without confirmation (interactive use)")
    for name, help_ in (("verify", "check the current state against mcp-lock.json"),
                        ("diff", "show field-level differences against mcp-lock.json")):
        sp = sub.add_parser(name, parents=[common], help=help_)
        sp.add_argument("--json", action="store_true", help="machine-readable output (same as --format json)")
        sp.add_argument("--format", choices=FORMATS, default=None,
                        help="output format: text (default), json, sarif (SARIF 2.1.0), markdown (PR summary)")
        sp.add_argument("--output", type=Path, help="write the --format output to this file instead of stdout")
        sp.add_argument("--report", type=_report_kv, action="append", default=[], metavar="FORMAT=PATH",
                        help="also write FORMAT to PATH from the same run (repeatable)")
        if name == "verify":
            sp.add_argument("--fail-on", choices=FAIL_ON, default="high",
                            help="lowest severity that makes verify exit 1 (default: high). "
                                 "Unverifiable items always exit 2, even with 'never'.")
    ev = sub.add_parser("evidence", parents=[common],
                        help="bundle lockfile, verify result and manifest into an evidence pack, or check one")
    ev.add_argument("--out", type=Path, default=Path("caplock-evidence"),
                    help="pack directory (or zip file with --zip) to create (default: ./caplock-evidence)")
    ev.add_argument("--zip", action="store_true", help="write a single deterministic zip file instead of a directory")
    ev.add_argument("--fail-on", choices=FAIL_ON, default="high", help="threshold for the verify run (default: high)")
    ev.add_argument("--sarif", type=Path, help="pack this existing SARIF log as produced (needs --markdown)")
    ev.add_argument("--markdown", type=Path, help="pack this existing Markdown report as produced (needs --sarif)")
    ev.add_argument("--verify", type=Path, metavar="PACK",
                    help="check a pack directory or zip against its manifest (tamper detection, not origin proof)")
    return p


def options_from(args) -> Options:
    if args.online and args.registry:
        raise SystemExit(_usage("--online and --registry are mutually exclusive"))
    return Options(
        workspace=args.workspace,
        lockfile=args.lockfile,
        configs=args.config,
        registry_dirs=args.registry,
        online=args.online,
        launch=dict(args.launch),
        allow_launch=set(args.allow_launch),
        surfaces={k: Path(v) for k, v in args.surface},
        pass_env=args.pass_env,
        timeout=args.timeout,
    )


def _usage(msg: str) -> int:
    print(f"caplock: error: {msg}", file=sys.stderr)
    return EXIT_USAGE


# --------------------------------------------------------------------------- rendering


def _short(v, limit: int = 100) -> str:
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, sort_keys=True)
    s = s.replace("\n", "\\n")
    from caplock.canonical import escape_invisible

    s = escape_invisible(s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _where(f: Finding) -> str:
    parts = [p for p in (f.server, f.tool) if p]
    return " / ".join(parts) if parts else "-"


def render_findings(findings: list[Finding], *, detail: bool, out) -> None:
    if not findings:
        print("No findings.", file=out)
        return
    print(f"Findings ({len(findings)}):", file=out)
    for f in findings:
        print(f"  {LABEL[f.severity]:<12} {_where(f):<28} {f.code:<28} {f.message}", file=out)
        if detail and (f.before is not None or f.after is not None):
            if f.field:
                print(f"  {'':<12} {'':<28} field: {f.field}", file=out)
            if f.before is not None:
                print(f"  {'':<12} {'':<28} - {_short(f.before)}", file=out)
            if f.after is not None:
                print(f"  {'':<12} {'':<28} + {_short(f.after)}", file=out)


def render_result(code: int, findings: list[Finding], out, *, fail_on: str = "high") -> None:
    n_unv = sum(f.unverifiable for f in findings)
    at = sum(not f.unverifiable and fail_on != "never" and RANK[f.severity] <= RANK[fail_on] for f in findings)
    below = sum(not f.unverifiable for f in findings) - at
    label = "high/critical" if fail_on == "high" else f"'{fail_on}'-or-above"
    if code == 2:
        line = f"UNVERIFIABLE (exit 2): {n_unv} item(s) could not be verified. This is not a pass."
        if at:
            line += f" Also {at} {label} finding(s)."
    elif code == 1:
        line = f"CHANGED (exit 1): {at} {label} finding(s) need review."
    elif below:
        head = "NO HIGH-SEVERITY CHANGES" if fail_on == "high" else f"BELOW FAIL-ON '{fail_on}'"
        kinds = "medium/info" if fail_on == "high" else "below-threshold"
        line = (f"{head} (exit 0): {below} {kinds} difference(s) from the lockfile "
                "shown above; run `caplock lock` to record them once reviewed.")
    else:
        line = "MATCH (exit 0): configuration, package identity and tool surface match the lockfile."
    print("", file=out)
    print(f"Result: {line}", file=out)
    print(f"Note: {LIMITATION_NOTICE}", file=out)


def render_servers(servers: dict[str, dict], out) -> None:
    for name, s in servers.items():
        pkg = s["package"]
        if pkg["status"] == "remote":
            p = f"remote {s['config'].get('url')}"
        elif pkg["ecosystem"] == "none":
            p = f"manual ({s['config'].get('command')})"
        else:
            ver = pkg.get("version") or pkg.get("requested") or "unpinned"
            integ = pkg.get("integrity")
            p = f"{pkg['ecosystem']} {pkg.get('name')}@{ver} [{pkg['status']}]"
            p += f" integrity {integ[:22]}…" if integ else " integrity: not recorded"
        surf = s["surface"]
        print(f"  {name}: {p}", file=out)
        if surf["status"] == "enumerated":
            print(f"    surface {surf['hash'][:22]}… via {surf['method']} ({surf['toolCount']} tools)", file=out)
            for tname, t in s["tools"].items():
                cap = t["capability"]
                hosts = f" hosts={','.join(cap['networkHosts'])}" if cap.get("networkHosts") else ""
                print(f"      - {tname}: {', '.join(cap['capabilities'])}{hosts}", file=out)
        else:
            print(f"    surface: {surf['status']}" + (f" ({surf['error']})" if surf.get("error") else ""), file=out)


def _json_out(findings: list[Finding], code: int, out) -> None:
    json.dump({"exitCode": code, "notice": LIMITATION_NOTICE, "findings": [f.to_dict() for f in findings]},
              out, indent=2, ensure_ascii=True)
    print(file=out)


# --------------------------------------------------------------------------- commands


def _render(fmt: str, report, code: int, fail_on: str, opts: Options, args) -> str:
    buf = io.StringIO()
    if fmt == "json":
        _json_out(report.findings, code, buf)
    elif fmt in ("sarif", "markdown"):
        ctx = build_context(report.findings, code, fail_on, workspace=Path(opts.workspace),
                            lockfile_path=opts.lockfile_path,
                            state_servers=report.state.servers if report.state else None,
                            lock_servers=report.lock["servers"] if report.lock else None)
        if fmt == "sarif":
            buf.write(json.dumps(to_sarif(ctx), indent=2, ensure_ascii=True) + "\n")
        else:
            buf.write(render_markdown(ctx))
    else:
        print(f"caplock {args.command}: workspace {opts.workspace} / lockfile {opts.lockfile_path}", file=buf)
        if report.state:
            print(f"registry backend: {report.state.backend}", file=buf)
        render_findings(report.findings, detail=args.command == "diff", out=buf)
        render_result(code, report.findings, buf, fail_on=fail_on)
    return buf.getvalue()


def cmd_verify(opts: Options, args, out) -> int:
    if args.json and args.format not in (None, "json"):
        return _usage("--json conflicts with --format " + args.format)
    fmt = args.format or ("json" if args.json else "text")
    fail_on = getattr(args, "fail_on", "high")
    report = verify(opts)
    code = exit_code(report.findings, fail_on)
    main_text = _render(fmt, report, code, fail_on, opts, args)
    if args.output:
        args.output.write_text(main_text, encoding="utf-8")
    else:
        out.write(main_text)
    for rfmt, path in args.report:
        path.write_text(_render(rfmt, report, code, fail_on, opts, args), encoding="utf-8")
    return code


def cmd_evidence(opts: Options, args, out) -> int:
    if args.verify:
        check = evidence.verify_pack(args.verify)
        label = {"intact": "INTACT", "tampered": "TAMPERED", "unverifiable": "UNVERIFIABLE"}[check.status]
        print(f"caplock evidence --verify {args.verify}", file=out)
        if check.manifest_digest:
            print(f"manifest digest: {check.manifest_digest}", file=out)
        for p in check.problems:
            print(f"  - {p}", file=out)
        if check.status == "intact":
            line = f"INTACT (exit 0): all {check.checked} file(s) match manifest.json."
        elif check.status == "tampered":
            line = f"TAMPERED (exit 1): {len(check.problems)} problem(s); the pack changed after it was made."
        else:
            line = f"{label} (exit 2): the pack could not be checked. This is not a pass."
        print(f"\nResult: {line}", file=out)
        print(f"Note: {evidence.INTEGRITY_NOTICE}", file=out)
        return check.exit_code
    if bool(args.sarif) != bool(args.markdown):
        return _usage("--sarif and --markdown must be given together")
    path = opts.lockfile_path
    try:
        lockfile.load(path)
    except FileNotFoundError:
        print(f"caplock evidence: {path} not found; run caplock lock first. Nothing written (exit 2).", file=out)
        return 2
    except lockfile.LockfileError as e:
        print(f"caplock evidence: lockfile is invalid ({e}). Nothing written (exit 2).", file=out)
        return 2
    if args.sarif:
        try:
            sarif_text = args.sarif.read_text(encoding="utf-8")
            md_text = args.markdown.read_text(encoding="utf-8")
        except OSError as e:
            return _usage(str(e))
        source = "supplied"
    else:
        report = verify(opts)
        code = exit_code(report.findings, args.fail_on)
        sarif_text = _render("sarif", report, code, args.fail_on, opts, args)
        md_text = _render("markdown", report, code, args.fail_on, opts, args)
        source = "run"
    try:
        files = evidence.build_files(workspace=opts.workspace, configs=opts.configs, lockfile_path=path,
                                     sarif_text=sarif_text, markdown_text=md_text, source=source)
        written = evidence.write_pack(files, args.out, args.zip)
    except evidence.EvidenceError as e:
        return _usage(str(e))
    m = json.loads(files[evidence.MANIFEST])
    v = m["verify"]
    print(f"caplock evidence: wrote {written} ({len(m['files'])} files + {evidence.MANIFEST})", file=out)
    print(f"manifest digest: {evidence.sha256_bytes(files[evidence.MANIFEST])}", file=out)
    print(f"rule catalog: {m['ruleCatalog']['version']} / verify ({source}): {v['verdict']} (exit {v['exitCode']})",
          file=out)
    print(f"\nResult: evidence pack written; packed verify verdict {v['verdict']} (exit {v['exitCode']}).", file=out)
    print(f"Note: {LIMITATION_NOTICE}", file=out)
    print(f"Note: {evidence.INTEGRITY_NOTICE}", file=out)
    print(f"Note: {evidence.POSITIONING_NOTICE}", file=out)
    return int(v["exitCode"]) if v["exitCode"] in (0, 1, 2) else 2


def cmd_lock(opts: Options, args, out) -> int:
    path = opts.lockfile_path
    old = None
    old_problem = None
    if path.exists():
        try:
            old = lockfile.load(path)
        except lockfile.LockfileError as e:
            old_problem = str(e)
    state = build_state(opts)
    new = lockfile.build_lock(state.servers)
    print(f"caplock lock: workspace {opts.workspace} / registry backend: {state.backend}", file=out)
    render_servers(state.servers, out)
    findings = discovery_findings(state, opts) + assess(state.servers, content_flags=True)
    changes: list[Finding] = []
    if old is not None:
        if lockfile.content_of(old) == lockfile.content_of(new):
            print("", file=out)
            render_findings(sort_findings(findings), detail=False, out=out)
            print(f"\nLockfile {path} is up to date; not rewritten.", file=out)
            return _lock_exit(findings, out)
        changes = diff_states(old["servers"], new["servers"])
    print("", file=out)
    all_findings = sort_findings(findings + changes)
    render_findings(all_findings, detail=True, out=out)

    if old is not None or old_problem is not None:
        what = "invalid existing lockfile" if old_problem else "existing lockfile"
        print(f"\nThis will overwrite the {what} {path}.", file=out)
        if old_problem:
            print(f"  ({old_problem})", file=out)
        if not args.yes:
            if not sys.stdin.isatty():
                print("Not a terminal and --yes not given: aborted, nothing written.", file=out)
                return EXIT_USAGE
            answer = input("Write lockfile? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("Aborted, nothing written.", file=out)
                return EXIT_USAGE
    lockfile.write(path, new)
    print(f"\nWrote {path} ({len(new['servers'])} server(s)).", file=out)
    return _lock_exit(findings, out)


def _lock_exit(findings: list[Finding], out) -> int:
    n_unv = sum(f.unverifiable for f in findings)
    if n_unv:
        print(f"Result: lockfile contains {n_unv} unverifiable item(s); `caplock verify` will exit 2 "
              "until they are fixed (exit 2).", file=out)
        print(f"Note: {LIMITATION_NOTICE}", file=out)
        return 2
    print(f"Note: {LIMITATION_NOTICE}", file=out)
    return 0


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        opts = options_from(args)
    except SystemExit as e:
        return int(e.code)
    if not Path(opts.workspace).is_dir():
        return _usage(f"workspace {opts.workspace} is not a directory")
    if args.command == "lock":
        return cmd_lock(opts, args, out)
    if args.command == "evidence":
        return cmd_evidence(opts, args, out)
    return cmd_verify(opts, args, out)


if __name__ == "__main__":
    raise SystemExit(main())
