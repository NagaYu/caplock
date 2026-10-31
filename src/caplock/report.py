"""Review-layer reports: shared context and the PR Markdown summary.

``caplock verify --format markdown`` renders a summary that can be pasted into a
pull request as-is. It is deterministic: no timestamps or temp paths, findings
ordered by severity → server → tool → code (then field, message).

Text that originates from tool definitions is untrusted. Every cell is
HTML-escaped, pipes are escaped, newlines flattened, invisible characters made
visible, and long values truncated, so a malicious description cannot inject
markup (or a fake CapLock marker) into the PR comment, and ``@`` is escaped so
package names such as ``@scope/pkg`` do not notify GitHub users or teams.
"""

from __future__ import annotations

import html
import os
from dataclasses import dataclass, field
from pathlib import Path

from caplock import LIMITATION_NOTICE
from caplock.canonical import escape_invisible
from caplock.diff import RANK, Finding

VERDICT = {0: "PASS", 1: "FAIL", 2: "UNVERIFIABLE"}
SEVERITY_ORDER = ("unverifiable", "critical", "high", "medium", "info")
SEVERITY_TITLE = {"unverifiable": "Unverifiable", "critical": "Critical", "high": "High",
                  "medium": "Medium", "info": "Info"}
CELL_LIMIT = 300


@dataclass
class ReportContext:
    findings: list[Finding]
    exit_code: int
    fail_on: str
    lockfile_uri: str  # for SARIF
    lockfile_display: str  # for Markdown (workspace-relative when possible)
    server_uris: dict[str, str] = field(default_factory=dict)
    server_display: dict[str, str] = field(default_factory=dict)


def verdict(code: int) -> str:
    return VERDICT.get(code, "ERROR")


def needs_review(f: Finding) -> bool:
    """Shown in the "needs review" section regardless of pass/fail."""
    return f.code == "version_changed" or f.severity == "medium"


def report_order(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (RANK[f.severity], f.server or "", f.tool or "", f.code,
                                           f.field or "", f.message))


def to_uri(path: Path) -> str:
    """Repository-relative posix path when possible (what code scanning expects), else a file URI."""
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            return p.resolve().as_uri()
    return Path(os.path.normpath(p)).as_posix()


def _display(path: Path, workspace: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(workspace).resolve()).as_posix()
    except ValueError:
        return Path(path).name


def build_context(findings: list[Finding], exit_code: int, fail_on: str, *, workspace: Path,
                  lockfile_path: Path, state_servers: dict | None, lock_servers: dict | None) -> ReportContext:
    ctx = ReportContext(
        findings=report_order(findings),
        exit_code=exit_code,
        fail_on=fail_on,
        lockfile_uri=to_uri(lockfile_path),
        lockfile_display=_display(lockfile_path, workspace),
    )
    for servers in (lock_servers or {}, state_servers or {}):  # current state wins
        for name, s in servers.items():
            if s.get("sources"):
                rel = s["sources"][0]["path"]
                ctx.server_uris[name] = to_uri(Path(workspace) / rel)
                ctx.server_display[name] = rel
    return ctx


def location_of(f: Finding, ctx: ReportContext) -> str:
    if f.server and f.server in ctx.server_uris:
        return ctx.server_uris[f.server]
    return ctx.lockfile_uri


# --------------------------------------------------------------------------- Markdown


def cell(value: object) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = escape_invisible(" ".join(text.split()))
    if len(text) > CELL_LIMIT:
        text = text[: CELL_LIMIT - 1] + "…"
    # "@scope/pkg" would become a GitHub user/team mention in a PR comment.
    return html.escape(text, quote=False).replace("|", "&#124;").replace("@", "&#64;")


def code_cell(value: object) -> str:
    return f"<code>{cell(value)}</code>" if value not in (None, "") else "—"


def _reason(ctx: ReportContext) -> str:
    fs = ctx.findings
    n_unv = sum(f.unverifiable for f in fs)
    at = [f for f in fs if not f.unverifiable and ctx.fail_on != "never" and RANK[f.severity] <= RANK[ctx.fail_on]]
    if ctx.exit_code == 2:
        r = f"{n_unv} item(s) could not be verified. This is not a pass."
        if at:
            r += f" Also {len(at)} finding(s) at or above `{ctx.fail_on}`."
        return r
    if ctx.exit_code == 1:
        return f"{len(at)} finding(s) at or above `{ctx.fail_on}` (`--fail-on {ctx.fail_on}`)."
    if not fs:
        return "configuration, package identity and tool surface match the lockfile."
    if ctx.fail_on == "never":
        return f"`--fail-on never`; {len(fs)} finding(s) listed below are not counted."
    return f"no finding at or above `{ctx.fail_on}`; {len(fs)} lower-severity finding(s) listed below."


def render_markdown(ctx: ReportContext) -> str:
    fs = ctx.findings
    out: list[str] = []
    out.append("## CapLock verify")
    out.append("")
    out.append(f"**Verdict: {verdict(ctx.exit_code)}** (exit {ctx.exit_code}): {_reason(ctx)}")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    for sev in SEVERITY_ORDER:
        out.append(f"| {SEVERITY_TITLE[sev]} | {sum(f.severity == sev for f in fs)} |")
    out.append("")
    out.append("### Findings")
    out.append("")
    if not fs:
        out.append("_No findings._")
        out.append("")
    for sev in SEVERITY_ORDER:
        group = [f for f in fs if f.severity == sev]
        if not group:
            continue
        out.append(f"#### {SEVERITY_TITLE[sev]} ({len(group)})")
        out.append("")
        out.append("| Server | Tool | Code | Field | Detail | Source |")
        out.append("|---|---|---|---|---|---|")
        for f in group:
            src = ctx.server_display.get(f.server or "", ctx.lockfile_display)
            out.append(f"| {cell(f.server) or '—'} | {cell(f.tool) or '—'} | `{f.code}` | {code_cell(f.field)} "
                       f"| {cell(f.message)} | {code_cell(src)} |")
        out.append("")
    out.append("### Needs review (separate from pass/fail)")
    out.append("")
    out.append("Version changes and medium findings do not fail the check by default, but re-pinning a new "
               "version or accepting a changed surface needs a human approval.")
    out.append("")
    review = [f for f in fs if needs_review(f)]
    if review:
        for f in review:
            where = " / ".join(cell(p) for p in (f.server, f.tool) if p) or "workspace"
            out.append(f"- **{where}** `{f.code}` ({f.severity}): {cell(f.message)}")
    else:
        out.append("_Nothing to review._")
    out.append("")
    out.append("### Updating the lockfile")
    out.append("")
    out.append("1. Run `caplock lock` locally with the same options as this check.")
    out.append(f"2. Review the changes with `caplock diff` and `git diff {cell(ctx.lockfile_display)}`.")
    out.append(f"3. Commit the updated `{cell(ctx.lockfile_display)}` to this pull request.")
    out.append("")
    out.append(f"> {LIMITATION_NOTICE}")
    return "\n".join(out) + "\n"
