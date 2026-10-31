"""PR Markdown summary: verdict line, needs-review section, deterministic order, escaping."""

import random
from pathlib import Path

import pytest

import harness as h
from caplock.diff import Finding
from caplock.report import build_context, render_markdown
from p2_common import scenario_ws

VERDICTS = {"A": "FAIL", "B": "FAIL", "C": "FAIL", "D": "FAIL", "E": "PASS", "F": "FAIL",
            "G1": "UNVERIFIABLE", "G2": "UNVERIFIABLE", "H": "PASS", "I": "PASS"}


def md_for(base, tmp_path, sid, *extra):
    ws, args = scenario_ws(base, tmp_path, sid)
    return h.run(["verify", "--format", "markdown", *extra] + args)


def section(md, title):
    start = md.index(f"### {title}")
    end = md.find("\n### ", start + 1)
    return md[start: end if end > 0 else None]


@pytest.mark.parametrize("sid", sorted(VERDICTS))
def test_verdict_line_and_structure(locked_base, tmp_path, sid):
    code, md = md_for(locked_base, tmp_path, sid)
    lines = md.splitlines()
    assert lines[0] == "## CapLock verify"
    assert lines[2].startswith(f"**Verdict: {VERDICTS[sid]}** (exit {code}): ")
    for title in ("Findings", "Needs review (separate from pass/fail)", "Updating the lockfile"):
        assert f"### {title}" in md
    steps = section(md, "Updating the lockfile")
    assert "1. Run `caplock lock`" in steps and "2. Review the changes" in steps and "3. Commit" in steps
    assert "does not attest" in md
    assert str(tmp_path) not in md  # no temp paths: identical across machines


@pytest.mark.parametrize("sid", sorted(VERDICTS))
def test_markdown_is_deterministic_across_runs_and_workspaces(locked_base, tmp_path, sid):
    assert md_for(locked_base, tmp_path / "a", sid) == md_for(locked_base, tmp_path / "b", sid)


def test_unverifiable_verdict_says_not_a_pass(locked_base, tmp_path):
    code, md = md_for(locked_base, tmp_path, "G1")
    assert code == 2 and "This is not a pass." in md.splitlines()[2]
    assert "#### Unverifiable (1)" in md


def test_needs_review_lists_version_change_even_on_pass(locked_base, tmp_path):
    code, md = md_for(locked_base, tmp_path, "I")
    assert code == 0 and "**Verdict: PASS**" in md
    review = section(md, "Needs review")
    assert "`version_changed` (info)" in review and "1.0.0 → 1.0.1" in review


def test_needs_review_lists_medium_findings(locked_base, tmp_path):
    _, md = md_for(locked_base, tmp_path, "E")
    assert "`tool_removed` (medium)" in section(md, "Needs review")
    _, md = md_for(locked_base, tmp_path / "a", "A")
    review = section(md, "Needs review")
    assert "`description_changed` (medium)" in review
    assert "instruction_injection" not in review  # high findings are in the findings tables only


def test_nothing_to_review_when_clean(locked_base, tmp_path):
    _, md = md_for(locked_base, tmp_path, "H")
    assert "_No findings._" in md and "_Nothing to review._" in md


def _render(findings, code=1, fail_on="high"):
    ctx = build_context(findings, code, fail_on, workspace=Path("."), lockfile_path=Path("mcp-lock.json"),
                        state_servers=None, lock_servers=None)
    return render_markdown(ctx)


def test_order_is_severity_server_tool_code_regardless_of_input_order():
    fs = [
        Finding("tool_added", "high", "m", server="b", tool="x"),
        Finding("tool_removed", "medium", "m", server="a", tool="y"),
        Finding("capability_expanded", "critical", "m", server="b", tool="a"),
        Finding("required_param_added", "high", "m", server="a", tool="z"),
        Finding("floating_version", "unverifiable", "m", server="c"),
        Finding("instruction_injection", "high", "m", server="a", tool="z"),
        Finding("version_changed", "info", "m", server="a"),
    ]
    expected = ["floating_version", "capability_expanded", "instruction_injection", "required_param_added",
                "tool_added", "tool_removed", "version_changed"]
    outputs = set()
    for seed in range(5):
        shuffled = fs[:]
        random.Random(seed).shuffle(shuffled)
        md = _render(shuffled, code=2)
        outputs.add(md)
        rows = [line for line in md.splitlines() if line.startswith("| ") and "`" in line]
        assert [r.split("`")[1] for r in rows] == expected
    assert len(outputs) == 1


def test_untrusted_text_is_escaped():
    evil = Finding("description_changed", "medium",
                   "x | y <!-- caplock --> <img src=x onerror=1>\nnext line ​ by @octo-org/team",
                   server="s|1", tool="t<b>", field="inputSchema.properties.a|b")
    md = _render([evil], code=0)
    assert "<!-- caplock -->" not in md and "<img" not in md and "<b>" not in md
    assert "&lt;!-- caplock --&gt;" in md
    assert "@octo-org" not in md and "&#64;octo-org" in md
    assert "​" not in md and "\\u200b" in md
    row = next(line for line in md.splitlines() if "`description_changed`" in line and line.startswith("|"))
    assert row.count("|") == 7  # 6 columns: no injected cell separators
    assert "next line" in row  # newline flattened into the same row


def test_long_cells_are_truncated():
    md = _render([Finding("description_changed", "medium", "a" * 5000, server="s", tool="t")], code=0)
    assert "a" * 299 + "…" in md and "a" * 301 not in md


@pytest.mark.parametrize("fail_on, verdict", [("high", "PASS"), ("medium", "FAIL"), ("never", "PASS")])
def test_verdict_follows_fail_on(locked_base, tmp_path, fail_on, verdict):
    code, md = md_for(locked_base, tmp_path, "E", "--fail-on", fail_on)
    assert md.splitlines()[2].startswith(f"**Verdict: {verdict}**")
    if fail_on == "medium":
        assert code == 1 and "at or above `medium`" in md
    if fail_on == "never":
        assert code == 0 and "`--fail-on never`" in md


def test_text_and_json_outputs_unchanged_by_phase_2(locked_base, tmp_path):
    ws, args = scenario_ws(locked_base, tmp_path, "C")
    code, text = h.run(["verify"] + args)
    assert code == 1 and "Result: CHANGED (exit 1): 2 high/critical finding(s) need review." in text
    code2, js = h.run_json(["verify"] + args)
    assert code2 == 1 and set(js) == {"exitCode", "notice", "findings"}
    code3, js3 = h.run(["verify", "--format", "json"] + args)
    assert code3 == 1 and js3 == h.run(["verify", "--json"] + args)[1]
