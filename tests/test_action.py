"""action.yml / ci.yml: light structural checks and referenced paths (no YAML parser in stdlib)."""

import re

import pytest

import harness as h

ACTION = (h.ROOT / "action.yml").read_text()
CI = (h.ROOT / ".github" / "workflows" / "ci.yml").read_text()


def run_blocks(text):
    """Bodies of `run: |` blocks (lines indented deeper than the `run:` key)."""
    blocks, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:- )?run: \|\s*$", lines[i])
        if m:
            indent = len(m.group(1))
            body = []
            i += 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                body.append(lines[i])
                i += 1
            blocks.append("\n".join(body))
        else:
            i += 1
    return blocks


def test_action_is_composite_with_required_inputs_and_defaults():
    assert re.search(r"^runs:\n  using: composite$", ACTION, re.M)
    defaults = dict(re.findall(r"^  ([a-z-]+):\n(?:    .*\n)*?    default: \"([^\"]*)\"$", ACTION, re.M))
    assert {k: defaults.get(k) for k in ("workspace", "lockfile", "fail-on", "online", "upload-sarif",
                                          "comment-pr")} == {
        "workspace": ".", "lockfile": "mcp-lock.json", "fail-on": "high", "online": "false",
        "upload-sarif": "true", "comment-pr": "true"}


def test_action_step_order():
    markers = ["actions/setup-python@", 'pip install --disable-pip-version-check "$CAPLOCK_SRC"', "caplock \"${args[@]}\"",
               "github/codeql-action/upload-sarif@", "scripts/pr_comment.py", "case \"$CAPLOCK_CODE\" in"]
    positions = [ACTION.index(m) for m in markers]
    assert positions == sorted(positions)
    assert 'python-version: "3.12"' in ACTION


def test_action_writes_sarif_and_markdown_from_one_run_and_reports_exit_2():
    assert '--report "sarif=$sarif" --report "markdown=$md"' in ACTION
    assert "--fail-on \"$CAPLOCK_FAIL_ON\"" in ACTION and "args+=(--online)" in ACTION
    assert re.search(r"2\) .*UNVERIFIABLE.*exit 2.*not a pass.*exit 2 ;;", ACTION)
    assert "1) " in ACTION and "exit 1 ;;" in ACTION


def test_action_referenced_paths_exist():
    assert "${{ github.action_path }}" in ACTION
    pyproject = (h.ROOT / "pyproject.toml").read_text()
    assert 'caplock = "caplock.cli:main"' in pyproject  # what `pip install <action_path>` provides
    assert (h.ROOT / "scripts" / "pr_comment.py").is_file()
    assert '"$CAPLOCK_SRC/scripts/pr_comment.py"' in ACTION


@pytest.mark.parametrize("name, text", [("action.yml", ACTION), ("ci.yml", CI)])
def test_third_party_actions_are_pinned_to_commit_shas(name, text):
    uses = re.findall(r"uses: (\S+)", text)
    assert uses
    for u in uses:
        if u == "./":
            continue
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u), f"{name}: {u} is not pinned to a SHA"


def test_no_expression_interpolation_inside_scripts():
    # Inputs reach scripts only through env: (avoids script injection).
    for block in run_blocks(ACTION):
        assert "${{" not in block, block


def test_extra_args_are_split_not_evaluated():
    assert "shlex.split" in ACTION and "eval " not in ACTION


def test_ci_runs_pytest_demo_and_dogfood_round_trip():
    order = ["python -m pytest", "python scripts/demo.py --brief", "caplock lock", "caplock verify \"${common[@]}\"",
             "fixtures/registry-mutations/F-code-only", 'test "$code" -eq 1']
    positions = [CI.index(m) for m in order]
    assert positions == sorted(positions)
    assert "permissions:\n  contents: read" in CI
    assert "uses: ./" in CI  # the action itself is exercised


def test_ci_referenced_paths_exist():
    for rel in ("examples/demo-workspace", "fixtures/registry", "fixtures/registry-mutations/F-code-only",
                "fixtures/servers/notes_server.py", "fixtures/servers/tools/benign.json",
                "fixtures/servers/tools/weather.json", "scripts/demo.py"):
        assert rel in CI
        assert (h.ROOT / rel).exists(), rel
