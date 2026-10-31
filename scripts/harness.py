"""Shared scenario harness for tests and scripts/demo.py.

Copies examples/demo-workspace, locks it against the benign fixture server,
applies a scenario from fixtures/scenarios/*.json, and runs the CLI.
Only the local fixture server is ever launched; registries are fixtures.
"""

from __future__ import annotations

import io
import json
import shlex
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from caplock.cli import main as caplock_main  # noqa: E402

DEMO = ROOT / "examples" / "demo-workspace"
SERVER = ROOT / "fixtures" / "servers" / "notes_server.py"
TOOLS = ROOT / "fixtures" / "servers" / "tools"
REGISTRY = ROOT / "fixtures" / "registry"
MUTATIONS = ROOT / "fixtures" / "registry-mutations"
SCENARIOS = ROOT / "fixtures" / "scenarios"


def server_cmd(tools_file: str) -> str:
    return " ".join(shlex.quote(p) for p in (sys.executable, str(SERVER), "--tools", str(TOOLS / tools_file)))


def prepare_workspace(dst: Path) -> Path:
    shutil.copytree(DEMO, dst, dirs_exist_ok=True)
    return dst


def cli_args(ws: Path, notes_tools: str = "benign.json", registry_overlay: str | None = None) -> list[str]:
    args = ["--workspace", str(ws)]
    if registry_overlay:
        args += ["--registry", str(MUTATIONS / registry_overlay)]
    args += ["--registry", str(REGISTRY)]
    args += ["--launch", f"notes={server_cmd(notes_tools)}"]
    args += ["--launch", f"weather={server_cmd('weather.json')}"]
    return args


def load_scenarios() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(SCENARIOS.glob("*.json"))]


def apply_scenario(ws: Path, scenario: dict) -> list[str]:
    """Mutate the workspace for the scenario and return the CLI args for verify/diff."""
    after = scenario.get("after", {})
    if after.get("vscode_config"):
        shutil.copy(SCENARIOS / "configs" / after["vscode_config"], ws / ".vscode" / "mcp.json")
    return cli_args(ws, after.get("tools", "benign.json"), after.get("registry_overlay"))


def run(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    code = caplock_main(argv, out=buf)
    return code, buf.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict]:
    code, out = run(argv + ["--json"])
    return code, json.loads(out)
