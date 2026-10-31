"""Phase 2 Step 0: PyPI integrity is a per-file set plus a digest of that set."""

import json

import pytest

import harness as h
from caplock import lockfile
from caplock.canonical import sha256_of
from caplock.config_discovery import ConfigSource, ServerEntry
from caplock.resolve import FixtureRegistry, resolve_entry

WEATHER = ServerEntry(name="weather", transport="stdio", command="uvx", args=["caplock-demo-weather==0.3.1"],
                      source=ConfigSource(".mcp.json", "portable"))


def test_integrity_set_is_sorted_per_file_and_digest_is_canonical():
    r = resolve_entry(WEATHER, FixtureRegistry([h.REGISTRY]))
    files = [e["file"] for e in r.integrity_set]
    assert files == sorted(files) == ["caplock_demo_weather-0.3.1-py3-none-any.whl",
                                      "caplock_demo_weather-0.3.1.tar.gz"]
    assert all(set(e) == {"file", "sha256"} and len(e["sha256"]) == 64 for e in r.integrity_set)
    assert r.integrity == sha256_of(r.integrity_set)
    d = r.to_dict()
    assert d["integritySet"] == r.integrity_set and "artifacts" not in d


def test_npm_and_docker_representation_unchanged():
    reg = FixtureRegistry([h.REGISTRY])
    npm = resolve_entry(ServerEntry(name="n", transport="stdio", command="npx",
                                    args=["@caplock-demo/notes-mcp@1.0.0"]), reg)
    assert npm.integrity.startswith("sha512-") and "integritySet" not in npm.to_dict()
    dock = resolve_entry(ServerEntry(name="d", transport="stdio", command="docker",
                                     args=["run", "-i", "ghcr.io/caplock-demo/notes-mcp:1.0.0"]), reg)
    assert dock.integrity.startswith("sha256:") and "integritySet" not in dock.to_dict()


@pytest.fixture
def locked(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    assert h.run(["lock"] + h.cli_args(ws))[0] == 0
    return ws


def test_lockfile_records_integrity_set(locked):
    pkg = json.loads((locked / "mcp-lock.json").read_text())["servers"]["weather"]["package"]
    assert [e["file"] for e in pkg["integritySet"]] == sorted(e["file"] for e in pkg["integritySet"])
    assert pkg["integrity"] == sha256_of(pkg["integritySet"])


@pytest.mark.parametrize("tamper, msg", [
    (lambda p: p["integritySet"][0].update(sha256="0" * 64), "does not match integritySet"),
    (lambda p: p["integritySet"].reverse(), "sorted by file"),
    (lambda p: p.pop("integritySet"), "missing 'integritySet'"),
])
def test_lockfile_validation_of_integrity_set(locked, tamper, msg):
    lock = json.loads((locked / "mcp-lock.json").read_text())
    tamper(lock["servers"]["weather"]["package"])
    with pytest.raises(lockfile.LockfileError, match=msg):
        lockfile.validate(lock)


def test_pypi_code_only_change_is_integrity_mismatch_naming_the_file(locked):
    args = h.cli_args(locked, registry_overlay="F-pypi-code-only")
    code, report = h.run_json(["verify"] + args)
    assert code == 1
    [f] = report["findings"]
    assert (f["code"], f["severity"], f["server"]) == ("integrity_mismatch", "critical", "weather")
    assert "changed: caplock_demo_weather-0.3.1-py3-none-any.whl" in f["message"]
    assert [e["file"] for e in f["before"]] == [e["file"] for e in f["after"]] == [
        "caplock_demo_weather-0.3.1-py3-none-any.whl"]


def test_scenario_F_still_critical_integrity_mismatch(locked):
    sc = next(s for s in h.load_scenarios() if s["id"] == "F")
    code, report = h.run_json(["verify"] + h.apply_scenario(locked, sc))
    assert code == 1
    assert [(f["code"], f["severity"]) for f in report["findings"]] == [("integrity_mismatch", "critical")]
