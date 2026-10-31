"""caplock evidence: pack generation, manifest verification and tamper detection (offline)."""

import json
import shutil
import zipfile

import pytest

import harness as h
from caplock import evidence
from caplock.sarif import RULE_CATALOG_VERSION, rule_catalog
from p2_common import scenario_ws

NOW = "2026-10-31T00:00:00Z"
PACKED = ["EVIDENCE.md", "approval.json", "mcp-lock.json", "rule-catalog.json", "verify.md", "verify.sarif"]


@pytest.fixture
def ws(locked_base, tmp_path):
    dst = tmp_path / "ws"
    shutil.copytree(locked_base, dst)
    return dst


def make_pack(ws, out, *extra):
    code, text = h.run(["evidence"] + h.cli_args(ws) + ["--out", str(out), *extra])
    return code, text


@pytest.fixture
def pack(ws, tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1793404800")
    out = tmp_path / "pack"
    code, text = make_pack(ws, out)
    assert code == 0, text
    return out


def check(path):
    return h.run(["evidence", "--verify", str(path)])


# --------------------------------------------------------------------------- catalog version


def test_rule_catalog_is_versioned_and_pinned():
    cat = rule_catalog()
    assert cat["version"] == RULE_CATALOG_VERSION == "1.0.0" and cat["ruleCount"] == 43
    # Changing any rule changes this digest: bump RULE_CATALOG_VERSION and update the pin together.
    assert cat["digest"] == "sha256:9adaf40a656a3c3f09d34eff36e0cd4502df88c8fee558e2867297fe3f6984c8"


def test_sarif_driver_records_catalog_version(ws, tmp_path):
    sarif = tmp_path / "v.sarif"
    code, _ = h.run(["verify"] + h.cli_args(ws) + ["--format", "sarif", "--output", str(sarif)])
    props = json.loads(sarif.read_text())["runs"][0]["tool"]["driver"]["properties"]
    assert props == {"ruleCatalogVersion": "1.0.0", "ruleCatalogDigest": rule_catalog()["digest"]}


# --------------------------------------------------------------------------- generate


def test_pack_contains_required_files_and_manifest(pack, ws):
    assert sorted(p.name for p in pack.iterdir()) == sorted(PACKED + ["manifest.json"])
    m = json.loads((pack / "manifest.json").read_text())
    assert m["format"] == "caplock-evidence/v1" and m["generatedAt"] == "2026-10-31T00:00:00Z"
    assert m["caplockVersion"] and m["ruleCatalog"]["version"] == "1.0.0"
    assert [f["path"] for f in m["files"]] == PACKED
    for f in m["files"]:
        assert f["sha256"] == evidence.sha256_bytes((pack / f["path"]).read_bytes())
    assert (pack / "mcp-lock.json").read_bytes() == (ws / "mcp-lock.json").read_bytes()
    lock = json.loads((ws / "mcp-lock.json").read_text())
    approval = json.loads((pack / "approval.json").read_text())
    assert {k: approval[k] for k in ("generatedAt", "caplockVersion")} == lock["approval"]
    assert m["verify"] == {"source": "run", "exitCode": 0, "verdict": "PASS", "failOn": "high",
                           "findingCounts": {}, "ruleCatalogVersion": "1.0.0"}
    assert m["workspace"]["configFiles"] == [{"path": ".vscode/mcp.json", "format": "vscode"},
                                             {"path": ".mcp.json", "format": "portable"}]
    assert json.loads((pack / "rule-catalog.json").read_text()) == rule_catalog()


def test_pack_states_its_limits(pack):
    text = (pack / "EVIDENCE.md").read_text() + (pack / "manifest.json").read_text()
    assert "does not attest to the runtime behavior" in text
    assert "does not prove who produced it" in text
    assert "Not an official Microsoft" in text
    assert "guarantee" not in text.lower() and "certified" not in text.lower()


def test_failing_verify_is_packed_and_exit_code_is_kept(locked_base, tmp_path):
    ws, args = scenario_ws(locked_base, tmp_path, "F")
    code, text = h.run(["evidence"] + args + ["--out", str(tmp_path / "p")])
    assert code == 1 and "FAIL (exit 1)" in text
    m = json.loads((tmp_path / "p" / "manifest.json").read_text())
    assert m["verify"]["verdict"] == "FAIL" and m["verify"]["findingCounts"] == {"critical": 1}
    assert "integrity_mismatch" in (tmp_path / "p" / "verify.sarif").read_text()


def test_unverifiable_verify_is_packed_as_exit_2(locked_base, tmp_path):
    ws, args = scenario_ws(locked_base, tmp_path, "G2")
    code, text = h.run(["evidence"] + args + ["--out", str(tmp_path / "p")])
    assert code == 2 and "UNVERIFIABLE (exit 2)" in text


def test_supplied_reports_are_packed_byte_for_byte(locked_base, tmp_path):
    ws, args = scenario_ws(locked_base, tmp_path, "F")
    sarif, md = tmp_path / "ci.sarif", tmp_path / "ci.md"
    assert h.run(["verify"] + args + ["--report", f"sarif={sarif}", "--report", f"markdown={md}"])[0] == 1
    code, _ = h.run(["evidence"] + args + ["--sarif", str(sarif), "--markdown", str(md), "--out", str(tmp_path / "p")])
    assert code == 1
    assert (tmp_path / "p" / "verify.sarif").read_bytes() == sarif.read_bytes()
    assert (tmp_path / "p" / "verify.md").read_bytes() == md.read_bytes()
    assert json.loads((tmp_path / "p" / "manifest.json").read_text())["verify"]["source"] == "supplied"


def test_no_secret_values_in_pack(locked_base, tmp_path):
    ws = tmp_path / "ws"
    shutil.copytree(locked_base, ws)
    cfg = json.loads((ws / ".vscode" / "mcp.json").read_text())
    cfg["servers"]["notes"]["env"] = {"NOTES_TOKEN": "sk-live-DO-NOT-LEAK-4242"}
    (ws / ".vscode" / "mcp.json").write_text(json.dumps(cfg))
    code, _ = h.run(["evidence"] + h.cli_args(ws) + ["--out", str(tmp_path / "p")])
    assert code in (0, 1)
    for f in (tmp_path / "p").iterdir():
        assert "DO-NOT-LEAK" not in f.read_text(), f.name


def test_missing_lockfile_writes_nothing(tmp_path):
    ws = h.prepare_workspace(tmp_path / "ws")
    code, text = h.run(["evidence"] + h.cli_args(ws) + ["--out", str(tmp_path / "p")])
    assert code == 2 and "Nothing written" in text and not (tmp_path / "p").exists()


def test_usage_errors(ws, tmp_path):
    assert h.run(["evidence"] + h.cli_args(ws) + ["--sarif", "x.sarif"])[0] == 3
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "keep.txt").write_text("x")
    assert h.run(["evidence"] + h.cli_args(ws) + ["--out", str(busy)])[0] == 3


# --------------------------------------------------------------------------- verify / tamper


def test_fresh_pack_verifies(pack):
    code, text = check(pack)
    assert code == 0 and "INTACT (exit 0): all 6 file(s)" in text and "manifest digest: sha256:" in text
    assert "not prove who produced it" in text


@pytest.mark.parametrize("name", PACKED)
def test_one_modified_file_is_detected(pack, name):
    p = pack / name
    p.write_bytes(p.read_bytes() + b" ")
    code, text = check(pack)
    assert code == 1 and "TAMPERED (exit 1)" in text and f"{name}: modified" in text


def test_missing_and_unlisted_files_are_detected(pack):
    (pack / "verify.md").unlink()
    (pack / "extra.txt").write_text("added later")
    code, text = check(pack)
    assert code == 1 and "verify.md: missing" in text and "extra.txt: not listed" in text


def test_lockfile_swap_with_matching_entry_but_stale_approval_is_detected(pack, ws):
    m = json.loads((pack / "manifest.json").read_text())
    (pack / "mcp-lock.json").write_text("{}\n")
    for f in m["files"]:
        if f["path"] == "mcp-lock.json":
            f["sha256"], f["bytes"] = evidence.sha256_bytes(b"{}\n"), 3
    (pack / "manifest.json").write_text(json.dumps(m))
    code, text = check(pack)
    assert code == 1 and "approval.lockfileSha256 does not match" in text


def test_consistent_rewrite_of_file_and_manifest_is_not_detected(pack):
    """Documented limit: the pack is unsigned, so a coordinated rewrite passes --verify."""
    new = b"# rewritten\n"
    (pack / "verify.md").write_bytes(new)
    m = json.loads((pack / "manifest.json").read_text())
    for f in m["files"]:
        if f["path"] == "verify.md":
            f["sha256"], f["bytes"] = evidence.sha256_bytes(new), len(new)
    before = check(pack)[1].split("manifest digest: ")[1].split()[0]
    (pack / "manifest.json").write_text(json.dumps(m))
    code, text = check(pack)
    assert code == 0
    assert text.split("manifest digest: ")[1].split()[0] != before  # only an out-of-band digest catches it


@pytest.mark.parametrize("content, why", [(None, "missing"), ("not json", "not a valid manifest"),
                                          ('{"format": "other", "files": []}', "not a valid manifest")])
def test_unusable_manifest_is_unverifiable_not_pass(pack, content, why):
    if content is None:
        (pack / "manifest.json").unlink()
    else:
        (pack / "manifest.json").write_text(content)
    code, text = check(pack)
    assert code == 2 and why in text and "This is not a pass" in text


def test_unsafe_manifest_path_is_rejected(pack):
    m = json.loads((pack / "manifest.json").read_text())
    m["files"].append({"path": "../outside.txt", "sha256": "sha256:00", "bytes": 0})
    (pack / "manifest.json").write_text(json.dumps(m))
    code, text = check(pack)
    assert code == 1 and "unsafe path" in text


def test_zip_pack_is_deterministic_and_tamper_evident(ws, tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1793404800")
    a, b = tmp_path / "a", tmp_path / "b"
    assert make_pack(ws, a, "--zip")[0] == 0 and make_pack(ws, b, "--zip")[0] == 0
    za, zb = tmp_path / "a.zip", tmp_path / "b.zip"
    assert za.read_bytes() == zb.read_bytes()
    assert check(za)[0] == 0
    tampered = tmp_path / "t.zip"
    with zipfile.ZipFile(za) as src, zipfile.ZipFile(tampered, "w") as dst:
        for info in src.infolist():
            data = src.read(info)
            dst.writestr(info, data.replace(b"PASS", b"FAIL") if info.filename == "verify.md" else data)
    code, text = check(tampered)
    assert code == 1 and "verify.md: modified" in text


def test_not_a_pack_is_unverifiable(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("hello")
    assert check(f)[0] == 2
