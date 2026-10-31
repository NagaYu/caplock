import json
from pathlib import Path

from caplock.capability import classify, name_tokens

TOOLS = Path(__file__).resolve().parent.parent / "fixtures" / "servers" / "tools"


def load(name):
    return {t["name"]: t for t in json.loads((TOOLS / name).read_text())["tools"]}


def sources(r, cap):
    return {e["source"] for e in r.evidence if e["capability"] == cap}


def test_name_tokens():
    assert name_tokens("fetchURLContent") == ["fetch", "url", "content"]
    assert name_tokens("delete-repo_item") == ["delete", "repo", "item"]


def test_benign_fixture_tools():
    tools = load("benign.json")
    r = classify(tools["read_note"])
    assert r.capabilities == ["read"]
    assert "annotations.readOnlyHint" in sources(r, "read")
    w = classify(tools["write_note"])
    assert w.capabilities == ["write"]
    f = classify(tools["fetch_status"])
    assert f.capabilities == ["read", "network"]
    assert f.network_hosts == ["status.example.com"]
    assert "description.url" in sources(f, "network")
    assert "annotations.openWorldHint" in sources(f, "network")


def test_annotations_drive_classification():
    r = classify({"name": "x", "annotations": {"readOnlyHint": False, "destructiveHint": True}})
    assert r.capabilities == ["write", "destructive"]


def test_destructive_hint_ignored_when_read_only():
    # MCP: destructiveHint is meaningful only when readOnlyHint == false
    r = classify({"name": "x", "annotations": {"readOnlyHint": True, "destructiveHint": True}})
    assert r.capabilities == ["read"]


def test_absent_annotations_are_not_assumed():
    # MCP defaults (destructiveHint=true, openWorldHint=true) are not applied.
    r = classify({"name": "frobnicate", "description": "Frobnicates the widget."})
    assert r.capabilities == ["unknown"]
    assert r.evidence == [{"capability": "unknown", "source": "none", "detail": "no rule matched"}]


def test_schema_properties():
    r = classify({"name": "notify", "inputSchema": {"type": "object", "properties": {
        "webhook_url": {"type": "string", "default": "https://hooks.example.org/x"}}}})
    assert "network" in r.capabilities
    assert r.network_hosts == ["hooks.example.org"]
    r = classify({"name": "x", "inputSchema": {"properties": {"forward_to": {"type": "string", "format": "email"}}}})
    assert r.capabilities == ["network"]
    assert sources(r, "network") == {"inputSchema.properties.forward_to",
                                     "inputSchema.properties.forward_to.format"}
    r = classify({"name": "x", "inputSchema": {"properties": {"command": {"type": "string"}}}})
    assert r.capabilities == ["exec"]


def test_exec_from_name_and_description():
    tools = load("D_tool_added.json")
    r = classify(tools["run_command"])
    assert "exec" in r.capabilities
    assert {"name", "description.phrase", "inputSchema.properties.command"} <= sources(r, "exec")


def test_destructive_from_name_and_phrase():
    r = classify({"name": "delete_item", "description": "Delete an item permanently."})
    assert r.capabilities == ["destructive"]
    assert sources(r, "destructive") == {"name", "description.leadingVerb", "description.phrase"}


def test_conflicts_are_kept_not_resolved():
    r = classify({"name": "delete_everything", "annotations": {"readOnlyHint": True}})
    assert r.capabilities == ["read", "destructive"]
    assert r.conflicts == ["annotations.readOnlyHint=true but 'destructive' evidence exists"]


def test_readonly_flip_adds_write():
    before = classify(load("benign.json")["read_note"])
    after = classify(load("C_readonly_flipped.json")["read_note"])
    assert set(after.capabilities) - set(before.capabilities) == {"write"}


def test_classification_is_deterministic():
    t = load("benign.json")["fetch_status"]
    assert classify(t).to_dict() == classify(json.loads(json.dumps(t))).to_dict()
