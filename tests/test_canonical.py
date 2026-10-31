import json

import pytest

from caplock.canonical import (
    CanonicalizationError,
    canonical_json,
    canonical_tool,
    escape_invisible,
    find_invisible_chars,
    surface_hash,
    tool_hash,
)

BASE = {
    "name": "read_note",
    "description": "Read a note by its identifier.",
    "inputSchema": {
        "type": "object",
        "properties": {"note_id": {"type": "string", "maxLength": 64}},
        "required": ["note_id"],
    },
    "annotations": {"readOnlyHint": True},
}


def test_key_order_and_formatting_do_not_change_hash():
    reordered = json.loads(
        """
        {  "annotations" : {"readOnlyHint":true},
           "inputSchema": {"required": ["note_id"],
                           "properties": {"note_id": {"maxLength": 64, "type": "string"}},
                           "type": "object"},
           "description": "Read a note by its identifier.",
           "name": "read_note" }
        """
    )
    assert tool_hash(reordered) == tool_hash(BASE)


def test_surrounding_whitespace_is_stripped():
    t = dict(BASE, description="  Read a note by its identifier.\n\t")
    assert tool_hash(t) == tool_hash(BASE)


def test_unicode_nfc_unifies_composed_and_decomposed():
    composed = dict(BASE, description="Café notes")
    decomposed = dict(BASE, description="Café notes")
    assert tool_hash(composed) == tool_hash(decomposed)


def test_number_representation_is_unified():
    a = json.loads('{"name":"x","inputSchema":{"maximum": 10, "minimum": 0.5}}')
    b = json.loads('{"name":"x","inputSchema":{"maximum": 10.0, "minimum": 5e-1}}')
    c = json.loads('{"name":"x","inputSchema":{"maximum": 1e1, "minimum": 0.50}}')
    assert tool_hash(a) == tool_hash(b) == tool_hash(c)


def test_booleans_are_not_confused_with_numbers():
    a = {"name": "x", "inputSchema": {"default": True}}
    b = {"name": "x", "inputSchema": {"default": 1}}
    assert tool_hash(a) != tool_hash(b)


def test_non_identity_fields_are_ignored():
    t = dict(BASE, _meta={"anything": 1}, icons=[{"src": "x.png"}])
    assert tool_hash(t) == tool_hash(BASE)
    assert "_meta" not in canonical_tool(t)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.update(description="Read a note by its id."),
        lambda t: t["inputSchema"]["properties"].update(cc={"type": "string"}),
        lambda t: t["inputSchema"]["required"].append("cc"),
        lambda t: t.update(annotations={"readOnlyHint": False}),
        lambda t: t.update(title="Read note"),
        lambda t: t.update(outputSchema={"type": "object"}),
        lambda t: t.update(description="Read a note  by its identifier."),  # inner whitespace kept
    ],
)
def test_substantive_change_changes_hash(mutate):
    t = json.loads(json.dumps(BASE))
    mutate(t)
    assert tool_hash(t) != tool_hash(BASE)


def test_array_order_is_significant():
    a = {"name": "x", "inputSchema": {"enum": ["a", "b"]}}
    b = {"name": "x", "inputSchema": {"enum": ["b", "a"]}}
    assert tool_hash(a) != tool_hash(b)


def test_invisible_chars_are_kept_and_detected():
    poisoned = dict(BASE, description="Read a note​ by its identifier.﻿")
    assert tool_hash(poisoned) != tool_hash(BASE)
    found = find_invisible_chars(canonical_tool(poisoned))
    cps = {f["codepoint"] for f in found}
    assert cps == {"U+200B", "U+FEFF"}
    assert all(f["path"] == "description" for f in found)
    # BOM at the edge is not stripped away by normalization
    assert canonical_tool(poisoned)["description"].endswith("﻿")


def test_invisible_chars_in_keys_and_tag_characters():
    t = {"name": "x", "inputSchema": {"properties": {"to⁠": {"description": "\U000E0041"}}}}
    found = find_invisible_chars(t)
    assert {f["codepoint"] for f in found} == {"U+2060", "U+E0041"}


def test_clean_definition_has_no_invisible_chars():
    assert find_invisible_chars(canonical_tool(BASE)) == []


def test_nan_is_rejected():
    with pytest.raises(CanonicalizationError):
        canonical_json({"x": float("nan")})


def test_surface_hash_is_order_independent():
    a = surface_hash({"a": "sha256:1", "b": "sha256:2"})
    b = surface_hash({"b": "sha256:2", "a": "sha256:1"})
    assert a == b


def test_escape_invisible_makes_chars_visible():
    assert escape_invisible("a​b") == "a\\u200bb"
    assert escape_invisible("\U000E0041") == "\\udb40\\udc41"
    assert escape_invisible("日本語") == "日本語"


def test_known_hash_is_fixed():
    # Pin the exact serialization so accidental rule changes are caught.
    assert canonical_json(BASE) == (
        '{"annotations":{"readOnlyHint":true},"description":"Read a note by its identifier.",'
        '"inputSchema":{"properties":{"note_id":{"maxLength":64,"type":"string"}},'
        '"required":["note_id"],"type":"object"},"name":"read_note"}'
    )
