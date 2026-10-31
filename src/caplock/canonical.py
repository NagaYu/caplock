"""Canonicalization and hashing of tool definitions.

Normalization rules (also documented in README.md, fixed by tests):

1. Only the tool-definition fields in ``TOOL_FIELDS`` participate; other
   fields (``_meta``, ``icons``, ...) are ignored.
2. Object keys are sorted recursively (code-point order). Keys are NFC
   normalized but not stripped.
3. Every string value is Unicode NFC normalized, then leading and trailing
   whitespace (``str.strip()``) is removed.
4. Numbers are unified: an integral float (``1.0``, ``1e2``, ``-0.0``) becomes
   the integer (``1``, ``100``, ``0``); other floats use the shortest
   round-trip repr. ``NaN``/``Infinity`` are rejected. Booleans stay booleans.
5. Array order is preserved (order can be meaningful, e.g. ``enum``).
6. Serialization: compact JSON (``","`` / ``":"``), UTF-8, no ASCII escaping.
   The hash is ``sha256:`` + hex digest of those bytes.

Invisible characters (zero-width, bidi controls, BOM, tag characters, ...)
are deliberately *not* removed: they change the hash and are reported
separately by ``find_invisible_chars``.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from typing import Any

TOOL_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

# Characters that render as nothing (or reorder text) but survive NFC and strip().
_INVISIBLE_RANGES = (
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x061C, 0x061C),  # arabic letter mark
    (0x115F, 0x1160),  # hangul fillers
    (0x17B4, 0x17B5),  # khmer vowel inherent
    (0x180B, 0x180F),  # mongolian free variation selectors / vowel separator
    (0x200B, 0x200F),  # zero width space/non-joiner/joiner, LRM, RLM
    (0x202A, 0x202E),  # bidi embedding / override
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x206F),  # bidi isolates, deprecated format chars
    (0x3164, 0x3164),  # hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFEFF, 0xFEFF),  # BOM / zero width no-break space
    (0xFFA0, 0xFFA0),  # halfwidth hangul filler
    (0xFFF9, 0xFFFB),  # interlinear annotation
    (0xE0000, 0xE007F),  # tag characters
    (0xE0100, 0xE01EF),  # variation selectors supplement
)


class CanonicalizationError(ValueError):
    pass


def is_invisible(ch: str) -> bool:
    cp = ord(ch)
    for lo, hi in _INVISIBLE_RANGES:
        if lo <= cp <= hi:
            return True
    # Other C0/C1 control characters except ordinary whitespace.
    if (cp < 0x20 and ch not in "\t\n\r") or 0x7F <= cp <= 0x9F:
        return True
    return False


def _canon_number(value: float) -> int | float:
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN/Infinity are not valid in tool definitions")
    if value == int(value):
        return int(value)
    return value


def canonicalize(value: Any) -> Any:
    """Return the normalized form of a JSON-compatible value."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return _canon_number(value)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value).strip()
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string key: {k!r}")
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise CanonicalizationError(f"duplicate key after NFC normalization: {nk!r}")
            out[nk] = canonicalize(v)
        return {k: out[k] for k in sorted(out)}
    if isinstance(value, (list, tuple)):
        return [canonicalize(v) for v in value]
    raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_of(value: Any) -> str:
    data = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_tool(tool: dict) -> dict:
    """Pick the identity-bearing fields of a tool definition and normalize them."""
    return canonicalize({k: tool[k] for k in TOOL_FIELDS if k in tool})


def tool_hash(tool: dict) -> str:
    return sha256_of(canonical_tool(tool))


def surface_hash(tool_hashes: dict[str, str]) -> str:
    """Server-level hash over the (name -> tool hash) mapping."""
    return sha256_of(tool_hashes)


def find_invisible_chars(value: Any, path: str = "") -> list[dict]:
    """Locate invisible characters in every string (keys included).

    Returns entries ``{"path", "codepoint", "name"}``; never modifies input.
    """
    found: list[dict] = []

    def scan_str(s: str, p: str) -> None:
        for ch in s:
            if is_invisible(ch):
                found.append(
                    {
                        "path": p,
                        "codepoint": f"U+{ord(ch):04X}",
                        "name": unicodedata.name(ch, "UNNAMED"),
                    }
                )

    def walk(v: Any, p: str) -> None:
        if isinstance(v, str):
            scan_str(v, p)
        elif isinstance(v, dict):
            for k, sub in v.items():
                scan_str(k, f"{p}.{k}" if p else k)
                walk(sub, f"{p}.{k}" if p else k)
        elif isinstance(v, list):
            for i, sub in enumerate(v):
                walk(sub, f"{p}[{i}]")

    walk(value, path)
    return found


def escape_invisible(text: str) -> str:
    """Make invisible characters visible as \\uXXXX escapes (for JSON output)."""
    out = []
    for ch in text:
        if is_invisible(ch) and ch not in "\t\n\r":
            cp = ord(ch)
            if cp > 0xFFFF:
                cp -= 0x10000
                out.append(f"\\u{0xD800 + (cp >> 10):04x}\\u{0xDC00 + (cp & 0x3FF):04x}")
            else:
                out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)
