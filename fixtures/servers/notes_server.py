#!/usr/bin/env python3
"""Benign fixture MCP server (stdio, newline-delimited JSON-RPC 2.0, stdlib only).

It serves tool / resource / prompt definitions from a JSON file and never
performs any real action: tools/call returns a canned text result.

Usage:
  notes_server.py [--tools FILE] [--page-size N] [--mode MODE] [--era ERA] [--protocol-version V]

Eras (MCP protocol generations):
  dual           answers server/discover (modern, 2026-07-28) and initialize (legacy). Default.
  modern         stateless only: requires _meta on every request, rejects initialize
  legacy         initialize handshake only; rejects server/discover with -32601
  legacy-silent  initialize handshake only; ignores unknown requests (no answer)

Modes (for client tests):
  normal           regular behavior (default)
  hang             never answers anything
  hang-tools       answers initialize, then never answers tools/list
  crash            exits immediately with status 3
  server-ping      sends a ping request and a log notification before tools/list
  no-aux           advertises tools only (resources/prompts capabilities absent)
  aux-error        advertises resources/prompts but answers them with errors
  bad-version      offers only an unsupported protocol version
  version-error    answers server/discover with UnsupportedProtocolVersionError (-32022)
"""

import argparse
import json
import sys
from pathlib import Path

MODERN = ["2026-07-28"]
LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
META_VERSION = "io.modelcontextprotocol/protocolVersion"
DEFAULT_TOOLS = Path(__file__).resolve().parent / "tools" / "benign.json"


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def page(items, cursor, size):
    start = int(cursor) if cursor else 0
    if size <= 0:
        return items[start:], None
    chunk = items[start : start + size]
    nxt = start + size
    return chunk, (str(nxt) if nxt < len(items) else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default=str(DEFAULT_TOOLS))
    ap.add_argument("--page-size", type=int, default=0)
    ap.add_argument("--mode", default="normal")
    ap.add_argument("--protocol-version", default=None)
    ap.add_argument("--era", default="dual", choices=["dual", "modern", "legacy", "legacy-silent"])
    opts = ap.parse_args()

    if opts.mode == "crash":
        sys.exit(3)

    data = json.loads(Path(opts.tools).read_text(encoding="utf-8"))
    if isinstance(data, list):
        data = {"tools": data}
    tools = data.get("tools", [])
    resources = data.get("resources")
    prompts = data.get("prompts")
    aux = opts.mode != "no-aux"
    modern_ok = opts.era in ("dual", "modern")
    legacy_ok = opts.era in ("dual", "legacy", "legacy-silent")
    initialized = False

    def caps():
        c = {"tools": {"listChanged": False}}
        if aux and resources is not None:
            c["resources"] = {}
        if aux and prompts is not None:
            c["prompts"] = {}
        return c

    def error(mid, code, message, data=None):
        err = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        send({"jsonrpc": "2.0", "id": mid, "error": err})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        if opts.mode == "hang":
            continue
        method = msg.get("method")
        mid = msg.get("id")
        if method is None or mid is None:
            # response to our ping, or a notification
            if method == "notifications/initialized" and opts.mode == "server-ping":
                send({"jsonrpc": "2.0", "id": "srv-ping-1", "method": "ping"})
                send({"jsonrpc": "2.0", "method": "notifications/message",
                      "params": {"level": "info", "data": "fixture server ready"}})
            continue

        params = msg.get("params") or {}
        meta = params.get("_meta") or {}
        is_modern = META_VERSION in meta

        if method == "server/discover":
            if not modern_ok:
                if opts.era == "legacy":
                    error(mid, -32601, "Method not found")
                continue  # legacy-silent: no answer
            if opts.mode == "version-error":
                error(mid, -32022, "Unsupported protocol version",
                      {"supported": ["2099-01-01"], "requested": meta.get(META_VERSION)})
                continue
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "resultType": "complete",
                "supportedVersions": ["2099-01-01"] if opts.mode == "bad-version" else MODERN,
                "capabilities": caps(),
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "caplock-fixture-notes", "version": "1.0.0"}},
            }})
            continue

        if method == "initialize":
            if not legacy_ok:
                error(mid, -32601, "Method not found (modern server; use server/discover)",
                      {"supported": MODERN})
                continue
            requested = params.get("protocolVersion")
            version = opts.protocol_version or (requested if requested in LEGACY else LEGACY[0])
            if opts.mode == "bad-version":
                version = "1999-01-01"
            initialized = True
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": version,
                "capabilities": caps(),
                "serverInfo": {"name": "caplock-fixture-notes", "version": "1.0.0"},
            }})
            continue

        # Every other request: modern requests carry _meta; legacy ones need a prior initialize.
        if is_modern and modern_ok:
            if meta.get(META_VERSION) not in MODERN:
                error(mid, -32022, "Unsupported protocol version",
                      {"supported": MODERN, "requested": meta.get(META_VERSION)})
                continue
        elif not (initialized and legacy_ok):
            if opts.era == "legacy-silent":
                continue
            error(mid, -32602, "Invalid params: missing _meta protocol fields" if modern_ok
                  else "Server not initialized")
            continue

        if method == "tools/list":
            if opts.mode == "hang-tools":
                continue
            cursor = (msg.get("params") or {}).get("cursor")
            chunk, nxt = page(tools, cursor, opts.page_size)
            result = {"tools": chunk}
            if is_modern:
                result["resultType"] = "complete"
            if nxt:
                result["nextCursor"] = nxt
            send({"jsonrpc": "2.0", "id": mid, "result": result})
        elif method in ("resources/list", "prompts/list") and aux:
            if opts.mode == "aux-error":
                send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": "unavailable"}})
                continue
            key = method.split("/")[0]
            items = resources if key == "resources" else prompts
            send({"jsonrpc": "2.0", "id": mid, "result": {key: items or []}})
        elif method == "tools/call":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": "fixture: no action performed"}]}})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        else:
            send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}})


if __name__ == "__main__":
    main()
