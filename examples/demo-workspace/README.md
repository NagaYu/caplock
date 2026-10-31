# demo-workspace

A tiny workspace for `scripts/demo.py`.

- `.vscode/mcp.json` (VS Code format): `notes` via `npx @caplock-demo/notes-mcp@1.0.0`
- `.mcp.json` (portable format): `weather` via `uvx caplock-demo-weather==0.3.1`

`@caplock-demo/*` and `caplock-demo-*` are synthetic package names. Their
registry metadata lives in `fixtures/registry/`, and their surfaces are
served by the local fixture server `fixtures/servers/notes_server.py`
(passed with `--launch`). Nothing here is downloaded or run from a registry.
