"""SARIF 2.1.0 output for ``caplock verify --format sarif``.

Mapping (decided in Phase 2):

* rule id = finding code; every code has a rule with name / shortDescription /
  fullDescription. The full catalog is always emitted so rule indices are stable.
* level: critical / high → error, medium → warning, info → note.
  Unverifiable findings are always ``error`` with ``properties.unverifiable = true``
  (and the ``unverifiable`` tag) so code scanning cannot quietly drop them.
* location: the config file the server came from when known, otherwise the
  lockfile. No region (CapLock does not track line numbers).
* partialFingerprints["caplockFinding/v1"]: sha256 of the canonical JSON of
  (server, tool, code, field), stable across runs and machines.

The output is deterministic: no timestamps, results in the report's sort order.

The rule catalog carries a version (Phase 3). ``rule_catalog()`` returns it
with a digest over every rule's id, name, severity and descriptions; the
digest is pinned in tests, so any change to the catalog forces a version bump.
"""

from __future__ import annotations

from caplock import LIMITATION_NOTICE, __version__
from caplock.canonical import sha256_of
from caplock.diff import Finding
from caplock.report import ReportContext, location_of, needs_review, verdict

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
FINGERPRINT_KEY = "caplockFinding/v1"

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "info": "note", "unverifiable": "error"}

# code: (name, default severity, short description, full description)
RULES: dict[str, tuple[str, str, str, str]] = {
    # --- unverifiable
    "floating_version": ("FloatingVersion", "unverifiable", "Package version is not pinned",
        "The launch spec has no exact version (no version, @latest, a range, a dist-tag, or a docker image "
        "without tag / with :latest). Whatever the registry serves at launch time will run, so the package "
        "identity cannot be verified."),
    "package_unresolvable": ("PackageUnresolvable", "unverifiable", "Package cannot be identified",
        "The command is not npx / uvx / docker run, or uses a git, URL or local path spec. CapLock cannot "
        "identify the package; manual review is required."),
    "integrity_unrecorded": ("IntegrityUnrecorded", "unverifiable", "Package integrity is not recorded",
        "No integrity is available for the pinned version (offline without registry records, or the "
        "version is not published)."),
    "remote_entity_unverifiable": ("RemoteEntityUnverifiable", "unverifiable", "Remote server code cannot be pinned",
        "HTTP servers are compared only through a recorded tools/list surface; the code behind the URL "
        "cannot be pinned or observed."),
    "enumeration_failed": ("EnumerationFailed", "unverifiable", "Tool surface could not be enumerated",
        "Starting or talking to the server failed (timeout, exit, protocol version, duplicate tool names...)."),
    "surface_not_enumerated": ("SurfaceNotEnumerated", "unverifiable", "No surface source was given",
        "No --launch, --allow-launch or --surface option was given for this server."),
    "lock_incomplete": ("LockIncomplete", "unverifiable", "Lockfile lacks integrity or surface",
        "The lockfile was written while this server was unverifiable; re-run caplock lock."),
    "lockfile_missing": ("LockfileMissing", "unverifiable", "Lockfile not found",
        "mcp-lock.json does not exist; run caplock lock and commit it."),
    "lockfile_invalid": ("LockfileInvalid", "unverifiable", "Lockfile failed validation",
        "The lockfile violates the schema or its recorded hashes do not match its recorded definitions."),
    "config_error": ("ConfigError", "unverifiable", "MCP configuration could not be read",
        "A configuration file is malformed, so the state cannot be reconstructed."),
    "no_config": ("NoConfig", "unverifiable", "No MCP configuration found",
        "Neither .vscode/mcp.json nor .mcp.json (nor any --config file) was found."),
    # --- critical
    "capability_expanded": ("CapabilityExpanded", "critical", "Tool gained a write/destructive/exec/network capability",
        "The deterministic classification of the tool now includes a capability it did not have when approved."),
    "annotation_readonly_revoked": ("ReadOnlyHintRevoked", "critical", "readOnlyHint changed from true",
        "annotations.readOnlyHint was true and is now false or absent (absent defaults to false)."),
    "annotation_destructive_added": ("DestructiveHintAdded", "critical", "destructiveHint became true",
        "annotations.destructiveHint is now explicitly true."),
    "integrity_mismatch": ("IntegrityMismatch", "critical", "Same version, different package content",
        "The pinned version now resolves to a different integrity than the lockfile recorded, even if the tool "
        "definitions are unchanged (code-only change)."),
    "package_changed": ("PackageChanged", "critical", "A different package is launched",
        "The ecosystem or package name of the launch spec changed."),
    "remote_host_changed": ("RemoteHostChanged", "critical", "Connection host changed",
        "The host of the configured server URL changed."),
    "network_host_added": ("NetworkHostAdded", "critical", "Tool has a new network target host",
        "A host appeared in the tool's description or schema defaults that was not there when approved."),
    # --- high
    "tool_added": ("ToolAdded", "high", "New tool", "The server exposes a tool that was not approved."),
    "server_added": ("ServerAdded", "high", "New server", "A server is configured that is not in the lockfile."),
    "instruction_injection": ("InstructionInjection", "high", "Instruction-like text appeared",
        "A known instruction-injection shape (hidden-instruction tag, 'ignore previous instructions', "
        "concealment from the user, sensitive file reference) appeared in the tool definition."),
    "invisible_chars": ("InvisibleCharacters", "high", "Invisible characters in tool definition",
        "Zero-width, bidi-control, BOM, tag or other invisible characters are present."),
    "required_param_added": ("RequiredParameterAdded", "high", "New required parameter",
        "A parameter was added as required, or an existing parameter became required."),
    "capability_unknown": ("CapabilityUnknown", "high", "Classification evidence disappeared",
        "No classification rule matches the tool any more; its capability is now unknown."),
    "config_changed": ("ConfigChanged", "medium", "Server configuration changed",
        "Command, transport, arguments, env/header keys, URL path or envFile changed. Command and transport "
        "changes are high, the others medium or info."),
    # --- medium
    "optional_param_added": ("OptionalParameterAdded", "medium", "New optional parameter",
        "A parameter was added to inputSchema without being required."),
    "param_removed": ("ParameterRemoved", "medium", "Parameter removed", "A parameter was removed from inputSchema."),
    "schema_changed": ("SchemaChanged", "medium", "inputSchema changed",
        "A parameter definition, the required list or another inputSchema keyword changed."),
    "description_changed": ("DescriptionChanged", "medium", "Description changed",
        "The tool description changed substantively (beyond whitespace and normalization)."),
    "title_changed": ("TitleChanged", "medium", "Title changed", "The tool title changed."),
    "output_schema_changed": ("OutputSchemaChanged", "medium", "outputSchema changed", "The outputSchema changed."),
    "annotation_changed": ("AnnotationChanged", "medium", "Annotation changed",
        "An annotation other than readOnlyHint / destructiveHint escalation changed."),
    "tool_removed": ("ToolRemoved", "medium", "Tool removed", "An approved tool is no longer exposed."),
    "server_removed": ("ServerRemoved", "medium", "Server removed", "A locked server is no longer configured."),
    "auxiliary_changed": ("AuxiliaryChanged", "medium", "resources / prompts / instructions changed",
        "resources/list, prompts/list or the server instructions changed, appeared or disappeared."),
    "config_drift": ("ConfigDrift", "medium", "Server defined differently in several files",
        "The same server name appears in several config files with different content; the first one is used."),
    # --- info
    "version_changed": ("VersionChanged", "info", "Package version changed",
        "The pinned version changed. Not a failure by itself, but re-pinning integrity needs human approval, "
        "so it is always marked as needing review."),
    "capability_reduced": ("CapabilityReduced", "info", "Capability removed", "The tool lost a capability."),
    "capability_changed": ("CapabilityChanged", "info", "Capability changed", "A non-escalating capability was added."),
    "network_host_removed": ("NetworkHostRemoved", "info", "Network target host removed",
        "A previously recorded network target host no longer appears."),
    "interactive_input_required": ("InteractiveInputRequired", "info", "Config needs interactive input",
        "The config uses ${input:...} values, which CapLock leaves unresolved."),
    "surface_source_changed": ("SurfaceSourceChanged", "info", "Surface obtained differently",
        "The surface was enumerated with a different method than at lock time."),
    "unknown_server_option": ("UnknownServerOption", "info", "Option names an unconfigured server",
        "A --launch / --surface / --allow-launch option refers to a server that is not configured."),
}

RULE_IDS = sorted(RULES)
RULE_INDEX = {rid: i for i, rid in enumerate(RULE_IDS)}

# Bump on any change to RULES (ids, names, default severities or texts).
RULE_CATALOG_VERSION = "1.0.0"


def rule_catalog() -> dict:
    """The versioned catalog: what a SARIF ruleId / finding code meant when a report was made."""
    rules = [{"id": rid, "name": RULES[rid][0], "severity": RULES[rid][1],
              "shortDescription": RULES[rid][2], "fullDescription": RULES[rid][3]} for rid in RULE_IDS]
    return {"version": RULE_CATALOG_VERSION, "digest": sha256_of(rules), "ruleCount": len(rules), "rules": rules}


def fingerprint(f: Finding) -> str:
    return sha256_of([f.server, f.tool, f.code, f.field]).split(":", 1)[1]


def _rule(rid: str) -> dict:
    name, sev, short, full = RULES[rid]
    tags = ["mcp", "caplock"]
    if sev == "unverifiable":
        tags.append("unverifiable")
    return {
        "id": rid,
        "name": name,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "defaultConfiguration": {"level": LEVEL[sev]},
        "properties": {"tags": tags, "caplockSeverity": sev},
    }


def _message(f: Finding) -> str:
    where = " / ".join(p for p in (f.server, f.tool) if p) or "workspace"
    field = f" [{f.field}]" if f.field else ""
    return f"{where}{field}: {f.message}"


def _result(f: Finding, ctx: ReportContext) -> dict:
    if f.code not in RULES:  # every emitted code must have a rule (enforced by tests/test_sarif.py)
        raise KeyError(f"no SARIF rule for finding code {f.code!r}")
    tags = []
    if f.unverifiable:
        tags.append("unverifiable")
    if needs_review(f):
        tags.append("needs-review")
    props = {"severity": f.severity, "unverifiable": f.unverifiable, "needsReview": needs_review(f), "tags": tags}
    for k in ("server", "tool", "field"):
        if getattr(f, k) is not None:
            props[k] = getattr(f, k)
    return {
        "ruleId": f.code,
        "ruleIndex": RULE_INDEX[f.code],
        "level": LEVEL[f.severity],
        "message": {"text": _message(f)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": location_of(f, ctx)}}}],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(f)},
        "properties": props,
    }


def to_sarif(ctx: ReportContext) -> dict:
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CapLock",
                        "semanticVersion": __version__,
                        "version": __version__,
                        "rules": [_rule(rid) for rid in RULE_IDS],
                        "properties": {"ruleCatalogVersion": RULE_CATALOG_VERSION,
                                       "ruleCatalogDigest": rule_catalog()["digest"]},
                    }
                },
                "invocations": [{"executionSuccessful": True, "exitCode": ctx.exit_code}],
                "results": [_result(f, ctx) for f in ctx.findings],
                "properties": {
                    "verdict": verdict(ctx.exit_code),
                    "exitCode": ctx.exit_code,
                    "failOn": ctx.fail_on,
                    "notice": LIMITATION_NOTICE,
                },
            }
        ],
    }
