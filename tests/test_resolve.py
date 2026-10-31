from pathlib import Path

import pytest

from caplock.config_discovery import ConfigSource, ServerEntry
from caplock.resolve import (
    FixtureRegistry,
    NullRegistry,
    args_without_version,
    parse_launch,
    resolve_entry,
)

ROOT = Path(__file__).resolve().parent.parent
REG = FixtureRegistry([ROOT / "fixtures" / "registry"])


def stdio(command, args):
    return ServerEntry(name="s", transport="stdio", command=command, args=args,
                       source=ConfigSource(".mcp.json", "portable"))


@pytest.mark.parametrize(
    "args, name, requested, pinned, reason",
    [
        (["-y", "@scope/pkg@1.2.3"], "@scope/pkg", "1.2.3", True, None),
        (["-y", "@scope/pkg"], "@scope/pkg", None, False, "no version specified"),
        (["--yes", "pkg@latest", "--flag"], "pkg", "latest", False, "@latest"),
        (["-y", "pkg@^1.2.0"], "pkg", "^1.2.0", False, "version range '^1.2.0'"),
        (["pkg@~1.2.0"], "pkg", "~1.2.0", False, "version range '~1.2.0'"),
        (["pkg@*"], "pkg", "*", False, "version range '*'"),
        (["pkg@1.2"], "pkg", "1.2", False, "version range '1.2'"),
        (["pkg@next"], "pkg", "next", False, "dist-tag 'next'"),
        (["-p", "pkg@2.0.0-beta.1", "bin-name", "arg"], "pkg", "2.0.0-beta.1", True, None),
        (["--registry", "https://r.example", "pkg@1.0.0"], "pkg", "1.0.0", True, None),
    ],
)
def test_npx_parsing(args, name, requested, pinned, reason):
    ref = parse_launch("npx", args)
    assert (ref.ecosystem, ref.name, ref.requested, ref.pinned, ref.floating_reason) == (
        "npm", name, requested, pinned, reason)


@pytest.mark.parametrize("args", [["github:user/repo"], ["user/repo"], ["./local"], ["-y"]])
def test_npx_non_registry_is_manual(args):
    assert parse_launch("npx", args).ecosystem == "none"


@pytest.mark.parametrize(
    "args, name, requested, pinned",
    [
        (["mcp-server-time==0.6.2"], "mcp-server-time", "0.6.2", True),
        (["mcp-server-time@0.6.2"], "mcp-server-time", "0.6.2", True),
        (["mcp-server-time@latest"], "mcp-server-time", "latest", False),
        (["mcp-server-time"], "mcp-server-time", None, False),
        (["mcp-server-time>=0.6"], "mcp-server-time", ">=0.6", False),
        (["--from", "pkg[extra]==1.0.0", "cmd"], "pkg", "1.0.0", True),
        (["--python", "3.12", "pkg==1.0.0"], "pkg", "1.0.0", True),
        (["pkg==1.*"], "pkg", "==1.*", False),
    ],
)
def test_uvx_parsing(args, name, requested, pinned):
    ref = parse_launch("uvx", args)
    assert (ref.ecosystem, ref.name, ref.requested, ref.pinned) == ("pypi", name, requested, pinned)
    assert (ref.floating_reason is None) == pinned


def test_uvx_with_and_git_are_manual():
    assert parse_launch("uvx", ["--with", "x", "pkg==1.0.0"]).ecosystem == "none"
    assert parse_launch("uvx", ["--from", "git+https://g.example/x", "x"]).ecosystem == "none"


@pytest.mark.parametrize(
    "args, name, tag, pinned, reason",
    [
        (["run", "-i", "--rm", "mcp/sqlite"], "mcp/sqlite", None, False, "no image tag (implies :latest)"),
        (["run", "-i", "mcp/sqlite:latest"], "mcp/sqlite", "latest", False, ":latest tag"),
        (["run", "-i", "-e", "TOKEN", "-v", "a:/b", "ghcr.io/x/y:v1.2"], "ghcr.io/x/y", "v1.2", True, None),
        (["run", "--env=A", "--name", "n", "localhost:5000/img:1"], "localhost:5000/img", "1", True, None),
    ],
)
def test_docker_parsing(args, name, tag, pinned, reason):
    ref = parse_launch("docker", args)
    assert (ref.ecosystem, ref.name, ref.requested, ref.pinned, ref.floating_reason) == (
        "docker", name, tag, pinned, reason)


def test_docker_digest_is_integrity_from_config():
    digest = "sha256:" + "a" * 64
    r = resolve_entry(stdio("docker", ["run", "-i", f"mcp/x:1.0@{digest}"]), NullRegistry())
    assert r.status == "resolved" and r.integrity == digest and r.method == "config-digest"


def test_other_commands_are_manual():
    r = resolve_entry(stdio("node", ["./server.js"]), REG)
    assert r.status == "manual" and "not a supported launcher" in r.detail
    assert resolve_entry(stdio("docker", ["compose", "up"]), REG).status == "manual"


def test_fixture_registry_resolves_npm_version_and_integrity():
    r = resolve_entry(stdio("npx", ["-y", "@caplock-demo/notes-mcp@1.0.0"]), REG)
    assert r.status == "resolved"
    assert r.version == "1.0.0"
    assert r.integrity.startswith("sha512-")
    assert r.method == "fixture-registry"
    d = r.to_dict()
    assert d["name"] == "@caplock-demo/notes-mcp" and d["pinned"] is True


def test_fixture_registry_resolves_pypi_files():
    r = resolve_entry(stdio("uvx", ["caplock-demo-weather==0.3.1"]), REG)
    assert r.status == "resolved"
    assert r.integrity.startswith("sha256:")  # Phase 2 Step 0: digest of the per-file integritySet
    assert len(r.integrity_set) == 2


def test_fixture_registry_resolves_docker_tag_to_digest():
    r = resolve_entry(stdio("docker", ["run", "-i", "ghcr.io/caplock-demo/notes-mcp:1.0.0"]), REG)
    assert r.status == "resolved" and r.integrity.startswith("sha256:")


def test_unpublished_version_is_unrecorded_not_silently_ok():
    r = resolve_entry(stdio("npx", ["@caplock-demo/notes-mcp@9.9.9"]), REG)
    assert r.status == "unrecorded" and r.integrity is None
    assert "unpublished or unavailable" in r.detail


def test_offline_without_registry_is_unrecorded():
    r = resolve_entry(stdio("npx", ["@caplock-demo/notes-mcp@1.0.0"]), NullRegistry())
    assert r.status == "unrecorded" and "offline" in r.detail


def test_floating_is_reported_with_registry_hint():
    r = resolve_entry(stdio("npx", ["-y", "@caplock-demo/notes-mcp@latest"]), REG)
    assert r.status == "floating" and r.integrity is None
    assert "1.0.1" in r.detail


def test_registry_overlay_order():
    overlay = FixtureRegistry([ROOT / "fixtures" / "registry-mutations" / "F-code-only",
                               ROOT / "fixtures" / "registry"])
    base = resolve_entry(stdio("npx", ["@caplock-demo/notes-mcp@1.0.0"]), REG)
    mutated = resolve_entry(stdio("npx", ["@caplock-demo/notes-mcp@1.0.0"]), overlay)
    assert base.integrity != mutated.integrity


def test_http_is_remote():
    e = ServerEntry(name="h", transport="http", url="https://x.example/mcp")
    assert resolve_entry(e, REG).status == "remote"


def test_args_without_version():
    assert args_without_version("npx", ["-y", "@a/b@1.0.0", "."]) == ["-y", "npm:@a/b", "."]
    assert args_without_version("npx", ["-y", "@a/b@2.0.0", "."]) == ["-y", "npm:@a/b", "."]
    assert args_without_version("node", ["x.js"]) == ["x.js"]


def test_online_registry_is_not_reachable_in_tests():
    # The guard in conftest.py turns any network attempt into a failure; the online
    # backend swallows errors and reports None, so it must surface as "unrecorded".
    from caplock.resolve import OnlineRegistry

    import pytest as _pytest

    with _pytest.raises(AssertionError, match="network access attempted"):
        import socket

        socket.create_connection(("registry.npmjs.org", 443))
    r = resolve_entry(stdio("npx", ["@caplock-demo/notes-mcp@1.0.0"]), OnlineRegistry(timeout=0.1))
    assert r.status == "unrecorded" and r.integrity is None
