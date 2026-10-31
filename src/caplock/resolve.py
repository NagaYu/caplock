"""Package resolution for stdio server entries.

Interprets ``npx`` / ``uvx`` / ``docker run`` launch commands, detects
floating (unpinned) specs, and resolves "version + integrity" through a
registry backend:

* ``NullRegistry``    – default; resolves nothing, so integrity is *unrecorded*.
* ``FixtureRegistry`` – recorded registry metadata on disk (tests, offline use).
* ``OnlineRegistry``  – live npm / PyPI metadata. Only used with ``--online``.
  It sends package names and versions only, never tool definitions.

Anything else (``node ./x.js``, git specs, local paths) is classified as
``manual``: CapLock cannot identify the package and says so.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from caplock.canonical import sha256_of
from caplock.config_discovery import ServerEntry

_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_PEP440_EXACT = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$")
_PEP508_OP = re.compile(r"(===|==|~=|!=|>=|<=|>|<)")
_RANGE_CHARS = set("^~*><|= ")

NPX_VALUE_FLAGS = {"--registry", "--cache", "--userconfig", "--node-options", "--shell"}
UVX_VALUE_FLAGS = {
    "--from", "--with", "--with-editable", "--with-requirements", "--python", "-p",
    "--index", "--index-url", "--extra-index-url", "--default-index", "--find-links", "-f",
    "--constraints", "-c", "--overrides", "--build-constraints", "--cache-dir", "--directory",
    "--project", "--config-file", "--index-strategy", "--keyring-provider", "--refresh-package",
    "--reinstall-package", "--upgrade-package", "--exclude-newer", "--resolution", "--prerelease",
    "--python-preference", "--color", "--env-file", "--allow-insecure-host", "--link-mode",
}
DOCKER_VALUE_FLAGS = {
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "-p", "--publish", "-w", "--workdir",
    "--name", "--network", "--net", "-u", "--user", "--entrypoint", "-l", "--label", "--label-file",
    "--add-host", "--cap-add", "--cap-drop", "--cpus", "-m", "--memory", "--platform", "--pull",
    "--restart", "-h", "--hostname", "--ulimit", "--device", "--dns", "--tmpfs", "--security-opt",
    "--log-driver", "--log-opt", "--gpus", "--ipc", "--pid", "--runtime", "--shm-size",
    "--stop-signal", "--stop-timeout", "--userns", "--uts", "--volumes-from", "--cidfile",
    "--expose", "--group-add", "--memory-swap", "--cpuset-cpus", "--cgroupns", "--isolation",
    "--health-cmd", "--health-interval", "--health-retries", "--health-timeout", "--mac-address",
    "--ip", "--ip6", "--link", "--pids-limit", "--storage-opt", "--sysctl", "-a", "--attach",
}


@dataclass
class PackageRef:
    ecosystem: str  # "npm" | "pypi" | "docker" | "none"
    launcher: str | None
    name: str | None = None
    requested: str | None = None  # version / tag / range text as written
    digest: str | None = None  # docker @sha256:... in the config
    pinned: bool = False
    floating_reason: str | None = None
    arg_index: int | None = None  # where the package spec sits in args
    note: str | None = None


@dataclass
class ResolvedPackage:
    ref: PackageRef
    status: str  # "resolved" | "floating" | "unrecorded" | "manual" | "remote"
    version: str | None = None
    integrity: str | None = None
    integrity_set: list[dict] = field(default_factory=list)  # PyPI: [{file, sha256}] sorted by file
    method: str = "none"
    detail: str | None = None

    def to_dict(self) -> dict:
        d = {
            "ecosystem": self.ref.ecosystem,
            "launcher": self.ref.launcher,
            "name": self.ref.name,
            "requested": self.ref.requested,
            "pinned": self.ref.pinned,
            "floatingReason": self.ref.floating_reason,
            "version": self.version,
            "integrity": self.integrity,
            "integritySet": self.integrity_set or None,
            "resolution": self.method,
            "status": self.status,
            "detail": self.detail,
        }
        return {k: v for k, v in d.items() if v is not None}


# --------------------------------------------------------------------------- npm


def parse_npm_spec(spec: str) -> tuple[str | None, str | None, str | None]:
    """Return (name, version_text, non_registry_reason)."""
    if (
        "://" in spec
        or spec.startswith(("git+", "github:", "gitlab:", "bitbucket:", "file:", ".", "/", "~"))
        or spec.endswith((".tgz", ".tar.gz"))
    ):
        return None, None, "non-registry npm spec (git/url/path)"
    if spec.startswith("@"):
        at = spec.find("@", 1)
        name, ver = (spec[:at], spec[at + 1 :]) if at > 0 else (spec, None)
        if "/" not in name:
            return None, None, "malformed scoped package name"
    else:
        name, _, ver = spec.partition("@")
        if "/" in name:
            return None, None, "GitHub shorthand spec (user/repo)"
    if ver and ver.startswith("npm:"):
        return None, None, "npm alias spec"
    return name, (ver or None), None


def npm_floating_reason(ver: str | None) -> str | None:
    if ver is None or ver == "":
        return "no version specified"
    if ver == "latest":
        return "@latest"
    if _SEMVER.match(ver.lstrip("=")):
        return None
    if any(c in _RANGE_CHARS for c in ver) or re.match(r"^v?\d+(\.(\d+|[xX*]))*$", ver):
        return f"version range '{ver}'"
    return f"dist-tag '{ver}'"


def _parse_npx(args: list[str]) -> PackageRef:
    ref = PackageRef(ecosystem="npm", launcher="npx")
    spec_idx = None
    i = 0
    positional = None
    while i < len(args):
        a = args[i]
        if a in ("-p", "--package"):
            if i + 1 < len(args) and spec_idx is None:
                spec_idx = i + 1
            i += 2
            continue
        if a.startswith("--package="):
            return _manual(ref, "npx --package=<spec> form is not interpreted in Phase 1")
        if a in ("-c", "--call"):
            if spec_idx is None:
                return _manual(ref, "npx --call without --package cannot be resolved")
            i += 2
            continue
        if a == "--":
            if i + 1 < len(args):
                positional = i + 1
            break
        if a in NPX_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        positional = i
        break
    if spec_idx is None:
        spec_idx = positional
    if spec_idx is None:
        return _manual(ref, "npx without a package argument")
    name, ver, bad = parse_npm_spec(args[spec_idx])
    if bad:
        return _manual(ref, bad)
    ref.name, ref.requested, ref.arg_index = name, ver, spec_idx
    ref.floating_reason = npm_floating_reason(ver)
    ref.pinned = ref.floating_reason is None
    if ref.pinned:
        ref.requested = ver.lstrip("=")  # type: ignore[union-attr]
    return ref


# --------------------------------------------------------------------------- PyPI


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_pypi_spec(spec: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (name, version_text, floating_reason, non_registry_reason)."""
    s = spec.strip()
    if "://" in s or s.startswith(("git+", ".", "/", "~")) or s.endswith((".whl", ".tar.gz", ".zip")):
        return None, None, None, "non-registry Python spec (git/url/path)"
    if " @ " in s:
        return None, None, None, "direct-reference Python spec"
    s = re.sub(r"\[[^\]]*\]", "", s)  # drop extras
    if ";" in s:
        return None, None, None, "environment markers are not interpreted"
    m = _PEP508_OP.search(s)
    if "@" in s and not m:
        name, _, ver = s.partition("@")
        if ver == "latest":
            return name, ver, "@latest", None
        if _PEP440_EXACT.match(ver):
            return name, ver, None, None
        return name, ver, f"version '{ver}' is not exact", None
    if not m:
        return s, None, "no version specified", None
    name = s[: m.start()].strip()
    rest = s[m.start() :].strip()
    if "," in rest:
        return name, rest, f"version range '{rest}'", None
    op = m.group(1)
    ver = rest[len(op) :].strip()
    if op in ("==", "===") and "*" not in ver and _PEP440_EXACT.match(ver):
        return name, ver, None, None
    return name, rest, f"version range '{rest}'", None


def _parse_uvx(args: list[str]) -> PackageRef:
    ref = PackageRef(ecosystem="pypi", launcher="uvx")
    from_idx = None
    positional = None
    has_with = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--from":
            from_idx = i + 1 if i + 1 < len(args) else None
            i += 2
            continue
        if a.startswith("--from="):
            return _manual(ref, "uvx --from=<spec> form is not interpreted in Phase 1")
        if a in ("--with", "--with-editable", "--with-requirements") or a.startswith("--with"):
            has_with = True
        if a in UVX_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        positional = i
        break
    if has_with:
        return _manual(ref, "uvx --with adds packages that Phase 1 does not resolve")
    idx = from_idx if from_idx is not None else positional
    if idx is None:
        return _manual(ref, "uvx without a package argument")
    name, ver, floating, bad = parse_pypi_spec(args[idx])
    if bad:
        return _manual(ref, bad)
    ref.name, ref.requested, ref.arg_index = name, ver, idx
    ref.floating_reason = floating
    ref.pinned = floating is None
    return ref


# --------------------------------------------------------------------------- docker


def parse_image(image: str) -> tuple[str, str | None, str | None]:
    """Return (name, tag, digest)."""
    ref, digest = image, None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    slash, colon = ref.rfind("/"), ref.rfind(":")
    if colon > slash:
        return ref[:colon], ref[colon + 1 :], digest
    return ref, None, digest


def _parse_docker(args: list[str]) -> PackageRef:
    ref = PackageRef(ecosystem="docker", launcher="docker")
    i = 0
    if args[:1] == ["run"]:
        i = 1
    elif args[:2] == ["container", "run"]:
        i = 2
    else:
        return _manual(ref, "only 'docker run' is interpreted")
    image_idx = None
    while i < len(args):
        a = args[i]
        if a in DOCKER_VALUE_FLAGS:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        image_idx = i
        break
    if image_idx is None:
        return _manual(ref, "docker run without an image")
    name, tag, digest = parse_image(args[image_idx])
    ref.name, ref.requested, ref.digest, ref.arg_index = name, tag, digest, image_idx
    if digest:
        if not re.match(r"^sha256:[0-9a-f]{64}$", digest):
            return _manual(ref, f"unrecognized image digest '{digest}'")
        ref.pinned = True
    elif tag is None:
        ref.floating_reason = "no image tag (implies :latest)"
    elif tag == "latest":
        ref.floating_reason = ":latest tag"
    else:
        ref.pinned = True
        ref.note = "tags are mutable; integrity is the digest the tag resolved to"
    return ref


def _manual(ref: PackageRef, reason: str) -> PackageRef:
    return PackageRef(ecosystem="none", launcher=ref.launcher, note=reason)


def _launcher_name(command: str) -> str:
    base = Path(command).name.lower()
    for suf in (".cmd", ".exe", ".bat"):
        if base.endswith(suf):
            base = base[: -len(suf)]
    return base


def parse_launch(command: str | None, args: list[str]) -> PackageRef:
    if not command:
        return PackageRef(ecosystem="none", launcher=None, note="no command")
    launcher = _launcher_name(command)
    if launcher == "npx":
        return _parse_npx(args)
    if launcher == "uvx":
        return _parse_uvx(args)
    if launcher in ("docker", "podman"):
        ref = _parse_docker(args)
        ref.launcher = launcher
        return ref
    return PackageRef(
        ecosystem="none",
        launcher=launcher,
        note=f"'{launcher}' is not a supported launcher (npx/uvx/docker); manual review required",
    )


def args_without_version(command: str | None, args: list[str]) -> list[str]:
    """Args with the package spec reduced to its name, for version-insensitive comparison."""
    ref = parse_launch(command, args)
    if ref.arg_index is None or ref.name is None:
        return list(args)
    out = list(args)
    out[ref.arg_index] = f"{ref.ecosystem}:{ref.name}"
    return out


# --------------------------------------------------------------------------- registries


class RegistryBackend:
    name = "none"

    def npm_version(self, name: str, version: str) -> dict | None:
        return None

    def npm_tag(self, name: str, tag: str) -> str | None:
        return None

    def pypi_files(self, name: str, version: str) -> list[dict] | None:
        return None

    def pypi_latest(self, name: str) -> str | None:
        return None

    def docker_digest(self, image: str, tag: str) -> str | None:
        return None


class NullRegistry(RegistryBackend):
    """No registry access at all (the offline default)."""

    name = "offline"


def _fixture_filename(name: str) -> str:
    return name.replace("/", "__").replace(":", "_") + ".json"


class FixtureRegistry(RegistryBackend):
    """Recorded registry metadata. Directories are searched in order (first hit wins).

    Layout per directory:
      npm/<name with / as __>.json     npm packument shape
      pypi/<pep503 name>.json          PyPI JSON API shape (info.version, releases)
      docker/<image with / as __>.json {"tags": {"<tag>": "sha256:..."}}
    """

    name = "fixture-registry"

    def __init__(self, dirs: list[Path]):
        self.dirs = [Path(d) for d in dirs]

    def _load(self, kind: str, name: str) -> dict | None:
        for d in self.dirs:
            p = d / kind / _fixture_filename(name)
            if p.is_file():
                return json.loads(p.read_text(encoding="utf-8"))
        return None

    def npm_version(self, name, version):
        doc = self._load("npm", name)
        v = (doc or {}).get("versions", {}).get(version)
        if not v:
            return None
        return {"integrity": v.get("dist", {}).get("integrity")}

    def npm_tag(self, name, tag):
        return ((self._load("npm", name) or {}).get("dist-tags") or {}).get(tag)

    def pypi_files(self, name, version):
        doc = self._load("pypi", pep503(name))
        files = (doc or {}).get("releases", {}).get(version)
        if not files:
            return None
        return [{"filename": f["filename"], "sha256": f["digests"]["sha256"]} for f in files]

    def pypi_latest(self, name):
        return ((self._load("pypi", pep503(name)) or {}).get("info") or {}).get("version")

    def docker_digest(self, image, tag):
        return ((self._load("docker", image) or {}).get("tags") or {}).get(tag)


class OnlineRegistry(RegistryBackend):
    """Live registry metadata (npm, PyPI). Explicit ``--online`` only.

    Docker registry resolution is not implemented in Phase 1 (returns None,
    so the integrity is recorded as unrecorded rather than guessed).
    """

    name = "online-registry"
    NPM = "https://registry.npmjs.org/"
    PYPI = "https://pypi.org/pypi/"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _get(self, url: str, accept: str = "application/json") -> dict | None:
        req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "caplock"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            return None

    def _npm_doc(self, name: str) -> dict | None:
        return self._get(self.NPM + urllib.parse.quote(name, safe="@"), "application/vnd.npm.install-v1+json")

    def npm_version(self, name, version):
        v = ((self._npm_doc(name) or {}).get("versions") or {}).get(version)
        return {"integrity": v.get("dist", {}).get("integrity")} if v else None

    def npm_tag(self, name, tag):
        return ((self._npm_doc(name) or {}).get("dist-tags") or {}).get(tag)

    def pypi_files(self, name, version):
        doc = self._get(f"{self.PYPI}{urllib.parse.quote(pep503(name))}/{urllib.parse.quote(version)}/json")
        urls = (doc or {}).get("urls")
        if not urls:
            return None
        return [{"filename": f["filename"], "sha256": f["digests"]["sha256"]} for f in urls]

    def pypi_latest(self, name):
        doc = self._get(f"{self.PYPI}{urllib.parse.quote(pep503(name))}/json")
        return ((doc or {}).get("info") or {}).get("version")


# --------------------------------------------------------------------------- resolution


def pypi_integrity_set(files: list[dict]) -> list[dict]:
    """Per-file sha256 of every distribution file of a release, sorted by file name."""
    return sorted(({"file": f["filename"], "sha256": f["sha256"]} for f in files), key=lambda e: e["file"])


def integrity_of_set(integrity_set: list[dict]) -> str:
    """Comparison digest: sha256 of the canonical JSON of the integrity set."""
    return sha256_of(integrity_set)


def resolve_entry(entry: ServerEntry, backend: RegistryBackend) -> ResolvedPackage:
    if entry.transport == "http":
        ref = PackageRef(ecosystem="none", launcher=None, note="remote server")
        return ResolvedPackage(
            ref=ref,
            status="remote",
            detail="remote server: the code behind the URL cannot be pinned or observed",
        )
    ref = parse_launch(entry.command, entry.args)
    if ref.ecosystem == "none":
        return ResolvedPackage(ref=ref, status="manual", detail=ref.note)

    if not ref.pinned:
        latest = None
        if ref.ecosystem == "npm":
            latest = backend.npm_tag(ref.name, ref.requested or "latest") if ref.requested in (None, "latest") else None
        elif ref.ecosystem == "pypi":
            latest = backend.pypi_latest(ref.name) if ref.requested in (None, "latest") else None
        detail = f"floating: {ref.floating_reason}; whatever the registry serves at launch time will run"
        if latest:
            detail += f" (registry currently reports {latest})"
        return ResolvedPackage(ref=ref, status="floating", version=None, method=backend.name, detail=detail)

    if ref.ecosystem == "npm":
        info = backend.npm_version(ref.name, ref.requested)
        integrity = (info or {}).get("integrity")
        return _finish(ref, ref.requested, integrity, [], backend)
    if ref.ecosystem == "pypi":
        files = backend.pypi_files(ref.name, ref.requested)
        iset = pypi_integrity_set(files) if files else []
        return _finish(ref, ref.requested, integrity_of_set(iset) if iset else None, iset, backend)
    # docker
    if ref.digest:
        return ResolvedPackage(
            ref=ref, status="resolved", version=ref.requested, integrity=ref.digest, method="config-digest"
        )
    digest = backend.docker_digest(ref.name, ref.requested)
    return _finish(ref, ref.requested, digest, [], backend)


def _finish(ref, version, integrity, integrity_set, backend) -> ResolvedPackage:
    if integrity:
        return ResolvedPackage(
            ref=ref, status="resolved", version=version, integrity=integrity,
            integrity_set=integrity_set, method=backend.name,
        )
    why = (
        "offline: no registry metadata available (use --registry DIR or --online)"
        if isinstance(backend, NullRegistry)
        else f"{backend.name} has no integrity for {ref.name}@{version} (unpublished or unavailable)"
    )
    return ResolvedPackage(ref=ref, status="unrecorded", version=version, method=backend.name, detail=why)
