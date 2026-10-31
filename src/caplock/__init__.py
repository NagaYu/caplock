"""CapLock: pin the approved surface and package identity of MCP servers."""

__version__ = "0.1.0"

# CapLock pins identity (configuration -> package -> tool surface -> capability).
# It does not attest to what a server actually does at runtime.
LIMITATION_NOTICE = (
    "CapLock pins the declared tool surface and the package identity. "
    "It does not attest to the runtime behavior or safety of any server."
)
