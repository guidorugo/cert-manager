"""Key-backend registry (finding A1).

`get_backend(name)` returns a backend by name; `backend_for_ca(ca)` returns the
backend a specific CA's key lives in (following `ca.key_backend`). New CAs use
the configured default `KEY_BACKEND`.
"""
from flask import current_app

from .base import KeyBackend, OcspResponseSpec
from .software import SoftwareBackend

_REGISTRY = {}


def _registry():
    # Lazily built so the (heavier) HSM backend is only imported when selected.
    if not _REGISTRY:
        _REGISTRY["software"] = SoftwareBackend()
    return _REGISTRY


def get_backend(name) -> KeyBackend:
    name = name or "software"
    reg = _registry()
    if name not in reg:
        if name == "softhsm":
            from .softhsm import Pkcs11Backend  # imported on demand (Phase 2)
            reg["softhsm"] = Pkcs11Backend()
        else:
            raise ValueError(f"Unknown key backend: {name}")
    return reg[name]


def default_backend_name() -> str:
    try:
        return current_app.config.get("KEY_BACKEND", "software")
    except RuntimeError:
        return "software"


def backend_for_ca(ca) -> KeyBackend:
    """Backend holding this CA's signing key. Raises for keyless CAs."""
    if not getattr(ca, "has_signing_key", False):
        raise ValueError("This CA has no signing key (imported certificate-only).")
    return get_backend(getattr(ca, "key_backend", None) or "software")


__all__ = ["KeyBackend", "OcspResponseSpec", "get_backend", "backend_for_ca", "default_backend_name"]
