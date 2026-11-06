"""Duta: a local-first bridge between AI applications and authorized filesystems."""

from .core import Duta, DutaError, AccessDeniedError, UnsafePathError

__all__ = ["Duta", "DutaError", "AccessDeniedError", "UnsafePathError"]
__version__ = "0.1.0"
