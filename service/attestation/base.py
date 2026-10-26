"""Attestation verification errors. Platform trust limits are in docs/SECURITY.md."""

from __future__ import annotations


class AttestationError(ValueError):
    """Raised by ios.py's App Attest verification functions."""
