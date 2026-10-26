"""Canonical message rendering and signature verification for approvals.

The apps sign the displayed message bytes, including the server-chosen
reference and expiry. See docs/SECURITY.md for trust limits.
"""

from __future__ import annotations

import base64
import datetime as dt

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def render_approval_message(ref: str, text: str, expires_at: dt.datetime) -> str:
    """The exact string the device shows in its confirmation UI and signs.

    The reference and expiry are included in the visible message so the
    signature covers request-specific metadata without hidden fields.
    """
    expires_str = expires_at.strftime("%Y-%m-%d %H:%M UTC")
    return f"Approve #{ref}: {text} (expires {expires_str})"


def load_public_key(public_key_pem: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected an EC public key")
    return key


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def der_public_key_to_pem(public_key_der: bytes) -> str:
    """Converts a SubjectPublicKeyInfo DER blob (e.g. an iOS confirmation
    key, or an App Attest public key) to the same PEM shape
    EnrolledDevice.public_key_pem always stores -- so approval signature
    verification stays platform-neutral regardless of which wire encoding
    a given enrollment flow used to deliver the key."""
    key = serialization.load_der_public_key(public_key_der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected an EC public key")
    return public_key_to_pem(key)


def verify_signature_bytes(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        public_key = load_public_key(public_key_pem)
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    """Verify a DER-encoded ECDSA/SHA-256 signature (Android Keystore's and
    iOS's Secure Enclave's shared default Signature output format for an EC
    key) over `message`.
    """
    return verify_signature_bytes(public_key_pem, message.encode("utf-8"), signature_b64)
