"""Verify a Ledger device's endorsement evidence.

A Countersign Ledger app signs with the device's slot-1 endorsement key
(endorsement scheme 1). Ledger OS computes every such signature over

    SHA-256(data || code_hash)

where code_hash is the SHA-256 of the installed application, appended by
the OS and never chosen by the app. A signature therefore only verifies
for the pinned Countersign app hash, which is what binds an approval to
the screen that displayed it.

Genuineness chains to Ledger's published root of trust. At provisioning
(ledger/host/bridge.py provision), the device's dashboard presents its
issuer certificate, a signature by Ledger's root over
0x02 || header || device_public_key, and signs the freshly generated
endorsement public key with the device key over 0xFF || endorsement_public_key.
That second signature is committed to the device as the slot's certificate,
so the Countersign app later returns it alongside the public key, and the
bridge keeps the issuer certificate to submit at enrollment. Verifying
root -> device key -> endorsement key is what Ledger's HSM used to do.

A deployment may instead (or additionally) accept a certificate signed by a
configured Owner key over 0xFE || endorsement_public_key: Speculos
provisions one from its attestation key, and an operator can sign one for a
device provisioned through a custom CA. Keys are secp256k1. See
docs/SECURITY.md for the resulting trust limits.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .. import crypto
from .base import AttestationError

OWNER_CERTIFICATE_ROLE = b"\xfe"
DEVICE_CERTIFICATE_ROLE = b"\xff"  # device key over an endorsement key (ENDORSE_SET_START)
ISSUER_CERTIFICATE_ROLE = b"\x02"  # Ledger root over a device key (GET_CERTIFICATE)
PUBLIC_KEY_LENGTH = 65
CODE_HASH_LENGTH = 32


def public_key_from_uncompressed(public_key: bytes) -> ec.EllipticCurvePublicKey:
    if len(public_key) != PUBLIC_KEY_LENGTH or public_key[0] != 0x04:
        raise AttestationError("endorsement public key must be a 65-byte uncompressed secp256k1 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
    except ValueError as exc:
        raise AttestationError(f"invalid endorsement public key: {exc}") from None


def parse_owner_public_keys(value: str) -> list[ec.EllipticCurvePublicKey]:
    """`value` is a comma-separated list of hex-encoded uncompressed secp256k1
    public keys, or the path of a file holding one per line."""
    if os.path.isfile(value):
        with open(value, encoding="ascii") as f:
            lines = [line.split("#", 1)[0] for line in f]
        entries = [entry for line in lines for entry in line.replace(",", " ").split()]
    else:
        entries = [entry.strip() for entry in value.split(",")]
    keys = []
    for entry in entries:
        if not entry:
            continue
        try:
            raw = bytes.fromhex(entry)
        except ValueError:
            raise AttestationError(f"owner public key is not hex: {entry[:16]}...") from None
        keys.append(public_key_from_uncompressed(raw))
    return keys


def verify_device_chain(
    device_public_key: bytes,
    issuer_certificate_header: bytes,
    issuer_signature: bytes,
    endorsement_public_key: bytes,
    device_signature: bytes,
    roots: list[ec.EllipticCurvePublicKey],
) -> None:
    """Ledger root -> device key -> endorsement key. Raises on any break."""
    if not roots:
        raise AttestationError("no Ledger root public keys configured")
    device_key = public_key_from_uncompressed(device_public_key)
    issued = ISSUER_CERTIFICATE_ROLE + issuer_certificate_header + device_public_key
    for root in roots:
        try:
            root.verify(issuer_signature, issued, ec.ECDSA(hashes.SHA256()))
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise AttestationError("issuer certificate does not verify under any configured Ledger root")
    try:
        device_key.verify(device_signature, DEVICE_CERTIFICATE_ROLE + endorsement_public_key, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise AttestationError("endorsement key is not signed by the attested device key") from None


def verify_owner_certificate(
    public_key: bytes, certificate: bytes, owner_keys: list[ec.EllipticCurvePublicKey]
) -> None:
    """Checks that one of `owner_keys` signed SHA-256(0xFE || public_key)."""
    if not owner_keys:
        raise AttestationError("no Ledger owner public keys configured")
    signed = OWNER_CERTIFICATE_ROLE + public_key
    for owner in owner_keys:
        try:
            owner.verify(certificate, signed, ec.ECDSA(hashes.SHA256()))
            return
        except (InvalidSignature, ValueError):
            continue
    raise AttestationError("owner certificate does not verify under any configured owner key")


def endorsed_payload(data: bytes, code_hash: bytes) -> bytes:
    """The bytes Ledger OS hashes for an endorsement scheme 1 signature."""
    if len(code_hash) != CODE_HASH_LENGTH:
        raise AttestationError("code hash must be 32 bytes")
    return data + code_hash


def verify_endorsement_signature(public_key_pem: str, data: bytes, code_hash: bytes, signature_b64: str) -> bool:
    return crypto.verify_signature_bytes(public_key_pem, endorsed_payload(data, code_hash), signature_b64)


def decode_b64(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise AttestationError(f"invalid base64 in {field_name}: {exc}") from None
