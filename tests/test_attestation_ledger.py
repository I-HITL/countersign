"""Tests for service/attestation/ledger.py.

Ledger's endorsement evidence is small enough to reproduce exactly: an
Owner certificate is a plain ECDSA signature over 0xFE || public_key, and
an endorsement scheme 1 signature covers SHA-256(data || code_hash) (see
Speculos's src/bolos/endorsement.c and environment.c, which these tests
mirror). The Speculos vector below uses the emulator's default attestation
and user keys, so the Ragger tests in ledger/countersign-app/tests and the
backend agree on the same bytes.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from service import crypto
from service.attestation import ledger
from service.attestation.base import AttestationError

# Speculos defaults (src/environment.c): --attestation-key signs Owner
# certificates, --user-private-key is the slot-1/2 endorsement key, and the
# code hash is a fixed 32-byte string.
SPECULOS_ATTESTATION_PRIVATE_KEY = bytes.fromhex("138fb9b91da745f12977a2b46f0bce2f0418b50fcb76631baf0f08ceefdb5d57")
SPECULOS_USER_PRIVATE_KEY = bytes.fromhex("e15e01d47082f0ea4771c99fe312f9d70093c89af47787fdf82e031f6728b710")
SPECULOS_CODE_HASH = b"12345678abcdef0000fedcba8765432\x00"


def _secp256k1(private_bytes: bytes | None = None) -> ec.EllipticCurvePrivateKey:
    if private_bytes is None:
        return ec.generate_private_key(ec.SECP256K1())
    return ec.derive_private_key(int.from_bytes(private_bytes, "big"), ec.SECP256K1())


def _uncompressed(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _owner_certificate(owner: ec.EllipticCurvePrivateKey, public_key: bytes) -> bytes:
    return owner.sign(ledger.OWNER_CERTIFICATE_ROLE + public_key, ec.ECDSA(hashes.SHA256()))


def _endorse(key: ec.EllipticCurvePrivateKey, data: bytes, code_hash: bytes) -> str:
    """What sys_endorsement_key1_sign_data returns, base64 as sent on the wire."""
    return base64.b64encode(key.sign(data + code_hash, ec.ECDSA(hashes.SHA256()))).decode("ascii")


def test_owner_certificate_verifies_under_the_owner_key():
    owner, device = _secp256k1(), _secp256k1()
    public_key = _uncompressed(device)
    ledger.verify_owner_certificate(public_key, _owner_certificate(owner, public_key), [owner.public_key()])


def test_owner_certificate_verifies_when_any_configured_owner_signed_it():
    owner, other, device = _secp256k1(), _secp256k1(), _secp256k1()
    public_key = _uncompressed(device)
    ledger.verify_owner_certificate(
        public_key, _owner_certificate(owner, public_key), [other.public_key(), owner.public_key()]
    )


def test_owner_certificate_is_rejected_under_the_wrong_owner_or_role_or_key():
    owner, other, device = _secp256k1(), _secp256k1(), _secp256k1()
    public_key = _uncompressed(device)
    certificate = _owner_certificate(owner, public_key)
    with pytest.raises(AttestationError, match="owner certificate"):
        ledger.verify_owner_certificate(public_key, certificate, [other.public_key()])
    with pytest.raises(AttestationError):
        ledger.verify_owner_certificate(public_key, owner.sign(b"\xff" + public_key, ec.ECDSA(hashes.SHA256())), [owner.public_key()])
    with pytest.raises(AttestationError):
        ledger.verify_owner_certificate(_uncompressed(other), certificate, [owner.public_key()])
    with pytest.raises(AttestationError, match="no Ledger owner"):
        ledger.verify_owner_certificate(public_key, certificate, [])


def test_speculos_default_keys_produce_a_verifiable_chain():
    # Mirrors env_init_user_certificate(): SHA-256(0xFE || pubkey) signed by
    # the attestation key; the signature itself is randomized so it is
    # recomputed here rather than pinned.
    owner = _secp256k1(SPECULOS_ATTESTATION_PRIVATE_KEY)
    device = _secp256k1(SPECULOS_USER_PRIVATE_KEY)
    public_key = _uncompressed(device)
    assert public_key.hex().startswith("04")
    ledger.verify_owner_certificate(public_key, _owner_certificate(owner, public_key), [owner.public_key()])
    pem = crypto.public_key_to_pem(device.public_key())
    assert ledger.verify_endorsement_signature(pem, b"hello", SPECULOS_CODE_HASH, _endorse(device, b"hello", SPECULOS_CODE_HASH))


def test_endorsement_signature_is_bound_to_the_code_hash():
    device = _secp256k1()
    pem = crypto.public_key_to_pem(device.public_key())
    code_hash = hashlib.sha256(b"countersign app").digest()
    message = "Approve #ABCD1234: pay $10 to alice (expires 2026-01-01 00:00 UTC)".encode()
    good = _endorse(device, message, code_hash)
    assert ledger.verify_endorsement_signature(pem, message, code_hash, good)
    # A plain signature over the message (sign_without_code_hash) must not verify.
    plain = base64.b64encode(device.sign(message, ec.ECDSA(hashes.SHA256()))).decode()
    assert not ledger.verify_endorsement_signature(pem, message, code_hash, plain)
    # The same signature does not verify for another app's hash or another message.
    assert not ledger.verify_endorsement_signature(pem, message, hashlib.sha256(b"other app").digest(), good)
    assert not ledger.verify_endorsement_signature(pem, message + b"!", code_hash, good)
    with pytest.raises(AttestationError, match="32 bytes"):
        ledger.endorsed_payload(message, b"short")


def _device_chain(root: ec.EllipticCurvePrivateKey, device: ec.EllipticCurvePrivateKey, endorsement_public_key: bytes):
    """What the dashboard returns: GET_CERTIFICATE (header, device key, root
    signature over 0x02 || header || device key) and ENDORSE_SET_START (device
    signature over 0xFF || endorsement key)."""
    device_public_key = _uncompressed(device)
    header = b"\xaa\xe8\x61\xc8\xe7\xbe\x96"
    issuer_signature = root.sign(ledger.ISSUER_CERTIFICATE_ROLE + header + device_public_key, ec.ECDSA(hashes.SHA256()))
    device_signature = device.sign(ledger.DEVICE_CERTIFICATE_ROLE + endorsement_public_key, ec.ECDSA(hashes.SHA256()))
    return device_public_key, header, issuer_signature, device_signature


def test_device_chain_verifies_from_ledger_root_to_endorsement_key():
    root, device, endorsement = _secp256k1(), _secp256k1(), _secp256k1()
    endorsement_public_key = _uncompressed(endorsement)
    device_public_key, header, issuer_signature, device_signature = _device_chain(root, device, endorsement_public_key)
    ledger.verify_device_chain(device_public_key, header, issuer_signature, endorsement_public_key, device_signature, [root.public_key()])


def test_device_chain_rejects_every_broken_link():
    root, other_root, device, other_device, endorsement = _secp256k1(), _secp256k1(), _secp256k1(), _secp256k1(), _secp256k1()
    endorsement_public_key = _uncompressed(endorsement)
    device_public_key, header, issuer_signature, device_signature = _device_chain(root, device, endorsement_public_key)
    roots = [root.public_key()]
    with pytest.raises(AttestationError, match="issuer certificate"):
        ledger.verify_device_chain(device_public_key, header, issuer_signature, endorsement_public_key, device_signature, [other_root.public_key()])
    with pytest.raises(AttestationError, match="issuer certificate"):
        ledger.verify_device_chain(device_public_key, header + b"x", issuer_signature, endorsement_public_key, device_signature, roots)
    # A genuine device's issuer certificate paired with another device's endorsement signature.
    _, _, _, foreign_signature = _device_chain(root, other_device, endorsement_public_key)
    with pytest.raises(AttestationError, match="not signed by the attested device key"):
        ledger.verify_device_chain(device_public_key, header, issuer_signature, endorsement_public_key, foreign_signature, roots)
    # A software key: no device ever signed it.
    with pytest.raises(AttestationError, match="not signed by the attested device key"):
        ledger.verify_device_chain(device_public_key, header, issuer_signature, _uncompressed(_secp256k1()), device_signature, roots)
    with pytest.raises(AttestationError, match="no Ledger root"):
        ledger.verify_device_chain(device_public_key, header, issuer_signature, endorsement_public_key, device_signature, [])


def test_bundled_ledger_root_parses():
    from pathlib import Path

    roots = ledger.parse_owner_public_keys(str(Path(__file__).resolve().parents[1] / "attestation_roots" / "ledger_root_of_trust.txt"))
    assert len(roots) == 1 and isinstance(roots[0].curve, ec.SECP256K1)


def test_public_key_parsing_rejects_malformed_points():
    device = _secp256k1()
    raw = _uncompressed(device)
    assert ledger.public_key_from_uncompressed(raw).public_numbers() == device.public_key().public_numbers()
    for bad in (raw[1:], b"\x02" + raw[1:33], raw[:-1] + b"\x00", b""):
        with pytest.raises(AttestationError):
            ledger.public_key_from_uncompressed(bad)


def test_owner_keys_parse_from_a_list_or_a_file(tmp_path):
    a, b = _secp256k1(), _secp256k1()
    hex_a, hex_b = _uncompressed(a).hex(), _uncompressed(b).hex()
    keys = ledger.parse_owner_public_keys(f"{hex_a}, {hex_b}")
    assert [k.public_numbers() for k in keys] == [a.public_key().public_numbers(), b.public_key().public_numbers()]
    path = tmp_path / "owners.txt"
    path.write_text(f"# Ledger attest_1 candidates\n{hex_a}\n\n{hex_b}\n")
    assert len(ledger.parse_owner_public_keys(str(path))) == 2
    with pytest.raises(AttestationError, match="not hex"):
        ledger.parse_owner_public_keys("zz")
    with pytest.raises(AttestationError):
        ledger.parse_owner_public_keys(hex_a[:-2])
