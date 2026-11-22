"""Speculos's deterministic endorsement material (speculos/src/environment.c).

--attestation-key signs Owner certificates; --user-private-key is the slot 1
endorsement key; the code hash is a fixed 32-byte string. Overridable with
the Speculos options of the same names, but the defaults are what Ragger
starts the emulator with. tests/test_attestation_ledger.py in the backend
uses the same values."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ATTESTATION_PRIVATE_KEY = bytes.fromhex("138fb9b91da745f12977a2b46f0bce2f0418b50fcb76631baf0f08ceefdb5d57")
USER_PRIVATE_KEY = bytes.fromhex("e15e01d47082f0ea4771c99fe312f9d70093c89af47787fdf82e031f6728b710")
CODE_HASH = b"12345678abcdef0000fedcba8765432\x00"
OWNER_CERTIFICATE_ROLE = b"\xfe"


def _key(private_bytes: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(private_bytes, "big"), ec.SECP256K1())


OWNER_PUBLIC_KEY = _key(ATTESTATION_PRIVATE_KEY).public_key()
ENDORSEMENT_PUBLIC_KEY = _key(USER_PRIVATE_KEY).public_key()


def verifies(public_key: ec.EllipticCurvePublicKey, signature: bytes, signed: bytes) -> bool:
    try:
        public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
