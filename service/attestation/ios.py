"""Verify Apple App Attest attestation objects and binding assertions.

Trusted Apple roots are supplied by the server configuration. Enrollment
binds a separate approval key; see docs/SECURITY.md for the trust limits.
"""

from __future__ import annotations

import base64
import hashlib
import io
from datetime import datetime, timezone
from typing import Optional

import cbor2
from asn1crypto import core
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .base import AttestationError

NONCE_OID = x509.ObjectIdentifier("1.2.840.113635.100.8.2")
DEVELOPMENT_AAGUID = b"appattestdevelop"
SANDBOX_AAGUID = b"appattestsandbox"
PRODUCTION_AAGUID = b"appattest" + b"\x00" * 7


class _AppAttestNonceExtension(core.Sequence):
    # Apple's nonce is an explicitly tagged OCTET STRING. Parsing this with
    # a generic Sequence turns the context-specific tag into the boolean
    # value `True`, which made genuine device attestations fail closed.
    _fields = [("nonce", core.OctetString, {"explicit": 1})]


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _verify_certificate(child: x509.Certificate, issuer: x509.Certificate) -> None:
    if child.issuer != issuer.subject:
        raise AttestationError("App Attest certificate issuer mismatch")
    issuer.public_key().verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))


def _decode_extensions(auth_data: bytes, offset: int) -> dict:
    if offset >= len(auth_data):
        return {}
    return cbor2.loads(auth_data[offset:])


def _validation_category(value) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, bytes) and len(value) == 4:
        return int.from_bytes(value, "little")
    return None


def _verify_chain_against_roots(cert: x509.Certificate, trusted_roots: list[x509.Certificate]) -> None:
    for root in trusted_roots:
        try:
            _verify_certificate(cert, root)
            return
        except (AttestationError, InvalidSignature, ValueError, TypeError):
            continue  # not issued by this root; try the next
    raise AttestationError("App Attest certificate chain does not terminate at a trusted root")


def verify_attestation(
    attestation: bytes,
    key_id: str,
    challenge: bytes,
    app_id: str,
    environment: str,
    trusted_roots: list[x509.Certificate],
    bundle_version: str,
) -> tuple[bytes, bytes]:
    obj = cbor2.loads(attestation)
    if obj.get("fmt") != "apple-appattest":
        raise AttestationError("Unexpected attestation format")
    auth = obj["authData"]
    chain = [x509.load_der_x509_certificate(item) for item in obj["attStmt"]["x5c"]]
    if len(chain) < 2:
        raise AttestationError("Incomplete App Attest certificate chain")
    _verify_certificate(chain[0], chain[1])
    for child, issuer in zip(chain[1:], chain[2:]):
        _verify_certificate(child, issuer)
    _verify_chain_against_roots(chain[-1], trusted_roots)
    now = datetime.now(timezone.utc)
    for cert in chain:
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AttestationError("Expired App Attest certificate")
    nonce = _sha256(auth + _sha256(challenge))
    extension = chain[0].extensions.get_extension_for_oid(NONCE_OID).value.value
    extracted = _AppAttestNonceExtension.load(extension)["nonce"].native
    if extracted != nonce:
        raise AttestationError("Attestation challenge nonce mismatch")
    public_key = chain[0].public_key()
    public_x963 = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id_bytes = base64.b64decode(key_id, validate=True)
    if _sha256(public_x963) != key_id_bytes:
        raise AttestationError("App Attest key identifier mismatch")
    if auth[:32] != _sha256(app_id.encode()):
        raise AttestationError("App ID / RP ID mismatch")
    if int.from_bytes(auth[33:37], "big") != 0:
        raise AttestationError("Initial App Attest counter is not zero")
    aaguid = auth[37:53]
    expected = {DEVELOPMENT_AAGUID, SANDBOX_AAGUID} if environment == "development" else {PRODUCTION_AAGUID}
    if aaguid not in expected:
        raise AttestationError("Wrong App Attest environment")
    credential_length = int.from_bytes(auth[53:55], "big")
    credential_id = auth[55 : 55 + credential_length]
    if credential_id != key_id_bytes:
        raise AttestationError("Credential identifier mismatch")
    stream = io.BytesIO(auth[55 + credential_length :])
    cbor2.CBORDecoder(stream).decode()
    extension_offset = 55 + credential_length + stream.tell()
    extensions = _decode_extensions(auth, extension_offset)
    category = _validation_category(extensions.get("apple_validation_category_01"))
    if category not in ({3, 10} if environment == "development" else {2, 4, 5}):
        raise AttestationError("Unexpected Apple validation category")
    if extensions.get("apple_bundle_version_01") != bundle_version:
        raise AttestationError("Bundle version mismatch")
    return (
        public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
        obj["attStmt"]["receipt"],
    )


def verify_assertion(
    assertion: bytes,
    client_data: bytes,
    public_key_der: bytes,
    app_id: str,
    previous_counter: int,
    bundle_version: str,
    environment: str,
) -> int:
    """Verify the assertion binding a confirmation key during enrollment.

    The caller supplies previous_counter=0 for this initial assertion.
    Later iOS approvals verify signatures from the bound confirmation key;
    this protocol does not request further App Attest assertions. See
    docs/SECURITY.md.
    """
    obj = cbor2.loads(assertion)
    auth = obj["authenticatorData"]
    if auth[:32] != _sha256(app_id.encode()):
        raise AttestationError("Assertion App ID mismatch")
    counter = int.from_bytes(auth[33:37], "big")
    if counter <= previous_counter:
        raise AttestationError("Assertion counter replay")
    nonce = _sha256(auth + _sha256(client_data))
    key = serialization.load_der_public_key(public_key_der)
    # App Attest uses ES256 to sign the nonce as its message. The ECDSA
    # implementation therefore applies SHA-256 to these nonce bytes; marking
    # them as a precomputed digest rejects genuine device assertions.
    try:
        key.verify(obj["signature"], nonce, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise AttestationError("Invalid App Attest assertion signature") from None
    extensions = _decode_extensions(auth, 37) if auth[32] & 0x80 else {}
    category = _validation_category(extensions.get("apple_validation_category_01"))
    if category not in ({3, 10} if environment == "development" else {2, 4, 5}):
        raise AttestationError("Unexpected assertion validation category")
    if extensions.get("apple_bundle_version_01") != bundle_version:
        raise AttestationError("Assertion bundle version mismatch")
    return counter
