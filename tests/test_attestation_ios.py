"""Tests for the ported Apple App Attest verifier in
service/attestation/ios.py.

Real caveat, stated plainly: a genuine end-to-end App Attest attestation
object can only be produced by Apple's own signing infrastructure inside a
real device's Secure Enclave plus a round-trip to Apple's servers -- there
is no way to synthesize one outside a physical iPhone (see
ios/countersign-app/README.md's own admission that even the Simulator
can't produce real evidence). So unlike tests/test_attestation.py, which
validates the Android DER walker against *real* certs Google published,
these tests cannot do the equivalent for iOS.

What they do instead -- and this is deliberately not "structure-only"
parsing tests -- is build a complete, correctly-shaped attestation object
and certificate chain from scratch, using test-generated EC keys standing
in for Apple's, and run it through the real verification code: real
ECDSA signature checks, real CBOR decoding, real byte-offset parsing of
authData. This exercises the actual verifier logic (and will catch a real
regression in it), it just can't tell you whether iOS's *real* App Attest
service produces data in the shape this code expects -- that can only be
confirmed against a real device. If/when real captured evidence becomes
available, it belongs in tests/fixtures/attestation/ios/ alongside a
README documenting how it was captured, mirroring
tests/fixtures/attestation/README.md's pattern for the Android fixtures.
"""

from __future__ import annotations

import datetime as dt
import hashlib

import cbor2
import pytest
from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from service.attestation import ios
from service.attestation.base import AttestationError

APP_ID = "TEAMID.com.example.countersigntest"
BUNDLE_VERSION = "1.0"
ENVIRONMENT = "development"
DEV_CATEGORY = 3


class _NonceSeq(core.Sequence):
    _fields = [("nonce", core.OctetString, {"explicit": 1})]


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _self_signed(key: ec.EllipticCurvePrivateKey, name: x509.Name) -> x509.Certificate:
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


def _key_id(key: ec.EllipticCurvePrivateKey) -> bytes:
    public_x963 = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return _sha256(public_x963)


def _build_auth_data(
    app_id: str = APP_ID,
    aaguid: bytes = ios.DEVELOPMENT_AAGUID,
    counter: int = 0,
    key_id_bytes: bytes | None = None,
    category: int = DEV_CATEGORY,
    bundle_version: str = BUNDLE_VERSION,
) -> bytes:
    header = _sha256(app_id.encode()) + bytes([0x00]) + counter.to_bytes(4, "big") + aaguid
    cred_len = len(key_id_bytes).to_bytes(2, "big")
    dummy_cose_key = cbor2.dumps({"dummy": 1})  # content unused; decoded only to find its length
    extensions = cbor2.dumps({"apple_validation_category_01": category, "apple_bundle_version_01": bundle_version})
    return header + cred_len + key_id_bytes + dummy_cose_key + extensions


def _build_leaf_cert(
    leaf_key: ec.EllipticCurvePrivateKey,
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    auth_data: bytes,
    challenge: bytes,
) -> x509.Certificate:
    nonce = _sha256(auth_data + _sha256(challenge))
    ext_der = _NonceSeq({"nonce": nonce}).dump()
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-app-attest-leaf")]))
        .issuer_name(root_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.UnrecognizedExtension(ios.NONCE_OID, ext_der), critical=False)
        .sign(root_key, hashes.SHA256())
    )


class _Fixture:
    """A complete, well-formed App Attest attestation setup: a self-signed
    test root, a leaf cert signed by it with the right nonce extension, and
    the matching CBOR attestation object -- all parameters overridable so
    each test can tamper exactly one thing."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_cert = _self_signed(
            self.root_key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-app-attest-root")])
        )
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.key_id_bytes = _key_id(self.leaf_key)
        self.challenge = b"server-issued-challenge-bytes!!"

    def attestation_bytes(self, **auth_overrides) -> bytes:
        auth_data = _build_auth_data(key_id_bytes=self.key_id_bytes, **auth_overrides)
        leaf_cert = _build_leaf_cert(self.leaf_key, self.root_key, self.root_cert, auth_data, self.challenge)
        obj = {
            "fmt": "apple-appattest",
            "authData": auth_data,
            "attStmt": {
                "x5c": [
                    leaf_cert.public_bytes(serialization.Encoding.DER),
                    self.root_cert.public_bytes(serialization.Encoding.DER),
                ],
                "receipt": b"fake-receipt-bytes",
            },
        }
        return cbor2.dumps(obj)

    def verify(self, *, trusted_roots=None, challenge=None, app_id=APP_ID, attestation_bytes=None):
        import base64

        return ios.verify_attestation(
            attestation_bytes if attestation_bytes is not None else self.attestation_bytes(),
            base64.b64encode(self.key_id_bytes).decode(),
            challenge if challenge is not None else self.challenge,
            app_id,
            ENVIRONMENT,
            trusted_roots if trusted_roots is not None else [self.root_cert],
            BUNDLE_VERSION,
        )


@pytest.fixture
def fixture():
    return _Fixture()


# --- verify_attestation: happy path ---


def test_valid_attestation_is_accepted(fixture):
    public_key_der, receipt = fixture.verify()
    assert receipt == b"fake-receipt-bytes"
    expected = fixture.leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert public_key_der == expected


# --- verify_attestation: adversarial / malformed inputs ---


def test_wrong_format_tag_is_rejected(fixture):
    bad = fixture.attestation_bytes()
    obj = cbor2.loads(bad)
    obj["fmt"] = "not-apple-appattest"
    with pytest.raises(AttestationError, match="format"):
        fixture.verify(attestation_bytes=cbor2.dumps(obj))


def test_chain_not_rooted_in_a_trusted_root_is_rejected(fixture):
    other_root_key = ec.generate_private_key(ec.SECP256R1())
    other_root_cert = _self_signed(
        other_root_key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "some-other-root")])
    )
    with pytest.raises(AttestationError, match="trusted root"):
        fixture.verify(trusted_roots=[other_root_cert])


def test_wrong_challenge_is_rejected(fixture):
    with pytest.raises(AttestationError, match="nonce"):
        fixture.verify(challenge=b"a-different-challenge-entirely!!")


def test_wrong_app_id_is_rejected(fixture):
    with pytest.raises(AttestationError, match="App ID"):
        fixture.verify(app_id="TEAMID.com.example.someone-else")


def test_nonzero_initial_counter_is_rejected(fixture):
    with pytest.raises(AttestationError, match="counter"):
        fixture.verify(attestation_bytes=fixture.attestation_bytes(counter=1))


def test_wrong_environment_aaguid_is_rejected(fixture):
    with pytest.raises(AttestationError, match="environment"):
        fixture.verify(attestation_bytes=fixture.attestation_bytes(aaguid=ios.PRODUCTION_AAGUID))


def test_wrong_validation_category_is_rejected(fixture):
    with pytest.raises(AttestationError, match="validation category"):
        fixture.verify(attestation_bytes=fixture.attestation_bytes(category=999))


def test_wrong_bundle_version_is_rejected(fixture):
    with pytest.raises(AttestationError, match="Bundle version"):
        fixture.verify(attestation_bytes=fixture.attestation_bytes(bundle_version="9.9"))


# --- verify_assertion ---


def _build_assertion(
    signing_key: ec.EllipticCurvePrivateKey,
    *,
    app_id: str = APP_ID,
    counter: int = 1,
    client_data: bytes = b"some client data payload",
    category: int = DEV_CATEGORY,
    bundle_version: str = BUNDLE_VERSION,
) -> tuple[bytes, bytes]:
    extensions = cbor2.dumps({"apple_validation_category_01": category, "apple_bundle_version_01": bundle_version})
    auth = _sha256(app_id.encode()) + bytes([0x80]) + counter.to_bytes(4, "big") + extensions
    nonce = _sha256(auth + _sha256(client_data))
    signature = signing_key.sign(nonce, ec.ECDSA(hashes.SHA256()))
    return cbor2.dumps({"authenticatorData": auth, "signature": signature}), client_data


def test_valid_assertion_returns_its_counter(fixture):
    public_key_der = fixture.leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assertion_bytes, client_data = _build_assertion(fixture.leaf_key, counter=1)
    counter = ios.verify_assertion(
        assertion_bytes, client_data, public_key_der, APP_ID, 0, BUNDLE_VERSION, ENVIRONMENT
    )
    assert counter == 1


def test_assertion_counter_replay_is_rejected(fixture):
    public_key_der = fixture.leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assertion_bytes, client_data = _build_assertion(fixture.leaf_key, counter=1)
    with pytest.raises(AttestationError, match="replay"):
        ios.verify_assertion(assertion_bytes, client_data, public_key_der, APP_ID, 1, BUNDLE_VERSION, ENVIRONMENT)


def test_assertion_with_wrong_app_id_is_rejected(fixture):
    public_key_der = fixture.leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assertion_bytes, client_data = _build_assertion(fixture.leaf_key, app_id="TEAMID.com.example.someone-else")
    with pytest.raises(AttestationError, match="App ID"):
        ios.verify_assertion(assertion_bytes, client_data, public_key_der, APP_ID, 0, BUNDLE_VERSION, ENVIRONMENT)


def test_assertion_signed_by_the_wrong_key_is_rejected(fixture):
    public_key_der = fixture.leaf_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    forger_key = ec.generate_private_key(ec.SECP256R1())
    assertion_bytes, client_data = _build_assertion(forger_key, counter=1)
    with pytest.raises(AttestationError, match="signature"):
        ios.verify_assertion(assertion_bytes, client_data, public_key_der, APP_ID, 0, BUNDLE_VERSION, ENVIRONMENT)
