"""Protocol tests for enrollment, signatures, replay, expiry, and integrity.

Enrollment uses self-signed keys with attestation verification explicitly
disabled by conftest.py. Separate attestation tests cover proof parsing.
Shared approval behavior is tested on all platforms; Play Integrity tests
apply only to Android. See docs/SECURITY.md for platform trust limits.
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from service.app import app
from service.integrity import compute_request_hash, make_fake_verdict
from service.models import ApprovalStatus, PendingApproval

PLATFORMS = ["android", "ios", "ledger"]
DEVICE_HEADERS = {"Authorization": "Bearer test-device-token"}
ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token"}
# Stands in for the SHA-256 of the Countersign Ledger app; Ledger OS appends
# it to everything the endorsement key signs (service/attestation/ledger.py).
LEDGER_TEST_CODE_HASH = bytes(range(32))


@pytest.fixture
def client():
    return TestClient(app, headers=DEVICE_HEADERS)


@pytest.fixture
def fake_verifier():
    return app.state.config.integrity_verifier


def _self_signed_cert(private_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-device")])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )


def _sign(private_key: ec.EllipticCurvePrivateKey, message: str, platform: str = "android") -> str:
    """Signs the way each platform's device does: the phones sign the exact
    UTF-8 message; a Ledger signs message || code_hash."""
    signed = message.encode("utf-8")
    if platform == "ledger":
        signed += LEDGER_TEST_CODE_HASH
    signature = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def _ledger_endorsement_body(
    endorsement_key: ec.EllipticCurvePrivateKey,
    challenge: bytes,
    owner_key: ec.EllipticCurvePrivateKey | None = None,
    code_hash: bytes = LEDGER_TEST_CODE_HASH,
) -> dict:
    """The exact bytes a Countersign Ledger app returns from ENROLL, base64."""
    public_key = endorsement_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    owner_key = owner_key or ec.generate_private_key(ec.SECP256K1())
    return {
        "endorsement_public_key_b64": base64.b64encode(public_key).decode(),
        "code_hash_b64": base64.b64encode(code_hash).decode(),
        "owner_certificate_b64": base64.b64encode(owner_key.sign(b"\xfe" + public_key, ec.ECDSA(hashes.SHA256()))).decode(),
        "challenge_signature_b64": base64.b64encode(
            endorsement_key.sign(challenge + code_hash, ec.ECDSA(hashes.SHA256()))
        ).decode(),
    }


def _enroll_ledger(client: TestClient) -> tuple[str, ec.EllipticCurvePrivateKey]:
    # skip_attestation (conftest.py) disables the Owner-certificate and
    # code-hash checks; the challenge proof-of-possession is still verified.
    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    endorsement_key = ec.generate_private_key(ec.SECP256K1())
    body = _ledger_endorsement_body(endorsement_key, base64.b64decode(begin["challenge_b64"]))
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "pending_manual_approval"
    approval = client.post(
        f"/v1/admin/enrollments/{resp.json()['device_id']}/approve",
        headers=ADMIN_HEADERS,
        json={"administrator": "test-admin"},
    )
    assert approval.status_code == 200, approval.text
    return resp.json()["device_id"], endorsement_key


def _enroll_android(client: TestClient, fake_verifier) -> tuple[str, ec.EllipticCurvePrivateKey]:
    begin = client.post("/v1/enroll/begin", json={"platform": "android"}).json()
    enrollment_id, challenge_b64 = begin["enrollment_id"], begin["challenge_b64"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    cert_der_b64 = base64.b64encode(_self_signed_cert(private_key).public_bytes(Encoding.DER)).decode("ascii")

    token = f"enroll-token-{enrollment_id}"
    fake_verifier.set_verdict(token, make_fake_verdict(request_hash=compute_request_hash(challenge_b64)))

    resp = client.post(
        f"/v1/enroll/{enrollment_id}/complete",
        json={"attestation_chain_der_b64": [cert_der_b64], "integrity_token": token},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "pending_manual_approval"
    approval = client.post(
        f"/v1/admin/enrollments/{resp.json()['device_id']}/approve",
        headers=ADMIN_HEADERS,
        json={"administrator": "test-admin"},
    )
    assert approval.status_code == 200, approval.text
    return resp.json()["device_id"], private_key


def _enroll_ios(client: TestClient) -> tuple[str, ec.EllipticCurvePrivateKey]:
    # skip_attestation (set in conftest.py) means the App Attest attestation
    # and assertion steps are never actually verified here -- this exercises
    # the two-round protocol shape and the confirmation-key proof-of-
    # possession check (which is NOT gated by skip_attestation), not the
    # App Attest parsing itself. See test_attestation_ios.py for that.
    begin = client.post("/v1/enroll/begin", json={"platform": "ios"}).json()
    enrollment_id = begin["enrollment_id"]

    attestation_resp = client.post(
        f"/v1/enroll/{enrollment_id}/attestation",
        json={
            "key_id": "test-app-attest-key-id",
            "attestation_b64": base64.b64encode(b"dummy-attestation-object").decode("ascii"),
        },
    )
    assert attestation_resp.status_code == 200, attestation_resp.text
    binding_challenge = base64.b64decode(attestation_resp.json()["binding_challenge_b64"])

    confirmation_key = ec.generate_private_key(ec.SECP256R1())
    confirmation_public_key_der = confirmation_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    payload = confirmation_public_key_der + binding_challenge
    confirmation_signature = confirmation_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    resp = client.post(
        f"/v1/enroll/{enrollment_id}/binding",
        json={
            "confirmation_public_key_der_b64": base64.b64encode(confirmation_public_key_der).decode("ascii"),
            "confirmation_signature_b64": base64.b64encode(confirmation_signature).decode("ascii"),
            "assertion_b64": base64.b64encode(b"dummy-assertion").decode("ascii"),
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "pending_manual_approval"
    approval = client.post(
        f"/v1/admin/enrollments/{resp.json()['device_id']}/approve",
        headers=ADMIN_HEADERS,
        json={"administrator": "test-admin"},
    )
    assert approval.status_code == 200, approval.text
    return resp.json()["device_id"], confirmation_key


def _enroll(
    client: TestClient, fake_verifier, platform: str = "android"
) -> tuple[str, ec.EllipticCurvePrivateKey]:
    if platform == "android":
        return _enroll_android(client, fake_verifier)
    if platform == "ios":
        return _enroll_ios(client)
    if platform == "ledger":
        return _enroll_ledger(client)
    raise ValueError(f"unknown platform: {platform}")


def _create_approval(client: TestClient, device_id: str, text: str = "pay $10 to alice", ttl_seconds: int = 300) -> dict:
    resp = client.post(
        "/v1/approvals",
        headers=ADMIN_HEADERS,
        json={"device_id": device_id, "text": text, "ttl_seconds": ttl_seconds},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _register_good_verdict(fake_verifier, token: str, message: str) -> None:
    fake_verifier.set_verdict(token, make_fake_verdict(request_hash=compute_request_hash(message)))


def _complete(
    client: TestClient,
    platform: str,
    key: ec.EllipticCurvePrivateKey,
    ref: str,
    message: str,
    fake_verifier=None,
    token: str | None = None,
):
    """Completes an approval the way each platform actually does: Android
    always sends a (real or fake-verifier-registered) integrity_token;
    iOS and Ledger send only a signature; see docs/SECURITY.md."""
    body = {"signature_b64": _sign(key, message, platform)}
    if platform == "android":
        token = token or f"token-for-{ref}"
        if fake_verifier is not None:
            _register_good_verdict(fake_verifier, token, message)
        body["integrity_token"] = token
    return client.post(f"/v1/approvals/{ref}/complete", json=body)


# --- happy path ---


@pytest.mark.parametrize("platform", PLATFORMS)
def test_full_enroll_approve_flow_succeeds(client, fake_verifier, platform):
    device_id, key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id)

    resp = _complete(client, platform, key, approval["ref"], approval["message"], fake_verifier)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"


# --- adversary: replay ---


@pytest.mark.parametrize("platform", PLATFORMS)
def test_completing_the_same_approval_twice_is_rejected(client, fake_verifier, platform):
    device_id, key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id)

    first = _complete(client, platform, key, approval["ref"], approval["message"], fake_verifier, token="token-1")
    assert first.status_code == 200 and first.json()["status"] == "approved"

    second = _complete(client, platform, key, approval["ref"], approval["message"], fake_verifier, token="token-2")
    assert second.status_code == 409


@pytest.mark.parametrize("platform", PLATFORMS)
def test_a_signature_from_one_approval_does_not_satisfy_a_different_approval_with_identical_text(
    client, fake_verifier, platform
):
    # This is the concrete regression test for the WYSIWYS design decision:
    # the server-chosen ref is folded into the *visible, signed* message, so
    # two approvals requesting identical text still never share signable
    # bytes -- a captured signature can't be replayed across them.
    device_id, key = _enroll(client, fake_verifier, platform)
    approval_a = _create_approval(client, device_id, text="pay $10 to alice")
    approval_b = _create_approval(client, device_id, text="pay $10 to alice")
    assert approval_a["message"] != approval_b["message"]

    signature_for_a = _sign(key, approval_a["message"], platform)
    body = {"signature_b64": signature_for_a}
    if platform == "android":
        token = "replay-attempt"
        _register_good_verdict(fake_verifier, token, approval_a["message"])  # matches A's bytes, not B's
        body["integrity_token"] = token
    resp = client.post(f"/v1/approvals/{approval_b['ref']}/complete", json=body)
    assert resp.status_code == 200  # request well-formed, but...
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("signature" in r for r in body["reasons"])


# --- adversary: forged signature ---


@pytest.mark.parametrize("platform", PLATFORMS)
def test_signature_from_an_unenrolled_key_is_rejected(client, fake_verifier, platform):
    device_id, _enrolled_key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id)

    forger_key = ec.generate_private_key(ec.SECP256R1())
    resp = _complete(client, platform, forger_key, approval["ref"], approval["message"], fake_verifier)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("signature" in r for r in body["reasons"])


# --- adversary: weak/stale integrity verdict (Android only) ---


def test_rooted_or_emulated_device_verdict_is_rejected(client, fake_verifier):
    device_id, key = _enroll(client, fake_verifier)
    approval = _create_approval(client, device_id)

    token = "rooted-device-token"
    fake_verifier.set_verdict(
        token,
        make_fake_verdict(
            request_hash=compute_request_hash(approval["message"]),
            device_integrity_labels=["MEETS_BASIC_INTEGRITY"],  # not in the allowed set
        ),
    )
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"]), "integrity_token": token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("device_integrity" in r for r in body["reasons"])


def test_stale_integrity_token_is_rejected(client, fake_verifier):
    device_id, key = _enroll(client, fake_verifier)
    approval = _create_approval(client, device_id)

    stale_timestamp = int((dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).timestamp() * 1000)
    token = "stale-token"
    fake_verifier.set_verdict(
        token,
        make_fake_verdict(request_hash=compute_request_hash(approval["message"]), timestamp_millis=stale_timestamp),
    )
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"]), "integrity_token": token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("old" in r for r in body["reasons"])


def test_integrity_token_bound_to_a_different_message_is_rejected(client, fake_verifier):
    # The device fetched approval A's message but the integrity token it
    # presents was minted for different text -- request_hash mismatch.
    device_id, key = _enroll(client, fake_verifier)
    approval = _create_approval(client, device_id)

    token = "wrong-binding-token"
    _register_good_verdict(fake_verifier, token, "some other message entirely")
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"]), "integrity_token": token},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("request_hash" in r for r in body["reasons"])


# --- the platform branch point itself ---


def test_ios_device_sending_an_integrity_token_is_rejected(client):
    device_id, key = _enroll(client, None, "ios")
    approval = _create_approval(client, device_id)
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"]), "integrity_token": "should-not-be-sent"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("must not be sent" in r for r in body["reasons"])


def test_ledger_device_sending_an_integrity_token_is_rejected(client):
    device_id, key = _enroll(client, None, "ledger")
    approval = _create_approval(client, device_id)
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"], "ledger"), "integrity_token": "should-not-be-sent"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("must not be sent for ledger" in r for r in body["reasons"])


def test_ledger_signature_without_the_code_hash_is_rejected(client):
    # What sys_endorsement_key1_sign_without_code_hash would produce, or a
    # signature from any non-Ledger holder of the key: not bound to the app.
    device_id, key = _enroll(client, None, "ledger")
    approval = _create_approval(client, device_id)
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"], "android")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("signature" in r for r in body["reasons"])


def test_ledger_endorsement_with_a_bad_challenge_signature_is_rejected(client):
    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    key = ec.generate_private_key(ec.SECP256K1())
    body = _ledger_endorsement_body(key, b"not the challenge" * 2)
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body)
    assert resp.status_code == 400
    assert any("challenge signature" in r for r in resp.json()["detail"]["reasons"])
    # A failed enrollment consumes the challenge.
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body).status_code == 404


def test_ledger_endorsement_rejects_malformed_evidence(client):
    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    key = ec.generate_private_key(ec.SECP256R1())  # wrong curve: not a secp256k1 point
    body = _ledger_endorsement_body(key, base64.b64decode(begin["challenge_b64"]))
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body).status_code == 400
    good_key = ec.generate_private_key(ec.SECP256K1())
    body = _ledger_endorsement_body(good_key, base64.b64decode(begin["challenge_b64"]), code_hash=b"short")
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body).status_code == 400
    body = _ledger_endorsement_body(good_key, base64.b64decode(begin["challenge_b64"]))
    body["owner_certificate_b64"] = "not base64!"
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body).status_code == 400


def test_ledger_endorsement_endpoint_rejects_other_platforms_enrollments(client):
    begin = client.post("/v1/enroll/begin", json={"platform": "ios"}).json()
    key = ec.generate_private_key(ec.SECP256K1())
    body = _ledger_endorsement_body(key, base64.b64decode(begin["challenge_b64"]))
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body).status_code == 400


def test_ledger_attestation_checks_run_when_configured(client, monkeypatch):
    # With skip_attestation off, the Owner certificate must chain to a
    # configured Owner and the reported code hash must match the pin.
    import dataclasses

    owner = ec.generate_private_key(ec.SECP256K1())
    config = dataclasses.replace(
        app.state.config,
        skip_attestation=False,
        ledger_owner_public_keys=[owner.public_key()],
        ledger_code_hash=LEDGER_TEST_CODE_HASH,
    )
    monkeypatch.setattr(app.state, "config", config)
    key = ec.generate_private_key(ec.SECP256K1())

    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    good = _ledger_endorsement_body(key, base64.b64decode(begin["challenge_b64"]), owner_key=owner)
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=good).status_code == 200

    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    wrong_owner = _ledger_endorsement_body(key, base64.b64decode(begin["challenge_b64"]))
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=wrong_owner)
    assert resp.status_code == 400
    assert any("owner certificate" in r for r in resp.json()["detail"]["reasons"])

    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    other_app = _ledger_endorsement_body(
        key, base64.b64decode(begin["challenge_b64"]), owner_key=owner, code_hash=bytes(32)
    )
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=other_app)
    assert resp.status_code == 400
    assert any("code hash" in r for r in resp.json()["detail"]["reasons"])


def test_ledger_enrollment_with_a_device_chain_is_verified_against_the_root(client, monkeypatch):
    import dataclasses

    from cryptography.hazmat.primitives.asymmetric import ec as _ec

    root, device, key = (_ec.generate_private_key(_ec.SECP256K1()) for _ in range(3))
    config = dataclasses.replace(
        app.state.config, skip_attestation=False, ledger_root_public_keys=[root.public_key()], ledger_owner_public_keys=[]
    )
    monkeypatch.setattr(app.state, "config", config)
    endorsement_public_key = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    device_public_key = device.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    header = b"\x01\x02\x03"
    issuer_signature = root.sign(b"\x02" + header + device_public_key, ec.ECDSA(hashes.SHA256()))
    device_signature = device.sign(b"\xff" + endorsement_public_key, ec.ECDSA(hashes.SHA256()))

    def body(challenge, **overrides):
        b = _ledger_endorsement_body(key, challenge)
        b["owner_certificate_b64"] = base64.b64encode(device_signature).decode()
        b["device_public_key_b64"] = base64.b64encode(device_public_key).decode()
        b["issuer_certificate_header_b64"] = base64.b64encode(header).decode()
        b["issuer_signature_b64"] = base64.b64encode(issuer_signature).decode()
        b.update(overrides)
        return b

    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=body(base64.b64decode(begin["challenge_b64"])))
    assert resp.status_code == 200, resp.text
    device_id = resp.json()["device_id"]
    client.post(f"/v1/admin/enrollments/{device_id}/approve", headers=ADMIN_HEADERS, json={"administrator": "a"})
    approval = _create_approval(client, device_id)
    assert _complete(client, "ledger", key, approval["ref"], approval["message"]).json()["status"] == "approved"
    proof = client.get(f"/v1/admin/approvals/{approval['ref']}/proof", headers=ADMIN_HEADERS).json()
    assert bytes.fromhex(proof["ledger_device_public_key_hex"]) == device_public_key
    issuer = base64.b64decode(proof["ledger_issuer_certificate_b64"])
    assert issuer == bytes([len(header)]) + header + bytes([len(issuer_signature)]) + issuer_signature

    # Without the chain, no Owner keys are configured, so strict mode rejects.
    monkeypatch.setattr(app.state, "config", dataclasses.replace(config, dev_mode=False))
    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    plain = _ledger_endorsement_body(key, base64.b64decode(begin["challenge_b64"]))
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=plain)
    assert resp.status_code == 400 and any("device chain" in r for r in resp.json()["detail"]["reasons"])

    # A chain whose root is not Ledger's, and an incomplete chain, are rejected.
    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    other_root = _ec.generate_private_key(_ec.SECP256K1())
    bad = body(base64.b64decode(begin["challenge_b64"]), issuer_signature_b64=base64.b64encode(
        other_root.sign(b"\x02" + header + device_public_key, ec.ECDSA(hashes.SHA256()))).decode())
    resp = client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=bad)
    assert resp.status_code == 400 and any("issuer certificate" in r for r in resp.json()["detail"]["reasons"])
    begin = client.post("/v1/enroll/begin", json={"platform": "ledger"}).json()
    incomplete = body(base64.b64decode(begin["challenge_b64"]), issuer_signature_b64=None)
    assert client.post(f"/v1/enroll/{begin['enrollment_id']}/endorsement", json=incomplete).status_code == 400


def test_ledger_approval_proof_carries_the_code_hash_and_owner_certificate(client):
    from service.attestation import ledger as ledger_attestation

    device_id, key = _enroll(client, None, "ledger")
    approval = _create_approval(client, device_id)
    assert _complete(client, "ledger", key, approval["ref"], approval["message"]).json()["status"] == "approved"
    proof = client.get(f"/v1/admin/approvals/{approval['ref']}/proof", headers=ADMIN_HEADERS).json()
    assert proof["platform"] == "ledger"
    assert proof["attestation_chain_der_b64"] is None
    assert bytes.fromhex(proof["ledger_code_hash_hex"]) == LEDGER_TEST_CODE_HASH
    assert proof["ledger_owner_certificate_b64"]
    assert ledger_attestation.verify_endorsement_signature(
        proof["public_key_pem"], proof["message"].encode(), LEDGER_TEST_CODE_HASH, proof["signature_b64"]
    )


def test_store_migrates_databases_created_before_ledger_support(tmp_path):
    import sqlite3

    from service.store import Store

    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(
        """
        CREATE TABLE pending_enrollments (
            enrollment_id TEXT PRIMARY KEY,
            platform TEXT NOT NULL CHECK(platform IN ('android','ios')),
            challenge BLOB NOT NULL, created_at TEXT NOT NULL, ios_round TEXT, ios_key_id TEXT,
            ios_attestation_public_key BLOB, ios_receipt BLOB, ios_binding_challenge BLOB);
        CREATE TABLE devices (
            device_id TEXT PRIMARY KEY,
            platform TEXT NOT NULL CHECK(platform IN ('android','ios')),
            public_key_pem TEXT NOT NULL, enrolled_at TEXT NOT NULL, package_name TEXT,
            certificate_sha256 TEXT, ios_key_id TEXT, ios_receipt_b64 TEXT, ios_assertion_counter INTEGER);
        INSERT INTO devices VALUES ('old-device', 'ios', 'pem', '2026-01-01T00:00:00+00:00', NULL, NULL, 'k', NULL, 1);
        """
    )
    old.close()

    store = Store(str(path))
    kept = store.get_device("old-device", include_pending=True)
    assert kept is not None and kept.platform == "ios" and kept.ios_key_id == "k"
    assert kept.status == "pending_manual_approval"
    store.begin_enrollment("ledger")  # would violate the old CHECK constraint


def test_android_device_omitting_integrity_token_is_rejected(client, fake_verifier):
    device_id, key = _enroll(client, fake_verifier, "android")
    approval = _create_approval(client, device_id)
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"])},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert any("required" in r for r in body["reasons"])


# --- expiry ---


@pytest.mark.parametrize("platform", PLATFORMS)
def test_completing_an_expired_approval_is_rejected(client, fake_verifier, platform):
    device_id, key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id, ttl_seconds=-1)  # already expired

    resp = _complete(client, platform, key, approval["ref"], approval["message"], fake_verifier)
    assert resp.status_code == 409
    assert resp.json()["detail"]["status"] == "expired"


# --- decline ---


@pytest.mark.parametrize("platform", PLATFORMS)
def test_declining_a_pending_approval_needs_no_proof(client, fake_verifier, platform):
    device_id, _key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id)

    resp = client.post(f"/v1/approvals/{approval['ref']}/decline")
    assert resp.status_code == 200
    assert resp.json()["status"] == "declined"

    status_resp = client.get(f"/v1/approvals/{approval['ref']}")
    assert status_resp.json()["status"] == "declined"


@pytest.mark.parametrize("platform", PLATFORMS)
def test_declining_an_already_completed_approval_is_rejected(client, fake_verifier, platform):
    device_id, key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id)
    _complete(client, platform, key, approval["ref"], approval["message"], fake_verifier)

    resp = client.post(f"/v1/approvals/{approval['ref']}/decline")
    assert resp.status_code == 409


@pytest.mark.parametrize("platform", PLATFORMS)
def test_declined_approvals_do_not_appear_in_the_pending_list(client, fake_verifier, platform):
    device_id, _key = _enroll(client, fake_verifier, platform)
    approval = _create_approval(client, device_id)
    client.post(f"/v1/approvals/{approval['ref']}/decline")

    resp = client.get("/v1/approvals", params={"device_id": device_id})
    assert resp.json() == []


# --- listing pending approvals ---


@pytest.mark.parametrize("platform", PLATFORMS)
def test_listing_pending_approvals_excludes_completed_and_expired(client, fake_verifier, platform):
    device_id, key = _enroll(client, fake_verifier, platform)
    pending = _create_approval(client, device_id, text="still pending")
    _create_approval(client, device_id, text="will expire", ttl_seconds=-1)
    completed = _create_approval(client, device_id, text="will be approved")

    _complete(client, platform, key, completed["ref"], completed["message"], fake_verifier)

    resp = client.get("/v1/approvals", params={"device_id": device_id})
    assert resp.status_code == 200
    refs = {a["ref"] for a in resp.json()}
    assert refs == {pending["ref"]}


def test_listing_pending_approvals_for_an_unenrolled_device_is_rejected(client):
    resp = client.get("/v1/approvals", params={"device_id": "no-such-device"})
    assert resp.status_code == 404


# --- basic input validation ---


def test_creating_an_approval_for_an_unenrolled_device_is_rejected(client):
    resp = client.post(
        "/v1/approvals", headers=ADMIN_HEADERS, json={"device_id": "no-such-device", "text": "hi"}
    )
    assert resp.status_code == 404


def test_completing_enrollment_with_an_unknown_enrollment_id_is_rejected(client):
    resp = client.post(
        "/v1/enroll/does-not-exist/complete",
        json={"attestation_chain_der_b64": [], "integrity_token": "x"},
    )
    assert resp.status_code in (400, 404)


def test_api_requires_the_correct_credential():
    unauthenticated = TestClient(app)
    assert unauthenticated.post("/v1/enroll/begin", json={"platform": "ios"}).status_code == 401
    assert unauthenticated.post("/v1/approvals", json={"device_id": "x", "text": "x"}).status_code == 401

    wrong = {"Authorization": "Bearer wrong-token"}
    assert unauthenticated.post("/v1/enroll/begin", headers=wrong, json={"platform": "ios"}).status_code == 401
    assert unauthenticated.get("/v1/admin/enrollments/pending", headers=DEVICE_HEADERS).status_code == 401


def test_technical_enrollment_is_inactive_until_manual_approval(client):
    begin = client.post("/v1/enroll/begin", json={"platform": "ios"}).json()
    attestation = client.post(
        f"/v1/enroll/{begin['enrollment_id']}/attestation",
        json={
            "key_id": "manual-approval-test",
            "attestation_b64": base64.b64encode(b"dummy").decode(),
        },
    ).json()
    key = ec.generate_private_key(ec.SECP256R1())
    public_der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    payload = public_der + base64.b64decode(attestation["binding_challenge_b64"])
    response = client.post(
        f"/v1/enroll/{begin['enrollment_id']}/binding",
        json={
            "confirmation_public_key_der_b64": base64.b64encode(public_der).decode(),
            "confirmation_signature_b64": base64.b64encode(
                key.sign(payload, ec.ECDSA(hashes.SHA256()))
            ).decode(),
            "assertion_b64": base64.b64encode(b"dummy").decode(),
        },
    )
    device_id = response.json()["device_id"]
    assert response.json()["status"] == "pending_manual_approval"
    assert client.get("/v1/approvals", params={"device_id": device_id}).status_code == 404
    assert client.post(
        "/v1/approvals",
        headers=ADMIN_HEADERS,
        json={"device_id": device_id, "text": "must not work yet"},
    ).status_code == 404

    approved = client.post(
        f"/v1/admin/enrollments/{device_id}/approve",
        headers=ADMIN_HEADERS,
        json={"administrator": "alice@example.test"},
    )
    assert approved.status_code == 200
    assert client.get(f"/v1/enrollments/{device_id}").json()["status"] == "approved"


def test_store_consumes_a_pending_approval_atomically():
    now = dt.datetime.now(dt.timezone.utc)
    approval = PendingApproval(
        ref="ATOMIC-" + now.isoformat(),
        device_id="atomic-device",
        request_text="test",
        rendered_message="test",
        created_at=now,
        expires_at=now + dt.timedelta(minutes=5),
    )
    store = app.state.store
    store.create_approval(approval)

    def consume() -> bool:
        candidate = copy.deepcopy(approval)
        candidate.status = ApprovalStatus.APPROVED
        candidate.completed_at = dt.datetime.now(dt.timezone.utc)
        return store.consume_pending_approval(candidate)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: consume(), range(2)))
    assert sorted(results) == [False, True]


# --- adversary: weaker device verdict, stale challenge; accountability proof ---


def test_device_integrity_without_strong_verdict_is_rejected(client, fake_verifier):
    device_id, key = _enroll(client, fake_verifier)
    approval = _create_approval(client, device_id)
    token = "device-only-token"
    fake_verifier.set_verdict(
        token,
        make_fake_verdict(
            request_hash=compute_request_hash(approval["message"]),
            device_integrity_labels=["MEETS_DEVICE_INTEGRITY"],
        ),
    )
    resp = client.post(
        f"/v1/approvals/{approval['ref']}/complete",
        json={"signature_b64": _sign(key, approval["message"]), "integrity_token": token},
    )
    assert resp.json()["status"] == "rejected"


def test_an_expired_enrollment_challenge_is_rejected(client):
    from service import store as store_module

    enrollment_id = client.post("/v1/enroll/begin", json={"platform": "android"}).json()["enrollment_id"]
    stored = app.state.store.get_enrollment(enrollment_id)
    assert stored is not None
    original = store_module.ENROLLMENT_CHALLENGE_TTL
    store_module.ENROLLMENT_CHALLENGE_TTL = dt.timedelta(seconds=-1)
    try:
        assert app.state.store.get_enrollment(enrollment_id) is None
    finally:
        store_module.ENROLLMENT_CHALLENGE_TTL = original


def test_approved_request_has_a_verifiable_proof(client, fake_verifier):
    device_id, key = _enroll(client, fake_verifier)
    approval = _create_approval(client, device_id)
    ref = approval["ref"]

    assert client.get(f"/v1/admin/approvals/{ref}/proof", headers=ADMIN_HEADERS).status_code == 404

    assert _complete(client, "android", key, ref, approval["message"], fake_verifier).json()["status"] == "approved"
    proof = client.get(f"/v1/admin/approvals/{ref}/proof", headers=ADMIN_HEADERS)
    assert proof.status_code == 200, proof.text
    body = proof.json()
    assert body["message"] == approval["message"]
    assert len(body["attestation_chain_der_b64"]) == 1
    from service import crypto

    assert crypto.verify_signature(body["public_key_pem"], body["message"], body["signature_b64"])
    assert client.get(f"/v1/admin/approvals/{ref}/proof").status_code in (401, 403)


def test_certificate_digest_comparison_ignores_base64_padding():
    from service.integrity import IntegrityPolicy, check_verdict

    request_hash = compute_request_hash("m")
    policy = IntegrityPolicy(expected_package_name="com.example.countersign", expected_certificate_sha256="abc=")
    for digest in ("abc", "abc="):
        ok, reasons = check_verdict(
            make_fake_verdict(request_hash=request_hash, certificate_sha256_digests=[digest]),
            expected_request_hash=request_hash,
            policy=policy,
        )
        assert ok, reasons
    ok, _ = check_verdict(
        make_fake_verdict(request_hash=request_hash, certificate_sha256_digests=["other"]),
        expected_request_hash=request_hash,
        policy=policy,
    )
    assert not ok
