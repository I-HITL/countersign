"""The explicit emulator mode bypasses trust evidence, never approval proofs."""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from service.app import app
from service.integrity import FakeIntegrityVerifier, compute_request_hash, make_fake_verdict
from service.store import Store


DEVICE_HEADERS = {"Authorization": "Bearer test-device-token"}
ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token"}
SIMULATION_TOKEN = "android-simulation-only-not-a-play-integrity-token"


def _certificate(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "simulation-device")])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def _enrollment_body(key):
    return {
        "attestation_chain_der_b64": [base64.b64encode(_certificate(key).public_bytes(Encoding.DER)).decode()],
        "integrity_token": SIMULATION_TOKEN,
    }


@pytest.fixture
def simulation_client(monkeypatch):
    config = dataclasses.replace(
        app.state.config,
        enabled_platforms=frozenset({"android"}),
        dev_mode=True,
        skip_attestation=True,
        skip_integrity=True,
        integrity_verifier=FakeIntegrityVerifier(),
    )
    monkeypatch.setattr(app.state, "config", config)
    monkeypatch.setattr(app.state, "store", Store(":memory:"))
    return TestClient(app, headers=DEVICE_HEADERS)


@pytest.mark.parametrize("signature_case", ["valid", "wrong_key", "changed_message"])
def test_simulated_attestation_keeps_admin_gate_and_signature_verification(simulation_client, signature_case):
    client = simulation_client
    key = ec.generate_private_key(ec.SECP256R1())
    begin = client.post("/v1/enroll/begin", json={"platform": "android"}).json()
    enrolled = client.post(f"/v1/enroll/{begin['enrollment_id']}/complete", json=_enrollment_body(key))
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["status"] == "pending_manual_approval"
    device_id = enrolled.json()["device_id"]
    request = {"device_id": device_id, "text": "wire transfer of $500 to Alice Chen (Acct ...4471)"}

    assert client.get("/v1/approvals", params={"device_id": device_id}).status_code == 404
    assert client.post("/v1/approvals", headers=ADMIN_HEADERS, json=request).status_code == 404
    assert client.post(
        f"/v1/admin/enrollments/{device_id}/approve", json={"administrator": "device-is-not-admin"}
    ).status_code == 401
    activated = client.post(
        f"/v1/admin/enrollments/{device_id}/approve", headers=ADMIN_HEADERS,
        json={"administrator": "simulation-admin"},
    )
    assert activated.status_code == 200

    created = client.post("/v1/approvals", headers=ADMIN_HEADERS, json=request)
    assert created.status_code == 200
    approval = created.json()
    signing_key = ec.generate_private_key(ec.SECP256R1()) if signature_case == "wrong_key" else key
    message = approval["message"] + (" altered" if signature_case == "changed_message" else "")
    signature = signing_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    body = {"signature_b64": base64.b64encode(signature).decode(), "integrity_token": SIMULATION_TOKEN}
    completed = client.post(f"/v1/approvals/{approval['ref']}/complete", json=body)
    assert completed.status_code == 200
    expected = "approved" if signature_case == "valid" else "rejected"
    assert completed.json()["status"] == expected
    if expected == "rejected":
        assert any("signature" in reason for reason in completed.json()["reasons"])
    assert client.post(f"/v1/approvals/{approval['ref']}/complete", json=body).status_code == 409


def test_strict_android_verification_rejects_simulation_certificate(simulation_client, monkeypatch):
    client = simulation_client
    # A valid integrity verdict is supplied by a test double to isolate the
    # attestation boundary: this certificate must fail even if Play accepts.
    verifier = FakeIntegrityVerifier()
    trusted_root = _certificate(ec.generate_private_key(ec.SECP256R1()))
    strict = dataclasses.replace(
        app.state.config, dev_mode=False, skip_attestation=False, skip_integrity=False,
        trusted_attestation_roots=[trusted_root], integrity_verifier=verifier,
    )
    monkeypatch.setattr(app.state, "config", strict)
    begin = client.post("/v1/enroll/begin", json={"platform": "android"}).json()
    verifier.set_verdict(SIMULATION_TOKEN, make_fake_verdict(request_hash=compute_request_hash(begin["challenge_b64"])))
    response = client.post(
        f"/v1/enroll/{begin['enrollment_id']}/complete",
        json=_enrollment_body(ec.generate_private_key(ec.SECP256R1())),
    )
    assert response.status_code == 400
    reasons = response.json()["detail"]["reasons"]
    assert any("certificate chain" in reason for reason in reasons)
    assert any("key attestation" in reason for reason in reasons)
    assert not app.state.store.list_devices(include_pending=True)
    assert app.state.store.get_enrollment(begin["enrollment_id"]) is None
