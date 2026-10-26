"""Protocol tests for enrollment, signatures, replay, expiry, and integrity.

Enrollment uses self-signed keys with attestation verification explicitly
disabled by conftest.py. Separate attestation tests cover proof parsing.
Shared approval behavior is tested on both platforms; Play Integrity tests
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

PLATFORMS = ["android", "ios"]
DEVICE_HEADERS = {"Authorization": "Bearer test-device-token"}
ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token"}


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


def _sign(private_key: ec.EllipticCurvePrivateKey, message: str) -> str:
    signature = private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


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
    iOS sends only its confirmation-key signature; see docs/SECURITY.md."""
    body = {"signature_b64": _sign(key, message)}
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

    signature_for_a = _sign(key, approval_a["message"])
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
