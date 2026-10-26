"""A partial deployment must reject disabled platforms, never weaken verification."""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from service.app import app
from service.config import load_config
from service.models import EnrolledDevice, PendingApproval
from service.store import Store


DEVICE_HEADERS = {"Authorization": "Bearer test-device-token"}
ADMIN_HEADERS = {"Authorization": "Bearer test-admin-token"}
APPLE_ROOT = Path(__file__).resolve().parents[1] / "attestation_roots/apple_app_attestation_root.pem"


@pytest.fixture
def strict_ios_environment(monkeypatch):
    for key in list(os.environ):
        if key.startswith("COUNTERSIGN_") or key == "GOOGLE_APPLICATION_CREDENTIALS":
            monkeypatch.delenv(key)
    values = {
        "COUNTERSIGN_ENABLED_PLATFORMS": "ios",
        "COUNTERSIGN_API_TOKEN": "test-device-token",
        "COUNTERSIGN_ADMIN_API_TOKEN": "test-admin-token",
        "COUNTERSIGN_IOS_APP_ID": "TESTTEAM.com.example.test",
        "COUNTERSIGN_IOS_BUNDLE_VERSION": "1",
        "COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH": str(APPLE_ROOT),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_strict_ios_needs_no_google_credentials_or_fake_verifier(strict_ios_environment, monkeypatch):
    # Stale skip flags cannot turn a strict deployment into a bypass.
    monkeypatch.setenv("COUNTERSIGN_SKIP_ATTESTATION", "1")
    monkeypatch.setenv("COUNTERSIGN_SKIP_INTEGRITY", "1")
    config = load_config()
    assert config.enabled_platforms == frozenset({"ios"})
    assert config.integrity_verifier is None
    assert not config.dev_mode
    assert not config.skip_attestation
    assert not config.skip_integrity
    assert config.ios_trusted_attestation_roots


@pytest.mark.parametrize("key", [
    "COUNTERSIGN_API_TOKEN", "COUNTERSIGN_ADMIN_API_TOKEN",
    "COUNTERSIGN_IOS_APP_ID", "COUNTERSIGN_IOS_BUNDLE_VERSION",
    "COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH",
])
def test_strict_ios_still_requires_its_credentials_and_attestation_config(strict_ios_environment, monkeypatch, key):
    monkeypatch.delenv(key)
    with pytest.raises(RuntimeError, match=key):
        load_config()


def test_default_both_platforms_still_require_google_credentials(strict_ios_environment, monkeypatch):
    monkeypatch.delenv("COUNTERSIGN_ENABLED_PLATFORMS")
    monkeypatch.setenv("COUNTERSIGN_PACKAGE_NAME", "com.example.test")
    monkeypatch.setenv("COUNTERSIGN_APP_CERT_SHA256", "test-cert-digest")
    # Config only parses the trust anchor here; Android chain validation is
    # independently exercised with Google fixtures in test_attestation.py.
    monkeypatch.setenv("COUNTERSIGN_ATTESTATION_ROOTS_PATH", str(APPLE_ROOT))
    with pytest.raises(RuntimeError, match="GOOGLE_APPLICATION_CREDENTIALS"):
        load_config()


@pytest.mark.parametrize("value", ["", "windows", "ios,unknown"])
def test_invalid_enabled_platforms_fail_startup(strict_ios_environment, monkeypatch, value):
    monkeypatch.setenv("COUNTERSIGN_ENABLED_PLATFORMS", value)
    with pytest.raises(RuntimeError, match="COUNTERSIGN_ENABLED_PLATFORMS"):
        load_config()


def test_empty_ios_trust_store_fails_startup(strict_ios_environment, monkeypatch, tmp_path):
    empty_roots = tmp_path / "empty.pem"
    empty_roots.write_text("")
    monkeypatch.setenv("COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH", str(empty_roots))
    with pytest.raises(RuntimeError, match="no trusted certificates"):
        load_config()


@pytest.fixture(params=["android", "ios"])
def disabled_platform(request, monkeypatch):
    disabled = request.param
    enabled = frozenset({"android", "ios"} - {disabled})
    config = dataclasses.replace(app.state.config, enabled_platforms=enabled)
    if disabled == "android":
        config.integrity_verifier = None
    monkeypatch.setattr(app.state, "config", config)
    monkeypatch.setattr(app.state, "store", Store(":memory:"))
    return disabled


def test_disabled_platform_cannot_begin_enrollment(disabled_platform, monkeypatch):
    def unexpected_begin(_platform):
        pytest.fail("disabled platform created enrollment state")

    monkeypatch.setattr(app.state.store, "begin_enrollment", unexpected_begin)
    response = TestClient(app, headers=DEVICE_HEADERS).post(
        "/v1/enroll/begin", json={"platform": disabled_platform}
    )
    assert response.status_code == 503
    assert disabled_platform in response.json()["detail"]


def test_existing_enrollment_cannot_advance_when_platform_disabled(disabled_platform):
    store = app.state.store
    session = store.begin_enrollment(disabled_platform)
    client = TestClient(app, headers=DEVICE_HEADERS)
    if disabled_platform == "android":
        attempts = [("complete", {"attestation_chain_der_b64": [], "integrity_token": "unused"})]
    else:
        attempts = [
            ("attestation", {"key_id": "unused", "attestation_b64": ""}),
            ("binding", {"confirmation_public_key_der_b64": "", "confirmation_signature_b64": "", "assertion_b64": ""}),
        ]
    for endpoint, body in attempts:
        response = client.post(f"/v1/enroll/{session.enrollment_id}/{endpoint}", json=body)
        assert response.status_code == 503
        assert store.get_enrollment(session.enrollment_id) == session
        assert not store.list_devices(include_pending=True)


def test_disabled_device_cannot_activate_or_mutate_approvals(disabled_platform):
    store = app.state.store
    now = dt.datetime.now(dt.timezone.utc)
    device = EnrolledDevice(
        device_id="disabled-approved", platform=disabled_platform, public_key_pem="unused",
        enrolled_at=now, status="approved",
    )
    store.add_device(device)
    pending_device = dataclasses.replace(device, device_id="disabled-pending", status="pending_manual_approval")
    store.add_device(pending_device)
    approval = PendingApproval(
        ref="DISABLED", device_id=device.device_id, request_text="Do not execute",
        rendered_message="Do not execute", created_at=now - dt.timedelta(minutes=10),
        expires_at=now - dt.timedelta(minutes=5),
    )
    store.create_approval(approval)
    client = TestClient(app, headers=DEVICE_HEADERS)
    attempts = [
        ("GET", f"/v1/enrollments/{device.device_id}", None, DEVICE_HEADERS),
        ("GET", f"/v1/approvals?device_id={device.device_id}", None, DEVICE_HEADERS),
        ("GET", f"/v1/approvals/{approval.ref}", None, DEVICE_HEADERS),
        ("GET", f"/v1/admin/approvals/{approval.ref}", None, ADMIN_HEADERS),
        ("POST", f"/v1/approvals/{approval.ref}/decline", None, DEVICE_HEADERS),
        ("POST", f"/v1/approvals/{approval.ref}/complete", {"signature_b64": "", "integrity_token": "unused"}, DEVICE_HEADERS),
        ("POST", "/v1/approvals", {"device_id": device.device_id, "text": "New request"}, ADMIN_HEADERS),
        ("POST", f"/v1/admin/enrollments/{pending_device.device_id}/approve", {"administrator": "test-admin"}, ADMIN_HEADERS),
    ]
    for method, path, body, headers in attempts:
        response = client.request(method, path, json=body, headers=headers)
        assert response.status_code == 503, (path, response.text)
        assert store.get_approval(approval.ref) == approval  # even expiry must remain untouched
        assert len(store.list_approvals_for_device(device.device_id)) == 1
        assert store.get_device(pending_device.device_id, include_pending=True) == pending_device


def test_ios_only_strict_deployment_rejects_fake_attestation(strict_ios_environment, monkeypatch):
    monkeypatch.setattr(app.state, "config", load_config())
    monkeypatch.setattr(app.state, "store", Store(":memory:"))
    client = TestClient(app, headers=DEVICE_HEADERS)
    begin = client.post("/v1/enroll/begin", json={"platform": "ios"})
    assert begin.status_code == 200
    response = client.post(
        f"/v1/enroll/{begin.json()['enrollment_id']}/attestation",
        json={"key_id": "fake", "attestation_b64": base64.b64encode(b"\xa0").decode()},
    )
    assert response.status_code == 400
    assert not app.state.store.list_devices(include_pending=True)
    health = client.get("/health")
    assert health.json() == {"status": "ok", "enabled_platforms": ["ios"], "verification_mode": "strict"}


def test_device_integrity_policy_defaults_to_strong_and_is_configurable(monkeypatch):
    from service.config import load_config

    monkeypatch.delenv("COUNTERSIGN_ALLOWED_DEVICE_INTEGRITY", raising=False)
    assert load_config().integrity_policy.allowed_device_integrity == {"MEETS_STRONG_INTEGRITY"}

    monkeypatch.setenv("COUNTERSIGN_ALLOWED_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY, MEETS_DEVICE_INTEGRITY")
    assert load_config().integrity_policy.allowed_device_integrity == {
        "MEETS_STRONG_INTEGRITY",
        "MEETS_DEVICE_INTEGRITY",
    }

    monkeypatch.setenv("COUNTERSIGN_ALLOWED_DEVICE_INTEGRITY", "MEETS_BASIC_INTEGRITY")
    with pytest.raises(RuntimeError):
        load_config()
