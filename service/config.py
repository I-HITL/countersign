"""Runtime configuration, loaded from environment variables. Fails closed:
outside dev mode, missing required config raises at startup rather than
silently degrading a security check.
"""

from __future__ import annotations

import dataclasses
import os

from cryptography import x509

from .attestation import SecurityLevel
from .integrity import FakeIntegrityVerifier, IntegrityPolicy, IntegrityVerifier, PlayIntegrityVerifier


@dataclasses.dataclass
class Config:
    enabled_platforms: frozenset[str]
    dev_mode: bool
    skip_attestation: bool
    skip_integrity: bool
    db_path: str
    device_api_token: str
    administrator_api_token: str
    expected_package_name: str
    trusted_attestation_roots: list[x509.Certificate]
    min_attestation_security_level: int
    integrity_verifier: IntegrityVerifier | None
    integrity_policy: IntegrityPolicy
    # iOS verifies App Attest at enrollment only; see docs/SECURITY.md.
    ios_app_id: str
    ios_attestation_environment: str
    ios_trusted_attestation_roots: list[x509.Certificate]
    ios_bundle_version: str


def _load_pem_roots(path: str) -> list[x509.Certificate]:
    """`path` may be a single PEM file with one or more concatenated certs,
    or a directory of .pem files."""
    pem_blobs: list[bytes] = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.endswith((".pem", ".crt")):
                with open(os.path.join(path, name), "rb") as f:
                    pem_blobs.append(f.read())
    else:
        with open(path, "rb") as f:
            pem_blobs.append(f.read())

    roots: list[x509.Certificate] = []
    for blob in pem_blobs:
        for cert_pem in _split_pem_certs(blob):
            roots.append(x509.load_pem_x509_certificate(cert_pem))
    return roots


def _split_pem_certs(blob: bytes) -> list[bytes]:
    marker_begin, marker_end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    certs = []
    start = 0
    while True:
        begin = blob.find(marker_begin, start)
        if begin == -1:
            break
        end = blob.find(marker_end, begin)
        if end == -1:
            break
        end += len(marker_end)
        certs.append(blob[begin:end])
        start = end
    return certs


def load_config() -> Config:
    enabled_platforms = frozenset(
        value.strip() for value in os.environ.get("COUNTERSIGN_ENABLED_PLATFORMS", "android,ios").split(",")
        if value.strip()
    )
    if not enabled_platforms or enabled_platforms - {"android", "ios"}:
        raise RuntimeError("COUNTERSIGN_ENABLED_PLATFORMS must contain android, ios, or both")
    android_enabled = "android" in enabled_platforms
    ios_enabled = "ios" in enabled_platforms
    dev_mode = os.environ.get("COUNTERSIGN_DEV_MODE") == "1"
    # Explicit second opt-in, on top of dev_mode, so dev_mode alone (e.g. to
    # use FakeIntegrityVerifier) doesn't silently also disable real
    # attestation checking. Never available outside dev_mode. Intended for
    # tests that exercise the approval protocol without needing a real
    # (or realistically-shaped) device attestation cert -- see
    # tests/test_protocol.py.
    skip_attestation = dev_mode and os.environ.get("COUNTERSIGN_SKIP_ATTESTATION") == "1"
    # Isolated test harness / Android simulation escape hatch only. Normal
    # debug and release app builds still request real Play Integrity evidence.
    skip_integrity = dev_mode and os.environ.get("COUNTERSIGN_SKIP_INTEGRITY") == "1"

    db_path = os.environ.get("COUNTERSIGN_DB_PATH", "countersign.db")
    device_api_token = os.environ.get("COUNTERSIGN_API_TOKEN", "")
    administrator_api_token = os.environ.get("COUNTERSIGN_ADMIN_API_TOKEN", "")
    if dev_mode:
        device_api_token = device_api_token or "development-device-token"
        administrator_api_token = administrator_api_token or "development-admin-token"
    elif not device_api_token or not administrator_api_token:
        raise RuntimeError(
            "COUNTERSIGN_API_TOKEN and COUNTERSIGN_ADMIN_API_TOKEN must be set outside dev mode"
        )

    expected_package_name = os.environ.get("COUNTERSIGN_PACKAGE_NAME", "")
    expected_cert_sha256 = os.environ.get("COUNTERSIGN_APP_CERT_SHA256", "")
    if android_enabled and not dev_mode and (not expected_package_name or not expected_cert_sha256):
        raise RuntimeError(
            "COUNTERSIGN_PACKAGE_NAME and COUNTERSIGN_APP_CERT_SHA256 must be set "
            "unless COUNTERSIGN_DEV_MODE=1"
        )
    expected_package_name = expected_package_name or "com.example.countersign"

    roots_path = os.environ.get("COUNTERSIGN_ATTESTATION_ROOTS_PATH")
    if not android_enabled:
        trusted_roots = []
    elif roots_path:
        trusted_roots = _load_pem_roots(roots_path)
    elif dev_mode:
        trusted_roots = []
    else:
        raise RuntimeError("COUNTERSIGN_ATTESTATION_ROOTS_PATH must be set unless COUNTERSIGN_DEV_MODE=1")
    if android_enabled and not dev_mode and not trusted_roots:
        raise RuntimeError("COUNTERSIGN_ATTESTATION_ROOTS_PATH contains no trusted certificates")

    min_security_level = int(
        os.environ.get(
            "COUNTERSIGN_MIN_SECURITY_LEVEL",
            str(SecurityLevel.TRUSTED_ENVIRONMENT),
        )
    )

    if not android_enabled:
        # Disabled platforms get no verifier, rather than a fake or permissive
        # substitute. API guards reject their operations before any mutation.
        integrity_verifier: IntegrityVerifier | None = None
    elif dev_mode and "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ:
        integrity_verifier = FakeIntegrityVerifier()
    else:
        if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            raise RuntimeError("GOOGLE_APPLICATION_CREDENTIALS must be set when Android is enabled outside dev mode")
        integrity_verifier = PlayIntegrityVerifier(
            expected_package_name, os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
        )

    allowed_device_integrity = frozenset(
        value.strip()
        for value in os.environ.get("COUNTERSIGN_ALLOWED_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY").split(",")
        if value.strip()
    )
    if not allowed_device_integrity or allowed_device_integrity - {"MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"}:
        raise RuntimeError(
            "COUNTERSIGN_ALLOWED_DEVICE_INTEGRITY must list MEETS_STRONG_INTEGRITY, MEETS_DEVICE_INTEGRITY, or both"
        )

    integrity_policy = IntegrityPolicy(
        expected_package_name=expected_package_name,
        expected_certificate_sha256=expected_cert_sha256,
        allowed_device_integrity=allowed_device_integrity,
    )

    ios_app_id = os.environ.get("COUNTERSIGN_IOS_APP_ID", "")
    ios_bundle_version = os.environ.get("COUNTERSIGN_IOS_BUNDLE_VERSION", "")
    if ios_enabled and not dev_mode and (not ios_app_id or not ios_bundle_version):
        raise RuntimeError(
            "COUNTERSIGN_IOS_APP_ID and COUNTERSIGN_IOS_BUNDLE_VERSION must be set "
            "unless COUNTERSIGN_DEV_MODE=1"
        )

    ios_roots_path = os.environ.get("COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH")
    if not ios_enabled:
        ios_trusted_roots = []
    elif ios_roots_path:
        ios_trusted_roots = _load_pem_roots(ios_roots_path)
    elif dev_mode:
        ios_trusted_roots = []
    else:
        raise RuntimeError("COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH must be set unless COUNTERSIGN_DEV_MODE=1")
    if ios_enabled and not dev_mode and not ios_trusted_roots:
        raise RuntimeError("COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH contains no trusted certificates")

    ios_attestation_environment = os.environ.get("COUNTERSIGN_IOS_ATTESTATION_ENVIRONMENT", "development")
    if ios_enabled and ios_attestation_environment not in {"development", "production"}:
        raise RuntimeError("COUNTERSIGN_IOS_ATTESTATION_ENVIRONMENT must be development or production")

    return Config(
        enabled_platforms=enabled_platforms,
        dev_mode=dev_mode,
        skip_attestation=skip_attestation,
        skip_integrity=skip_integrity,
        db_path=db_path,
        device_api_token=device_api_token,
        administrator_api_token=administrator_api_token,
        expected_package_name=expected_package_name,
        trusted_attestation_roots=trusted_roots,
        min_attestation_security_level=min_security_level,
        integrity_verifier=integrity_verifier,
        integrity_policy=integrity_policy,
        ios_app_id=ios_app_id,
        ios_attestation_environment=ios_attestation_environment,
        ios_trusted_attestation_roots=ios_trusted_roots,
        ios_bundle_version=ios_bundle_version,
    )
