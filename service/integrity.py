"""Play Integrity API client and verdict policy checks.

Two implementations of `IntegrityVerifier`:
  - `PlayIntegrityVerifier`: calls Google's real decode endpoint. Needs a
    service account with Play Integrity access (GOOGLE_APPLICATION_CREDENTIALS)
    and requires the app to actually be registered in Play Console -- see
    README.md. Real network call, not used in tests.
  - `FakeIntegrityVerifier`: returns a canned verdict, no network. Used by
    tests and for local development before the Android app / Play Console
    registration exist.
"""

from __future__ import annotations

import abc
import base64
import dataclasses
import hashlib
import logging
import time

import httpx
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account

logger = logging.getLogger("countersign.service")

PLAY_INTEGRITY_SCOPE = "https://www.googleapis.com/auth/playintegrity"
DECODE_URL_TEMPLATE = "https://playintegrity.googleapis.com/v1/{package_name}:decodeIntegrityToken"


def compute_request_hash(message: str) -> str:
    """The value we ask the device to bind into its integrity token request,
    and that we then check comes back unmodified in the verdict. Ties a
    specific integrity verdict to a specific approval message.
    """
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


@dataclasses.dataclass
class IntegrityVerdict:
    device_integrity_labels: list[str]
    app_recognition_verdict: str  # PLAY_RECOGNIZED / UNRECOGNIZED_VERSION / UNEVALUATED
    package_name: str | None
    certificate_sha256_digests: list[str]
    request_hash: str | None
    timestamp_millis: int | None
    raw: dict


class IntegrityVerifier(abc.ABC):
    @abc.abstractmethod
    async def verify_token(self, token: str) -> IntegrityVerdict: ...


class PlayIntegrityVerifier(IntegrityVerifier):
    def __init__(self, package_name: str, service_account_file: str):
        self._package_name = package_name
        self._credentials = service_account.Credentials.from_service_account_file(
            service_account_file, scopes=[PLAY_INTEGRITY_SCOPE]
        )

    def _access_token(self) -> str:
        if not self._credentials.valid:
            self._credentials.refresh(GoogleAuthRequest())
        return self._credentials.token

    async def verify_token(self, token: str) -> IntegrityVerdict:
        url = DECODE_URL_TEMPLATE.format(package_name=self._package_name)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {self._access_token()}"},
                json={"integrityToken": token},
                timeout=10.0,
            )
        response.raise_for_status()
        payload = response.json().get("tokenPayloadExternal", {})
        return _parse_verdict_payload(payload)


class FakeIntegrityVerifier(IntegrityVerifier):
    """Returns a preconfigured verdict per token, for tests / dev mode.

    Register verdicts with `set_verdict(token, verdict)`; unregistered
    tokens raise, so tests are explicit about what they're exercising.
    """

    def __init__(self):
        self._verdicts: dict[str, IntegrityVerdict] = {}

    def set_verdict(self, token: str, verdict: IntegrityVerdict) -> None:
        self._verdicts[token] = verdict

    async def verify_token(self, token: str) -> IntegrityVerdict:
        if token not in self._verdicts:
            raise ValueError(f"FakeIntegrityVerifier: no verdict registered for token {token!r}")
        return self._verdicts[token]


def make_fake_verdict(
    *,
    device_integrity_labels: list[str] | None = None,
    app_recognition_verdict: str = "PLAY_RECOGNIZED",
    package_name: str = "com.example.countersign",
    certificate_sha256_digests: list[str] | None = None,
    request_hash: str | None = None,
    timestamp_millis: int | None = None,
) -> IntegrityVerdict:
    """Convenience builder for tests."""
    return IntegrityVerdict(
        device_integrity_labels=device_integrity_labels
        if device_integrity_labels is not None
        else ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"],
        app_recognition_verdict=app_recognition_verdict,
        package_name=package_name,
        certificate_sha256_digests=certificate_sha256_digests or ["fake-cert-digest"],
        request_hash=request_hash,
        timestamp_millis=timestamp_millis if timestamp_millis is not None else int(time.time() * 1000),
        raw={},
    )


def _parse_verdict_payload(payload: dict) -> IntegrityVerdict:
    device_integrity = payload.get("deviceIntegrity", {})
    app_integrity = payload.get("appIntegrity", {})
    request_details = payload.get("requestDetails", {})
    return IntegrityVerdict(
        device_integrity_labels=device_integrity.get("deviceRecognitionVerdict", []),
        app_recognition_verdict=app_integrity.get("appRecognitionVerdict", "UNEVALUATED"),
        package_name=app_integrity.get("packageName") or request_details.get("requestPackageName"),
        certificate_sha256_digests=app_integrity.get("certificateSha256Digest", []),
        request_hash=request_details.get("requestHash"),
        timestamp_millis=(
            int(request_details["timestampMillis"]) if "timestampMillis" in request_details else None
        ),
        raw=payload,
    )


@dataclasses.dataclass
class IntegrityPolicy:
    expected_package_name: str
    expected_certificate_sha256: str
    # STRONG: certified device, locked bootloader, unmodified system image,
    # and a recent security patch.
    allowed_device_integrity: frozenset[str] = frozenset({"MEETS_STRONG_INTEGRITY"})
    max_age_seconds: int = 300


def check_verdict(
    verdict: IntegrityVerdict, *, expected_request_hash: str, policy: IntegrityPolicy
) -> tuple[bool, list[str]]:
    """Fails closed: any missing/mismatched field is a rejection."""
    reasons: list[str] = []

    if not set(verdict.device_integrity_labels) & policy.allowed_device_integrity:
        reasons.append(
            f"device_integrity_labels={verdict.device_integrity_labels} does not "
            f"intersect allowed set {sorted(policy.allowed_device_integrity)}"
        )
    if verdict.app_recognition_verdict != "PLAY_RECOGNIZED":
        reasons.append(f"app_recognition_verdict={verdict.app_recognition_verdict!r}, need PLAY_RECOGNIZED")
    if verdict.package_name != policy.expected_package_name:
        reasons.append(f"package_name={verdict.package_name!r}, expected {policy.expected_package_name!r}")
    # Google's URL-safe base64 may or may not carry '=' padding; compare without it.
    if policy.expected_certificate_sha256.rstrip("=") not in {
        digest.rstrip("=") for digest in verdict.certificate_sha256_digests
    }:
        reasons.append("expected certificate digest not present in certificateSha256Digests")
        logger.warning("certificateSha256Digests from Play Integrity: %s", verdict.certificate_sha256_digests)
    if verdict.request_hash != expected_request_hash:
        reasons.append("request_hash does not match the approval message we expected")
    if verdict.timestamp_millis is None:
        reasons.append("missing timestampMillis")
    else:
        age_seconds = time.time() - (verdict.timestamp_millis / 1000)
        if age_seconds > policy.max_age_seconds:
            reasons.append(f"integrity token is {age_seconds:.0f}s old, max is {policy.max_age_seconds}s")
        elif age_seconds < -30:
            reasons.append(f"integrity token timestamp is {-age_seconds:.0f}s in the future")

    return not reasons, reasons