"""Device enrollment and signed approval API. See docs/SECURITY.md for limits."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import logging
import secrets

from pathlib import Path

from cryptography import x509
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from . import attestation, crypto
from .attestation import ios as ios_attestation
from .attestation.base import AttestationError
from .config import Config, load_config
from .integrity import IntegrityVerifier, check_verdict, compute_request_hash
from .models import (
    BeginEnrollmentRequest,
    BeginEnrollmentResponse,
    CompleteApprovalRequest,
    CompleteApprovalResponse,
    CompleteEnrollmentRequest,
    CompleteEnrollmentResponse,
    CreateApprovalRequest,
    CreateApprovalResponse,
    EnrolledDevice,
    PendingApproval,
    PendingApprovalView,
    ApprovalProof,
    ApprovalStatus,
    ApproveDeviceRequest,
    ApproveDeviceResponse,
    PendingDeviceView,
    SubmitIosAttestationRequest,
    SubmitIosAttestationResponse,
    SubmitIosBindingRequest,
)
from .store import Store

app = FastAPI(title="Countersign")
logger = logging.getLogger("countersign.service")
app.state.config = load_config()
app.state.store = Store(app.state.config.db_path)

def _bearer_token(authorization: str | None) -> str:
    prefix = "Bearer "
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(401, "Bearer authentication required", headers={"WWW-Authenticate": "Bearer"})
    return authorization[len(prefix):]


def authenticate_device(authorization: str | None = Header(default=None)) -> None:
    if not hmac.compare_digest(_bearer_token(authorization), app.state.config.device_api_token):
        raise HTTPException(401, "Invalid device credential", headers={"WWW-Authenticate": "Bearer"})


def authenticate_administrator(authorization: str | None = Header(default=None)) -> None:
    if not hmac.compare_digest(_bearer_token(authorization), app.state.config.administrator_api_token):
        raise HTTPException(401, "Invalid administrator credential", headers={"WWW-Authenticate": "Bearer"})


router = APIRouter(prefix="/v1", dependencies=[Depends(authenticate_device)])
admin_router = APIRouter(prefix="/v1", dependencies=[Depends(authenticate_administrator)])


def _require_platform_enabled(platform: str) -> None:
    if platform not in app.state.config.enabled_platforms:
        raise HTTPException(503, f"{platform} is not enabled on this service")


def _android_integrity_verifier() -> IntegrityVerifier:
    _require_platform_enabled("android")
    verifier = app.state.config.integrity_verifier
    if verifier is None:
        raise HTTPException(503, "Android integrity verification is unavailable")
    return verifier


@app.get("/health")
def health() -> dict:
    config: Config = app.state.config
    return {
        "status": "ok",
        "enabled_platforms": sorted(config.enabled_platforms),
        "verification_mode": "development" if config.dev_mode else "strict",
    }


def _decode_urlsafe_b64(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value)
    except ValueError:
        return b""


def _decode_b64(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, f"invalid base64 in {field_name}: {exc}") from None


@router.post("/enroll/begin", response_model=BeginEnrollmentResponse)
def begin_enrollment(body: BeginEnrollmentRequest) -> BeginEnrollmentResponse:
    _require_platform_enabled(body.platform)
    store: Store = app.state.store
    enrollment = store.begin_enrollment(body.platform)
    return BeginEnrollmentResponse(
        enrollment_id=enrollment.enrollment_id,
        challenge_b64=base64.b64encode(enrollment.challenge).decode("ascii"),
        platform=enrollment.platform,
    )


@router.post("/enroll/{enrollment_id}/complete", response_model=CompleteEnrollmentResponse)
async def complete_enrollment(enrollment_id: str, body: CompleteEnrollmentRequest) -> CompleteEnrollmentResponse:
    """Android only -- see /enroll/{enrollment_id}/attestation and
    .../binding for iOS's two-round equivalent."""
    _require_platform_enabled("android")
    store: Store = app.state.store
    config: Config = app.state.config

    enrollment = store.get_enrollment(enrollment_id)
    if enrollment is None:
        raise HTTPException(404, "unknown or already-completed enrollment_id")
    if enrollment.platform != "android":
        raise HTTPException(400, "this enrollment_id was started for a different platform")

    if not body.attestation_chain_der_b64:
        raise HTTPException(400, "attestation_chain_der_b64 must not be empty")
    # cryptography's X.509 loader rejects an explicit NULL in the ECDSA
    # AlgorithmIdentifier parameters. That affects Google's ~2019 example
    # certificates (see tests/fixtures/attestation/README.md), not the chains
    # produced by current phones.
    try:
        chain = [
            x509.load_der_x509_certificate(_decode_b64(c, "attestation_chain_der_b64"))
            for c in body.attestation_chain_der_b64
        ]
    except ValueError as exc:
        logger.warning("android enrollment %s: could not parse certificate chain: %s", enrollment_id, exc)
        raise HTTPException(400, f"could not parse attestation certificate chain: {exc}") from None
    leaf = chain[0]

    reasons: list[str] = []

    if config.skip_attestation:
        pass  # dev-mode-only escape hatch -- see Config.skip_attestation.
    else:
        if config.trusted_attestation_roots:
            chain_ok, chain_reason = attestation.verify_chain(chain, config.trusted_attestation_roots)
            if not chain_ok:
                reasons.append(f"certificate chain: {chain_reason}")
        elif not config.dev_mode:
            raise HTTPException(500, "no trusted attestation roots configured")
        # dev_mode with no configured roots: chain trust intentionally skipped.

        policy_result = attestation.check_policy_for_cert(
            leaf,
            expected_challenge=enrollment.challenge,
            expected_package_name=config.integrity_policy.expected_package_name,
            expected_certificate_sha256=_decode_urlsafe_b64(config.integrity_policy.expected_certificate_sha256),
            min_security_level=config.min_attestation_security_level,
        )
        if not policy_result.ok:
            reasons.extend(f"key attestation: {r}" for r in policy_result.reasons)

    verdict = None
    if config.skip_integrity:
        pass  # dev-mode-only escape hatch -- see Config.skip_integrity.
    else:
        verdict = await _android_integrity_verifier().verify_token(body.integrity_token)
        expected_request_hash = compute_request_hash(base64.b64encode(enrollment.challenge).decode("ascii"))
        integrity_ok, integrity_reasons = check_verdict(
            verdict, expected_request_hash=expected_request_hash, policy=config.integrity_policy
        )
        if not integrity_ok:
            reasons.extend(f"integrity: {r}" for r in integrity_reasons)

    if reasons:
        logger.warning("android enrollment %s rejected: %s", enrollment_id, reasons)
        store.consume_enrollment(enrollment_id)
        raise HTTPException(400, {"reasons": reasons})

    public_key_pem = crypto.public_key_to_pem(leaf.public_key())
    device_id = hashlib.sha256(public_key_pem.encode("ascii")).hexdigest()
    store.add_device(
        EnrolledDevice(
            device_id=device_id,
            platform="android",
            public_key_pem=public_key_pem,
            enrolled_at=dt.datetime.now(dt.timezone.utc),
            package_name=verdict.package_name or "" if verdict else "",
            certificate_sha256=next(iter(verdict.certificate_sha256_digests), "") if verdict else "",
            attestation_chain_der_b64=body.attestation_chain_der_b64,
        )
    )
    store.consume_enrollment(enrollment_id)
    return CompleteEnrollmentResponse(device_id=device_id, status="pending_manual_approval")


@router.post("/enroll/{enrollment_id}/attestation", response_model=SubmitIosAttestationResponse)
def submit_ios_attestation(enrollment_id: str, body: SubmitIosAttestationRequest) -> SubmitIosAttestationResponse:
    """iOS round 1 of 2. App Attest's attestKey call is rate-limited by
    Apple and only usable once per key, so unlike Android's one-shot
    enrollment, iOS needs a second round (.../binding) to register the
    separate confirmation key that signs approvals. See docs/SECURITY.md."""
    _require_platform_enabled("ios")
    store: Store = app.state.store
    config: Config = app.state.config

    enrollment = store.get_enrollment(enrollment_id)
    if enrollment is None:
        raise HTTPException(404, "unknown or already-completed enrollment_id")
    if enrollment.platform != "ios":
        raise HTTPException(400, "this enrollment_id was started for a different platform")
    if enrollment.ios_round != "awaiting_attestation":
        raise HTTPException(409, "enrollment is not awaiting an attestation")

    attestation_bytes = _decode_b64(body.attestation_b64, "attestation_b64")

    if config.skip_attestation:
        attestation_public_key_der, receipt = b"", b""  # dev-mode-only escape hatch
    else:
        try:
            attestation_public_key_der, receipt = ios_attestation.verify_attestation(
                attestation_bytes,
                body.key_id,
                enrollment.challenge,
                config.ios_app_id,
                config.ios_attestation_environment,
                config.ios_trusted_attestation_roots,
                config.ios_bundle_version,
            )
        except AttestationError as exc:
            logger.warning("iOS App Attest verification failed for enrollment %s: %s", enrollment_id, exc)
            store.consume_enrollment(enrollment_id)
            raise HTTPException(400, {"reasons": [f"app attest: {exc}"]}) from None

    binding_challenge = secrets.token_bytes(32)
    store.advance_ios_enrollment(
        enrollment_id,
        key_id=body.key_id,
        attestation_public_key_der=attestation_public_key_der,
        receipt=receipt,
        binding_challenge=binding_challenge,
    )
    return SubmitIosAttestationResponse(binding_challenge_b64=base64.b64encode(binding_challenge).decode("ascii"))


@router.post("/enroll/{enrollment_id}/binding", response_model=CompleteEnrollmentResponse)
def submit_ios_binding(enrollment_id: str, body: SubmitIosBindingRequest) -> CompleteEnrollmentResponse:
    """iOS round 2 of 2. Success records technical verification, but an
    administrator must approve this specific device before it becomes active."""
    _require_platform_enabled("ios")
    store: Store = app.state.store
    config: Config = app.state.config

    enrollment = store.get_enrollment(enrollment_id)
    if enrollment is None:
        raise HTTPException(404, "unknown or already-completed enrollment_id")
    if enrollment.platform != "ios":
        raise HTTPException(400, "this enrollment_id was started for a different platform")
    if enrollment.ios_round != "awaiting_binding":
        raise HTTPException(409, "enrollment is not awaiting binding")

    confirmation_public_key_der = _decode_b64(
        body.confirmation_public_key_der_b64, "confirmation_public_key_der_b64"
    )
    try:
        confirmation_public_key_pem = crypto.der_public_key_to_pem(confirmation_public_key_der)
    except ValueError as exc:
        raise HTTPException(400, f"invalid confirmation_public_key_der_b64: {exc}") from None

    # The payload both the confirmation key's proof-of-possession signature
    # and the App Attest assertion must cover -- derived server-side from
    # pieces we already know, rather than trusting an opaque client-supplied
    # blob, so there's nothing here for a client to tamper with.
    payload = confirmation_public_key_der + enrollment.ios_binding_challenge

    reasons: list[str] = []
    if not crypto.verify_signature_bytes(confirmation_public_key_pem, payload, body.confirmation_signature_b64):
        reasons.append("confirmation key did not sign the binding payload")

    assertion_counter = 0
    if config.skip_attestation:
        pass  # dev-mode-only escape hatch -- see Config.skip_attestation.
    else:
        try:
            assertion_bytes = _decode_b64(body.assertion_b64, "assertion_b64")
            assertion_counter = ios_attestation.verify_assertion(
                assertion_bytes,
                payload,
                enrollment.ios_attestation_public_key_der,
                config.ios_app_id,
                0,
                config.ios_bundle_version,
                config.ios_attestation_environment,
            )
        except AttestationError as exc:
            logger.warning("iOS App Attest assertion failed for enrollment %s: %s", enrollment_id, exc)
            reasons.append(f"app attest assertion: {exc}")

    if reasons:
        store.consume_enrollment(enrollment_id)
        raise HTTPException(400, {"reasons": reasons})

    device_id = hashlib.sha256(confirmation_public_key_pem.encode("ascii")).hexdigest()
    store.add_device(
        EnrolledDevice(
            device_id=device_id,
            platform="ios",
            public_key_pem=confirmation_public_key_pem,
            enrolled_at=dt.datetime.now(dt.timezone.utc),
            ios_key_id=enrollment.ios_key_id,
            ios_receipt_b64=base64.b64encode(enrollment.ios_receipt).decode("ascii")
            if enrollment.ios_receipt
            else None,
            ios_assertion_counter=assertion_counter,
        )
    )
    store.consume_enrollment(enrollment_id)
    return CompleteEnrollmentResponse(device_id=device_id, status="pending_manual_approval")


@router.get("/enrollments/{device_id}")
def enrollment_status(device_id: str) -> dict[str, str]:
    store: Store = app.state.store
    device = store.get_device(device_id, include_pending=True)
    if device is None:
        raise HTTPException(404, "unknown device")
    _require_platform_enabled(device.platform)
    return {"device_id": device.device_id, "status": device.status}


_DEMO_HTML_PATH = Path(__file__).parent / "static" / "demo.html"


@app.get("/v1/demo", response_class=HTMLResponse)
def demo_page() -> str:
    """Dev-mode-only demo frontend: enroll -> send request -> approve.
    Lists device_ids in the clear and has no caller auth on creating
    approvals -- fine for a local demo, not how a real deployment works.
    """
    config: Config = app.state.config
    if not config.dev_mode:
        raise HTTPException(404)
    return _DEMO_HTML_PATH.read_text()


@admin_router.get("/devices")
def list_devices() -> list[dict]:
    """Dev convenience only: lets you look up a device_id without having to
    transcribe it off the phone screen. Not gated by skip_attestation/
    skip_integrity -- just dev_mode, since this isn't a security bypass, it's
    read access to enrollment records that would be sensitive in a real
    deployment.
    """
    config: Config = app.state.config
    if not config.dev_mode:
        raise HTTPException(404)
    store: Store = app.state.store
    return [
        {
            "device_id": d.device_id,
            "platform": d.platform,
            "package_name": d.package_name,
            "enrolled_at": d.enrolled_at.isoformat(),
            "status": d.status,
        }
        for d in store.list_devices(include_pending=True)
    ]


@admin_router.get("/admin/enrollments/pending", response_model=list[PendingDeviceView])
def list_pending_enrollments() -> list[PendingDeviceView]:
    return [
        PendingDeviceView(
            device_id=device.device_id,
            platform=device.platform,
            technical_verified_at=device.enrolled_at,
        )
        for device in app.state.store.list_devices(include_pending=True)
        if device.status == "pending_manual_approval"
    ]


@admin_router.post("/admin/enrollments/{device_id}/approve", response_model=ApproveDeviceResponse)
def approve_enrollment(device_id: str, body: ApproveDeviceRequest) -> ApproveDeviceResponse:
    pending_device = app.state.store.get_device(device_id, include_pending=True)
    if pending_device is not None:
        _require_platform_enabled(pending_device.platform)
    device = app.state.store.approve_device(device_id, body.administrator)
    if device is None:
        raise HTTPException(409, "Enrollment is unknown or is not pending manual approval")
    return ApproveDeviceResponse(
        device_id=device.device_id,
        approved_at=device.approved_at,
        approved_by=device.approved_by,
    )


@admin_router.get("/admin/approvals/{ref}", response_model=PendingApprovalView)
def get_approval_for_administrator(ref: str) -> PendingApprovalView:
    approval = app.state.store.get_approval(ref)
    if approval is None:
        raise HTTPException(404, "unknown approval ref")
    approval = _maybe_expire(approval, app.state.store)
    return PendingApprovalView(
        ref=approval.ref,
        message=approval.rendered_message,
        status=approval.status,
        expires_at=approval.expires_at,
    )


@admin_router.get("/admin/approvals/{ref}/proof", response_model=ApprovalProof)
def get_approval_proof(ref: str) -> ApprovalProof:
    store: Store = app.state.store
    approval = store.get_approval(ref)
    if approval is None or approval.status != ApprovalStatus.APPROVED or approval.signature_b64 is None:
        raise HTTPException(404, "no approved request with this ref")
    device = store.get_device(approval.device_id, include_pending=True)
    if device is None:
        raise HTTPException(500, "approval references a device that is no longer enrolled")
    return ApprovalProof(
        ref=approval.ref,
        platform=device.platform,
        message=approval.rendered_message,
        signature_b64=approval.signature_b64,
        public_key_pem=device.public_key_pem,
        attestation_chain_der_b64=device.attestation_chain_der_b64,
    )


@admin_router.post("/approvals", response_model=CreateApprovalResponse)
def create_approval(body: CreateApprovalRequest) -> CreateApprovalResponse:
    store: Store = app.state.store
    device = store.get_device(body.device_id)
    if device is None:
        raise HTTPException(404, "device is not enrolled")
    _require_platform_enabled(device.platform)

    ref = secrets.token_hex(4).upper()
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = now + dt.timedelta(seconds=body.ttl_seconds)
    message = crypto.render_approval_message(ref, body.text, expires_at)

    store.create_approval(
        PendingApproval(
            ref=ref,
            device_id=body.device_id,
            request_text=body.text,
            rendered_message=message,
            created_at=now,
            expires_at=expires_at,
        )
    )
    return CreateApprovalResponse(ref=ref, message=message, expires_at=expires_at)


def _maybe_expire(approval: PendingApproval, store: Store) -> PendingApproval:
    # Reads can expire a request, so check platform availability before even
    # that state transition. Disabled platforms retain their stored evidence.
    device = store.get_device(approval.device_id, include_pending=True)
    if device is None:
        raise HTTPException(500, "approval references a device that is no longer enrolled")
    _require_platform_enabled(device.platform)
    if approval.status == ApprovalStatus.PENDING and dt.datetime.now(dt.timezone.utc) > approval.expires_at:
        approval.status = ApprovalStatus.EXPIRED
        store.update_approval(approval)
    return approval


@router.get("/approvals", response_model=list[PendingApprovalView])
def list_pending_approvals(device_id: str) -> list[PendingApprovalView]:
    store: Store = app.state.store
    device = store.get_device(device_id)
    if device is None:
        raise HTTPException(404, "device is not enrolled")
    _require_platform_enabled(device.platform)
    views = []
    for approval in store.list_approvals_for_device(device_id):
        approval = _maybe_expire(approval, store)
        if approval.status == ApprovalStatus.PENDING:
            views.append(
                PendingApprovalView(
                    ref=approval.ref,
                    message=approval.rendered_message,
                    status=approval.status,
                    expires_at=approval.expires_at,
                )
            )
    return views


@router.get("/approvals/{ref}", response_model=PendingApprovalView)
def get_approval(ref: str) -> PendingApprovalView:
    store: Store = app.state.store
    approval = store.get_approval(ref)
    if approval is None:
        raise HTTPException(404, "unknown approval ref")
    approval = _maybe_expire(approval, store)
    return PendingApprovalView(
        ref=approval.ref, message=approval.rendered_message, status=approval.status, expires_at=approval.expires_at
    )


@router.post("/approvals/{ref}/decline", response_model=CompleteApprovalResponse)
def decline_approval(ref: str) -> CompleteApprovalResponse:
    """The human said no. No signature or integrity proof required -- see
    ApprovalStatus.DECLINED's docstring for why that's fine here."""
    store: Store = app.state.store
    approval = store.get_approval(ref)
    if approval is None:
        raise HTTPException(404, "unknown approval ref")
    approval = _maybe_expire(approval, store)
    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(409, {"status": approval.status.value, "reasons": approval.rejection_reasons})

    approval.status = ApprovalStatus.DECLINED
    approval.completed_at = dt.datetime.now(dt.timezone.utc)
    if not store.consume_pending_approval(approval):
        current = store.get_approval(ref)
        raise HTTPException(409, {"status": current.status.value if current else "unknown"})
    return CompleteApprovalResponse(ref=approval.ref, status=approval.status, reasons=[])


@router.post("/approvals/{ref}/complete", response_model=CompleteApprovalResponse)
async def complete_approval(ref: str, body: CompleteApprovalRequest) -> CompleteApprovalResponse:
    store: Store = app.state.store
    config: Config = app.state.config

    approval = store.get_approval(ref)
    if approval is None:
        raise HTTPException(404, "unknown approval ref")
    approval = _maybe_expire(approval, store)
    if approval.status != ApprovalStatus.PENDING:
        raise HTTPException(409, {"status": approval.status.value, "reasons": approval.rejection_reasons})

    device = store.get_device(approval.device_id)
    if device is None:
        raise HTTPException(500, "approval references a device that is no longer enrolled")

    reasons: list[str] = []
    if not crypto.verify_signature(device.public_key_pem, approval.rendered_message, body.signature_b64):
        reasons.append("signature does not verify against the enrolled device key")

    if device.platform == "android":
        if body.integrity_token is None:
            reasons.append("integrity_token is required for android devices")
        elif config.skip_integrity:
            pass  # dev-mode-only escape hatch -- see Config.skip_integrity.
        else:
            verdict = await _android_integrity_verifier().verify_token(body.integrity_token)
            expected_request_hash = compute_request_hash(approval.rendered_message)
            integrity_ok, integrity_reasons = check_verdict(
                verdict, expected_request_hash=expected_request_hash, policy=config.integrity_policy
            )
            if not integrity_ok:
                reasons.extend(integrity_reasons)
    else:
        # This protocol uses App Attest only during iOS enrollment. Later
        # approvals use the bound confirmation key, with no integrity token.
        # Reject an unexpected token; see docs/SECURITY.md for this limitation.
        if body.integrity_token is not None:
            reasons.append("integrity_token must not be sent for ios devices")

    approval.status = ApprovalStatus.APPROVED if not reasons else ApprovalStatus.REJECTED
    approval.signature_b64 = body.signature_b64
    approval.completed_at = dt.datetime.now(dt.timezone.utc)
    approval.rejection_reasons = reasons
    if not store.consume_pending_approval(approval):
        current = store.get_approval(ref)
        raise HTTPException(
            409,
            {
                "status": current.status.value if current else "unknown",
                "reasons": current.rejection_reasons if current else [],
            },
        )

    return CompleteApprovalResponse(ref=approval.ref, status=approval.status, reasons=reasons)


app.include_router(router)
app.include_router(admin_router)
