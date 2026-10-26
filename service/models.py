from __future__ import annotations

import dataclasses
import datetime as dt
import enum
from typing import Literal

from pydantic import BaseModel, Field

# The two platforms' attestation proofs are genuinely different shapes
# (Android: a one-shot Key Attestation cert chain; iOS: a two-round App
# Attest attestation-then-binding-assertion) -- `platform` is how a single
# shared enrollment/approval protocol tells them apart, not something that
# gets abstracted away.
Platform = Literal["android", "ios"]


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"  # signature/integrity verification failed
    DECLINED = "declined"  # device requested cancellation; no signature required
    EXPIRED = "expired"


# --- internal store records (not pydantic -- these never cross the wire directly) ---


@dataclasses.dataclass
class PendingEnrollment:
    enrollment_id: str
    platform: Platform
    challenge: bytes
    created_at: dt.datetime
    # --- iOS-only multi-round state; always None for platform="android",
    # since Android's attestation is a one-shot cert chain with no
    # analogous second round. ---
    ios_round: Literal["awaiting_attestation", "awaiting_binding"] | None = None
    ios_key_id: str | None = None
    ios_attestation_public_key_der: bytes | None = None
    ios_receipt: bytes | None = None
    ios_binding_challenge: bytes | None = None


@dataclasses.dataclass
class EnrolledDevice:
    device_id: str
    platform: Platform
    public_key_pem: str
    enrolled_at: dt.datetime
    status: Literal["pending_manual_approval", "approved"] = "pending_manual_approval"
    approved_at: dt.datetime | None = None
    approved_by: str | None = None
    # --- Android-only; None for iOS ---
    package_name: str | None = None
    certificate_sha256: str | None = None
    # Leaf-first key attestation chain, kept so approvals can be verified by a third party.
    attestation_chain_der_b64: list[str] | None = None
    # iOS enrollment evidence; None for Android. The assertion counter is
    # recorded at binding only; approvals do not request further assertions.
    # See docs/SECURITY.md.
    ios_key_id: str | None = None
    ios_receipt_b64: str | None = None
    ios_assertion_counter: int | None = None


@dataclasses.dataclass
class PendingApproval:
    ref: str
    device_id: str
    request_text: str
    rendered_message: str
    created_at: dt.datetime
    expires_at: dt.datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    signature_b64: str | None = None
    completed_at: dt.datetime | None = None
    rejection_reasons: list[str] = dataclasses.field(default_factory=list)


# --- API schemas ---


class BeginEnrollmentRequest(BaseModel):
    platform: Platform


class BeginEnrollmentResponse(BaseModel):
    enrollment_id: str
    challenge_b64: str
    platform: Platform


class CompleteEnrollmentRequest(BaseModel):
    attestation_chain_der_b64: list[str] = Field(description="Leaf-first certificate chain.")
    integrity_token: str


class CompleteEnrollmentResponse(BaseModel):
    device_id: str
    status: Literal["pending_manual_approval", "approved"] = "pending_manual_approval"


class PendingDeviceView(BaseModel):
    device_id: str
    platform: Platform
    technical_verified_at: dt.datetime


class ApproveDeviceRequest(BaseModel):
    administrator: str = Field(min_length=1, max_length=200)


class ApproveDeviceResponse(BaseModel):
    device_id: str
    status: Literal["approved"] = "approved"
    approved_at: dt.datetime
    approved_by: str


class SubmitIosAttestationRequest(BaseModel):
    key_id: str
    attestation_b64: str


class SubmitIosAttestationResponse(BaseModel):
    binding_challenge_b64: str
    status: str = "awaiting_binding"


class SubmitIosBindingRequest(BaseModel):
    confirmation_public_key_der_b64: str = Field(
        description="The separate confirmation public key used for approval signatures, "
        "bound to the App Attest identity during enrollment. See docs/SECURITY.md."
    )
    confirmation_signature_b64: str = Field(
        description="Signed by the confirmation key over "
        "confirmation_public_key_der || binding_challenge -- proof the client "
        "holds that key's private half. The server reconstructs this payload "
        "itself rather than trusting a client-supplied blob."
    )
    assertion_b64: str = Field(description="The App Attest key's assertion over the same payload.")


class CreateApprovalRequest(BaseModel):
    device_id: str
    text: str
    ttl_seconds: int = 300


class CreateApprovalResponse(BaseModel):
    ref: str
    message: str
    expires_at: dt.datetime


class PendingApprovalView(BaseModel):
    ref: str
    message: str
    status: ApprovalStatus
    expires_at: dt.datetime


class CompleteApprovalRequest(BaseModel):
    signature_b64: str
    # Required for Android devices; forbidden for iOS devices in this protocol.
    integrity_token: str | None = None


class CompleteApprovalResponse(BaseModel):
    ref: str
    status: ApprovalStatus
    reasons: list[str] = []


class ApprovalProof(BaseModel):
    """Everything a third party needs to verify an approval: the signed message,
    the signature, and the enrolled key with the attestation chain that vouches
    for it. The chain is absent for iOS, whose evidence is not exported."""

    ref: str
    platform: Platform
    message: str
    signature_b64: str
    public_key_pem: str
    attestation_chain_der_b64: list[str] | None = None
