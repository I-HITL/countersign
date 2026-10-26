"""Android attestation names re-exported; the iOS verifier is imported explicitly:
`from .attestation import ios as ios_attestation`."""

from __future__ import annotations

from .android import (
    AUTH_TYPE_BIOMETRIC,
    AUTH_TYPE_PASSWORD,
    VERIFIED_BOOT_VERIFIED,
    AttestationPolicyResult,
    AuthorizationList,
    DerParseError,
    KeyDescription,
    SecurityLevel,
    check_policy,
    check_policy_for_cert,
    extract_key_description,
    parse_key_description,
    verify_chain,
)
from .base import AttestationError

__all__ = [
    "AUTH_TYPE_BIOMETRIC",
    "AUTH_TYPE_PASSWORD",
    "VERIFIED_BOOT_VERIFIED",
    "AttestationError",
    "AttestationPolicyResult",
    "AuthorizationList",
    "DerParseError",
    "KeyDescription",
    "SecurityLevel",
    "check_policy",
    "check_policy_for_cert",
    "extract_key_description",
    "parse_key_description",
    "verify_chain",
]
