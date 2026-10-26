"""Parses and validates Android Key Attestation certificate chains.

Schema reference: https://source.android.com/docs/security/features/keystore/attestation
(OID 1.3.6.1.4.1.11129.2.1.17, the "KeyDescription" extension).

    KeyDescription ::= SEQUENCE {
        attestationVersion         INTEGER,
        attestationSecurityLevel   SecurityLevel,   -- ENUMERATED
        keyMintVersion              INTEGER,
        keyMintSecurityLevel        SecurityLevel,
        attestationChallenge         OCTET_STRING,
        uniqueId                      OCTET_STRING,
        softwareEnforced               AuthorizationList,
        hardwareEnforced                AuthorizationList,
    }

AuthorizationList fields use explicit context tags. The parser extracts purpose
[1], userAuthType [504], noAuthRequired [503], origin [702], rootOfTrust [704]
and attestationApplicationId [709]. The policy checks the security levels,
challenge, key origin and purpose, per-use biometric authentication, verified
boot state, and the identity of the app that generated the key.
Certificate validation checks signatures, validity dates and CA constraints,
not revocation. See docs/SECURITY.md before deployment.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ENCODING_DER = Encoding.DER
_FORMAT_SUBJECT_PUBLIC_KEY_INFO = PublicFormat.SubjectPublicKeyInfo

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

# Context tags inside AuthorizationList we know how to look for (EXPLICIT).
TAG_PURPOSE = 1
TAG_NO_AUTH_REQUIRED = 503
TAG_USER_AUTH_TYPE = 504
TAG_ORIGIN = 702
TAG_ROOT_OF_TRUST = 704
TAG_ATTESTATION_APPLICATION_ID = 709

PURPOSE_SIGN = 2
ORIGIN_GENERATED = 0
VERIFIED_BOOT_VERIFIED = 0

# userAuthType bitmask (HardwareAuthenticatorType).
AUTH_TYPE_PASSWORD = 1
AUTH_TYPE_BIOMETRIC = 2


class SecurityLevel:
    SOFTWARE = 0
    TRUSTED_ENVIRONMENT = 1
    STRONG_BOX = 2

    _NAMES = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}

    @classmethod
    def name(cls, value: int) -> str:
        return cls._NAMES.get(value, f"Unknown({value})")


class DerParseError(ValueError):
    pass


@dataclasses.dataclass
class _Tlv:
    tag_class: int  # 0=universal, 1=application, 2=context, 3=private
    constructed: bool
    tag_number: int
    content: bytes


def _read_tlv(data: bytes, offset: int) -> tuple[_Tlv, int]:
    if offset >= len(data):
        raise DerParseError("unexpected end of data reading TLV tag")
    first = data[offset]
    tag_class = (first >> 6) & 0b11
    constructed = bool(first & 0b0010_0000)
    tag_number = first & 0b0001_1111
    pos = offset + 1
    if tag_number == 0x1F:
        # High tag number form: base-128 varint, MSB=1 means "more bytes follow".
        tag_number = 0
        while True:
            if pos >= len(data):
                raise DerParseError("unexpected end of data reading high tag number")
            b = data[pos]
            tag_number = (tag_number << 7) | (b & 0x7F)
            pos += 1
            if not (b & 0x80):
                break

    if pos >= len(data):
        raise DerParseError("unexpected end of data reading length")
    length_byte = data[pos]
    pos += 1
    if length_byte & 0x80:
        num_length_bytes = length_byte & 0x7F
        if num_length_bytes == 0:
            raise DerParseError("indefinite-length DER encoding is not supported")
        if pos + num_length_bytes > len(data):
            raise DerParseError("unexpected end of data reading long-form length")
        length = int.from_bytes(data[pos : pos + num_length_bytes], "big")
        pos += num_length_bytes
    else:
        length = length_byte

    if pos + length > len(data):
        raise DerParseError("TLV content runs past end of data")
    content = data[pos : pos + length]
    return _Tlv(tag_class, constructed, tag_number, content), pos + length


def _read_sequence(data: bytes) -> list[_Tlv]:
    """Reads consecutive top-level TLVs from a SEQUENCE's content bytes."""
    elements = []
    offset = 0
    while offset < len(data):
        tlv, offset = _read_tlv(data, offset)
        elements.append(tlv)
    return elements


def _parse_der_integer(content: bytes) -> int:
    if not content:
        raise DerParseError("empty INTEGER content")
    return int.from_bytes(content, "big", signed=True)


@dataclasses.dataclass
class AuthorizationList:
    purpose_raw: list[int] | None = None
    origin_raw: int | None = None
    user_auth_type_raw: int | None = None
    no_auth_required: bool = False
    device_locked: bool | None = None
    verified_boot_state: int | None = None
    app_package_names: list[str] | None = None
    app_signature_digests: list[bytes] | None = None


def _parse_root_of_trust(content: bytes, result: AuthorizationList) -> None:
    # RootOfTrust ::= SEQUENCE { verifiedBootKey, deviceLocked BOOLEAN,
    #                            verifiedBootState ENUMERATED, ... }
    fields = _read_sequence(_read_tlv(content, 0)[0].content)
    result.device_locked = fields[1].content != b"\x00"
    result.verified_boot_state = _parse_der_integer(fields[2].content)


def _parse_application_id(content: bytes, result: AuthorizationList) -> None:
    # The extension holds an OCTET STRING wrapping
    # AttestationApplicationId ::= SEQUENCE { SET OF AttestationPackageInfo
    # { packageName OCTET STRING, version INTEGER }, SET OF OCTET STRING }.
    octets, _ = _read_tlv(content, 0)
    package_infos, digests = _read_sequence(_read_tlv(octets.content, 0)[0].content)[:2]
    result.app_package_names = [
        _read_sequence(info.content)[0].content.decode("utf-8", "replace")
        for info in _read_sequence(package_infos.content)
    ]
    result.app_signature_digests = [digest.content for digest in _read_sequence(digests.content)]


def _parse_authorization_list(content: bytes) -> AuthorizationList:
    result = AuthorizationList()
    for tlv in _read_sequence(content):
        if tlv.tag_class != 2:  # only context-tagged fields are meaningful here
            continue
        if tlv.tag_number == TAG_PURPOSE:
            # EXPLICIT wraps a SET OF INTEGER.
            inner, _ = _read_tlv(tlv.content, 0)
            result.purpose_raw = [_parse_der_integer(item.content) for item in _read_sequence(inner.content)]
        elif tlv.tag_number == TAG_ORIGIN:
            inner, _ = _read_tlv(tlv.content, 0)
            result.origin_raw = _parse_der_integer(inner.content)
        elif tlv.tag_number == TAG_USER_AUTH_TYPE:
            # EXPLICIT wraps an INTEGER.
            inner, _ = _read_tlv(tlv.content, 0)
            result.user_auth_type_raw = _parse_der_integer(inner.content)
        elif tlv.tag_number == TAG_ROOT_OF_TRUST:
            _parse_root_of_trust(tlv.content, result)
        elif tlv.tag_number == TAG_ATTESTATION_APPLICATION_ID:
            _parse_application_id(tlv.content, result)
        elif tlv.tag_number == TAG_NO_AUTH_REQUIRED:
            result.no_auth_required = True
    return result


@dataclasses.dataclass
class KeyDescription:
    attestation_security_level: int
    keymint_security_level: int
    attestation_challenge: bytes
    # attestationApplicationId is reported in softwareEnforced; everything else
    # the policy reads is hardwareEnforced.
    software_enforced: AuthorizationList
    hardware_enforced: AuthorizationList


def parse_key_description(extension_der: bytes) -> KeyDescription:
    top, _ = _read_tlv(extension_der, 0)
    fields = _read_sequence(top.content)
    if len(fields) != 8:
        raise DerParseError(f"expected 8 KeyDescription fields, got {len(fields)}")
    _version, sec_level, _km_version, km_sec_level, challenge, _unique_id, sw_enforced, hw_enforced = fields
    return KeyDescription(
        attestation_security_level=_parse_der_integer(sec_level.content),
        keymint_security_level=_parse_der_integer(km_sec_level.content),
        attestation_challenge=challenge.content,
        software_enforced=_parse_authorization_list(sw_enforced.content),
        hardware_enforced=_parse_authorization_list(hw_enforced.content),
    )


def extract_key_description(cert: x509.Certificate) -> KeyDescription:
    ext = cert.extensions.get_extension_for_oid(KEY_DESCRIPTION_OID)
    der_bytes = ext.value.value if hasattr(ext.value, "value") else bytes(ext.value)
    return parse_key_description(der_bytes)


@dataclasses.dataclass
class AttestationPolicyResult:
    ok: bool
    reasons: list[str]
    key_description: KeyDescription | None


def check_policy_for_cert(
    cert: x509.Certificate,
    *,
    expected_challenge: bytes,
    expected_package_name: str,
    expected_certificate_sha256: bytes,
    min_security_level: int = SecurityLevel.TRUSTED_ENVIRONMENT,
) -> AttestationPolicyResult:
    """Convenience wrapper: extract + check in one call. See `check_policy`
    for the actual decision logic (kept separate and cert-free so it can be
    tested against a `KeyDescription` directly, without needing a certificate
    `cryptography.x509` can load -- see the note in tests/test_attestation.py
    about cert0.pem in our real-world fixtures).
    """
    try:
        kd = extract_key_description(cert)
    except (DerParseError, x509.ExtensionNotFound) as exc:
        return AttestationPolicyResult(ok=False, reasons=[f"could not parse KeyDescription: {exc}"], key_description=None)
    return check_policy(
        kd,
        expected_challenge=expected_challenge,
        expected_package_name=expected_package_name,
        expected_certificate_sha256=expected_certificate_sha256,
        min_security_level=min_security_level,
    )


def check_policy(
    kd: KeyDescription,
    *,
    expected_challenge: bytes,
    expected_package_name: str,
    expected_certificate_sha256: bytes,
    min_security_level: int = SecurityLevel.TRUSTED_ENVIRONMENT,
) -> AttestationPolicyResult:
    """Fails closed: the key must be hardware-generated for signing, require
    biometric authentication on every use, belong to the expected app, and
    come from a locked, verified-boot device."""
    reasons: list[str] = []
    hw = kd.hardware_enforced
    app = kd.software_enforced

    for label, level in (
        ("attestation_security_level", kd.attestation_security_level),
        ("keymint_security_level", kd.keymint_security_level),
    ):
        if level < min_security_level:
            reasons.append(
                f"{label}={SecurityLevel.name(level)}, need >= {SecurityLevel.name(min_security_level)}"
            )
    if kd.attestation_challenge != expected_challenge:
        reasons.append("attestation_challenge does not match the challenge we issued")
    if hw.origin_raw != ORIGIN_GENERATED:
        reasons.append(f"hardware_enforced.origin={hw.origin_raw}, need key generated in hardware")
    if hw.purpose_raw is None or PURPOSE_SIGN not in hw.purpose_raw:
        reasons.append(f"hardware_enforced.purpose={hw.purpose_raw}, need signing")
    if hw.no_auth_required or hw.user_auth_type_raw is None:
        reasons.append("hardware_enforced: key does not require user authentication")
    elif not hw.user_auth_type_raw & AUTH_TYPE_BIOMETRIC or hw.user_auth_type_raw & AUTH_TYPE_PASSWORD:
        reasons.append(f"hardware_enforced.user_auth_type={hw.user_auth_type_raw}, need biometric only")
    if hw.device_locked is not True or hw.verified_boot_state != VERIFIED_BOOT_VERIFIED:
        reasons.append(
            f"root of trust: device_locked={hw.device_locked}, verified_boot_state={hw.verified_boot_state}; "
            "need a locked device in the Verified boot state"
        )
    if app.app_package_names != [expected_package_name]:
        reasons.append(f"attestation application package names {app.app_package_names}, expected {expected_package_name!r}")
    if app.app_signature_digests != [expected_certificate_sha256]:
        reasons.append("attestation application signing certificate does not match the expected digest")

    return AttestationPolicyResult(ok=not reasons, reasons=reasons, key_description=kd)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def verify_chain(
    chain: list[x509.Certificate],
    trusted_roots: list[x509.Certificate],
    *,
    at: dt.datetime | None = None,
) -> tuple[bool, str]:
    """Verifies each cert in `chain` (leaf-first) is signed by the next, that
    every certificate is within its validity period at `at` (default: now) and
    every issuer is a CA, and that the final cert is (or is signed by) one of
    `trusted_roots`.

    This is not full X.509 path validation -- no revocation/CRL checking and no
    other policy constraints. Root certificates must be supplied by the
    operator (Google publishes and periodically rotates them; fetch and pin
    them out of band -- see docs/SECURITY.md).
    """
    if not chain:
        return False, "empty certificate chain"

    now = at or dt.datetime.now(dt.timezone.utc)
    for i, cert in enumerate(chain):
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            return False, f"chain[{i}] is outside its validity period"
        if i > 0 and not _is_ca(cert):
            return False, f"chain[{i}] is not a CA certificate"

    for i in range(len(chain) - 1):
        subject_cert = chain[i]
        issuer_cert = chain[i + 1]
        if subject_cert.issuer != issuer_cert.subject:
            return False, f"chain[{i}].issuer does not match chain[{i + 1}].subject"
        if not _verify_signed_by(subject_cert, issuer_cert):
            return False, f"chain[{i}] signature does not verify under chain[{i + 1}]'s key"

    root_candidate = chain[-1]
    for trusted in trusted_roots:
        if not trusted.not_valid_before_utc <= now <= trusted.not_valid_after_utc:
            continue
        if root_candidate.public_key().public_bytes(
            encoding=_ENCODING_DER, format=_FORMAT_SUBJECT_PUBLIC_KEY_INFO
        ) == trusted.public_key().public_bytes(
            encoding=_ENCODING_DER, format=_FORMAT_SUBJECT_PUBLIC_KEY_INFO
        ):
            return True, "root matches a trusted root"
        if root_candidate.issuer == trusted.subject and _verify_signed_by(root_candidate, trusted):
            return True, "chain root is signed by a trusted root"

    return False, "chain does not terminate at a trusted root"


def _verify_signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    issuer_key = issuer.public_key()
    try:
        if isinstance(issuer_key, rsa.RSAPublicKey):
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_key, ec.EllipticCurvePublicKey):
            issuer_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:
        return False
