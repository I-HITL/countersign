"""Tests for the DER walker in service/attestation.py, against real Android
Key Attestation certificate chains -- see tests/fixtures/attestation/README.md
for where they came from.

Note: `cryptography`'s X.509 loader
refuses to parse the leaf cert (cert0.pem) in either fixture chain -- it's
strict about ECDSA's AlgorithmIdentifier having no `parameters` field, and
these ~2019 Google example certs include a redundant explicit NULL there
(openssl is lenient about it and loads them fine). So:
  - `parse_key_description` / `check_policy` are tested against the leaf's
    KeyDescription extension bytes directly (cert0_key_description.der,
    extracted via openssl -- see the fixtures README), not by loading
    cert0.pem as an x509.Certificate.
  - `verify_chain` is tested against cert1/cert2/cert3, which *do* load
    fine, giving a real 3-certificate chain with two genuine ECDSA
    signatures to verify.
  - Certificates from a real phone parse normally; the quirk is specific to
    these example certificates.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from service import attestation

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "attestation")


def _load_key_description(example: str) -> attestation.KeyDescription:
    path = os.path.join(FIXTURES_DIR, example, "cert0_key_description.der")
    with open(path, "rb") as f:
        return attestation.parse_key_description(f.read())


def _load_cert(example: str, name: str) -> x509.Certificate:
    path = os.path.join(FIXTURES_DIR, example, f"{name}.pem")
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


# --- parsing real certs ---


def test_parses_real_strongbox_leaf():
    kd = _load_key_description("strongbox")
    assert kd.attestation_security_level == attestation.SecurityLevel.STRONG_BOX
    assert kd.keymint_security_level == attestation.SecurityLevel.STRONG_BOX
    assert kd.attestation_challenge == b"abc"
    assert kd.hardware_enforced.purpose_raw == [2, 3]
    assert kd.hardware_enforced.origin_raw == 0
    assert kd.hardware_enforced.no_auth_required is True


def test_parses_real_tee_leaf():
    kd = _load_key_description("tee")
    assert kd.attestation_security_level == attestation.SecurityLevel.TRUSTED_ENVIRONMENT
    assert kd.attestation_challenge == b"abc"


# --- policy checks, against the real parsed data ---

PACKAGE = "com.countersign.app"
CERT_DIGEST = bytes(range(32))


def _policy(kd, **overrides):
    args = {"expected_challenge": b"abc", "expected_package_name": PACKAGE, "expected_certificate_sha256": CERT_DIGEST}
    return attestation.check_policy(kd, **{**args, **overrides})


def _compliant_key_description() -> attestation.KeyDescription:
    """Google's real StrongBox example with only the fields our own app's key
    would differ in replaced (plain dataclass fields, not re-encoded DER)."""
    kd = _load_key_description("strongbox")
    return dataclasses.replace(
        kd,
        software_enforced=dataclasses.replace(
            kd.software_enforced, app_package_names=[PACKAGE], app_signature_digests=[CERT_DIGEST]
        ),
        hardware_enforced=dataclasses.replace(
            kd.hardware_enforced,
            no_auth_required=False,
            user_auth_type_raw=attestation.AUTH_TYPE_BIOMETRIC,
            device_locked=True,
            verified_boot_state=attestation.VERIFIED_BOOT_VERIFIED,
        ),
    )


def _with_hardware(kd, **fields):
    return dataclasses.replace(kd, hardware_enforced=dataclasses.replace(kd.hardware_enforced, **fields))


def _with_software(kd, **fields):
    return dataclasses.replace(kd, software_enforced=dataclasses.replace(kd.software_enforced, **fields))


def test_check_policy_rejects_the_real_example_key():
    # Ground truth: Google's example keys need no auth, run on an unlocked
    # device, and belong to system packages -- all rejected for us.
    result = _policy(_load_key_description("strongbox"))
    assert not result.ok
    assert any("does not require user authentication" in r for r in result.reasons)
    assert any("root of trust" in r for r in result.reasons)
    assert any("package names" in r for r in result.reasons)


def test_check_policy_accepts_a_compliant_key():
    result = _policy(_compliant_key_description())
    assert result.ok, result.reasons


def test_check_policy_rejects_password_fallback():
    kd = _with_hardware(
        _compliant_key_description(),
        user_auth_type_raw=attestation.AUTH_TYPE_BIOMETRIC | attestation.AUTH_TYPE_PASSWORD,
    )
    assert any("biometric only" in r for r in _policy(kd).reasons)


def test_check_policy_rejects_wrong_challenge():
    result = _policy(_compliant_key_description(), expected_challenge=b"not-what-we-issued")
    assert any("challenge" in r for r in result.reasons)


def test_check_policy_rejects_software_security_levels():
    for field in ("attestation_security_level", "keymint_security_level"):
        kd = dataclasses.replace(_compliant_key_description(), **{field: attestation.SecurityLevel.SOFTWARE})
        assert any(field in r for r in _policy(kd).reasons)


def test_check_policy_rejects_imported_or_non_signing_keys():
    kd = _compliant_key_description()
    assert any("origin" in r for r in _policy(_with_hardware(kd, origin_raw=2)).reasons)
    assert any("purpose" in r for r in _policy(_with_hardware(kd, purpose_raw=[3])).reasons)


def test_check_policy_rejects_unlocked_or_unverified_boot():
    kd = _compliant_key_description()
    assert any("root of trust" in r for r in _policy(_with_hardware(kd, device_locked=False)).reasons)
    assert any("root of trust" in r for r in _policy(_with_hardware(kd, verified_boot_state=2)).reasons)
    assert any("root of trust" in r for r in _policy(_with_hardware(kd, device_locked=None)).reasons)


def test_check_policy_rejects_a_key_from_another_app():
    kd = _compliant_key_description()
    assert any("package names" in r for r in _policy(_with_software(kd, app_package_names=["evil.app"])).reasons)
    assert any("package names" in r for r in _policy(_with_software(kd, app_package_names=None)).reasons)
    assert any("signing certificate" in r for r in _policy(_with_software(kd, app_signature_digests=[b"x" * 32])).reasons)


def test_parses_the_real_root_of_trust_and_application_id():
    kd = _load_key_description("strongbox")
    assert kd.hardware_enforced.device_locked is False
    assert kd.hardware_enforced.verified_boot_state == 2
    assert kd.software_enforced.app_package_names[:2] == ["android", "com.android.keychain"]
    assert len(kd.software_enforced.app_signature_digests) == 1


# --- chain verification, against the real intermediates + root ---

# Google's example certificates are valid 2018-2028 (the TEE root only to 2026).
WITHIN_VALIDITY = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)


def test_verify_chain_accepts_the_real_strongbox_subchain():
    cert1 = _load_cert("strongbox", "cert1")
    cert2 = _load_cert("strongbox", "cert2")
    cert3_root = _load_cert("strongbox", "cert3")
    ok, reason = attestation.verify_chain([cert1, cert2, cert3_root], trusted_roots=[cert3_root], at=WITHIN_VALIDITY)
    assert ok, reason


def test_verify_chain_rejects_an_untrusted_root():
    cert1 = _load_cert("strongbox", "cert1")
    cert2 = _load_cert("strongbox", "cert2")
    cert3_root = _load_cert("strongbox", "cert3")
    wrong_root = _load_cert("tee", "cert3")  # a real cert, but the wrong chain's root
    ok, _reason = attestation.verify_chain([cert1, cert2, cert3_root], trusted_roots=[wrong_root], at=WITHIN_VALIDITY)
    assert not ok


def test_verify_chain_rejects_a_chain_with_a_broken_link():
    # Splice in an intermediate from the unrelated tee chain -- issuer/subject
    # won't line up, so this must fail.
    cert1 = _load_cert("strongbox", "cert1")
    wrong_cert2 = _load_cert("tee", "cert2")
    cert3_root = _load_cert("strongbox", "cert3")
    ok, _reason = attestation.verify_chain([cert1, wrong_cert2, cert3_root], trusted_roots=[cert3_root], at=WITHIN_VALIDITY)
    assert not ok


def test_verify_chain_rejects_expired_and_not_yet_valid_certificates():
    chain = [_load_cert("strongbox", n) for n in ("cert1", "cert2", "cert3")]
    for at in (dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc), dt.datetime(2015, 1, 1, tzinfo=dt.timezone.utc)):
        ok, reason = attestation.verify_chain(chain, trusted_roots=[chain[-1]], at=at)
        assert not ok and "validity period" in reason


def test_verify_chain_rejects_a_non_ca_issuer():
    def cert(subject: str, issuer: str, key, signing_key, ca: bool | None) -> x509.Certificate:
        name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name(subject))
            .issuer_name(name(issuer))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2020, 1, 1))
            .not_valid_after(dt.datetime(2040, 1, 1))
        )
        if ca is not None:
            builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        return builder.sign(signing_key, hashes.SHA256())

    root_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    leaf = cert("leaf", "root", leaf_key, root_key, ca=False)
    for ca, expected in ((None, False), (False, False), (True, True)):
        root = cert("root", "root", root_key, root_key, ca=ca)
        ok, reason = attestation.verify_chain([leaf, root], trusted_roots=[root], at=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
        assert ok is expected, reason
