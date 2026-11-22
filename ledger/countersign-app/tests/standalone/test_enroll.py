import os

import pytest
from application_client.countersign_client import (
    SW_DENY,
    SW_INCORRECT_DATA,
    CountersignClient,
    parse_enroll_response,
)
from cryptography.hazmat.primitives import serialization
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .navigation import cancel_enrollment, confirm_enrollment
from .speculos_keys import (
    CODE_HASH,
    ENDORSEMENT_PUBLIC_KEY,
    OWNER_CERTIFICATE_ROLE,
    OWNER_PUBLIC_KEY,
    verifies,
)


def test_enroll_returns_verifiable_evidence(backend: BackendInterface, navigator: Navigator, device) -> None:
    client = CountersignClient(backend)
    challenge = os.urandom(32)
    with client.enroll(challenge):
        confirm_enrollment(navigator, device)
    response = client.get_async_response()
    assert response is not None and response.status == 0x9000
    evidence = parse_enroll_response(response.data)

    # The key is the slot-1 endorsement key Speculos was started with.
    expected = ENDORSEMENT_PUBLIC_KEY.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert evidence.public_key == expected
    assert evidence.code_hash == CODE_HASH
    # Owner certificate: SHA-256(0xFE || public_key) signed by the Owner key.
    assert verifies(OWNER_PUBLIC_KEY, evidence.owner_certificate, OWNER_CERTIFICATE_ROLE + evidence.public_key)
    # Scheme 1: SHA-256(challenge || code_hash) signed by the endorsement key.
    assert verifies(ENDORSEMENT_PUBLIC_KEY, evidence.challenge_signature, challenge + evidence.code_hash)
    assert not verifies(ENDORSEMENT_PUBLIC_KEY, evidence.challenge_signature, challenge)


def test_enroll_can_be_cancelled(backend: BackendInterface, navigator: Navigator, device) -> None:
    client = CountersignClient(backend)
    with pytest.raises(ExceptionRAPDU) as error:
        with client.enroll(os.urandom(32)):
            cancel_enrollment(navigator, device)
    assert error.value.status == SW_DENY


@pytest.mark.parametrize("challenge", [b"", b"short", bytes(33)])
def test_enroll_rejects_a_malformed_challenge(backend: BackendInterface, challenge: bytes) -> None:
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(cla=0xE0, ins=0x10, data=challenge)
    assert error.value.status == SW_INCORRECT_DATA
