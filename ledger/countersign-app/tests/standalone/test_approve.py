import pytest
from application_client.countersign_client import SW_DENY, SW_INCORRECT_DATA, CountersignClient
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from .navigation import approve_request, reject_request
from .speculos_keys import CODE_HASH, ENDORSEMENT_PUBLIC_KEY, verifies

MESSAGE = "Approve #B66AC921: wire transfer of $500 to Alice Chen (Acct ...4471) (expires 2026-10-25 00:48 UTC)"


def test_approve_signs_exactly_the_displayed_message(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, device
) -> None:
    client = CountersignClient(backend)
    message = MESSAGE.encode()
    with client.approve(message):
        approve_request(scenario_navigator, device)
    response = client.get_async_response()
    assert response is not None and response.status == 0x9000
    signature = response.data
    assert verifies(ENDORSEMENT_PUBLIC_KEY, signature, message + CODE_HASH)
    # Not a plain signature over the message, and not valid for other bytes.
    assert not verifies(ENDORSEMENT_PUBLIC_KEY, signature, message)
    assert not verifies(ENDORSEMENT_PUBLIC_KEY, signature, message + b"!" + CODE_HASH)


def test_approve_accepts_the_maximum_message_length(
    backend: BackendInterface, scenario_navigator: NavigateWithScenario, device
) -> None:
    client = CountersignClient(backend)
    message = ("Approve #FFFFFFFF: " + "x" * 236).encode()
    assert len(message) == 255
    with client.approve(message):
        approve_request(scenario_navigator, device)
    response = client.get_async_response()
    assert response is not None and verifies(ENDORSEMENT_PUBLIC_KEY, response.data, message + CODE_HASH)


def test_decline_returns_no_signature(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    client = CountersignClient(backend)
    with pytest.raises(ExceptionRAPDU) as error:
        with client.approve(MESSAGE.encode()):
            reject_request(scenario_navigator)
    assert error.value.status == SW_DENY


@pytest.mark.parametrize("message", [b"", b"\xff\xfe not utf-8", b"with\x00nul"])
def test_approve_rejects_malformed_messages(backend: BackendInterface, message: bytes) -> None:
    with pytest.raises(ExceptionRAPDU) as error:
        backend.exchange(cla=0xE0, ins=0x20, data=message)
    assert error.value.status == SW_INCORRECT_DATA
