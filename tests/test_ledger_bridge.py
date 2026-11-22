"""Unit tests for the Ledger host bridge (ledger/host/bridge.py) and the
provisioning helper (ledger/host/endorse.py). The device and the service
are faked: the real APDU exchange is covered by the Ragger tests in
ledger/countersign-app/tests, the real service by tests/test_protocol.py."""

from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import sys
from pathlib import Path

import httpx
import pytest

HOST = Path(__file__).resolve().parents[1] / "ledger" / "host"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, HOST / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bridge = _load("bridge")


def _enroll_bytes(cert: bytes, sig: bytes) -> bytes:
    return b"\x04" + bytes(64) + bytes(range(32)) + bytes([len(cert)]) + cert + bytes([len(sig)]) + sig


def test_apdu_framing():
    assert bridge.build_apdu(0x10, b"\x01\x02") == bytes([0xE0, 0x10, 0, 0, 2, 1, 2])
    assert bridge.build_apdu(0x03) == bytes([0xE0, 0x03, 0, 0, 0])
    with pytest.raises(ValueError):
        bridge.build_apdu(0x20, bytes(256))


def test_enroll_response_parsing_round_trips_into_the_service_request():
    cert, sig = b"\x30\x06cert", b"\x30\x05sig"
    evidence = bridge.parse_enroll_response(_enroll_bytes(cert, sig))
    assert evidence.public_key == b"\x04" + bytes(64)
    assert evidence.code_hash == bytes(range(32))
    assert evidence.owner_certificate == cert and evidence.challenge_signature == sig
    body = evidence.to_request_body()
    assert base64.b64decode(body["owner_certificate_b64"]) == cert
    assert set(body) == {
        "endorsement_public_key_b64", "code_hash_b64", "owner_certificate_b64", "challenge_signature_b64",
    }


@pytest.mark.parametrize(
    "data",
    [b"", bytes(96), _enroll_bytes(b"c", b"s")[:-1], _enroll_bytes(b"c", b"s") + b"x", bytes(97) + b"\x05ab"],
)
def test_malformed_enroll_responses_are_rejected(data):
    with pytest.raises(ValueError):
        bridge.parse_enroll_response(data)


def test_message_size_guard_counts_utf8_bytes():
    assert bridge.message_fits("x" * 255)
    assert not bridge.message_fits("x" * 256)
    assert not bridge.message_fits("é" * 128)  # 256 bytes
    assert not bridge.message_fits("")


def test_expiry_uses_the_service_timestamp():
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat()
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    assert not bridge.is_expired({"expires_at": future})
    assert bridge.is_expired({"expires_at": past})


def test_service_errors_surface_the_servers_reasons():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer device-token"
        if request.url.path == "/v1/enroll/x/endorsement":
            return httpx.Response(400, json={"detail": {"reasons": ["owner certificate: bad", "code hash: bad"]}})
        if request.url.path == "/v1/enrollments/gone":
            return httpx.Response(404, json={"detail": "unknown device"})
        return httpx.Response(200, json={"status": "approved"})

    service = bridge.Service("http://service.test", "device-token")
    service._client = httpx.Client(base_url="http://service.test", headers=service._client.headers, transport=httpx.MockTransport(handler))
    with pytest.raises(bridge.ServiceError) as error:
        service.submit_endorsement("x", bridge.parse_enroll_response(_enroll_bytes(b"c", b"s")))
    assert error.value.status == 400 and "owner certificate: bad\ncode hash: bad" == str(error.value)
    with pytest.raises(bridge.ServiceError) as error:
        service.enrollment_status("gone")
    assert error.value.status == 404
    assert service.complete_approval("REF", b"sig")["status"] == "approved"


def test_device_exchange_retries_while_the_app_shows_a_status_page(monkeypatch):
    monkeypatch.setattr(bridge.time, "sleep", lambda _s: None)

    class FakeTransport:
        def __init__(self, answers):
            self.answers, self.sent = answers, []

        def exchange_raw(self, apdu):
            self.sent.append(apdu)
            return self.answers.pop(0)

    device = object.__new__(bridge.Device)
    device._transport = FakeTransport([(bridge.SW_BUSY, b""), (bridge.SW_BUSY, b""), (bridge.SW_OK, b"sig")])
    assert device.exchange(bridge.INS_APPROVE, b"m") == b"sig"
    assert len(device._transport.sent) == 3 and device._transport.sent[0] == bridge.build_apdu(bridge.INS_APPROVE, b"m")

    device._transport = FakeTransport([(bridge.SW_DENY, b"")])
    with pytest.raises(bridge.DeviceError) as error:
        device.exchange(bridge.INS_APPROVE, b"m")
    assert error.value.sw == bridge.SW_DENY

    device._transport = FakeTransport([(bridge.SW_BUSY, b"")] * 5)
    with pytest.raises(bridge.DeviceError) as error:
        device.exchange(bridge.INS_APPROVE, b"m")
    assert error.value.sw == bridge.SW_BUSY


def test_state_file_round_trip(tmp_path):
    state = bridge.State(tmp_path / "nested" / "ledger.json")
    assert state.device_id() is None
    state.save("abc")
    assert json.loads(state.path.read_text()) == {"device_id": "abc"}
    assert state.device_id() == "abc"
    state.clear()
    assert state.device_id() is None


def test_owner_key_recovery_finds_the_signing_key():
    pytest.importorskip("ecdsa")
    endorse = _load("endorse")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    owner = ec.generate_private_key(ec.SECP256K1())
    device = ec.generate_private_key(ec.SECP256K1()).public_key()
    public_key = device.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    certificate = owner.sign(b"\xfe" + public_key, ec.ECDSA(hashes.SHA256()))
    owner_bytes = owner.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    candidates = endorse.recover_owner_keys(public_key, certificate)
    assert owner_bytes in candidates and len(candidates) <= 4


def test_operator_owner_key_is_created_once_and_signs_verifiable_certificates(tmp_path):
    endorse = _load("endorse")
    from cryptography.hazmat.primitives.asymmetric import ec

    path = tmp_path / "owner" / "key.pem"
    first = endorse.load_or_create_owner_key(path)
    assert path.exists() and (path.stat().st_mode & 0o777) == 0o600
    second = endorse.load_or_create_owner_key(path)
    assert endorse.owner_public_key_hex(first) == endorse.owner_public_key_hex(second)
    assert len(bytes.fromhex(endorse.owner_public_key_hex(first))) == 65

    device = ec.generate_private_key(ec.SECP256K1()).public_key()
    from cryptography.hazmat.primitives import serialization

    public_key = device.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    certificate = endorse.sign_owner_certificate(first, public_key)
    # Exactly what service/attestation/ledger.py checks, with the pinned key.
    from service.attestation import ledger

    ledger.verify_owner_certificate(public_key, certificate, ledger.parse_owner_public_keys(endorse.owner_public_key_hex(first)))
    assert endorse.owner_public_key_hex(first) in [c.hex() for c in endorse.recover_owner_keys(public_key, certificate)]


def test_dashboard_certificate_and_endorse_response_parsing():
    header, pub, sig = b"\xaa\xe8", b"\x04" + bytes(64), b"\x30\x06abcdef"
    cert = bytes([len(header)]) + header + bytes([len(pub)]) + pub + bytes([len(sig)]) + sig
    assert bridge.parse_dashboard_certificate(cert) == (header, pub, sig)
    for bad in (cert[:-1], cert + b"\x00", b"", bytes([1]) + b"h" + bytes([3]) + b"xyz" + bytes([1]) + b"s"):
        with pytest.raises(ValueError):
            bridge.parse_dashboard_certificate(bad)
    assert bridge.parse_endorse_start_response(pub + sig) == (pub, sig)
    for bad in (pub, b"\x02" + bytes(64) + sig, pub[:-1]):
        with pytest.raises(ValueError):
            bridge.parse_endorse_start_response(bad)


def test_local_chain_check_and_state_chain_round_trip(tmp_path):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    def raw(key):
        return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    root, device, endorsement = (ec.generate_private_key(ec.SECP256K1()) for _ in range(3))
    header = b"\x01\x02"
    chain = bridge.DeviceChain(raw(device), header, root.sign(b"\x02" + header + raw(device), ec.ECDSA(hashes.SHA256())), raw(endorsement))
    device_signature = device.sign(b"\xff" + raw(endorsement), ec.ECDSA(hashes.SHA256()))
    roots = tmp_path / "roots.txt"
    roots.write_text("# test root\n" + raw(root).hex() + "\n")
    assert bridge.verify_chain_locally(chain, device_signature, roots) == "ok"
    assert "does not verify" in bridge.verify_chain_locally(chain, device_signature, tmp_path / "missing.txt") or "not found" in bridge.verify_chain_locally(chain, device_signature, tmp_path / "missing.txt")
    other = ec.generate_private_key(ec.SECP256K1())
    assert "did not sign" in bridge.verify_chain_locally(chain, other.sign(b"\xff" + raw(endorsement), ec.ECDSA(hashes.SHA256())), roots)
    roots.write_text(raw(other).hex() + "\n")
    assert "does not verify" in bridge.verify_chain_locally(chain, device_signature, roots)

    state = bridge.State(tmp_path / "ledger.json")
    state.save("dev-1")
    state.save_chain(chain)
    assert state.device_id() is None and state.chain() == chain  # a new key forgets the old identity
    state.save("dev-2")
    assert state.chain() == chain and state.device_id() == "dev-2"
    state.clear()
    assert state.device_id() is None and state.chain() == chain
    body = bridge.parse_enroll_response(_enroll_bytes(b"c", b"s")).to_request_body(chain)
    assert base64.b64decode(body["device_public_key_b64"]) == raw(device)
    assert base64.b64decode(body["issuer_certificate_header_b64"]) == header
