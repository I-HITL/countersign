import tomllib
from pathlib import Path

from application_client.countersign_client import CountersignClient, SW_INS_NOT_SUPPORTED, SW_WRONG_P1P2
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU


def test_version_matches_cargo_manifest(backend: BackendInterface) -> None:
    manifest = tomllib.loads((Path(__file__).resolve().parents[2] / "Cargo.toml").read_text())
    expected = bytes(int(part) for part in manifest["package"]["version"].split("."))
    assert CountersignClient(backend).get_version().data == expected


def test_app_name(backend: BackendInterface) -> None:
    assert CountersignClient(backend).get_app_name().data == b"Countersign"


def test_unknown_instruction_and_bad_p1p2_are_rejected(backend: BackendInterface) -> None:
    try:
        backend.exchange(cla=0xE0, ins=0x42)
        assert False, "unknown INS was accepted"
    except ExceptionRAPDU as error:
        assert error.status == SW_INS_NOT_SUPPORTED
    try:
        backend.exchange(cla=0xE0, ins=0x03, p1=1)
        assert False, "bad P1 was accepted"
    except ExceptionRAPDU as error:
        assert error.status == SW_WRONG_P1P2
