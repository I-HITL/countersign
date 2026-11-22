"""APDU client for the Countersign Ledger app, shared by the Ragger tests.
The same framing lives in ledger/host/bridge.py for real use."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Generator

from ragger.backend.interface import BackendInterface, RAPDU

CLA = 0xE0
INS_GET_VERSION = 0x03
INS_GET_APP_NAME = 0x04
INS_ENROLL = 0x10
INS_APPROVE = 0x20

SW_OK = 0x9000
SW_DENY = 0x6985
SW_INCORRECT_DATA = 0x6A80
SW_WRONG_P1P2 = 0x6A86
SW_INS_NOT_SUPPORTED = 0x6D00
SW_ENDORSEMENT_UNAVAILABLE = 0xB010

PUBLIC_KEY_LENGTH = 65
CODE_HASH_LENGTH = 32


@dataclass
class EnrollmentEvidence:
    public_key: bytes
    code_hash: bytes
    owner_certificate: bytes
    challenge_signature: bytes


def parse_enroll_response(data: bytes) -> EnrollmentEvidence:
    offset = 0
    public_key = data[offset : offset + PUBLIC_KEY_LENGTH]
    offset += PUBLIC_KEY_LENGTH
    code_hash = data[offset : offset + CODE_HASH_LENGTH]
    offset += CODE_HASH_LENGTH
    cert_len = data[offset]
    offset += 1
    certificate = data[offset : offset + cert_len]
    offset += cert_len
    sig_len = data[offset]
    offset += 1
    signature = data[offset : offset + sig_len]
    offset += sig_len
    if len(public_key) != PUBLIC_KEY_LENGTH or len(code_hash) != CODE_HASH_LENGTH:
        raise ValueError("enroll response is too short")
    if len(certificate) != cert_len or len(signature) != sig_len or offset != len(data):
        raise ValueError("enroll response has inconsistent lengths")
    return EnrollmentEvidence(public_key, code_hash, certificate, signature)


class CountersignClient:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=INS_GET_VERSION)

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=INS_GET_APP_NAME)

    @contextmanager
    def enroll(self, challenge: bytes) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=INS_ENROLL, data=challenge):
            yield

    @contextmanager
    def approve(self, message: bytes) -> Generator[None, None, None]:
        with self.backend.exchange_async(cla=CLA, ins=INS_APPROVE, data=message):
            yield

    def get_async_response(self) -> RAPDU | None:
        return self.backend.last_async_response
