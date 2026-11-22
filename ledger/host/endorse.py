#!/usr/bin/env python3
"""Alternative provisioning of a Ledger's endorsement key with an Owner
certificate. The default path is `bridge.py provision`, which needs no Owner:
it captures the device chain to Ledger's published root instead.

  endorse.py setup [--owner operator|ledger]
      With the device unlocked and on the dashboard: has the device generate
      its slot-1 endorsement key and stores the Owner certificate, a
      signature over SHA-256(0xFE || public_key).

      --owner operator (default): the operator is the Owner. Needs the
      custom CA that `ledgerctl install-ca` installs (same key file), since
      the endorsement commands run inside an authenticated secure channel.
      The Owner key is created on first use in ~/.countersign/ledger-owner-key.pem
      and its public key is what the service pins. The device/issuer
      certificate is not verifiable here (Ledger's issuer keys are not
      published), so this attests "this operator provisioned this device".

      --owner ledger: Ledger's HSM signs the certificate after checking the
      device is genuine (ledgerwallet's `LedgerClient.endorse(1)`). As of
      November 2026 the HSM host the tooling uses,
      hsmprod.hardwarewallet.com, no longer resolves, so this path fails.

  endorse.py read
      With the Countersign app open on the device: asks it for its public
      key, code hash and Owner certificate (an ENROLL with a random
      challenge; confirm on the device) and prints them. Needs no service.

  endorse.py owner-key --public-key HEX --certificate HEX
      Ledger does not publish the Owner ("attest_1") public key, so recover
      the candidate keys from a certificate (`read` or `bridge.py enroll`
      print both values). ECDSA recovery yields two candidates; pin both in
      COUNTERSIGN_LEDGER_OWNER_PUBLIC_KEYS, or run it for a second device and
      keep the key both lists share.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bridge  # noqa: E402  (ledger/host/bridge.py: APDU framing and the device transport)

OWNER_CERTIFICATE_ROLE = b"\xfe"
DEFAULT_OWNER_KEY_FILE = "~/.countersign/ledger-owner-key.pem"


def cmd_setup_ledger(scheme: int) -> None:
    from ledgerwallet.client import LedgerClient

    client = LedgerClient()
    try:
        client.endorse(scheme)
    finally:
        client.close()
    print(f"Endorsement slot {scheme} provisioned with Ledger as Owner.")
    print("Load the Countersign app and run `endorse.py read` to see the key and certificate.")


def load_or_create_owner_key(path: Path):
    """The operator's Owner key (secp256k1), created on first use."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256K1):
            raise SystemExit(f"{path} is not a secp256k1 private key")
        return key
    key = ec.generate_private_key(ec.SECP256K1())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    print(f"Created the Owner key at {path} (keep it private; it is the service's trust root).")
    return key


def owner_public_key_hex(key) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()


def sign_owner_certificate(owner_key, public_key: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    return owner_key.sign(OWNER_CERTIFICATE_ROLE + public_key, ec.ECDSA(hashes.SHA256()))


def cmd_setup_operator(scheme: int, owner_key_file: Path) -> None:
    from ledgerwallet.client import LedgerClient
    from ledgerwallet.ledgerctl import get_private_key  # the custom CA key `ledgerctl install-ca` installed
    from ledgerwallet.simpleserver import SimpleServer
    from ledgerwallet.utils import LedgerIns

    owner_key = load_or_create_owner_key(owner_key_file)
    client = LedgerClient(private_key=get_private_key())
    try:
        # Secure channel authenticated with the custom CA; the device asks to allow it.
        client.authenticate(SimpleServer(client.private_key))
        data = bytes(client.apdu_exchange(LedgerIns.ENDORSE_SET_START, p1=scheme))
        public_key = data[:65]
        if len(public_key) != 65 or public_key[0] != 0x04:
            raise SystemExit(f"unexpected endorsement response: {data.hex()}")
        certificate = sign_owner_certificate(owner_key, public_key)
        client.apdu_exchange(LedgerIns.ENDORSE_SET_COMMIT, certificate)
    finally:
        client.close()
    print(f"Endorsement slot {scheme} provisioned with the operator as Owner.")
    print(f"Endorsement public key: {public_key.hex()}")
    print(f"Owner certificate: {certificate.hex()}")
    print(f"\nCOUNTERSIGN_LEDGER_OWNER_PUBLIC_KEYS={owner_public_key_hex(owner_key)}")


def cmd_read(transport_spec: str) -> None:
    print("Confirm the enrollment prompt on the Ledger...")
    device = bridge.Device(transport_spec)
    try:
        evidence = bridge.parse_enroll_response(device.exchange(bridge.INS_ENROLL, os.urandom(32)))
    except bridge.DeviceError as error:
        if error.sw == bridge.SW_ENDORSEMENT_UNAVAILABLE:
            raise SystemExit("The device has no endorsement key. Run `endorse.py setup` first.") from None
        raise SystemExit(str(error)) from None
    finally:
        device.close()
    print(f"Endorsement public key: {evidence.public_key.hex()}")
    print(f"Code hash (COUNTERSIGN_LEDGER_CODE_HASH): {evidence.code_hash.hex()}")
    print(f"Owner certificate: {evidence.owner_certificate.hex()}")
    print("\nNext: endorse.py owner-key --public-key <key> --certificate <certificate>")


def recover_owner_keys(public_key: bytes, certificate: bytes) -> list[bytes]:
    from ecdsa import SECP256k1, VerifyingKey
    from ecdsa.util import sigdecode_der

    digest = hashlib.sha256(OWNER_CERTIFICATE_ROLE + public_key).digest()
    candidates = VerifyingKey.from_public_key_recovery_with_digest(
        certificate, digest, SECP256k1, hashfunc=hashlib.sha256, sigdecode=sigdecode_der
    )
    return [candidate.to_string("uncompressed") for candidate in candidates]


def cmd_owner_key(public_key_hex: str, certificate_hex: str) -> None:
    public_key, certificate = bytes.fromhex(public_key_hex), bytes.fromhex(certificate_hex)
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise SystemExit("--public-key must be a 65-byte uncompressed secp256k1 point in hex")
    candidates = recover_owner_keys(public_key, certificate)
    print("Candidate Owner public keys (one of them signed this certificate):")
    for candidate in candidates:
        print(candidate.hex())
    print("\nCOUNTERSIGN_LEDGER_OWNER_PUBLIC_KEYS=" + ",".join(c.hex() for c in candidates))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup", help="generate the endorsement key and store its Owner certificate")
    setup.add_argument("--scheme", type=int, choices=(1, 2), default=1, help="endorsement slot/scheme (Countersign uses 1)")
    setup.add_argument("--owner", choices=("operator", "ledger"), default="operator",
                       help="who signs the Owner certificate (default: operator, via the ledgerctl custom CA)")
    setup.add_argument("--owner-key-file", default=os.environ.get("COUNTERSIGN_LEDGER_OWNER_KEY_FILE", DEFAULT_OWNER_KEY_FILE),
                       help=f"operator Owner key, created if missing (default {DEFAULT_OWNER_KEY_FILE})")
    read = sub.add_parser("read", help="print the key, code hash and Owner certificate the Countersign app reports")
    read.add_argument("--transport", default=os.environ.get("COUNTERSIGN_LEDGER_TRANSPORT", "hid"),
                      help="hid (default) or tcp:<host>:<port> for Speculos")
    owner = sub.add_parser("owner-key", help="recover the Owner public key candidates from a certificate")
    owner.add_argument("--public-key", required=True, help="endorsement public key, hex")
    owner.add_argument("--certificate", required=True, help="Owner certificate (DER signature), hex")
    args = parser.parse_args(argv)
    if args.command == "setup" and args.owner == "ledger":
        cmd_setup_ledger(args.scheme)
    elif args.command == "setup":
        cmd_setup_operator(args.scheme, Path(args.owner_key_file).expanduser())
    elif args.command == "read":
        cmd_read(args.transport)
    else:
        cmd_owner_key(args.public_key, args.certificate)


if __name__ == "__main__":
    main()
