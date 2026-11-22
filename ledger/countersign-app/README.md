# Countersign for Ledger devices

One Rust app for Ledger Nano S+, Nano X, Stax, Flex and Apex P. The device shows a request on its own screen and, once the human approves, signs exactly those bytes with the device's **endorsement key**: a secp256k1 key that Ledger OS keeps in the Secure Element, that the device's factory-certified key vouches for (a chain to Ledger's published root of trust), and whose every signature Ledger OS binds to the hash of the app that asked for it. The service pins that hash, so a verifying signature means *the Countersign app on a genuine Ledger displayed this message*.

Because a Ledger has no network, a small host program (`ledger/host/bridge.py`) relays between the service and the device. It is the untrusted platform of the I-HITL model: it holds no key and the device signs only what it shows.

| Piece | Where |
| --- | --- |
| Device app (Rust, ~370 lines) | `src/` |
| Host bridge (enroll, pending, approve, decline) | `../host/bridge.py` |
| One-time provisioning of the endorsement key | `../host/endorse.py` |
| Functional tests on the Speculos emulator (Ragger) | `tests/standalone/` |
| Service-side verification | `../../service/attestation/ledger.py` |

## How it maps to the phones

| | Android / iPhone | Ledger |
| --- | --- | --- |
| Key | Hardware-backed, biometric-gated | Slot-1 endorsement key in the Secure Element |
| Evidence at enrollment | Key attestation + Play Integrity / App Attest | Device chain (Ledger root → device key → endorsement key) + code hash + challenge signature |
| Approval | Biometric prompt, signature over the message | Button/touch confirmation, signature over `message ‖ code_hash` (the OS appends the hash) |
| Screens | Home with pending list, review screen | Home on the device; pending list in the bridge; review screen on the device |

## APDU protocol

CLA is `0xE0`, P1 and P2 are always `0x00`.

| INS | Data | Device | Response |
| --- | --- | --- | --- |
| `0x03` GET_VERSION | none | none | `major minor patch` |
| `0x04` GET_APP_NAME | none | none | `Countersign` |
| `0x10` ENROLL | 32-byte challenge | "Enroll this device?" confirmation | `pubkey(65) ‖ code_hash(32) ‖ cert_len(1) ‖ cert ‖ sig_len(1) ‖ sig`; `cert` is the slot's stored certificate (the device key's signature over `0xFF ‖ pubkey` after `bridge.py provision`), `sig` = scheme-1 signature over the challenge |
| `0x20` APPROVE | message, UTF-8, 1..255 bytes | Review screen showing the message verbatim | DER signature, scheme 1, over the message |

Status words: `9000` ok, `6985` declined on the device, `6A80` malformed data (wrong challenge length, empty or over-long message, invalid UTF-8), `6A86` bad P1/P2, `6D00` unknown INS, `B010` endorsement key not provisioned, `B011` signing failed. A message travels in one APDU, so it is limited to 255 bytes; the bridge refuses longer ones.

Endorsement scheme 1 (`sys_endorsement_key1_sign_data`) signs `SHA-256(data ‖ code_hash)` with the slot-1 key. The app never calls the variant without the code hash. `src/endorsement.rs` is the only `unsafe` code.

## Build

Builds run in Ledger's `ledger-app-dev-tools` Docker image, which contains the Rust toolchain, `cargo-ledger`, Speculos and Ragger. From this directory:

```sh
docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
docker run --rm -v "$(pwd -P):/app" -v countersign-cargo-registry:/opt/.cargo/registry \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest cargo ledger build flex
```

Replace `flex` with `nanosplus`, `nanox`, `stax` or `apex_p`. Each build writes `target/<device>/release/countersign` (ELF), `countersign.apdu` (install script) and `countersign.sha256`, the application hash that Ledger OS reports as the code hash. The named volume only caches crates.

## Emulator demo (no device needed)

1. Build for a device, then start the emulator from the same image, exposing the APDU port:

   ```sh
   docker run --rm -it -v "$(pwd -P):/app" --publish 5001:5001 --publish 9999:9999 \
     ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
     speculos --model flex --apdu-port 9999 --api-port 5001 --display headless target/flex/release/countersign
   ```

   The screen is at <http://127.0.0.1:5001> (use `--model nanosp` with `target/nanosplus/...` for a Nano S+).
2. From the repository root, start the simulation backend and run the bridge over TCP:

   ```sh
   ./run_ledger_simulation.command            # http://127.0.0.1:8002, pins Speculos's keys
   export COUNTERSIGN_SERVER_URL=http://127.0.0.1:8002 COUNTERSIGN_DEVICE_TOKEN=development-device-token
   export COUNTERSIGN_LEDGER_TRANSPORT=tcp:127.0.0.1:9999 COUNTERSIGN_LEDGER_STATE=runs/ledger-simulation/state.json
   uv run --group ledger python ledger/host/bridge.py enroll   # confirm on the emulator screen
   ```

3. Open the [demo page](http://127.0.0.1:8002/v1/demo), enter `development-admin-token`, approve the enrollment and send a request. Then:

   ```sh
   uv run --group ledger python ledger/host/bridge.py pending
   uv run --group ledger python ledger/host/bridge.py approve <ref>   # approve or reject on the emulator
   ```

   The demo page shows the result; `GET /v1/admin/approvals/<ref>/proof` returns the signed message, signature, public key, code hash and Owner certificate.

The emulator's Owner key and endorsement key are Speculos's published defaults, so this verifies the full chain but proves nothing about a real device.

## Physical device

Needs a Ledger with current firmware, `uv sync --frozen --group ledger` (installs `ledgercomm`, `ledgerwallet` and `ledgerblue`), and Docker for the build. Close Ledger Live first: it holds the USB connection. On Linux, install the udev rules from Ledger's documentation first. Nothing below installs a custom CA or needs physical access by anyone but the device's user.

1. **Provision the endorsement key** (once per device; device unlocked, on the dashboard, Countersign app not open). The bridge opens the dashboard's secure channel with a throwaway key, captures the device's issuer certificate (Ledger's published root of trust signing the device key), has the device generate its slot-1 endorsement key and sign it with the device key, and commits that signature as the slot's certificate. Accept the connection on the device when asked.

   ```sh
   uv run --group ledger python ledger/host/bridge.py provision
   ```

   The chain is checked locally against `attestation_roots/ledger_root_of_trust.txt` and kept in the bridge's state file for enrollment. Running it again generates a new key (a new identity).

2. **Load the app** (device on the dashboard; accept the prompts on the device):

   ```sh
   cd ledger/countersign-app
   uv run --group ledger python -m ledgerblue.runScript --elfFile target/flex/release/countersign \
     --fileName target/flex/release/countersign.apdu --apdu --scp
   cd ../..
   ```

   Sideloading works on Nano S+, Stax and Flex (not Nano X).

3. **Configure the backend.** Copy `.env.ledger.example` to `.env`, generate the tokens ([Create `.env`](../../docs/SETUP.md#create-env)), and set `COUNTERSIGN_LEDGER_CODE_HASH` to the contents of `target/flex/release/countersign.sha256`. Ledger's root of trust is loaded from the repository by default; `COUNTERSIGN_LEDGER_OWNER_PUBLIC_KEYS` stays empty. Start it with `./run_live_backend.command`.

4. **Enroll and approve.** Open Countersign on the device, export `COUNTERSIGN_SERVER_URL=http://127.0.0.1:8000` and `COUNTERSIGN_DEVICE_TOKEN`, run `bridge.py enroll` and confirm on the device. The service verifies root → device key → endorsement key, the pinned code hash, and the challenge signature. Then activate the enrollment and send a request with the [demo workflow](../../docs/SETUP.md#run-the-demo), `bridge.py approve <ref>`, and approve on the device. The proof carries the device chain, so anyone holding Ledger's published root can re-verify it.

### Alternative trust roots

`endorse.py` provisions a device the older way, with an *Owner* certificate (a signature over `0xFE ‖ key`) instead of the device chain: `--owner ledger` asks Ledger's HSM, whose host `hsmprod.hardwarewallet.com` no longer resolves as of November 2026; `--owner operator` signs with a key held by the service administrator through a custom CA installed in recovery mode. The service accepts such certificates under `COUNTERSIGN_LEDGER_OWNER_PUBLIC_KEYS`; the Speculos emulator is provisioned this way by its default attestation key. An Owner certificate is only as good as the Owner: if the device's user holds the Owner key, they can certify a software key (see the [security notes](../../docs/SECURITY.md)).

## Verified on hardware

On 2026-11-02, with a Ledger Flex (OS 1.7.0, target `0x33300004`): provisioning through the dashboard, the issuer certificate verifying under Ledger's published root, loading the app, enrollment against the strict backend (device-reported code hash equal to the build's `.sha256`), approval and device-side decline, and offline re-verification of the proof from the root. The Ragger suite passes on Speculos for all five targets.

## Tests

Functional tests run on Speculos through Ragger and make only cryptographic assertions (no golden screenshots), so they pass unchanged on every device:

```sh
cd ../..   # repository root: Ragger reads ledger_app.toml from the git root
docker run --rm -it -v "$(pwd -P):/app" -w /app/ledger/countersign-app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest \
  bash -c '/opt/venv/bin/pip install -q -r tests/standalone/requirements.txt && /opt/venv/bin/python -m pytest tests/standalone -v --device flex'
```

Use `--device nanosp`, `nanox`, `stax` or `apex_p` for the others (build each target first). The backend's `tests/test_attestation_ledger.py` uses the same Speculos key material.
