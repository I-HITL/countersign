#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  echo "Create the Python environment described in README.md first."
  exit 1
fi

exec .venv/bin/python - <<'PY'
import os
from pathlib import Path

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# This service must never inherit the live backend's credentials, platform
# configuration, or database. In particular, do not load the live .env file.
for key in list(os.environ):
    if key.startswith('COUNTERSIGN_') or key == 'GOOGLE_APPLICATION_CREDENTIALS':
        del os.environ[key]

# Speculos's default --attestation-key signs the emulator's Owner certificate
# (speculos/src/environment.c); its code hash is a fixed string. Pinning both
# means the real Ledger verification code runs, nothing is skipped.
speculos_owner = ec.derive_private_key(
    int.from_bytes(bytes.fromhex('138fb9b91da745f12977a2b46f0bce2f0418b50fcb76631baf0f08ceefdb5d57'), 'big'),
    ec.SECP256K1(),
).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
speculos_code_hash = b'12345678abcdef0000fedcba8765432\x00'

database = Path('runs/ledger-simulation/countersign.db').resolve()
database.parent.mkdir(parents=True, exist_ok=True)
os.environ.update({
    'COUNTERSIGN_ENABLED_PLATFORMS': 'ledger',
    'COUNTERSIGN_DEV_MODE': '1',
    'COUNTERSIGN_SKIP_ATTESTATION': '0',
    'COUNTERSIGN_SKIP_INTEGRITY': '0',
    'COUNTERSIGN_DB_PATH': str(database),
    'COUNTERSIGN_API_TOKEN': 'development-device-token',
    'COUNTERSIGN_ADMIN_API_TOKEN': 'development-admin-token',
    'COUNTERSIGN_LEDGER_OWNER_PUBLIC_KEYS': speculos_owner.hex(),
    'COUNTERSIGN_LEDGER_CODE_HASH': speculos_code_hash.hex(),
})

print('Countersign Ledger simulation: http://127.0.0.1:8002', flush=True)
print('Trust root is the Speculos emulator attestation key. Local testing only.', flush=True)
print('Approval signatures and administrator activation remain required.', flush=True)
print(f'Separate simulation database: {database}', flush=True)
uvicorn.run('service.app:app', host='127.0.0.1', port=8002)
PY
