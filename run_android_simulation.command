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

# This service must never inherit the live backend's credentials, platform
# configuration, or database. In particular, do not load the live .env file.
for key in list(os.environ):
    if key.startswith('COUNTERSIGN_') or key == 'GOOGLE_APPLICATION_CREDENTIALS':
        del os.environ[key]

database = Path('runs/android-simulation/countersign.db').resolve()
database.parent.mkdir(parents=True, exist_ok=True)
os.environ.update({
    'COUNTERSIGN_ENABLED_PLATFORMS': 'android',
    'COUNTERSIGN_DEV_MODE': '1',
    'COUNTERSIGN_SKIP_ATTESTATION': '1',
    'COUNTERSIGN_SKIP_INTEGRITY': '1',
    'COUNTERSIGN_DB_PATH': str(database),
    'COUNTERSIGN_API_TOKEN': 'development-device-token',
    'COUNTERSIGN_ADMIN_API_TOKEN': 'development-admin-token',
    'COUNTERSIGN_PACKAGE_NAME': 'com.countersign.app.simulation',
})

print('Countersign Android simulation: http://127.0.0.1:8001', flush=True)
print('Hardware attestation and Play Integrity are SIMULATED. Local testing only.', flush=True)
print('Approval signatures and administrator activation remain required.', flush=True)
print(f'Separate simulation database: {database}', flush=True)
uvicorn.run('service.app:app', host='127.0.0.1', port=8001)
PY
