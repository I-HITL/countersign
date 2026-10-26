#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python || ! -f .env ]]; then
  echo "Run 'uv sync --frozen' and create .env as described in docs/SETUP.md."
  exit 1
fi

exec .venv/bin/python - <<'PY'
import os
from dotenv import dotenv_values
import uvicorn

config = dotenv_values('.env')
for flag in ('COUNTERSIGN_DEV_MODE', 'COUNTERSIGN_SKIP_ATTESTATION', 'COUNTERSIGN_SKIP_INTEGRITY'):
    if config.get(flag) == '1':
        raise SystemExit(f'{flag} must be disabled for the live backend')
    os.environ[flag] = '0'
os.environ.update({key: value for key, value in config.items() if value is not None})
print('Countersign live backend: http://127.0.0.1:8000 (real verification enabled)', flush=True)
uvicorn.run('service.app:app', host='127.0.0.1', port=8000)
PY
