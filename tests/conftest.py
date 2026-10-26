"""Must run (and set these) before service.app is imported anywhere in the
test session -- Config is built once, at module import time, from the
environment. conftest.py is loaded by pytest before it collects sibling test
modules, which is what makes this timing work.
"""

import os

os.environ.setdefault("COUNTERSIGN_DEV_MODE", "1")
os.environ.setdefault("COUNTERSIGN_SKIP_ATTESTATION", "1")
# Each test run gets its own private in-memory DB -- no file left behind,
# no state leaking between runs.
os.environ.setdefault("COUNTERSIGN_DB_PATH", ":memory:")
os.environ.setdefault("COUNTERSIGN_API_TOKEN", "test-device-token")
os.environ.setdefault("COUNTERSIGN_ADMIN_API_TOKEN", "test-admin-token")
# Must match FakeIntegrityVerifier's make_fake_verdict() default in
# service/integrity.py, so tests don't have to pass it explicitly.
os.environ.setdefault("COUNTERSIGN_APP_CERT_SHA256", "fake-cert-digest")
