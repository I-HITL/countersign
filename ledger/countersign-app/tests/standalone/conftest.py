# Functional tests run against Speculos through Ragger. No golden screenshots:
# every assertion is cryptographic, so the suite runs unchanged on all devices.
pytest_plugins = ("ragger.conftest.base_conftest",)
