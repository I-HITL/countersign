# Prototype limitations

Countersign is a prototype of the I-HITL design, not an audited service. See the paper for the design and its guarantees.

- **Android verification:** the service checks the attestation chain's signatures, validity periods, CA constraints and trust root, but not certificate revocation or full X.509 path validation. Google's root certificates must be refreshed by hand.
- **iPhone:** App Attest is checked at enrollment only. It does not attest that the confirmation key lives in the Secure Enclave or requires biometrics; those properties rely on the genuine app and OS.
- **Proof of approval:** `GET /v1/admin/approvals/{ref}/proof` returns the signed message, signature, public key and, for Android, the attestation chain. It omits the Play Integrity verdict, which can only be decoded with the operator's Google Cloud credentials, so independent verification would need access to that service account. The iPhone proof does not include the attestation.
- **Android emulator:** the simulation build and backend skip attestation and Play Integrity. A simulated fingerprint is a test input.
- **Display:** the Android approval screen's overlay defenses are best-effort, and the screen is not a protected display.
- **Service:** The backend is a minimal implementation using shared bearer tokens (the device token is compiled into the Android app), a single-process SQLite store, and no rate limiting, tenant isolation or device revocation.
- **Testing:** the automated tests use Google's example certificates and synthetic data. Real-device flows must be run by hand.
