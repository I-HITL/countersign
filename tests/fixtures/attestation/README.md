# Attestation test fixtures

Real Android Key Attestation certificate chains, copied verbatim from
Google's own reference implementation's test resources:

https://github.com/google/android-key-attestation/tree/master/src/test/resources/pem/algorithm_EC_SecurityLevel_StrongBox
https://github.com/google/android-key-attestation/tree/master/src/test/resources/pem/algorithm_EC_SecurityLevel_TEE

These third-party fixtures retain Google's upstream Apache 2.0 license,
included in [LICENSE](LICENSE). The repository's MIT license does not replace
their upstream terms. The extracted DER files come from the same certificates.

`cert0.pem` is the leaf (the attested key), `cert1.pem`/`cert2.pem` are
intermediates, `cert3.pem` is the (self-signed, example-only -- not a real
production Google root) root. Chain order is leaf-first, matching what
`service/attestation.verify_chain` expects.

`cert0_key_description.der` is the raw bytes of the `KeyDescription`
extension (OID 1.3.6.1.4.1.11129.2.1.17) extracted from `cert0.pem`, via:

```
offset=$(openssl asn1parse -in cert0.pem | grep -A1 "11129.2.1.17" | tail -1 | sed -E 's/^ *([0-9]+):.*/\1/')
openssl asn1parse -in cert0.pem -strparse $offset -noout -out cert0_key_description.der
```

It is checked in separately because `cryptography`'s X.509 loader refuses to
parse `cert0.pem` itself (see the note in `tests/test_attestation.py`). Chains
from current phones do not have this problem.

Both example keys have `hardwareEnforced.noAuthRequired` set (neither requires
user authentication). They are Google's generic demo keys, not biometric-gated
ones, so they serve as a negative test for the policy that requires
authentication. The positive biometric case is covered by synthetic
KeyDescriptions in `tests/test_attestation.py`.
