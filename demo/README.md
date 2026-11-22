# Demo screenshots

The supplied captures show the physical iPhone flow, the Android emulator flow with simulated attestation, and the Ledger flow on the Speculos emulator (Flex and Nano S+, captured during the automated end-to-end run). Requests contain fictional transfer details.

| Step | iPhone | Android emulator |
| --- | --- | --- |
| Not enrolled | [View](ios/unenrolled.png) | [View](android/not-enrolled.png) |
| Enrolling | [View](ios/enrolling.png) | — |
| Waiting for administrator | [View](ios/enroll-pending-approval.png) | [View](android/pending-approval.png) |
| Enrolled | [View](ios/enrolled.png) | [View](android/enrolled.png) |
| Pending request | [View](ios/request-1.png) | [View](android/request-1.png) |
| Review request | [View](ios/request-2.png) | [View](android/request-2.png) |
| Biometric prompt | — | [View](android/approving.png) |
| Approved | [View](ios/approved.png) | [View](android/approved.png) |

| Step | Ledger Flex (Speculos) | Ledger Nano S+ (Speculos) |
| --- | --- | --- |
| Not enrolled (home) | [View](ledger/flex-not-enrolled.png) | [View](ledger/nanosp-not-enrolled.png) |
| Enrollment prompt | [View](ledger/flex-enroll-prompt.png) | [View](ledger/nanosp-enroll-prompt.png) |
| Enrolled | [View](ledger/flex-enrolled.png) | [View](ledger/nanosp-enrolled.png) |
| Review request | [View](ledger/flex-review-request.png) | [View](ledger/nanosp-review-request.png) |
| Request text | [View](ledger/flex-review-message.png) | [View](ledger/nanosp-review-message.png) |
| Confirm | [View](ledger/flex-review-confirm.png) | — |
| Approved | [View](ledger/flex-approved.png) | [View](ledger/nanosp-approved.png) |
| Declined | — | [View](ledger/nanosp-declined.png) |

On a Ledger the pending list lives in the host bridge (`ledger/host/bridge.py pending`), since the device has no network.
