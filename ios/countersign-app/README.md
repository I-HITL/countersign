# Countersign for iPhone

## Requirements

- A **physical iPhone on the latest iOS**, with Face ID enrolled and Developer Mode enabled. This project currently targets **iOS 27.0+** and builds with Xcode 27 or later. That deployment target is an app requirement, not the minimum OS version of App Attest itself.
- Membership in the **paid Apple Developer Program**. A free Personal Team cannot provision the App Attest capability. See Apple's [supported capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-ios).
- The [shared backend](../../docs/SETUP.md), reachable from the iPhone over HTTPS.

App Attest enrollment and Secure Enclave approval signing require the physical device; the iOS Simulator cannot complete this demo.

## 1. Configure signing and App Attest

Open `Countersign.xcodeproj` and select the **Countersign** target and scheme.

1. In **Signing & Capabilities**, select your Developer Program team and enable automatic signing.
2. Replace `com.countersign.app` with your own unique bundle identifier and register its explicit App ID in your developer account.
3. Ensure **App Attest** is enabled for the target and supported by its provisioning profile. `Countersign/Countersign.entitlements` already contains `com.apple.developer.devicecheck.appattest-environment = development` for an Xcode-installed demo.
4. Connect the iPhone, trust the Mac, and select the phone as the run destination.

Apple documents the [App Attest entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment) and [device signing](https://developer.apple.com/documentation/xcode/running-your-app-in-simulator-or-on-a-device).

## 2. Configure and start the backend

1. Create `.env` and the tokens: [Create `.env`](../../docs/SETUP.md#create-env).
2. Set these in `.env`:

   ```dotenv
   COUNTERSIGN_ENABLED_PLATFORMS=ios
   COUNTERSIGN_IOS_APP_ID=YOUR_APP_ID_PREFIX.your.bundle.identifier
   COUNTERSIGN_IOS_BUNDLE_VERSION=1
   COUNTERSIGN_IOS_ATTESTATION_ENVIRONMENT=development
   COUNTERSIGN_IOS_ATTESTATION_ROOTS_PATH=attestation_roots/apple_app_attestation_root.pem
   ```

   The App ID prefix is normally your 10-character Team ID; use the registered App ID's actual prefix. The bundle identifier and build number must match the signed app.
3. [Start the backend and tunnel](../../docs/SETUP.md#start-the-backend-and-tunnel) and note the HTTPS URL.

## 3. Run the demo

1. Build and run on the iPhone in Xcode.
2. In the app's connection settings, enter the HTTPS URL and the **device token** (`COUNTERSIGN_API_TOKEN`). The token is stored in Keychain; never enter the administrator token.
3. Tap **Enroll this device** and complete Face ID. The app should show **Pending administrator approval**.
4. Activate that enrollment and send a request with the [demo workflow](../../docs/SETUP.md#run-the-demo).
5. Refresh the app, open the request and tap **Approve with Face ID**. The backend verifies the signature over the displayed message. The demo records the decision; it does not transfer money.

For TestFlight or App Store distribution, use a separate backend configured with `COUNTERSIGN_IOS_ATTESTATION_ENVIRONMENT=production` and enroll again. Apple uses production App Attest after distribution regardless of the development entitlement; development and production keys cannot be mixed. See [Apple's environment guidance](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service).

App Attest verifies app/device evidence during enrollment. Face ID protects the separate approval key locally; it is not a server-verifiable biometric receipt. See [security limits](../../docs/SECURITY.md).
