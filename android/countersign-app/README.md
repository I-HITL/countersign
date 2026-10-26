# Android

Two builds use the same enrollment and approval UI:

| Build | Where to run | Attestation |
| --- | --- | --- |
| `simulation` / **Countersign Sim** | Android emulator | Key Attestation and Play Integrity are simulated; approval signatures are still verified. |
| `debug`, `release` / **Countersign** | Physical Android 11+ device with Google Play services and a strong biometric | Android Key Attestation at enrollment; Play Integrity at enrollment and approval. |

## Emulator demo

1. Complete the [backend prerequisites](../../docs/SETUP.md). Install [Android Studio](https://developer.android.com/studio), Android SDK 36, Build Tools 36.1.0, and an Android 36 Google APIs emulator image matching your computer's architecture. In Device Manager, create a Pixel emulator named `Countersign_API_36`. Use Android Studio's bundled JDK or set `JAVA_HOME` to a JDK supported by the Gradle wrapper (tested with JDK 22).
2. Start the simulation backend from the repository root:

   ```sh
   ./run_android_simulation.command
   ```

   In another terminal, start the app:

   ```sh
   cd android/countersign-app
   export ANDROID_HOME="$HOME/Library/Android/sdk"  # Set your actual SDK path.
   ./open-simulation.command
   ```

   Set `COUNTERSIGN_AVD` if your AVD has a different name. The launcher installs a separate app, forwards port 8001 over ADB, and preserves its data. The service uses its own database and public development credentials; keep it local.
3. In the emulator's Android Settings, create a screen lock and enroll a fingerprint. While the fingerprint enrollment screen requests touches, repeatedly run the command below until enrollment completes. Use the same ID for later authentication:

   ```sh
   "$ANDROID_HOME/platform-tools/adb" devices
   "$ANDROID_HOME/platform-tools/adb" -s emulator-5554 emu finger touch 1
   ```

   Substitute your emulator's serial if different. **Extended Controls → Finger 1** may use a different ID from console ID `1`; mixing them causes **Not recognized**. See [Google's fingerprint simulation guide](https://developer.android.com/studio/run/emulator-console#fingerprint-simulation-and-validation).
4. Tap **Enroll this device**, then use the [backend demo](../../docs/SETUP.md#run-the-demo) to activate the enrollment and send a request. Tap **Approve with biometrics** and send `emu finger touch 1` while the biometric prompt is open.

## Physical device with real attestation

You need a Google Play Console developer account. The phone must pass Play Integrity with `MEETS_STRONG_INTEGRITY` (certified device, locked bootloader, recent security patch) and report a locked, Verified boot state in key attestation; other devices are rejected at enrollment. Do the steps in order.

1. **Create the Play app.** In Play Console, create an app for an application ID you control and set it in `app/build.gradle.kts` (`defaultConfig.applicationId`). Under **Test and release → App integrity**, enable Play Integrity API and link your Cloud project (create one in the [Cloud console](https://console.cloud.google.com/) first if needed). Note the project's numeric **project number**, shown on the Cloud console dashboard under **Project info** and in Play Console next to the linked project; it is not the project ID or name. Also note the SHA-256 fingerprint of the **app signing key certificate**, shown on the same page under **Play app signing**. It is not the fingerprint of your upload key, which is listed beside it.
2. **Create a service account** in that project and download its JSON key. The backend uses it as `GOOGLE_APPLICATION_CREDENTIALS` to decode Standard API tokens; never put it in the app. See Google's [setup](https://developer.android.com/google/play/integrity/setup) and [server verification](https://developer.android.com/google/play/integrity/standard#decrypt-verify).
3. **Create `.env`** from `.env.android.example` and generate the tokens: [Create `.env`](../../docs/SETUP.md#create-env).
4. **Set the Android values in `.env`.**
   - `COUNTERSIGN_PACKAGE_NAME`: the application ID.
   - `COUNTERSIGN_APP_CERT_SHA256`: the Play app signing fingerprint as URL-safe base64. The server checks it against both the Play Integrity verdict and the key attestation, and ignores `=` padding. Convert the fingerprint with:

     ```sh
     python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1].replace(":",""))).decode())' "AB:CD:..."
     ```

   - `COUNTERSIGN_ATTESTATION_ROOTS_PATH`: Google's hardware roots, fetched from the repository root. Keep them current per [Google's guidance](https://developer.android.com/privacy-and-security/security-key-attestation).

     ```sh
     mkdir -p attestation_roots
     curl --fail --silent --show-error https://android.googleapis.com/attestation/root \
       -o attestation_roots/google-roots.json
     python3 - <<'PY'
     import json
     from pathlib import Path
     roots = json.loads(Path("attestation_roots/google-roots.json").read_text())
     assert isinstance(roots, list) and roots
     Path("attestation_roots/google_hardware_attestation_roots.pem").write_text("\n".join(roots) + "\n")
     PY
     ```

   - `GOOGLE_APPLICATION_CREDENTIALS`: the service-account JSON from step 2. The default minimum security level `1` accepts TEE or StrongBox; `2` requires StrongBox. If your phone reports only `MEETS_DEVICE_INTEGRITY`, set `COUNTERSIGN_ALLOWED_DEVICE_INTEGRITY=MEETS_STRONG_INTEGRITY,MEETS_DEVICE_INTEGRITY` for testing.
5. **Start the backend and tunnel:** [Start the backend and tunnel](../../docs/SETUP.md#start-the-backend-and-tunnel). Keep both running and note the HTTPS URL.
6. **Configure the app.** The values are compiled in, so changing any of them needs a rebuild and a new upload.

   ```sh
   cp deployment.properties.example deployment.properties   # ignored by Git
   ```

   Set `backendUrl` (HTTPS, no trailing slash), `deviceApiToken` (the device token only, never the admin token; it is packaged in the APK) and `cloudProjectNumber` (the project number from step 1).
7. **Sign and upload.** In Android Studio, use **Build → Generate Signed Bundle / APK → Android App Bundle**, the `release` variant and your upload keystore (Android Studio can create one; keep it out of Git, for example in the ignored `keystore/` directory, and back it up with its password). Play re-signs the app with its own app signing key, which is the one the backend pins. Raise `versionCode` in `app/build.gradle.kts` for every upload. Upload to an internal testing track and install on the phone as an eligible tester; the verifier requires `PLAY_RECOGNIZED`, so a sideloaded debug APK may not qualify. Disable Play Console test-verdict overrides. See [app signing](https://developer.android.com/studio/publish/app-signing).
8. **Enroll and test.** Enroll a strong biometric in Android Settings, open Countersign and tap **Enroll this device**. If it is rejected, the backend log prints the reasons. Then activate the enrollment, send a request and approve it with the [demo workflow](../../docs/SETUP.md#run-the-demo) (API commands; the real backend has no demo page), and fetch the approval's `/proof`.

This is a public demo, not a completed production verifier. Enrollment checks the key's origin, purpose, biometric policy, boot state and app identity, but revocation checking and complete X.509 path validation remain incomplete; see [security limitations](../../docs/SECURITY.md) before deployment beyond testing.

## Build checks

```sh
./gradlew :app:assembleSimulation :app:lintSimulation
./gradlew :app:assembleDebug :app:lintDebug
./gradlew :app:assembleRelease :app:lintRelease
```

The emulator APK is `app/build/outputs/apk/simulation/app-simulation.apk`. A release built without signing remains unsigned; use the signing workflow above for Play distribution.
