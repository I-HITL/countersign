# Backend and demo

Run commands from the repository root. The backend needs Python 3.13+ and [uv](https://docs.astral.sh/uv/getting-started/installation/); install the dependencies before starting either backend:

```sh
uv sync --frozen
```

Pick the backend for your device, then follow the [demo workflow](#run-the-demo):

| Device | Backend | Admin steps |
| --- | --- | --- |
| Android emulator | [Emulator backend](#android-emulator-backend) (simulated checks, loopback only) | Demo page or API |
| Physical Android or iPhone | [Physical-device backend](#physical-device-backend) (strict verification, HTTPS) | API |

## Android emulator backend

```sh
./run_android_simulation.command
```

Keep this process running. It serves `http://127.0.0.1:8001`, uses a separate database in `runs/android-simulation/`, and ignores the real backend's `.env`. Its local device token is `development-device-token`; its administrator token is `development-admin-token`.

Attestation and Play Integrity are simulated. Keep this backend on loopback. Continue with [Android emulator setup](../android/countersign-app/README.md#emulator-demo).

## Physical-device backend

The platform guides ([iPhone](../ios/countersign-app/README.md), [physical Android](../android/countersign-app/README.md#physical-device-with-real-attestation)) walk through the whole sequence and link back here for two shared steps.

### Create `.env`

```sh
cp .env.ios.example .env      # iPhone
cp .env.android.example .env  # physical Android (use one or the other)
chmod 600 .env
```

Generate two different tokens and paste them into `COUNTERSIGN_API_TOKEN` (device) and `COUNTERSIGN_ADMIN_API_TOKEN` (operator):

```sh
python3 -c 'import secrets; print(secrets.token_urlsafe(32)); print(secrets.token_urlsafe(32))'
```

For both platforms on one backend, set `COUNTERSIGN_ENABLED_PLATFORMS=android,ios` and supply both sets of settings. Keep `.env`, service-account JSON, signing keys and databases out of Git.

### Start the backend and tunnel

Once the platform's attestation settings are in `.env`, start the backend (it needs Python 3.13+ and [uv](https://docs.astral.sh/uv/getting-started/installation/)):

```sh
uv sync --frozen
./run_live_backend.command
curl --fail http://127.0.0.1:8000/health
```

Health must report `verification_mode: strict` and your enabled platforms. Missing credentials or trust roots stop startup. Keep `COUNTERSIGN_DEV_MODE`, `COUNTERSIGN_SKIP_ATTESTATION` and `COUNTERSIGN_SKIP_INTEGRITY` at `0`.

The phone needs an HTTPS URL. With Node.js installed, [LocalTunnel](https://github.com/localtunnel/localtunnel) can forward port 8000 (its URL changes on restart):

```sh
npx --yes localtunnel@2.0.2 --port 8000 --local-host 127.0.0.1
```

Confirm `<your-https-url>/health` returns the same JSON. For a hosted demo, use an HTTPS reverse proxy, persistent SQLite storage and one worker.

The app gets only the **device token**; the administrator token stays with the operator.

## Run the demo

1. Run the mobile app and tap **Enroll this device**. On an iPhone, complete the Face ID prompt; on the Android emulator, send the simulated fingerprint described in the Android guide. The app should show **Pending administrator approval**.
2. Activate the enrollment as the administrator, matching the device ID shown in the app:
   - **Emulator backend:** open [the demo page](http://127.0.0.1:8001/v1/demo), enter the administrator token, and click **Approve enrollment**.
   - **Real backend:** the demo page is disabled in strict mode, so use the API. Set `HOST` to your HTTPS URL and `ADMIN` to `COUNTERSIGN_ADMIN_API_TOKEN`:

     ```sh
     curl -s -H "Authorization: Bearer $ADMIN" $HOST/v1/admin/enrollments/pending
     curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
       -d '{"administrator":"you"}' $HOST/v1/admin/enrollments/<device_id>/approve
     ```

   Refresh the iPhone; Android refreshes automatically while its home screen is visible.
3. Send a request to the activated device (the demo page's **Send** button, or on the real backend):

   ```sh
   curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
     -d '{"device_id":"<device_id>","text":"wire transfer of $500 to Alice Chen (Acct ...4471)","ttl_seconds":300}' \
     $HOST/v1/approvals
   ```

4. Open the request on the phone, check its text and expiry, and approve with biometrics or decline. On the emulator, send the fingerprint ID used during Android Settings enrollment, as described in the Android guide.
5. Check the final status (the demo page shows it, or on the real backend):

   ```sh
   curl -s -H "Authorization: Bearer $ADMIN" $HOST/v1/admin/approvals/<ref>
   curl -s -H "Authorization: Bearer $ADMIN" $HOST/v1/admin/approvals/<ref>/proof   # approved requests only
   ```

   The proof holds the signed message, the signature, the enrolled public key and, for Android, the key attestation chain, so a third party can re-verify the approval. Expired requests cannot be approved; create another request to retry.

The API reference is available at `/docs` on either backend. Device operations use `COUNTERSIGN_API_TOKEN`; enrollment activation, request creation, and administrator views use `COUNTERSIGN_ADMIN_API_TOKEN`.
