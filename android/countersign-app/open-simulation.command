#!/bin/bash
# Start the isolated Android emulator demo.
set -euo pipefail
cd "$(dirname "$0")"
android_sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
adb_bin="$android_sdk/platform-tools/adb"
emulator_bin="$android_sdk/emulator/emulator"
avd_name="${COUNTERSIGN_AVD:-Countersign_API_36}"
if [[ ! -x "$adb_bin" || ! -x "$emulator_bin" ]]; then
  echo "Android SDK not found at $android_sdk. See README.md in this folder."
  exit 1
fi
export ANDROID_HOME="$android_sdk"
"$adb_bin" start-server
find_device() {
  local candidate
  for candidate in $("$adb_bin" devices | awk '$1 ~ /^emulator-/ && $2 == "device" { print $1 }'); do
    if [[ "$("$adb_bin" -s "$candidate" emu avd name 2>/dev/null | head -n 1 | tr -d '\r')" == "$avd_name" ]]; then
      echo "$candidate"
      return
    fi
  done
}
device_serial="$(find_device)"
if [[ -z "$device_serial" ]]; then
  if ! "$emulator_bin" -list-avds | grep -Fxq "$avd_name"; then
    echo "The $avd_name virtual device is missing. See README.md for setup."
    exit 1
  fi
  nohup "$emulator_bin" -avd "$avd_name" -no-boot-anim > "${TMPDIR:-/tmp/}countersign-emulator.log" 2>&1 &
  echo "Starting the Countersign Android emulator…"
fi
./gradlew :app:assembleSimulation --console=plain
for attempt in {1..120}; do
  device_serial="$(find_device)"
  if [[ -n "$device_serial" && "$("$adb_bin" -s "$device_serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; then
    break
  fi
  sleep 2
done
if [[ -z "$device_serial" || "$("$adb_bin" -s "$device_serial" shell getprop sys.boot_completed | tr -d '\r')" != "1" ]]; then
  echo "The emulator has not finished starting. Run this launcher again after it boots."
  exit 1
fi
"$adb_bin" -s "$device_serial" install -r app/build/outputs/apk/simulation/app-simulation.apk
application_id="$(python3 -c 'import json; print(json.load(open("app/build/outputs/apk/simulation/output-metadata.json"))["applicationId"])')"
"$adb_bin" -s "$device_serial" reverse tcp:8001 tcp:8001
"$adb_bin" -s "$device_serial" shell am start -n "$application_id/com.example.countersign.MainActivity"
printf '\nCountersign Sim is open. Keep ../../run_android_simulation.command running.\n'
printf 'Set up an emulator screen lock and fingerprint in Android Settings before enrolling the app.\n'
