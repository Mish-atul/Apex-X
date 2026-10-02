# Dynamic Analysis — Automated Emulator Sandbox

APEX-X runs every uploaded APK through **real dynamic analysis inside an Android
emulator that the backend boots automatically**. No physical phone and no USB
cable are required. If no emulator can be started, the platform falls back to a
clearly-labelled code-level heuristic scan.

## How it works

For each case, after static analysis completes, the backend:

1. **Boots an Android emulator** (`emulator_manager.ensure_emulator`) using the
   Android SDK. It prefers a dedicated, rooted AVD named `ApexX_Sandbox`.
2. **Installs the APK** and resolves its Linux UID so all evidence can be scoped
   to the app itself (system/Google background noise is excluded).
3. **Instruments the app with Frida** (`frida_manager`): it spawns the app with
   hooks already in place and records sensitive API usage
   (`frida_scripts/apex_monitor.js`) — device-ID reads, SMS, contacts/SMS
   content queries, clipboard access, `Runtime.exec`, dynamic code loading,
   accessibility-service activation, location and crypto. TLS interception
   (`ssl_network_hooks.js`) is available behind `APEX_FRIDA_SSL=1`.
4. **Exercises the UI** with the Android Monkey, relaunching the app if it
   navigates away or crashes.
5. **Injects external stimuli** (`emulator_manager.simulate_events`) — an
   incoming SMS/OTP, a GPS fix, low battery, a connectivity toggle and key
   broadcasts — so trigger-based malware runs its payload.
6. **Collects evidence**, all attributed to the app's UID:
   - logcat (its own lines + system-server lines naming the package)
   - sockets owned by the UID, polled for the whole run
   - a full packet capture from the emulator NIC (DNS names, TLS SNI, byte
     counts), parsed with scapy
   - AppOps actually exercised, running services, kernel per-UID traffic counters
   - packages installed during the run (dropper detection)
7. **Re-correlates** C2 intelligence and the vulnerability scan with the new
   runtime data, then **uninstalls** the sample to keep the sandbox clean.

The live stage (booting → installing → executing → collecting) is exposed at
`GET /api/v1/cases/{id}/dynamic/status` and shown in the UI.

## Prerequisites

- Android SDK with `emulator`, `platform-tools` (adb) and `build-tools`.
- A rooted (non-Play-Store) system image, e.g.
  `system-images;android-35;google_apis;x86_64`.
- An AVD. A dedicated one is recommended:
  ```
  avdmanager create avd -n ApexX_Sandbox -k "system-images;android-35;google_apis;x86_64" -d medium_phone
  ```
- Hardware acceleration (WHPX/HAXM/KVM). Verify with `emulator -accel-check`.
- `frida-server` matching the installed `frida` version, placed in
  `tools/frida/` (git-ignored). The platform pushes and starts it automatically.

## Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `APEX_AUTO_DYNAMIC` | `1` | Run dynamic analysis automatically after upload |
| `APEX_DYNAMIC_DURATION` | `90` | Seconds to exercise the app |
| `APEX_AVD_NAME` | _(auto)_ | Force a specific AVD |
| `APEX_EMULATOR_HEADLESS` | `0` | `1` launches the emulator with `-no-window` |
| `APEX_EMULATOR_BOOT_TIMEOUT` | `600` | Max seconds to wait for boot |
| `APEX_ENABLE_FRIDA` | `1` | Enable Frida instrumentation |
| `APEX_FRIDA_SSL` | `0` | Also load the TLS-interception script (heavier) |
| `APEX_KEEP_INSTALLED` | `0` | `1` keeps the sample installed after the run |
| `APEX_DATA_DIR` | `backend/data` | Root for cases, reports and the RAG index |
| `APEX_CORS_ORIGINS` | localhost dev origins | Comma-separated allowed origins |

## Accuracy and limitations

Dynamic analysis is real but not infallible. Emulator-aware malware may stay
dormant (Frida cloaking reduces but does not eliminate this), UI exploration is
automated rather than goal-driven, and HTTPS payloads are only decrypted when
`APEX_FRIDA_SSL` is enabled. Results always record which mode produced them
(`emulator` = real execution, `heuristic` = static code scan).
