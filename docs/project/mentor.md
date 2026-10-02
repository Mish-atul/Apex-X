# APEX-X: Intern Progress Report & Architecture Evolution

**Project Name:** APEX-X — Autonomous Android Threat Intelligence, Reverse Engineering & C2 Attribution Platform  
**Author / Intern:** Atul Mishra ([GitHub: Mish-atul](https://github.com/Mish-atul))  
**Target Repository:** [https://github.com/Mish-atul/Apex-X.git](https://github.com/Mish-atul/Apex-X.git)  
**Reporting Period:** Post-Hackathon to Current Internship Milestone  
**Document Purpose:** Comprehensive Intern Progress Report covering project evolution, technical difficulties, solutions, architectural implementations, and mentor feedback alignment.

---

## 1. Executive Summary & Hackathon Foundation

### 1.1 Where We Started (The Hackathon MVP)
At the hackathon where APEX-X won 1st place, the system served as a proof-of-concept demonstrating automated static and dynamic APK triage. The original MVP consisted of:
- Basic static decompilation using `apktool` and `jadx` to extract `AndroidManifest.xml` and permissions.
- Basic pattern matching for URLs and IP addresses.
- Initial YARA rule engine scanning for common malware signatures.
- Simulated/mocked dynamic analysis when no Android Virtual Device (AVD) was configured.
- Graph-based visualization of contacted infrastructure and basic CVSS scoring.

### 1.2 The Post-Hackathon Directive
While effective for competition demos, real-world cyber threat investigation (specifically mobile banking trojans, SMS stealers, and targeted droppers rampant in India, such as the **Wedding Invitation scam malware**) requires deep forensic evidence. 

Our mentor directed us to transform APEX-X from an automated scanner into a **forensic-grade mobile investigation workbench** capable of answering critical questions:
1. *Which APK does a connection belong to — the parent dropper APK or the secondary child APK?*
2. *What is the exact data volume (bytes sent and received) transferred over the wire?*
3. *Can we use dynamic instrumentation (Frida) and fake certificates to bypass SSL pinning and inspect encrypted payloads?*
4. *When a fake UPI payment screen appears in a child APK, what API calls is it making and where is it pushing stolen data?*
5. *How exactly are adversaries capturing the victim's UPI PIN and exfiltrating it to C2 servers?*
6. *Can an investigator filter by unique package names, inspect all running/installed apps, and remotely uninstall them from the connected phone?*
7. *When an indicator (IP, URL, UPI ID) is detected during static analysis, can the system point directly to the exact file and line number in the decompiled source code?*

Over the course of this internship period, all 7 directives were fully designed, implemented, and verified in code.

---

## 2. Chronological Changes & Technical Implementation

### Directive 1: Parent APK vs. Child APK Network Attribution
- **Problem:** When an Android malware dropper installs a secondary payload (child APK), both apps run under distinct Android Linux UIDs. Traditional network capture or netstat merges all phone traffic, making it impossible to prove whether a malicious connection was made by the downloaded wedding card app or the dropped banking trojan.
- **Solution:**
  - Implemented UID-to-package tracking in `backend/app/engines/dynamic/device_monitor.py`.
  - The runtime monitor inspects `/proc/net/tcp` and `/proc/net/tcp6`, mapping Linux socket UIDs directly to installed application packages (`pm list packages -U`).
  - Connections are tagged with `apk_type`: `"parent"` (for the primary analyzed APK), `"child"` (for secondary dropped APKs), or `"system"` (for Android background services).
  - In `DynamicTab.tsx`, every network connection displays an **Attribution Badge**:
    - `📱 Parent APK` with package identifier
    - `📦 Child APK` highlighted with high-contrast alert styling
    - `⚙️ System` for background OS processes

### Directive 2: Accurate Data Transfer Sizing & Bandwidth Measurement
- **Problem:** Knowing an IP was contacted is insufficient for court evidence or damage assessment; investigators must know how much data was exfiltrated (e.g. a 50-byte ping vs. a 12 MB exfiltration of photos/SMS).
- **Solution:**
  - Integrated **PCAPdroid** for non-root automated network capture, generating standard `.pcap` files on the device.
  - Implemented kernel traffic byte accounting via `/proc/uid_stat/<uid>/tcp_snd` and `/proc/uid_stat/<uid>/tcp_rcv` polled across the session.
  - Implemented `dumpsys netstats detail` fallback parser to extract per-UID transmission metrics without needing root.
  - Built an automated PCAP stream parser calculating exact total bytes, protocols (TCP, UDP, DNS), and packet counts.
  - The UI now features a dedicated **Data Column** showing `↑ bytes sent / ↓ bytes received` formatted cleanly (e.g. `↑1.4 KB / ↓4.2 KB`) for each destination.

### Directive 3: Dynamic Instrumentation via Frida & SSL Pinning Bypass (Fake Certs)
- **Problem:** Modern Android banking trojans use HTTPS with certificate pinning (OkHttp3 `CertificatePinner`, Network Security Config, or custom `TrustManager`), rendering Wireshark and proxy tools blind.
- **Solution:**
  - Created `backend/app/engines/dynamic/frida_manager.py` managing the complete Frida server lifecycle on connected physical devices.
  - Automatic architecture detection (`arm64-v8a`, `armeabi-v7a`, `x86_64`) via `ro.product.cpu.abi` with auto-download and push of matching `frida-server`.
  - Built `backend/app/engines/dynamic/frida_scripts/ssl_network_hooks.js`:
    1. **TrustManager Hook:** Injects a custom `com.apexx.TrustManager` into `javax.net.ssl.SSLContext.init()` that trusts all certificates (fake certificate injection).
    2. **OkHttp3 Bypass:** Hooks `okhttp3.CertificatePinner.check()` and `check$okhttp()` to disable certificate pinning checks.
    3. **WebView SSL Bypass:** Hooks `WebViewClient.onReceivedSslError()` and invokes `handler.proceed()`.
    4. **Network Interceptor:** Hooks `RealCall.execute()` in OkHttp and `URL.openConnection()` to capture HTTP method, full URL, request headers, and full payload bodies (up to 4KB).

### Directive 4 & 5: UPI Screen, PIN Capture & API Push Forensics
- **Problem:** In mobile banking fraud, adversaries capture UPI PINs through deceptive screens. Mentors and investigators need clarity on the exact mechanics: *How is the PIN stolen? What API call is made? Where is it pushed?*
- **Solution:**
  - Developed `backend/app/engines/dynamic/frida_scripts/upi_payment_hooks.js` and a dedicated **UPI Payment & Credential Theft Forensics** intelligence panel.
  - **Capture Mechanism Unveiled:**
    - **Overlay Attack (`SYSTEM_ALERT_WINDOW`):** The child APK renders a full-screen window mimicking an NPCI / Bank UPI gateway on top of legitimate apps.
    - **Accessibility Service Keylogger (`AccessibilityService`):** Exploits accessibility permissions to read `AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED` and `TYPE_VIEW_FOCUSED` events across the entire OS.
    - **EditText Hooking:** Hooks `android.widget.EditText.getText()` detecting `TYPE_NUMBER_VARIATION_PASSWORD` fields to capture 4-digit or 6-digit numeric UPI PINs in cleartext.
    - **SharedPreferences Scraping:** Hooks `SharedPreferencesImpl$EditorImpl.putString()` flagging keys containing `pin`, `upi`, `otp`, `vpa`, or `token`.
  - **Exfiltration Vector Unveiled:**
    - Traces the exact outbound API call (e.g. `POST https://103.250.147.228:8443/api/v1/collect_upi` or Telegram Bot API `sendMessage`).
    - Maps out the payload structure: `{ device_id, upi_vpa, upi_pin, bank_name, sms_otp }`.
    - Quantifies data exfiltration volume (~1.4 KB) and correlates it with the child APK process.

### Directive 6: Package-Based Filtering & Multi-Stage Device Uninstallation
- **Problem:** Malware on test devices must be isolated by package name and completely eradicated without leaving residual background services, auto-start receivers, or cached payload files.
- **Solution:**
  - Added package-level filtering across all timeline events and network connections in `DynamicTab.tsx`.
  - Built a multi-stage uninstallation pipeline in `_uninstall_packages_from_device()` in `device_monitor.py`:
    1. `am force-stop <pkg>`: Immediately terminates all active threads and activities.
    2. `pm clear <pkg>`: Wipes all app data, local databases, shared preferences, and cached payloads.
    3. `adb uninstall <pkg>`: Standard package manager removal.
    4. `pm uninstall <pkg>`: Shell fallback.
    5. `pm uninstall --user 0 <pkg>`: Removal from user 0 (removes icon from launcher and workspace).
    6. `pm uninstall -k --user 0 <pkg>`: Fallback keeping caches if deletion fails.
    7. `pm disable-user --user 0 <pkg>`: Disables and quarantines the package if uninstall is locked.
    8. Root fallback (`su -c pm uninstall`): High-privilege removal for system-installed persistence.
  - Exposed via REST endpoints `POST /cases/{id}/pentest/clean` and `POST /cases/{id}/pentest/uninstall-package`.
  - Added individual `[🗑 Uninstall]` buttons per child application in the UI table.

### Directive 7: Static Analysis Code Pointers for IPs & IOCs (Connecting Indicators to Code)
- **Problem:** Static analysis tools traditionally report a list of IPs or URLs without telling the reverse engineer where that indicator exists in the APK code.
- **Solution:**
  - Enhanced `backend/app/engines/static/ioc_extractor.py` to scan Smali bytecode, Java decompilations, XML manifests, and JSON resources line-by-line with exact line number tracking.
  - Built `code_references`:
    ```json
    {
      "103.250.147.228": [
        {
          "file": "smali/net/noce/vihupi/neyuyu/suvupo/MainActivity.smali",
          "line": 142,
          "context": "const-string v0, \"103.250.147.228\""
        }
      ]
    }
    ```
  - Upgraded `IOCTable.tsx` with a **Code Location** column rendering interactive badges (`⚡ MainActivity.smali:142`) with full code context and copyable references.
  - Implemented **Static-to-Dynamic Cross-Referencing**: Runtime network connections in `DynamicTab.tsx` cross-reference the static IOC database and display `⚡ Found in Code` pointing to the exact Smali source file.

### Directive 8: Total C2 Intelligence Integration (Static + Dynamic + VirusTotal)
- **Problem:** C2 infrastructure graphs were previously fragmented, displaying only static URLs or only runtime connections.
- **Solution:**
  - In `backend/app/engines/c2/__init__.py` and `graph_builder.py`, integrated all three data sources:
    1. **Static Analysis:** Hardcoded C2 IPs, domains, and base64-decoded endpoints.
    2. **Dynamic Analysis:** Live sockets, PCAP capture, and Frida-intercepted URLs.
    3. **VirusTotal v3 API:** Sandbox behaviors, DNS resolutions, contacted IP telemetry, and multi-engine AV detection ratios.
  - Graph construction unifies all nodes into a consolidated threat infrastructure map with automated family attribution (e.g., SpyNote, SOVA, FakeGov, WeddingMalware).

---

## 3. Difficulties & Engineering Challenges Faced

1. **Android Permission & Root Barriers on Physical Devices:**
   - *Challenge:* Frida and raw socket inspection typically require root (`su`), but forensic workstations often inspect non-rooted consumer test devices.
   - *Mitigation:* Implemented a tiered strategy: when root is detected, Frida hooks and raw sockets are activated; on unrooted devices, APEX-X falls back to PCAPdroid VPN interception, `dumpsys netstats`, and static heuristic bytecode analysis.

2. **Self-Deleting Dropper APKs:**
   - *Challenge:* Advanced droppers install a child APK, launch it, and immediately delete or uninstall themselves to hinder detection.
   - *Mitigation:* Implemented continuous background polling (`_package_poll_thread`) combined with pre-session and post-session diff snapshots so transient child APKs are logged the millisecond they register with Android's `PackageManager`.

3. **Frida Multi-Architecture Deployment:**
   - *Challenge:* Pushing an x86 Frida server binary to an ARM64 physical device causes silent crashes.
   - *Mitigation:* Built ABI architecture detection (`ro.product.cpu.abi`) that queries GitHub releases, pulls the precise matching version (`arm64`, `arm`, `x86_64`), decompresses XZ archives in memory, and starts the daemon with proper SELinux permissions.

4. **False Positive Domain Filtering:**
   - *Challenge:* Java/Kotlin package strings (e.g. `android.view`, `java.lang`, `rect.bottom`) match generic regex patterns for domain names.
   - *Mitigation:* Engineered a strict filtering heuristic with whitelists for common package prefixes, method names, and false-positive suffixes.

5. **Cross-Platform Pathing & Windows CRLF Inconsistencies:**
   - *Challenge:* Smali decompilations generated on Windows created backslash paths, while Linux tools expected forward slashes.
   - *Mitigation:* Normalized all relative file paths across the backend and frontend using POSIX-standard forward slashes.

---

## 4. Ideas & Technologies Used

| Domain | Technology / Library | Purpose in APEX-X |
|---|---|---|
| **Backend Core** | Python 3.11, FastAPI, Pydantic | High-performance asynchronous REST API backend |
| **Database & ORM** | PostgreSQL / SQLite, SQLAlchemy | Case management, audit logs, and analysis artifacts |
| **Android Disassembly** | `apktool`, `jadx`, Smali | Bytecode decompilation, manifest parsing, source extraction |
| **Static Threat Detection** | YARA (`yara-python`) | Signature matching for banking trojans, SMS stealers |
| **Dynamic Instrumentation** | Frida Framework, JavaScript Hooks | SSL pinning bypass, fake cert injection, UPI PIN capture |
| **Network Interception** | PCAPdroid, Scapy, ADB | Physical device packet capture, TCP/UDP byte accounting |
| **Threat Intelligence** | VirusTotal v3 API | Cloud sandbox correlation, multi-scanner verdicts |
| **Frontend Framework** | Next.js 14 (App Router), React, TypeScript | Investigator portal with zero-lag state management |
| **Styling & Aesthetics** | Tailwind CSS, Dark Mode, Glassmorphism | Forensic workstation UI adhering to professional standards |

---

## 5. Summary of Modified Codebase Files

- **`backend/app/engines/dynamic/frida_manager.py`**: Complete Frida instrumentation manager for Android devices.
- **`backend/app/engines/dynamic/frida_scripts/ssl_network_hooks.js`**: TrustManager, OkHttp3, and WebView SSL bypass hooks.
- **`backend/app/engines/dynamic/frida_scripts/upi_payment_hooks.js`**: EditText, SharedPreferences, and Intent monitoring hooks for UPI fraud.
- **`backend/app/engines/dynamic/device_monitor.py`**: Physical device monitoring, UID attribution, PCAP parsing, multi-stage package uninstallation.
- **`backend/app/engines/static/ioc_extractor.py`**: Line-by-line IOC extractor with file and line code reference tracking.
- **`backend/app/engines/c2/__init__.py` & `graph_builder.py`**: Static + Dynamic + VirusTotal unified C2 graph builder.
- **`backend/app/api/routes/cases.py`**: REST endpoints for pentest control, device cleanup, and single-package uninstallation.
- **`frontend/src/app/cases/[id]/DynamicTab.tsx`**: Attribution badges, package filtering, per-child package uninstallation, UPI forensics panel.
- **`frontend/src/app/cases/[id]/StaticTab.tsx`**: Passes line references to IOC tables.
- **`frontend/src/components/IOCTable.tsx`**: Renders clickable code location references (`⚡ file:line`) with context.
- **`frontend/src/services/api.ts`**: API client methods for device management and remote package uninstallation.

---

## 6. Next Steps & Future Roadmap

1. **Automated Evidence Report Generation:** Exporting court-admissible PDF forensic reports complying with Indian Evidence Act Section 65B requirements.
2. **Memory Dump Analysis:** Live process memory dumping (`gcore`/Frida) to capture dynamically decrypted DEX payloads in RAM.
3. **Real-Time Device Screen Mirroring:** Embedding `scrcpy` over WebSocket into the APEX-X dashboard for real-time interaction alongside logcat.

---
*Report prepared by Atul Mishra for Mentor Review & Progress Assessment.*
