"""
Frida Manager — Dynamic Instrumentation for APEX-X
Manages Frida server setup, hook injection, and message collection
for SSL interception, network monitoring, and UPI/payment capture.
"""

import os
import time
import logging
import threading
import subprocess
from typing import Dict, Any, List
from datetime import datetime, timezone
from uuid import uuid4

from app.engines.dynamic import vm_orchestrator

logger = logging.getLogger(__name__)

# Frida server binary location on device
FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
FRIDA_SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "frida_scripts")

# Architecture mapping from Android CPU ABI to Frida release name
ABI_TO_FRIDA_ARCH = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}


class FridaManager:
    """Manages Frida instrumentation lifecycle for a device/package."""

    def __init__(self, device_serial: str, package_name: str):
        self.device = device_serial
        self.package = package_name
        self.session = None
        self.scripts = []
        self.messages: List[Dict[str, Any]] = []
        self._message_lock = threading.Lock()
        self._frida_available = False
        self._device_obj = None
        self.attach_mode = None  # "spawn" | "attach"

        # Check if frida Python module is available
        try:
            import frida
            self._frida_available = True
        except ImportError:
            logger.warning("[Frida] frida Python module not installed. Run: pip install frida frida-tools")

    def is_available(self) -> bool:
        """Check if Frida is usable (Python module + server on device)."""
        return self._frida_available

    # ═══════════════════════════════════════════════════════════
    # SETUP — Ensure frida-server is running on the device
    # ═══════════════════════════════════════════════════════════

    def _su(self, command: str) -> Dict[str, Any]:
        """Run a root shell command. Emulators booted with `adb root` already run the
        shell as uid 0; physical/Magisk devices need `su 0 -c`. Try both."""
        direct = vm_orchestrator._run_adb(["shell", command], device=self.device, timeout=15)
        if direct["success"] and "permission denied" not in (direct["stdout"] + direct["stderr"]).lower():
            return direct
        return vm_orchestrator._run_adb(["shell", "su", "0", "-c", command], device=self.device, timeout=15)

    def check_root(self) -> bool:
        """Check if the device has root access (adb root or su)."""
        if "uid=0" in vm_orchestrator._run_adb(["shell", "id"], device=self.device, timeout=5)["stdout"]:
            logger.info("[Frida] Root confirmed (adb root)")
            return True
        if "uid=0" in self._su("id")["stdout"]:
            logger.info("[Frida] Root confirmed (su)")
            return True
        logger.warning("[Frida] No root access on device — Frida requires root")
        return False

    def is_frida_server_running(self) -> bool:
        """Check if frida-server is already running on the device."""
        pid = self._su("pidof frida-server")["stdout"].strip()
        if pid:
            return True
        ps = self._su("ps -A")["stdout"]
        return "frida-server" in ps

    def setup_frida_server(self) -> bool:
        """
        Ensure frida-server is installed and running on the device.
        Downloads the correct version if needed.
        """
        if not self._frida_available:
            return False

        if not self.check_root():
            logger.error("[Frida] Cannot setup without root access")
            return False

        # Check if already running
        if self.is_frida_server_running():
            logger.info("[Frida] frida-server already running")
            return True

        # Check if binary exists on device
        check = self._su(f"ls -la {FRIDA_SERVER_PATH}")
        
        if not check["success"] or "No such file" in check.get("stderr", ""):
            # Prefer the binary bundled in tools/frida; only hit the network if absent
            if not self._push_frida_server_fallback():
                if not self._download_and_push_frida_server():
                    return False

        # Start frida-server
        return self._start_frida_server()

    def _get_device_arch(self) -> str:
        """Get the device CPU architecture."""
        result = vm_orchestrator._run_adb(
            ["shell", "getprop", "ro.product.cpu.abi"],
            device=self.device, timeout=5
        )
        if result["success"]:
            abi = result["stdout"].strip()
            return ABI_TO_FRIDA_ARCH.get(abi, "arm")
        return "arm"  # Default fallback

    def _download_and_push_frida_server(self) -> bool:
        """Download the correct frida-server binary and push to device."""
        try:
            import frida
            frida_version = frida.__version__
        except ImportError:
            logger.error("[Frida] Cannot determine Frida version")
            return False

        arch = self._get_device_arch()
        filename = f"frida-server-{frida_version}-android-{arch}"
        url = f"https://github.com/frida/frida/releases/download/{frida_version}/{filename}.xz"

        logger.info(f"[Frida] Downloading frida-server v{frida_version} for {arch}...")

        # Download to temp location
        import tempfile
        temp_dir = tempfile.mkdtemp()
        xz_path = os.path.join(temp_dir, f"{filename}.xz")
        server_path = os.path.join(temp_dir, "frida-server")

        try:
            import urllib.request
            urllib.request.urlretrieve(url, xz_path)
            logger.info(f"[Frida] Downloaded to {xz_path}")
        except Exception as e:
            logger.error(f"[Frida] Download failed: {e}")
            # Try alternative: use frida-tools to get the server
            return self._push_frida_server_fallback()

        # Decompress .xz
        try:
            import lzma
            with lzma.open(xz_path) as f_in:
                with open(server_path, "wb") as f_out:
                    f_out.write(f_in.read())
        except Exception as e:
            logger.error(f"[Frida] XZ decompression failed: {e}")
            return False

        # Push to device
        push_result = vm_orchestrator._run_adb(
            ["push", server_path, FRIDA_SERVER_PATH],
            device=self.device, timeout=30
        )
        if not push_result["success"]:
            logger.error(f"[Frida] Push failed: {push_result.get('error')}")
            return False

        # Set permissions
        self._su(f"chmod 755 {FRIDA_SERVER_PATH}")

        logger.info("[Frida] frida-server pushed and ready")
        return True

    def _push_frida_server_fallback(self) -> bool:
        """Push a frida-server binary bundled in tools/frida or tools/ that matches this arch + version."""
        try:
            import frida
            version = frida.__version__
        except ImportError:
            version = ""
        arch = self._get_device_arch()
        backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        repo_root = os.path.dirname(backend_root)
        search_dirs = [os.path.join(repo_root, "tools", "frida"), os.path.join(repo_root, "tools"),
                       os.path.join(backend_root, "tools", "frida")]

        candidates = []
        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            for f in os.listdir(d):
                if f.startswith("frida-server") and arch in f:
                    candidates.append(os.path.join(d, f))
        # Prefer an exact version match so the Python client and server agree
        candidates.sort(key=lambda p: (version and version in os.path.basename(p)), reverse=True)

        for local_path in candidates:
            logger.info(f"[Frida] Pushing bundled frida-server: {local_path}")
            push_result = vm_orchestrator._run_adb(
                ["push", local_path, FRIDA_SERVER_PATH], device=self.device, timeout=120
            )
            if push_result["success"]:
                self._su(f"chmod 755 {FRIDA_SERVER_PATH}")
                return True
        logger.warning("[Frida] No bundled frida-server found for arch=%s version=%s", arch, version)
        return False

    def _start_frida_server(self) -> bool:
        """Start frida-server on the device in background."""
        # Kill any existing instance
        self._su("pkill -f frida-server")
        time.sleep(1)

        # Start detached via setsid so it survives the adb command returning.
        # Emulators rooted through `adb root` run the shell as uid 0 already, so try
        # a plain shell first and fall back to `su -c` for devices that need it.
        adb = vm_orchestrator._find_adb()
        # chmod in the same shell as exec: a fresh `adb push` lands as 0666 and SELinux
        # refuses to execute it until the +x bit is set in this invocation.
        start_cmd = (f"chmod 755 {FRIDA_SERVER_PATH}; "
                     f"setsid {FRIDA_SERVER_PATH} -D </dev/null >/dev/null 2>&1 &")
        for wrapper in ([], ["su", "0", "-c"]):
            cmd = [adb, "-s", self.device, "shell"] + wrapper + [start_cmd]
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL)
            except Exception as e:
                logger.error(f"[Frida] Failed to launch frida-server: {e}")
                continue
            for _ in range(6):
                time.sleep(1)
                if self.is_frida_server_running():
                    logger.info("[Frida] frida-server started successfully")
                    return True
        logger.error("[Frida] frida-server failed to start")
        return False

    # ═══════════════════════════════════════════════════════════
    # ATTACH — Connect to target app and inject hooks
    # ═══════════════════════════════════════════════════════════

    def attach(self) -> bool:
        """Attach Frida to the target package."""
        if not self._frida_available:
            return False

        try:
            import frida

            # Connect to device
            self._device_obj = frida.get_usb_device(timeout=10)
            logger.info(f"[Frida] Connected to device: {self._device_obj.name}")

            # Try to attach to running process
            try:
                self.session = self._device_obj.attach(self.package)
                logger.info(f"[Frida] Attached to running process: {self.package}")
            except frida.ProcessNotFoundError:
                # Spawn the process
                logger.info(f"[Frida] Process not running, spawning: {self.package}")
                pid = self._device_obj.spawn([self.package])
                self.session = self._device_obj.attach(pid)
                self._device_obj.resume(pid)
                logger.info(f"[Frida] Spawned and attached to PID {pid}")

            self.session.on("detached", self._on_detached)
            return True

        except Exception as e:
            logger.error(f"[Frida] Attach failed: {e}")
            return False

    def spawn_and_inject(self, script_names: List[str] = None) -> bool:
        """
        Spawn the app paused, inject hooks, then resume — so instrumentation
        (SSL unpinning, API monitors) is active before any app code executes.
        Returns True if hooks were injected into a live session.
        """
        if not self._frida_available:
            return False
        import frida
        try:
            try:
                self._device_obj = frida.get_device(self.device, timeout=10)
            except Exception:
                self._device_obj = frida.get_usb_device(timeout=10)
        except Exception as e:
            logger.error(f"[Frida] Device unavailable: {e}")
            return False
        logger.info(f"[Frida] Using device: {self._device_obj.name}")

        # Spawn can time out while a freshly booted device is still warming up.
        # Retry with a force-stop in between, backing off each time.
        last_err = None
        for attempt in range(1, 4):
            try:
                vm_orchestrator._run_adb(["shell", "am", "force-stop", self.package], device=self.device)
                pid = self._device_obj.spawn([self.package])
                self.session = self._device_obj.attach(pid)
                self.session.on("detached", self._on_detached)
                results = self.inject_hooks(script_names)
                self._device_obj.resume(pid)
                self.attach_mode = "spawn"
                logger.info(f"[Frida] Spawned {self.package} (pid {pid}, attempt {attempt}); hooks: {results}")
                return any(results.values()) if isinstance(results, dict) else False
            except Exception as e:
                last_err = e
                logger.warning(f"[Frida] Spawn attempt {attempt} failed: {e}")
                self._cleanup_session()
                time.sleep(3 * attempt)

        # Fallback: launch normally, then attach to the running process
        try:
            vm_orchestrator.launch_app(self.package, device=self.device)
            for _ in range(10):
                time.sleep(1)
                pid = vm_orchestrator._run_adb(["shell", "pidof", self.package], device=self.device)["stdout"].split()
                if pid:
                    self.session = self._device_obj.attach(int(pid[0]))
                    self.session.on("detached", self._on_detached)
                    results = self.inject_hooks(script_names)
                    self.attach_mode = "attach"
                    logger.info(f"[Frida] Attached to running {self.package} (pid {pid[0]}); hooks: {results}")
                    return any(results.values()) if isinstance(results, dict) else False
        except Exception as e:
            last_err = e
        logger.error(f"[Frida] Instrumentation failed after retries: {last_err}")
        return False

    def _cleanup_session(self):
        for s in self.scripts:
            try:
                s.unload()
            except Exception:
                pass
        self.scripts.clear()
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None

    def _on_detached(self, reason, crash):
        """Handle Frida session detach."""
        logger.warning(f"[Frida] Session detached: reason={reason}")
        if crash:
            logger.error(f"[Frida] Crash report: {crash}")
        with self._message_lock:
            self.messages.append({
                "type": "frida_event",
                "subtype": "detached",
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    # ═══════════════════════════════════════════════════════════
    # INJECT — Load JavaScript hooks
    # ═══════════════════════════════════════════════════════════

    def inject_hooks(self, script_names: List[str] = None) -> Dict[str, bool]:
        """Inject Frida JavaScript hooks into the attached process."""
        if not self.session:
            return {"error": "Not attached"}

        if script_names is None:
            script_names = ["ssl_network_hooks.js", "upi_payment_hooks.js"]

        results = {}
        for script_name in script_names:
            script_path = os.path.join(FRIDA_SCRIPTS_DIR, script_name)
            if not os.path.exists(script_path):
                logger.error(f"[Frida] Script not found: {script_path}")
                results[script_name] = False
                continue

            try:
                with open(script_path, "r", encoding="utf-8") as f:
                    source = f.read()

                script = self.session.create_script(source)
                script.on("message", self._on_message)
                script.load()
                self.scripts.append(script)
                results[script_name] = True
                logger.info(f"[Frida] Loaded script: {script_name}")

            except Exception as e:
                logger.error(f"[Frida] Failed to load {script_name}: {e}")
                results[script_name] = False

        return results

    def _on_message(self, message, data):
        """Handle messages from Frida scripts."""
        if message["type"] == "send":
            payload = message["payload"]
            payload["_frida_timestamp"] = datetime.now(timezone.utc).isoformat()
            payload["_package"] = self.package

            with self._message_lock:
                self.messages.append(payload)

            # Log important events
            msg_type = payload.get("type", "")
            if msg_type == "network":
                url = payload.get("url", "")
                method = payload.get("method", "")
                logger.info(f"[Frida] HTTP {method} {url}")
            elif msg_type == "upi_input":
                logger.info(f"[Frida] UPI input captured: {payload.get('subtype', '')}")
            elif msg_type == "ssl_bypass":
                logger.info(f"[Frida] SSL bypass: {payload.get('detail', '')}")

        elif message["type"] == "error":
            logger.error(f"[Frida] Script error: {message.get('description', '')}")

    # ═══════════════════════════════════════════════════════════
    # COLLECT — Get all captured messages
    # ═══════════════════════════════════════════════════════════

    def collect_messages(self) -> List[Dict[str, Any]]:
        """Get all collected Frida messages (thread-safe)."""
        with self._message_lock:
            return list(self.messages)

    def collect_network_events(self) -> List[Dict[str, Any]]:
        """Extract network-related events from collected messages."""
        with self._message_lock:
            return [m for m in self.messages if m.get("type") == "network"]

    def collect_upi_events(self) -> List[Dict[str, Any]]:
        """Extract UPI/payment-related events."""
        with self._message_lock:
            return [m for m in self.messages if m.get("type") in ("upi_input", "data_access")]

    def collect_dns_events(self) -> List[Dict[str, Any]]:
        """Extract DNS lookup events."""
        with self._message_lock:
            return [m for m in self.messages if m.get("type") == "dns"]

    def collect_intent_events(self) -> List[Dict[str, Any]]:
        """Extract intent/IPC events."""
        with self._message_lock:
            return [m for m in self.messages if m.get("type") == "intent"]

    # ═══════════════════════════════════════════════════════════
    # CONVERT — Transform Frida events into APEX-X report format
    # ═══════════════════════════════════════════════════════════

    def to_network_activity(self) -> List[Dict[str, Any]]:
        """Convert Frida network events to the network_activity format."""
        network_events = self.collect_network_events()
        dns_events = self.collect_dns_events()

        # Build DNS lookup table
        dns_map = {}
        for d in dns_events:
            dns_map[d.get("resolved_ip", "")] = d.get("hostname", "")

        activity = []
        seen = set()

        for evt in network_events:
            subtype = evt.get("subtype", "")

            if subtype in ("okhttp_request", "url_connection"):
                url = evt.get("url", "")
                if not url or url in seen:
                    continue
                seen.add(url)

                # Parse URL to extract host/port
                import urllib.parse
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or (443 if parsed.scheme == "https" else 80)

                activity.append({
                    "destination": host,
                    "hostname": host,
                    "ip": "",
                    "port": str(port),
                    "protocol": "HTTPS" if parsed.scheme == "https" else "HTTP",
                    "direction": "OUTBOUND",
                    "first_seen": evt.get("_frida_timestamp", ""),
                    "bytes_sent": len(evt.get("body", "")),
                    "bytes_received": 0,
                    "source": "frida_intercept",
                    "attributed_package": evt.get("_package", self.package),
                    "frida_data": {
                        "url": url,
                        "method": evt.get("method", "GET"),
                        "headers": evt.get("headers", {}),
                        "body": evt.get("body", ""),
                    },
                })

            elif subtype == "socket_connect":
                dest = evt.get("destination", "")
                if dest in seen:
                    continue
                seen.add(dest)

                # Parse socket address "host:port" or "/host:port"
                dest_clean = dest.lstrip("/")
                parts = dest_clean.rsplit(":", 1)
                host = parts[0] if parts else dest_clean
                port = parts[1] if len(parts) > 1 else "0"

                hostname = dns_map.get(host, "")

                activity.append({
                    "destination": hostname or host,
                    "hostname": hostname,
                    "ip": host,
                    "port": port,
                    "protocol": "TCP",
                    "direction": "OUTBOUND",
                    "first_seen": evt.get("_frida_timestamp", ""),
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "source": "frida_intercept",
                    "attributed_package": evt.get("_package", self.package),
                })

        return activity

    def to_behavior_events(self) -> List[Dict[str, Any]]:
        """Convert ALL Frida events into behavior timeline events."""
        events = []

        for msg in self.collect_messages():
            msg_type = msg.get("type", "")
            timestamp = msg.get("_frida_timestamp", datetime.now(timezone.utc).isoformat())

            if msg_type == "network":
                subtype = msg.get("subtype", "")
                if subtype == "okhttp_request":
                    events.append({
                        "id": str(uuid4()),
                        "timestamp": timestamp,
                        "api_call": f"HTTP {msg.get('method', 'GET')} {msg.get('url', '')}",
                        "description": f"Intercepted HTTP request: {msg.get('method', '')} {msg.get('url', '')}",
                        "category": "network",
                        "risk_level": "HIGH",
                        "class_name": self.package,
                        "source": "frida_intercept",
                    })
                elif subtype == "okhttp_response":
                    events.append({
                        "id": str(uuid4()),
                        "timestamp": timestamp,
                        "api_call": f"HTTP Response {msg.get('status', '')} from {msg.get('url', '')}",
                        "description": f"Response: status={msg.get('status', '')}, type={msg.get('content_type', '')}, size={msg.get('content_length', '')}",
                        "category": "network",
                        "risk_level": "MEDIUM",
                        "class_name": self.package,
                        "source": "frida_intercept",
                    })

            elif msg_type == "upi_input":
                subtype = msg.get("subtype", "")
                risk = "CRITICAL" if msg.get("is_password_field") else "HIGH"
                events.append({
                    "id": str(uuid4()),
                    "timestamp": timestamp,
                    "api_call": f"UPI Input Capture: {subtype}",
                    "description": f"App read input field (hint='{msg.get('hint', '')}', password={msg.get('is_password_field', False)}, len={msg.get('field_length', 0)})",
                    "category": "data_exfil",
                    "risk_level": risk,
                    "class_name": self.package,
                    "source": "frida_intercept",
                })

            elif msg_type == "intent":
                events.append({
                    "id": str(uuid4()),
                    "timestamp": timestamp,
                    "api_call": f"Intent: {msg.get('action', '')}",
                    "description": f"Intent fired: action={msg.get('action', '')}, data={msg.get('data', '')}, component={msg.get('component', '')}",
                    "category": "general",
                    "risk_level": "MEDIUM",
                    "class_name": self.package,
                    "source": "frida_intercept",
                })

            elif msg_type == "ssl_bypass":
                events.append({
                    "id": str(uuid4()),
                    "timestamp": timestamp,
                    "api_call": "SSL Pinning Bypass Active",
                    "description": msg.get("detail", "SSL certificate validation bypassed"),
                    "category": "crypto",
                    "risk_level": "HIGH",
                    "class_name": self.package,
                    "source": "frida_intercept",
                })

            elif msg_type == "data_access":
                events.append({
                    "id": str(uuid4()),
                    "timestamp": timestamp,
                    "api_call": f"Data Access: {msg.get('uri', '')}",
                    "description": f"App queried sensitive content provider: {msg.get('uri', '')}",
                    "category": "data_exfil",
                    "risk_level": "CRITICAL",
                    "class_name": self.package,
                    "source": "frida_intercept",
                })

            elif msg_type == "apex_event":
                events.append({
                    "id": str(uuid4()),
                    "timestamp": timestamp,
                    "api_call": msg.get("api", "API call"),
                    "description": msg.get("detail", ""),
                    "category": msg.get("category", "general"),
                    "risk_level": msg.get("risk", "MEDIUM"),
                    "class_name": self.package,
                    "source": "frida_runtime",
                })

            elif msg_type == "webview":
                events.append({
                    "id": str(uuid4()),
                    "timestamp": timestamp,
                    "api_call": f"WebView: {msg.get('subtype', '')}",
                    "description": f"WebView activity: {msg.get('url', msg.get('interface_name', ''))}",
                    "category": "network",
                    "risk_level": "MEDIUM",
                    "class_name": self.package,
                    "source": "frida_intercept",
                })

        return events

    # ═══════════════════════════════════════════════════════════
    # CLEANUP
    # ═══════════════════════════════════════════════════════════

    def detach(self):
        """Detach from the target process and clean up."""
        for script in self.scripts:
            try:
                script.unload()
            except Exception:
                pass
        self.scripts.clear()

        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None

        logger.info("[Frida] Detached and cleaned up")

    def stop_frida_server(self):
        """Stop frida-server on the device."""
        self._su("pkill -f frida-server")
        logger.info("[Frida] frida-server stopped")
