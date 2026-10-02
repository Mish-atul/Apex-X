import React, { useState, useEffect, useCallback } from "react";
import BehaviorTimeline from "@/components/BehaviorTimeline";
import {
  runDynamicAnalysis,
  getDynamicStatus,
  bootEmulator,
  downloadPcap,
  scanPentestDevices,
  startPentestSession,
  getPentestStatus,
  stopPentestSession,
  cleanPentestDevice,
  uninstallPackageFromDevice,
} from "@/services/api";
import { useAuth } from "@/hooks/useAuth";
import { useFeedback } from "@/components/Feedback";

interface DynamicTabProps {
  caseData: any;
  analysisResults?: any;
  isMockCase: boolean;
}

type DynamicMode = "select" | "emulator" | "pentest";

interface PentestDevice {
  serial: string;
  model: string;
  brand: string;
  android_version: string;
  display_name: string;
}

interface PentestLiveStatus {
  status: string;
  elapsed_seconds: number;
  events_captured: number;
  network_connections: number;
  child_apks_detected: number;
  child_apk_details: any[];
  pcapdroid_active: boolean;
  device_serial: string;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const k = 1024;
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1);
  const value = bytes / Math.pow(k, i);
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

export default function DynamicTab({ caseData, analysisResults, isMockCase }: DynamicTabProps) {
  const { token } = useAuth();
  const { toast, confirm } = useFeedback();

  // Emulator state
  const [isStarting, setIsStarting] = useState(false);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [dynStatus, setDynStatus] = useState<any>(null);
  const [isBooting, setIsBooting] = useState(false);

  const phaseStatus = Array.isArray(analysisResults)
    ? analysisResults.find((r: any) => r.phase === "dynamic")?.result?.status
    : undefined;

  // Poll live dynamic status while analysis is queued/running; reload when it finishes
  useEffect(() => {
    if (isMockCase) return;
    let wasRunning = phaseStatus === "running" || phaseStatus === "queued";
    let stopped = false;
    const tick = async () => {
      try {
        const st = await getDynamicStatus(caseData.id);
        if (stopped) return;
        setDynStatus(st);
        if (st.running) wasRunning = true;
        else if (wasRunning) window.location.reload();
      } catch {}
    };
    tick();
    const iv = setInterval(tick, 3000);
    return () => { stopped = true; clearInterval(iv); };
  }, [caseData.id, isMockCase, phaseStatus]);

  // Mode selection state
  const [dynamicMode, setDynamicMode] = useState<DynamicMode>("select");

  // Pentest state
  const [pentestDevices, setPentestDevices] = useState<PentestDevice[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [isPentestActive, setIsPentestActive] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [isCleaning, setIsCleaning] = useState(false);
  const [pentestStatus, setPentestStatus] = useState<PentestLiveStatus | null>(null);

  // Handle countdown timer (emulator mode)
  useEffect(() => {
    if (countdown === null) return;

    if (countdown <= 0) {
      window.location.reload();
      return;
    }

    const timer = setTimeout(() => {
      setCountdown(countdown - 1);
    }, 1000);

    return () => clearTimeout(timer);
  }, [countdown]);

  // Poll pentest status every 2 seconds while active
  useEffect(() => {
    if (!isPentestActive) return;

    const interval = setInterval(async () => {
      try {
        const status = await getPentestStatus(caseData.id);
        if (status.status === "no_active_session") {
          setIsPentestActive(false);
          setPentestStatus(null);
          return;
        }
        setPentestStatus(status);
      } catch (e) {
        console.error("Failed to poll pentest status:", e);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [isPentestActive, caseData.id]);

  // ── Emulator Handlers ──

  const handleRunEmulator = async () => {
    try {
      setIsStarting(true);
      await runDynamicAnalysis(caseData.id);
      setDynStatus({ running: true, stage: "booting_emulator", message: "Starting Android emulator" });
      toast("info", "Dynamic analysis started", "The emulator is booting and the app will run automatically.");
    } catch (e) {
      toast("error", "Could not start dynamic analysis", String(e));
    } finally {
      setIsStarting(false);
    }
  };

  const [isDownloadingPcap, setIsDownloadingPcap] = useState(false);
  const handleDownloadPcap = async () => {
    try {
      setIsDownloadingPcap(true);
      await downloadPcap(caseData.id);
      toast("success", "Packet capture downloaded", "Open the .pcap file in Wireshark for full traffic analysis.");
    } catch (e: any) {
      toast("error", "PCAP not available", e?.message || String(e));
    } finally {
      setIsDownloadingPcap(false);
    }
  };

  const handleBootEmulator = async () => {
    try {
      setIsBooting(true);
      toast("info", "Booting emulator", "This can take up to a minute on first start.");
      for (let i = 0; i < 100; i++) {
        const st = await bootEmulator();
        if (st.booted) break;
        await new Promise((r) => setTimeout(r, 3000));
      }
      await handleScanDevices();
    } catch (e) {
      toast("error", "Failed to boot emulator", String(e));
    } finally {
      setIsBooting(false);
    }
  };

  // ── Pentest Handlers ──

  const handleScanDevices = async () => {
    try {
      setIsScanning(true);
      const result = await scanPentestDevices(caseData.id);
      const devicesList = result.devices || [];
      setPentestDevices(devicesList);
      if (devicesList.length === 0) {
        toast("warning", "No devices detected",
          "Click “Boot Emulator” to use a virtual device (no USB needed), or connect a phone with USB debugging enabled.");
      } else {
        setSelectedDevice(devicesList[0].serial);
        toast("success", `${devicesList.length} device(s) found`);
      }
    } catch (e) {
      toast("error", "Device scan failed", String(e));
    } finally {
      setIsScanning(false);
    }
  };

  const handleStartPentest = async () => {
    if (!selectedDevice) {
      toast("warning", "Select a device first");
      return;
    }

    const deviceObj = pentestDevices.find(d => d.serial === selectedDevice);
    if (deviceObj && (deviceObj as any).status === "unauthorized") {
      toast("warning", "Device unauthorized",
        "Unlock the phone and allow USB debugging for this computer, then scan again.");
      return;
    }

    try {
      setIsStarting(true);
      await startPentestSession(caseData.id, selectedDevice);
      setIsPentestActive(true);
      toast("success", "Monitoring session started");
    } catch (e) {
      toast("error", "Could not start monitoring", String(e));
    } finally {
      setIsStarting(false);
    }
  };

  const handleStopPentest = async () => {
    const confirmed = await confirm({
      title: "Stop monitoring and generate report?",
      message: "This stops network capture, detects any dropped child APKs, runs static analysis on them, enriches with threat intelligence, and compiles the full dynamic report.",
      confirmLabel: "Stop & generate",
    });
    if (!confirmed) return;

    try {
      setIsStopping(true);
      await stopPentestSession(caseData.id);
      setCountdown(10);
      setIsPentestActive(false);
      toast("info", "Finalising report", "Results will appear in a few seconds.");
    } catch (e) {
      toast("error", "Could not stop session", String(e));
    } finally {
      setIsStopping(false);
    }
  };

  const handleCleanDevice = async () => {
    const confirmed = await confirm({
      title: "Uninstall test apps from device?",
      message: "This force-stops and removes the target APK and any dropped child APKs from the connected device.",
      confirmLabel: "Clean device",
      tone: "danger",
    });
    if (!confirmed) return;

    try {
      setIsCleaning(true);
      const res = await cleanPentestDevice(caseData.id, selectedDevice || undefined);
      const uninstalled = res.uninstalled_packages || [];
      if (uninstalled.length > 0) {
        toast("success", "Device cleaned", uninstalled.map((p: string) => `• ${p}`).join("\n"));
      } else {
        toast("info", "Device already clean", "No test packages are currently installed.");
      }
    } catch (e: any) {
      toast("error", "Clean failed", e?.message || String(e));
    } finally {
      setIsCleaning(false);
    }
  };

  const [uninstallingPkg, setUninstallingPkg] = useState<string | null>(null);

  const handleUninstallSingle = async (pkgName: string) => {
    const ok = await confirm({
      title: "Uninstall package?",
      message: `Completely remove “${pkgName}” from the connected device.`,
      confirmLabel: "Uninstall",
      tone: "danger",
    });
    if (!ok) return;
    setUninstallingPkg(pkgName);
    try {
      const res = await uninstallPackageFromDevice(caseData?.id, pkgName, selectedDevice || undefined);
      if (res.success) {
        toast("success", "Package removed", `“${pkgName}” was uninstalled from the device.`);
      } else {
        toast("info", "Uninstall requested", res.error || "Triggered on device.");
      }
    } catch (e: any) {
      toast("error", "Uninstall failed", e.message);
    } finally {
      setUninstallingPkg(null);
    }
  };

  // ── Parse existing results ──

  let dynamicResult = null;
  let hasRealDynamic = false;
  if (analysisResults && Array.isArray(analysisResults)) {
    const dynPhase = analysisResults.find((r: any) => r.phase === "dynamic");
    if (dynPhase?.result) {
      dynamicResult = dynPhase.result;
      // Only treat as "real dynamic" if mode is emulator or manual_pentest
      const mode = dynPhase.result.mode;
      hasRealDynamic = mode === "emulator" || mode === "manual_pentest";
    }
  }


  // Map to BehaviorTimeline events
  const rawEvents = dynamicResult?.events || [];

  const dynamicEvents = rawEvents.map((evt: any) => {
    let type = "api_call";
    if (evt.category === "network") type = "network";
    if (evt.category === "file_io") type = "file_io";
    if (evt.category === "crypto") type = "crypto";
    if (evt.category === "sms") type = "sms";
    if (evt.category === "data_exfil") type = "permission";
    if (evt.category === "surveillance") type = "permission";
    if (evt.category === "dropper") type = "file_io";

    let severity = "info";
    if (evt.risk_level === "CRITICAL") severity = "critical";
    else if (evt.risk_level === "HIGH" || evt.risk_level === "MEDIUM") severity = "warning";

    return {
      id: evt.id,
      timestamp: evt.timestamp,
      type: type,
      title: evt.api_call,
      description: evt.description + (
        evt.source === "heuristic_code_scan" ? " (Heuristic Scan)" :
        evt.source === "manual_pentest" ? " (Manual Pentest)" :
        " (Logcat)"
      ),
      severity: severity,
    };
  });

  const timelineEventsToUse = (dynamicEvents && dynamicEvents.length > 0)
    ? dynamicEvents
    : [];

  // Process Suspicious APIs
  const dynamicApis = rawEvents.reduce((acc: any[], evt: any) => {
    const apiName = evt.api_call || "Unknown";
    if (!acc.some((t: any) => t.api === apiName)) {
      acc.push({
        api: apiName,
        cls: evt.class_name || evt.category,
        risk: evt.risk_level || "LOW",
        source: evt.source,
      });
    }
    return acc;
  }, []);

  const apisToUse = (dynamicApis && dynamicApis.length > 0) ? dynamicApis : [];

  // Process Network Connections
  const dynamicConnections = dynamicResult?.network_activity?.map((conn: any) => ({
    dest: conn.destination || conn.ip,
    hostname: conn.hostname || "",
    ip: conn.ip || "",
    proto: conn.protocol || "TCP",
    port: String(conn.port || 443),
    bytesSent: conn.bytes_sent || 0,
    bytesRecv: conn.bytes_received || 0,
    packets: conn.packets || 0,
    firstSeen: conn.first_seen || "",
    dir: conn.direction || "OUTBOUND",
    source: conn.source,
    attributedPackage: conn.attributed_package || conn.source_package || "",
    apkType: conn.apk_type || "parent",
    sourcePackage: conn.source_package || "",
    staticRef: conn.static_reference || null,
    fridaData: conn.frida_data || null,
  })) || [];

  const networkToUse = (dynamicConnections && dynamicConnections.length > 0) ? dynamicConnections : [];

  // Extract pentest-specific data
  const pentestData = dynamicResult?.pentest_data || null;
  const childApks = pentestData?.child_apks || [];

  // ── Package Filter ──
  const [packageFilter, setPackageFilter] = useState<string>("all");

  // Extract unique packages from events for filtering
  const uniquePackages = (() => {
    const pkgs = new Set<string>();
    rawEvents.forEach((evt: any) => {
      if (evt.class_name) pkgs.add(evt.class_name);
      if (evt.source_package) pkgs.add(evt.source_package);
    });
    dynamicConnections?.forEach((conn: any) => {
      if (conn.attributedPackage) pkgs.add(conn.attributedPackage);
    });
    return Array.from(pkgs).filter(p => p && p.length > 2);
  })();

  // Apply package filter
  const filteredTimeline = packageFilter === "all"
    ? timelineEventsToUse
    : timelineEventsToUse.filter((evt: any) => {
        const rawEvt = rawEvents.find((r: any) => r.id === evt.id);
        return rawEvt?.class_name?.includes(packageFilter) || rawEvt?.source_package?.includes(packageFilter);
      });

  const filteredNetwork = packageFilter === "all"
    ? networkToUse
    : networkToUse.filter((conn: any) => conn.attributedPackage?.includes(packageFilter) || conn.source?.includes(packageFilter));

  // Determine analysis mode label
  const modeLabel = dynamicResult?.mode === "emulator"
    ? "Real Emulator"
    : dynamicResult?.mode === "manual_pentest"
    ? "Manual Pentest"
    : dynamicResult?.mode === "heuristic"
    ? "Heuristic (No VM)"
    : "Not run";
  const dynRunning = !!dynStatus?.running || phaseStatus === "running" || phaseStatus === "queued";

  return (
    <div className="space-y-4">
      {/* Dynamic Header */}
      <div className="flex justify-between items-center mb-6 border-b border-gray-700/50 pb-4">
        <div>
          <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-400">
            Dynamic Analysis
          </h2>
          <p className="text-sm text-gray-400 mt-1">Runtime behavior and network activity monitoring</p>
        </div>
      </div>

      {/* ── Mode Selector (only when no results yet and not in active session) ── */}
      {!isMockCase && !hasRealDynamic && !dynRunning && !isPentestActive && dynamicMode === "select" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Emulator Option */}
          <button
            onClick={() => { setDynamicMode("emulator"); handleRunEmulator(); }}
            disabled={isStarting || dynRunning}
            className="bg-panel border-2 border-border-subtle hover:border-blue-500/50 p-6 text-left transition-all group cursor-pointer"
          >
            <div className="flex items-center space-x-3 mb-3">
              <span className="text-3xl">🖥️</span>
              <div>
                <h3 className="font-display font-bold text-lg text-primary group-hover:text-blue-400 transition-colors">
                  Emulator Analysis
                </h3>
                <span className="text-xs font-mono text-green-400 bg-green-500/10 px-2 py-0.5 rounded">AUTOMATED</span>
              </div>
            </div>
            <p className="text-sm text-primary/60 leading-relaxed">
              Launch Android Virtual Machine and run automated UI exploration (Monkey Runner).
              The system automatically installs the APK, grants permissions, and collects runtime data for 90 seconds.
            </p>
            <div className="mt-4 flex items-center space-x-2 text-xs font-mono text-primary/40">
              <span>⏱ ~90s</span>
              <span>•</span>
              <span>🤖 Fully Automated</span>
              <span>•</span>
              <span>📊 Logcat + Network</span>
            </div>
          </button>

          {/* Manual Pentest Option */}
          <button
            onClick={() => setDynamicMode("pentest")}
            className="bg-panel border-2 border-border-subtle hover:border-red-500/50 p-6 text-left transition-all group cursor-pointer"
          >
            <div className="flex items-center space-x-3 mb-3">
              <span className="text-3xl">📱</span>
              <div>
                <h3 className="font-display font-bold text-lg text-primary group-hover:text-red-400 transition-colors">
                  Manual Penetration Testing
                </h3>
                <span className="text-xs font-mono text-red-400 bg-red-500/10 px-2 py-0.5 rounded">ADVANCED</span>
              </div>
            </div>
            <p className="text-sm text-primary/60 leading-relaxed">
              Use the built-in emulator (no USB) or a physical phone. You manually install and interact with the APK while the system monitors
              all activities. <strong className="text-red-400">Detects hidden child/dropper APKs</strong> that install in the background.
            </p>
            <div className="mt-4 flex items-center space-x-2 text-xs font-mono text-primary/40">
              <span>📡 PCAPdroid</span>
              <span>•</span>
              <span>👤 Manual Control</span>
              <span>•</span>
              <span>🕵️ Child APK Detection</span>
            </div>
          </button>
        </div>
      )}

      {/* ── Live emulator analysis status ── */}
      {!isMockCase && dynRunning && (
        <div className="bg-panel border border-blue-500/30 p-6 text-center">
          <svg className="animate-spin mx-auto h-8 w-8 text-blue-400 mb-3" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
          <p className="text-lg font-semibold text-blue-400">Emulator Analysis Running</p>
          <p className="text-sm text-primary/60 mt-1">
            {dynStatus?.message || "Queued — waiting for the emulator"}
          </p>
          <p className="text-xs text-primary/40 mt-2 font-mono">
            Results load automatically when finished (typically 2–4 minutes including emulator boot).
          </p>
        </div>
      )}

      {/* ── Re-run on emulator ── */}
      {!isMockCase && hasRealDynamic && !dynRunning && !isPentestActive && (
        <div className="flex justify-between items-center bg-panel border border-border-subtle p-3">
          <span className="text-xs font-mono text-primary/60">
            Mode: <strong>{modeLabel}</strong>
            {dynamicResult?.device ? ` • ${dynamicResult.device}` : ""}
            {dynamicResult?.duration_seconds ? ` • ${Math.round(dynamicResult.duration_seconds)}s` : ""}
            {dynamicResult?.dropped_packages?.length ? ` • ${dynamicResult.dropped_packages.length} dropped package(s)` : ""}
          </span>
          <div className="flex gap-2">
            <button
              onClick={handleDownloadPcap}
              disabled={isDownloadingPcap}
              className="px-3 py-1.5 text-xs font-medium border border-border-subtle bg-panel hover:bg-surface disabled:opacity-50"
              title="Packet capture recorded during the run — open in Wireshark"
            >
              {isDownloadingPcap ? "Preparing..." : "⬇ Download PCAP"}
            </button>
            <button
              onClick={handleRunEmulator}
              disabled={isStarting}
              className="px-3 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50"
            >
              {isStarting ? "Starting..." : "↻ Re-run on Emulator"}
            </button>
          </div>
        </div>
      )}

      {/* ── Child / dropped apps observed during emulator run ── */}
      {dynamicResult?.mode === "emulator" && (
        <div className="bg-panel border border-border-subtle p-4">
          <div className="flex items-center justify-between mb-3 border-b border-border-subtle pb-2">
            <h3 className="font-display font-semibold text-sm">Child Apps Installed During Run</h3>
            <span className={`text-xs font-mono px-2 py-0.5 rounded ${
              (dynamicResult.child_apps?.length || 0) > 0 ? "bg-red-50 text-red-700" : "bg-emerald-50 text-emerald-700"}`}>
              {(dynamicResult.child_apps?.length || 0) > 0
                ? `${dynamicResult.child_apps.length} dropped`
                : "None detected"}
            </span>
          </div>
          {(dynamicResult.child_apps?.length || 0) === 0 ? (
            <p className="text-xs text-text-muted">
              The app did not install any other package while it ran. Every installed package is tracked
              automatically, including its network connections, logs and permission use.
            </p>
          ) : (
            <div className="space-y-3">
              {dynamicResult.child_apps.map((child: any) => (
                <div key={child.package} className="border border-red-200 bg-red-50/40 rounded-md p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span className="font-mono text-sm font-semibold text-text">{child.package}</span>
                      {child.app_name && <span className="text-xs text-text-muted ml-2">({child.app_name})</span>}
                    </div>
                    <span className="text-xs font-mono text-text-muted">uid {child.uid ?? "?"} · detected {child.detected_at?.slice(11, 19)}</span>
                  </div>
                  {child.sha256 && <p className="text-[11px] font-mono text-text-muted break-all mt-1">SHA-256: {child.sha256}</p>}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-2 text-xs">
                    <div><span className="text-text-muted block">Connections</span><strong>{child.network?.length || 0}</strong></div>
                    <div><span className="text-text-muted block">Permissions</span><strong>{child.permissions?.length || 0}</strong></div>
                    <div><span className="text-text-muted block">Dangerous</span><strong className="text-red-600">{child.dangerous_permissions?.length || 0}</strong></div>
                    <div><span className="text-text-muted block">Runtime ops used</span><strong>{child.runtime_ops?.length || 0}</strong></div>
                  </div>
                  {child.network?.length > 0 && (
                    <div className="mt-2">
                      <span className="text-xs text-text-muted">Contacted:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {child.network.slice(0, 12).map((n: any, i: number) => (
                          <span key={i} className="text-[11px] font-mono bg-white border border-border-subtle px-1.5 py-0.5 rounded">
                            {n.destination}:{n.port}{n.ip && n.destination !== n.ip ? ` (${n.ip})` : ""}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {child.dangerous_permissions?.length > 0 && (
                    <p className="text-[11px] text-red-700 mt-2 font-mono break-words">
                      {child.dangerous_permissions.map((p: string) => p.split(".").pop()).join(", ")}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!isMockCase && dynamicResult?.mode === "heuristic" && !dynRunning && (
        <div className="bg-amber-50 border border-amber-300 p-3 text-sm text-amber-800">
          No emulator could be started, so these results come from a code-level heuristic scan, not real execution.
          {dynamicResult?.errors?.length ? <span className="block text-xs font-mono mt-1">{dynamicResult.errors.join(" | ")}</span> : null}
        </div>
      )}

      {/* ── Manual Pentest Panel ── */}
      {!isMockCase && dynamicMode === "pentest" && !hasRealDynamic && (
        <div className="bg-panel border border-red-500/20 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <span className="text-2xl">📱</span>
              <div>
                <h3 className="font-display font-bold text-lg text-primary">Manual Penetration Testing</h3>
                <p className="text-xs text-primary/50">Use the built-in Android emulator, or a phone connected via USB</p>
              </div>
            </div>
            {!isPentestActive && (
              <button
                onClick={() => setDynamicMode("select")}
                className="text-xs text-primary/40 hover:text-primary/60 transition-colors"
              >
                ← Back to mode selection
              </button>
            )}
          </div>

          {/* Device Scanner */}
          {!isPentestActive && (
            <div className="space-y-3">
              <div className="flex items-center space-x-3">
                <button
                  onClick={handleScanDevices}
                  disabled={isScanning}
                  className="px-4 py-2 bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-600 hover:to-orange-700 text-white rounded-lg shadow-lg shadow-red-500/25 transition-all font-medium text-sm disabled:opacity-50"
                >
                  {isScanning ? "Scanning..." : "🔍 Scan Devices"}
                </button>
                <button
                  onClick={handleBootEmulator}
                  disabled={isBooting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-all font-medium text-sm disabled:opacity-50"
                  title="Start the Android emulator — no phone or USB cable required"
                >
                  {isBooting ? "Booting emulator..." : "🖥️ Boot Emulator"}
                </button>
                <button
                  onClick={handleCleanDevice}
                  disabled={isCleaning}
                  className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-border-subtle text-red-400 hover:text-red-300 rounded-lg transition-all font-medium text-sm disabled:opacity-50 flex items-center space-x-1.5 cursor-pointer"
                  title="Forcefully uninstall test APK and any dropped child APKs from connected device"
                >
                  <span>🧹</span>
                  <span>{isCleaning ? "Cleaning..." : "Clean Phone"}</span>
                </button>
                {pentestDevices.length > 0 && (
                  <select
                    value={selectedDevice}
                    onChange={(e) => setSelectedDevice(e.target.value)}
                    className="bg-canvas border border-border-subtle px-3 py-2 text-sm font-mono text-primary rounded-lg flex-1"
                  >
                    <option value="">Select a device...</option>
                    {pentestDevices.map((d) => (
                      <option key={d.serial} value={d.serial}>
                        {d.display_name} [{d.serial}]
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {selectedDevice && (
                <button
                  onClick={handleStartPentest}
                  disabled={isStarting}
                  className="w-full px-4 py-3 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white rounded-lg shadow-lg shadow-green-500/25 transition-all font-semibold disabled:opacity-50"
                >
                  {isStarting ? "Initializing..." : "▶ Start Monitoring Session"}
                </button>
              )}

              <div className="bg-canvas/50 border border-border-subtle p-3 rounded-lg">
                <p className="text-xs text-primary/50 leading-relaxed">
                  <strong className="text-primary/70">How it works:</strong> Click &ldquo;Start Monitoring&rdquo; to begin capturing all device activity.
                  Then install and interact with the suspicious APK on the device (emulator or phone).
                  The system detects hidden child APKs, captures network traffic, and monitors runtime
                  behaviour. Click &ldquo;Stop&rdquo; when you are done to generate the full report.
                </p>
              </div>
            </div>
          )}

          {/* Live Monitoring Dashboard */}
          {isPentestActive && pentestStatus && (
            <div className="space-y-4">
              {/* Live status indicator */}
              <div className="flex items-center space-x-2">
                <span className="relative flex h-3 w-3">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                </span>
                <span className="text-sm font-semibold text-red-400">LIVE MONITORING</span>
                <span className="text-xs text-primary/40 font-mono">
                  {Math.floor(pentestStatus.elapsed_seconds / 60)}m {pentestStatus.elapsed_seconds % 60}s elapsed
                </span>
              </div>

              {/* Live stats grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-canvas border border-border-subtle p-3 rounded-lg">
                  <div className="text-xs text-primary/50 font-mono uppercase">Events</div>
                  <div className="text-2xl font-bold text-blue-400">{pentestStatus.events_captured}</div>
                </div>
                <div className="bg-canvas border border-border-subtle p-3 rounded-lg">
                  <div className="text-xs text-primary/50 font-mono uppercase">Network</div>
                  <div className="text-2xl font-bold text-orange-400">{pentestStatus.network_connections}</div>
                </div>
                <div className="bg-canvas border border-border-subtle p-3 rounded-lg">
                  <div className="text-xs text-primary/50 font-mono uppercase">Child APKs</div>
                  <div className={`text-2xl font-bold ${pentestStatus.child_apks_detected > 0 ? 'text-red-500' : 'text-green-400'}`}>
                    {pentestStatus.child_apks_detected}
                  </div>
                </div>
                <div className="bg-canvas border border-border-subtle p-3 rounded-lg">
                  <div className="text-xs text-primary/50 font-mono uppercase">PCAPdroid</div>
                  <div className={`text-sm font-bold mt-1 ${pentestStatus.pcapdroid_active ? 'text-green-400' : 'text-yellow-400'}`}>
                    {pentestStatus.pcapdroid_active ? "✅ Capturing" : "⚠ ADB Only"}
                  </div>
                </div>
              </div>

              {/* Child APK alerts */}
              {pentestStatus.child_apk_details?.length > 0 && (
                <div className="bg-red-500/5 border border-red-500/30 p-4 rounded-lg">
                  <h4 className="text-sm font-bold text-red-400 mb-2">⚠ Child/Dropper APKs Detected!</h4>
                  {pentestStatus.child_apk_details.map((child: any, i: number) => (
                    <div key={i} className="flex items-center space-x-2 text-xs font-mono text-red-300 mt-1">
                      <span className="text-red-500">●</span>
                      <span>{child.package_name}</span>
                      <span className="text-primary/30">at {child.detected_at}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Stop button */}
              <button
                onClick={handleStopPentest}
                disabled={isStopping}
                className="w-full px-4 py-3 bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white rounded-lg shadow-lg shadow-red-500/30 transition-all font-bold text-lg disabled:opacity-50"
              >
                {isStopping ? "Finalizing..." : "⏹ Stop Monitoring & Generate Report"}
              </button>
            </div>
          )}

          {/* Countdown after stopping */}
          {countdown !== null && dynamicMode === "pentest" && (
            <div className="text-center py-4">
              <svg className="animate-spin mx-auto h-8 w-8 text-red-400 mb-3" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <p className="text-sm text-primary/60">Generating report... Refreshing in <strong>{countdown}s</strong></p>
            </div>
          )}
        </div>
      )}

      {/* ── Results Section (shown once analysis is complete) ── */}

      {/* Package Filter Bar */}
      {uniquePackages.length > 1 && (
        <div className="bg-panel border border-border-subtle p-3 mb-4 flex items-center gap-3">
          <span className="text-xs font-mono text-primary/60 uppercase tracking-wider whitespace-nowrap">📦 Filter by Package:</span>
          <select
            value={packageFilter}
            onChange={(e) => setPackageFilter(e.target.value)}
            className="bg-surface border border-border-subtle text-xs font-mono text-primary px-3 py-1.5 rounded flex-1 max-w-md"
          >
            <option value="all">All Packages ({rawEvents.length} events)</option>
            {uniquePackages.map((pkg) => (
              <option key={pkg} value={pkg}>{pkg}</option>
            ))}
          </select>
          {packageFilter !== "all" && (
            <button
              onClick={() => setPackageFilter("all")}
              className="text-xs font-mono text-red-400 hover:text-red-300 bg-red-500/10 px-2 py-1 rounded border border-red-500/20"
            >
              ✕ Clear
            </button>
          )}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <div className="bg-panel border border-border-subtle p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono text-primary/60 uppercase tracking-wider">Analysis Mode</span>
            {modeLabel === "Manual Pentest" && (
              <button
                onClick={handleCleanDevice}
                disabled={isCleaning}
                className="text-[11px] font-mono bg-red-500/10 hover:bg-red-500/20 text-red-400 px-2 py-0.5 rounded border border-red-500/20 cursor-pointer transition-colors"
                title="Forcefully uninstall test APK and any dropped child APKs from phone"
              >
                {isCleaning ? "Cleaning..." : "🧹 Clean Phone"}
              </button>
            )}
          </div>
          <span className="text-xl font-display font-bold text-primary">{modeLabel}</span>
        </div>
        <div className="bg-panel border border-border-subtle p-4 flex flex-col justify-between">
          <span className="text-xs font-mono text-primary/60 uppercase tracking-wider mb-1">Total Events</span>
          <span className="text-xl font-display font-bold text-blue-600">{filteredTimeline.length} Captured</span>
        </div>
        <div className="bg-panel border border-border-subtle p-4 flex flex-col justify-between">
          <span className="text-xs font-mono text-primary/60 uppercase tracking-wider mb-1">Critical APIs</span>
          <span className="text-xl font-display font-bold text-red-600">{apisToUse.filter((a: any) => a.risk === "CRITICAL").length} Detected</span>
        </div>
        <div className="bg-panel border border-border-subtle p-4 flex flex-col justify-between">
          <span className="text-xs font-mono text-primary/60 uppercase tracking-wider mb-1">Network Activity</span>
          <span className="text-xl font-display font-bold text-orange-600">{filteredNetwork.length} Endpoints</span>
          {pentestData?.frida_used && (
            <div className="mt-1 flex flex-wrap gap-1">
              <span className="text-[10px] font-mono bg-green-500/10 text-green-400 px-1.5 py-0.5 rounded border border-green-500/20">
                🔓 Frida Active
              </span>
              {pentestData?.frida_data?.ssl_bypasses > 0 && (
                <span className="text-[10px] font-mono bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded">
                  {pentestData.frida_data.ssl_bypasses} SSL Bypasses
                </span>
              )}
            </div>
          )}
          {pentestData?.static_crossref_matches > 0 && (
            <span className="text-[10px] font-mono bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded mt-1 w-fit">
              ⚡ {pentestData.static_crossref_matches} Static Match{pentestData.static_crossref_matches > 1 ? 'es' : ''}
            </span>
          )}
        </div>
      </div>

      {/* Child APK Detection Report (pentest-specific) */}
      {pentestData && childApks.length > 0 && (
        <div className="bg-panel border-2 border-red-500/30 p-4">
          <h3 className="font-display font-semibold text-sm mb-3 border-b border-red-500/20 pb-2 text-red-400">
            🕵️ Child / Dropper APK Detection Report
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-canvas border border-border-subtle p-3 rounded-lg">
              <div className="text-xs text-primary/50 font-mono uppercase">Total Child APKs</div>
              <div className="text-2xl font-bold text-red-500">{pentestData.child_apk_count}</div>
            </div>
            <div className="bg-canvas border border-border-subtle p-3 rounded-lg">
              <div className="text-xs text-primary/50 font-mono uppercase">Hidden (No Launcher Icon)</div>
              <div className="text-2xl font-bold text-red-600">{pentestData.hidden_child_apks?.length || 0}</div>
            </div>
          </div>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border-subtle text-left">
                  <th className="pb-2 font-mono text-xs text-primary/60">Package Name</th>
                  <th className="pb-2 font-mono text-xs text-primary/60">Hidden</th>
                  <th className="pb-2 font-mono text-xs text-primary/60">Running</th>
                  <th className="pb-2 font-mono text-xs text-primary/60">Services</th>
                  <th className="pb-2 font-mono text-xs text-primary/60">Risk</th>
                  <th className="pb-2 font-mono text-xs text-primary/60 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {childApks.map((child: any, i: number) => (
                  <tr key={i} className="border-b border-border-subtle/50 hover:bg-canvas/50">
                    <td className="py-2 font-mono text-xs">
                      <span className="font-semibold text-purple-400">{child.package_name}</span>
                    </td>
                    <td className="py-2 text-xs">
                      {child.is_hidden ? (
                        <span className="text-red-400 font-bold">⚠ HIDDEN</span>
                      ) : (
                        <span className="text-green-400">Visible</span>
                      )}
                    </td>
                    <td className="py-2 text-xs">
                      {child.is_running ? (
                        <span className="text-red-400 font-bold">🔴 Active</span>
                      ) : (
                        <span className="text-primary/40">Inactive</span>
                      )}
                    </td>
                    <td className="py-2 text-xs font-mono text-primary/60">
                      {child.services?.length || 0} services
                    </td>
                    <td className="py-2">
                      <span className={`text-xs font-mono font-semibold px-2 py-0.5 rounded-sm ${
                        child.risk_level === "CRITICAL" ? "bg-red-100 text-red-700" :
                        child.risk_level === "HIGH" ? "bg-orange-100 text-orange-700" :
                        "bg-yellow-100 text-yellow-700"
                      }`}>
                        {child.risk_level}
                      </span>
                    </td>
                    <td className="py-2 text-right">
                      <button
                        onClick={() => handleUninstallSingle(child.package_name)}
                        disabled={uninstallingPkg === child.package_name}
                        className="px-2 py-1 text-[11px] font-mono bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded cursor-pointer disabled:opacity-50"
                        title={`Uninstall ${child.package_name} from device`}
                      >
                        {uninstallingPkg === child.package_name ? "Uninstalling..." : "🗑 Uninstall"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Data-Driven Credential Theft Forensic Analysis ── */}
      {(() => {
        // Derive UPI/financial fraud indicators from actual analysis data
        const upiKeywords = ["upi", "payment", "pin", "otp", "bank", "paytm", "phonepe", "gpay", "npci", "vpa", "imps", "neft"];
        const overlayPerms = ["android.permission.SYSTEM_ALERT_WINDOW", "SYSTEM_ALERT_WINDOW"];
        const a11yPerms = ["android.permission.BIND_ACCESSIBILITY_SERVICE", "BIND_ACCESSIBILITY_SERVICE"];

        // 1. Check events for UPI-related API calls
        const upiEvents = rawEvents.filter((evt: any) => {
          const text = `${evt.api_call || ""} ${evt.description || ""} ${evt.class_name || ""}`.toLowerCase();
          return upiKeywords.some(kw => text.includes(kw));
        });

        // 2. Check events for overlay/accessibility abuse
        const overlayEvents = rawEvents.filter((evt: any) => {
          const text = `${evt.api_call || ""} ${evt.description || ""} ${evt.class_name || ""}`.toLowerCase();
          return text.includes("system_alert") || text.includes("overlay") || text.includes("accessibility") || text.includes("edittext") || text.includes("keylog");
        });

        // 3. Check permissions from static analysis for overlay/a11y
        const staticPerms: string[] = analysisResults?.static?.permissions?.map((p: any) => typeof p === "string" ? p : p.permission || p.name || "") || [];
        const hasOverlayPerm = staticPerms.some(p => overlayPerms.some(op => p.includes(op)));
        const hasA11yPerm = staticPerms.some(p => a11yPerms.some(ap => p.includes(ap)));

        // 4. Identify suspicious outbound connections (C2 exfiltration targets)
        const exfilConnections = filteredNetwork.filter((conn: any) => {
          const port = parseInt(conn.port) || 0;
          return conn.dir === "OUTBOUND" && (port === 443 || port === 8443 || port === 80 || port === 8080);
        });

        // 5. Compute total data transferred
        const totalBytesSent = filteredNetwork.reduce((sum: number, c: any) => sum + (c.bytesSent || 0), 0);
        const totalBytesRecv = filteredNetwork.reduce((sum: number, c: any) => sum + (c.bytesRecv || 0), 0);
        const formatBytes = (b: number) => b < 1024 ? `${b} B` : b < 1048576 ? `${(b/1024).toFixed(1)} KB` : `${(b/1048576).toFixed(2)} MB`;

        // 6. Extract Frida hook data if available
        const fridaData = pentestData?.frida_data || null;
        const fridaUsed = pentestData?.frida_used || false;

        // 7. Check for Telegram bot API or known exfil patterns in connections
        const telegramConns = filteredNetwork.filter((conn: any) =>
          (conn.dest || conn.hostname || "").toLowerCase().includes("telegram") ||
          (conn.dest || conn.hostname || "").toLowerCase().includes("api.telegram")
        );

        // Only render this panel if there's actual evidence
        const hasFinancialIndicators = upiEvents.length > 0 || hasOverlayPerm || hasA11yPerm || overlayEvents.length > 0;
        const hasExfilEvidence = exfilConnections.length > 0 || telegramConns.length > 0;
        const hasAnyEvidence = hasFinancialIndicators || hasExfilEvidence || fridaUsed;

        if (!hasAnyEvidence) return null;

        return (
          <div className="bg-panel border-2 border-amber-500/30 p-5 rounded-lg">
            <div className="flex items-center justify-between border-b border-amber-500/20 pb-3 mb-4">
              <div className="flex items-center space-x-2">
                <span className="text-2xl">💳</span>
                <div>
                  <h3 className="font-display font-bold text-base text-amber-400">
                    Credential Theft & Exfiltration Forensics
                  </h3>
                  <p className="text-xs text-primary/60">
                    Evidence derived from {rawEvents.length} captured events, {filteredNetwork.length} network connections
                    {fridaUsed ? ", and Frida instrumentation" : ""}
                  </p>
                </div>
              </div>
              <span className={`px-2.5 py-1 text-xs font-mono font-semibold rounded ${
                hasFinancialIndicators && hasExfilEvidence
                  ? "bg-red-500/10 text-red-400 border border-red-500/20"
                  : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
              }`}>
                {hasFinancialIndicators && hasExfilEvidence ? "CRITICAL FRAUD VECTOR" : "SUSPICIOUS INDICATORS"}
              </span>
            </div>

            {/* Evidence Grid - dynamically populated */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              {/* Box 1: Overlay / Phishing Evidence */}
              <div className="bg-canvas border border-border-subtle p-3 rounded">
                <div className="text-[11px] font-mono text-primary/50 uppercase tracking-wider mb-1">
                  1. Overlay / Screen Hijack
                </div>
                <div className="text-sm font-semibold text-primary mb-1">
                  {hasOverlayPerm || overlayEvents.length > 0 ? "⚠ Evidence Found" : "✓ No Evidence"}
                </div>
                <div className="text-xs text-primary/70 leading-relaxed space-y-1">
                  {hasOverlayPerm && (
                    <p>• <code className="text-amber-400 text-[11px]">SYSTEM_ALERT_WINDOW</code> permission declared</p>
                  )}
                  {hasA11yPerm && (
                    <p>• <code className="text-amber-400 text-[11px]">BIND_ACCESSIBILITY_SERVICE</code> requested</p>
                  )}
                  {overlayEvents.length > 0 && (
                    <p>• {overlayEvents.length} overlay/accessibility event(s) captured at runtime</p>
                  )}
                  {!hasOverlayPerm && !hasA11yPerm && overlayEvents.length === 0 && (
                    <p className="italic text-primary/50">No overlay or accessibility abuse detected in this session</p>
                  )}
                </div>
              </div>

              {/* Box 2: Input Capture Evidence */}
              <div className="bg-canvas border border-border-subtle p-3 rounded">
                <div className="text-[11px] font-mono text-primary/50 uppercase tracking-wider mb-1">
                  2. Input / Credential Capture
                </div>
                <div className="text-sm font-semibold text-primary mb-1">
                  {upiEvents.length > 0 ? `⚠ ${upiEvents.length} UPI Event(s)` : "✓ No UPI Events"}
                </div>
                <div className="text-xs text-primary/70 leading-relaxed space-y-1">
                  {upiEvents.length > 0 ? (
                    upiEvents.slice(0, 3).map((evt: any, i: number) => (
                      <p key={i}>• <code className="text-amber-400 text-[11px]">{evt.api_call || "API call"}</code>
                        {evt.class_name && <span className="text-primary/50"> in {evt.class_name.split(".").pop()}</span>}
                      </p>
                    ))
                  ) : (
                    <p className="italic text-primary/50">No UPI/payment related API calls captured. Try longer session or trigger payment flow on device.</p>
                  )}
                  {upiEvents.length > 3 && (
                    <p className="text-primary/50">...and {upiEvents.length - 3} more</p>
                  )}
                </div>
              </div>

              {/* Box 3: Exfiltration Evidence */}
              <div className="bg-canvas border border-border-subtle p-3 rounded">
                <div className="text-[11px] font-mono text-primary/50 uppercase tracking-wider mb-1">
                  3. Data Exfiltration
                </div>
                <div className="text-sm font-semibold text-primary mb-1">
                  {exfilConnections.length > 0 ? `⚠ ${exfilConnections.length} Outbound Endpoint(s)` : "✓ No Outbound Traffic"}
                </div>
                <div className="text-xs text-primary/70 leading-relaxed space-y-1">
                  {exfilConnections.slice(0, 3).map((conn: any, i: number) => (
                    <p key={i}>
                      • <code className="text-red-400 text-[11px]">{conn.dest || conn.ip}:{conn.port}</code>
                      <span className="text-primary/50"> ({conn.proto})</span>
                      {conn.apkType === "child" && <span className="text-orange-400 ml-1">[Child APK]</span>}
                    </p>
                  ))}
                  {telegramConns.length > 0 && (
                    <p>• <code className="text-red-400 text-[11px]">Telegram Bot API</code> connection detected</p>
                  )}
                  {exfilConnections.length === 0 && telegramConns.length === 0 && (
                    <p className="italic text-primary/50">No suspicious outbound endpoints captured</p>
                  )}
                </div>
              </div>
            </div>

            {/* Network Exfiltration Details — from real captured data */}
            {exfilConnections.length > 0 && (
              <div className="bg-canvas border border-border-subtle p-4 rounded text-xs font-mono space-y-2">
                <div className="flex justify-between items-center text-primary/70 border-b border-border-subtle pb-2">
                  <span>📡 Captured Exfiltration Targets ({exfilConnections.length})</span>
                  <span className="text-green-400">
                    Total: ↑ {formatBytes(totalBytesSent)} sent · ↓ {formatBytes(totalBytesRecv)} received
                  </span>
                </div>
                <div className="space-y-1.5 pt-1">
                  {exfilConnections.map((conn: any, i: number) => (
                    <div key={i} className="flex items-center justify-between py-1 border-b border-border-subtle/50 last:border-0">
                      <div className="flex items-center space-x-3">
                        <span className={`px-1.5 py-0.5 text-[10px] rounded ${
                          conn.apkType === "child" ? "bg-orange-500/10 text-orange-400 border border-orange-500/20"
                            : "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                        }`}>
                          {conn.apkType === "child" ? "📦 Child APK" : "📱 Parent APK"}
                        </span>
                        <span className="text-red-400">{conn.dest || conn.ip}:{conn.port}</span>
                        <span className="text-primary/50">{conn.proto}</span>
                        {conn.attributedPackage && (
                          <span className="text-cyan-400/70 text-[10px]">pkg: {conn.attributedPackage}</span>
                        )}
                      </div>
                      <div className="text-primary/50">
                        {conn.bytesSent > 0 && <span>↑ {formatBytes(conn.bytesSent)}</span>}
                        {conn.bytesRecv > 0 && <span className="ml-2">↓ {formatBytes(conn.bytesRecv)}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Frida Instrumentation Status */}
            <div className="mt-3 bg-canvas border border-border-subtle p-3 rounded text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="text-primary/50">Interception Layer:</span>
                <span className={fridaUsed ? "text-purple-400 font-bold" : "text-primary/50 italic"}>
                  {fridaUsed ? "🔓 Frida SSL Bypass + TrustManager Hook Active" : "⚡ Frida not active this session — enable for TLS interception"}
                </span>
              </div>
              {fridaData && typeof fridaData === "object" && Object.keys(fridaData).length > 0 && (
                <div className="mt-2 pt-2 border-t border-border-subtle/50">
                  <span className="text-primary/50 block mb-1">Frida Captured Data:</span>
                  {Object.entries(fridaData).slice(0, 5).map(([key, val]) => (
                    <div key={key} className="flex items-center space-x-2 py-0.5">
                      <span className="text-cyan-400">{key}:</span>
                      <span className="text-primary/80 truncate max-w-md">{typeof val === "string" ? val : JSON.stringify(val)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      })()}


      {/* Behavioral Event Timeline */}
      <div className="bg-panel border border-border-subtle p-4">
        <h3 className="font-display font-semibold text-sm mb-3 border-b border-border-subtle pb-2">
          Behavioral Event Timeline
        </h3>
        {filteredTimeline.length === 0 ? (
          <p className="text-xs text-primary/50 italic py-8 text-center">Waiting for dynamic analysis events...</p>
        ) : (
          <div className="h-[500px]">
            <BehaviorTimeline events={filteredTimeline} />
          </div>
        )}
      </div>

      {/* Suspicious API Calls */}
      <div className="bg-panel border border-border-subtle p-4 overflow-hidden">
        <h3 className="font-display font-semibold text-sm mb-3 border-b border-border-subtle pb-2">
          Suspicious API Calls
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[600px]">
            <thead>
              <tr className="border-b border-border-subtle text-left">
                <th className="pb-2 font-mono text-xs text-primary/60">API</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Context</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Risk</th>
              </tr>
            </thead>
            <tbody>
              {apisToUse.length === 0 ? (
                <tr><td colSpan={3} className="text-xs text-center text-primary/50 py-4">No suspicious APIs detected</td></tr>
              ) : apisToUse.map((row: any, idx: number) => (
                <tr key={`${row.api}-${idx}`} className="border-b border-border-subtle/50 hover:bg-canvas/50">
                  <td className="py-2 font-mono text-xs">
                    <span className="font-semibold">{row.api}</span>
                    <span className="block text-[10px] text-primary/40 mt-0.5">
                      {row.source === "heuristic_code_scan" ? "Inferred (Heuristic Scan)" :
                       row.source === "manual_pentest" ? "Observed (Manual Pentest)" :
                       "Observed (Runtime)"}
                    </span>
                  </td>
                  <td className="py-2 text-xs text-primary/60 font-mono break-all">{row.cls}</td>
                  <td className="py-2">
                    <span
                      className={`text-xs font-mono font-semibold px-2 py-0.5 rounded-sm ${
                        row.risk === "CRITICAL"
                          ? "bg-red-100 text-red-700 border-red-200"
                          : row.risk === "HIGH"
                          ? "bg-orange-100 text-orange-700 border-orange-200"
                          : row.risk === "MEDIUM"
                          ? "bg-yellow-100 text-yellow-700 border-yellow-200"
                          : "bg-blue-100 text-blue-700 border-blue-200"
                      }`}
                    >
                      {row.risk}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Network Activity */}
      <div className="bg-panel border border-border-subtle p-4 overflow-hidden">
        <div className="flex items-center justify-between mb-3 border-b border-border-subtle pb-2">
          <h3 className="font-display font-semibold text-sm">
            Network Activity
          </h3>
          {pentestData?.pcap_analysis && (
            <div className="flex items-center space-x-3 text-[11px] font-mono text-primary/50">
              <span>📦 {pentestData.pcap_analysis.total_packets?.toLocaleString() || 0} packets</span>
              <span>•</span>
              <span>💾 {formatBytes(pentestData.pcap_analysis.total_bytes || 0)}</span>
              {pentestData.pcap_analysis.dns_domains?.length > 0 && (
                <>
                  <span>•</span>
                  <span>🌐 {pentestData.pcap_analysis.dns_domains.length} DNS domains</span>
                </>
              )}
            </div>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[900px]">
            <thead>
              <tr className="border-b border-border-subtle text-left">
                <th className="pb-2 font-mono text-xs text-primary/60">Destination / Hostname</th>
                <th className="pb-2 font-mono text-xs text-primary/60">IP Address</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Attribution</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Protocol</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Port</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Data</th>
                <th className="pb-2 font-mono text-xs text-primary/60">First Seen</th>
                <th className="pb-2 font-mono text-xs text-primary/60">Static Ref</th>
              </tr>
            </thead>
            <tbody>
              {filteredNetwork.length === 0 ? (
                <tr><td colSpan={8} className="text-xs text-center text-primary/50 py-4">No network activity detected</td></tr>
              ) : filteredNetwork.map((row: any, index: number) => (
                <tr key={`${row.dest}-${row.port}-${index}`} className="border-b border-border-subtle/50 hover:bg-canvas/50">
                  <td className="py-2 font-mono text-xs">
                    <span className="font-semibold">{row.hostname || row.dest}</span>
                    {row.source && (
                      <span className="block text-[10px] text-primary/40 mt-0.5">
                        {row.source === "Static IOC cross-reference" ? "Inferred (Static IOC)" :
                         row.source === "manual_pentest_runtime" ? "Captured (Runtime Poll)" :
                         row.source === "pcap_capture" ? "📦 Captured (PCAP)" :
                         row.source === "child_apk_network" ? "⚠ Child APK Traffic" :
                         row.source === "deep_scan" ? "VT Enrichment" :
                         "Observed (Runtime)"}
                      </span>
                    )}
                  </td>
                  <td className="py-2 text-xs font-mono text-primary/60">
                    {row.ip || row.dest}
                  </td>
                  <td className="py-2 text-xs">
                    {row.attributedPackage ? (
                      <div className="flex flex-col gap-0.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                          row.apkType === 'child' || row.source === 'child_apk_network'
                            ? 'bg-purple-500/15 text-purple-400 border border-purple-500/20'
                            : row.apkType === 'system'
                            ? 'bg-gray-500/10 text-gray-400 border border-gray-500/20'
                            : 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        }`}>
                          {row.apkType === 'child' || row.source === 'child_apk_network' ? '📦 Child APK' :
                           row.apkType === 'system' ? '⚙️ System' :
                           row.source === 'frida_intercept' ? '🔍 Frida' :
                           '📱 Parent APK'}
                        </span>
                        <span className="text-[9px] text-primary/40 font-mono truncate max-w-[150px]" title={row.attributedPackage}>
                          {row.attributedPackage}
                        </span>
                      </div>
                    ) : (
                      <span className="text-primary/30">—</span>
                    )}
                  </td>
                  <td className="py-2 text-xs font-mono">
                    <span className={`px-1.5 py-0.5 rounded text-[11px] ${
                      row.proto === "UDP" ? "bg-purple-500/10 text-purple-400" :
                      row.proto === "TCP" ? "bg-blue-500/10 text-blue-400" :
                      "bg-zinc-500/10 text-zinc-400"
                    }`}>
                      {row.proto}
                    </span>
                  </td>
                  <td className="py-2 text-xs font-mono">{row.port}</td>
                  <td className="py-2 text-xs font-mono">
                    {(row.bytesSent > 0 || row.bytesRecv > 0) ? (
                      <div>
                        <span className="text-orange-400">↑{formatBytes(row.bytesSent)}</span>
                        <span className="text-primary/30 mx-1">/</span>
                        <span className="text-blue-400">↓{formatBytes(row.bytesRecv)}</span>
                      </div>
                    ) : row.packets > 0 ? (
                      <span className="text-primary/50">{row.packets} pkts</span>
                    ) : (
                      <span className="text-primary/30">-</span>
                    )}
                  </td>
                  <td className="py-2 text-xs font-mono text-primary/50">
                    {row.firstSeen ? new Date(row.firstSeen).toLocaleTimeString() : "-"}
                  </td>
                  <td className="py-2">
                    {row.staticRef ? (
                      <div className="flex flex-col gap-0.5">
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/20 font-mono">
                          ⚡ Found in Code
                        </span>
                        {row.staticRef.code_location && (
                          <span className="text-[9px] text-primary/40 font-mono truncate max-w-[120px]" title={row.staticRef.code_location}>
                            {row.staticRef.code_location}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-primary/30">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
