import React from "react";
import PermissionMatrix from "@/components/PermissionMatrix";
import IOCTable from "@/components/IOCTable";

interface StaticTabProps {
  caseData: any;
  analysisResults?: any;
  isMockCase: boolean;
}

export default function StaticTab({ caseData, analysisResults, isMockCase }: StaticTabProps) {
  // Extract real data from analysis results array
  const staticResult = Array.isArray(analysisResults)
    ? analysisResults.find((r: any) => r.phase === "static")?.result
    : null;

  // Build permissions from real data
  let permissionsToUse: any[] = [];
  if (staticResult) {
    const steps = staticResult.steps || {};
    // Try manifest data first, then androguard
    const manifestPerms = steps.manifest?.data?.permissions || {};
    const agPerms = steps.androguard?.data?.permissions || {};

    // Determine format
    if (manifestPerms && Array.isArray(manifestPerms.all)) {
      // It's in Androguard fallback format
      permissionsToUse = manifestPerms.all.map((p: string) => ({
        name: p,
        protection_level: manifestPerms.dangerous?.includes(p) ? "dangerous" : "normal",
        description: p.split(".").pop(),
        risk: manifestPerms.dangerous?.includes(p) ? "high" : "low",
        granted: true,
      }));
    } else if (Object.keys(manifestPerms).length > 0 && !manifestPerms.all) {
      // It's in standard APKTool format
      permissionsToUse = Object.entries(manifestPerms).map(([name, info]: any) => ({
        name,
        protection_level: info.protection_level || "normal",
        description: info.description || name.split(".").pop(),
        risk: info.protection_level === "dangerous" ? "high" : "low",
        granted: true,
      }));
    } else if (agPerms && Array.isArray(agPerms.all)) {
      // Fallback to strict Androguard phase output
      permissionsToUse = agPerms.all.map((p: string) => ({
        name: p,
        protection_level: agPerms.dangerous?.includes(p) ? "dangerous" : "normal",
        description: p.split(".").pop(),
        risk: agPerms.dangerous?.includes(p) ? "high" : "low",
        granted: true,
      }));
    }
  }

  // Build YARA matches from real data
  let rawYaraMatches: any[] = [];
  if (staticResult?.steps?.yara?.data?.matches) {
    rawYaraMatches = staticResult.steps.yara.data.matches.map((m: any) => ({
      rule_name: m.rule,
      category: m.namespace || "general",
      description: m.meta?.description || `Matched in ${m.file || "APK"}`,
      severity: m.meta?.severity || "medium",
      strings_matched: m.strings || [],
      file: m.file || "APK",
    }));
  }

  // Deduplicate and aggregate YARA matches by rule_name to prevent duplicate cards and React key collisions
  const yaraGroupMap = new Map<string, any>();
  for (const m of rawYaraMatches) {
    const key = m.rule_name || "Unknown";
    if (!yaraGroupMap.has(key)) {
      yaraGroupMap.set(key, {
        rule_name: m.rule_name,
        category: m.category,
        description: m.description,
        severity: m.severity,
        files: m.file ? [m.file] : [],
        strings_matched: [...(m.strings_matched || [])],
        match_count: 1,
      });
    } else {
      const existing = yaraGroupMap.get(key);
      existing.match_count += 1;
      if (m.file && !existing.files.includes(m.file)) {
        existing.files.push(m.file);
      }
      for (const s of (m.strings_matched || [])) {
        if (!existing.strings_matched.includes(s)) {
          existing.strings_matched.push(s);
        }
      }
      const sevWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      if ((sevWeight[m.severity] || 0) > (sevWeight[existing.severity] || 0)) {
        existing.severity = m.severity;
      }
    }
  }
  const yaraMatchesToUse = Array.from(yaraGroupMap.values());

  // APKiD packer / anti-analysis results
  const apkidStep = staticResult?.steps?.apkid;
  const apkidData = apkidStep?.status === "success" ? apkidStep.data : null;
  const apkidGroups: [string, string, string[]][] = [
    ["packers", "Packers"], ["protectors", "Protectors"], ["obfuscators", "Obfuscators"],
    ["compilers", "Compilers"], ["anti_vm", "Anti-VM"], ["anti_debug", "Anti-Debug"],
    ["manipulators", "Manipulators"],
  ].map(([k, l]) => [k, l, Array.isArray(apkidData?.[k]) ? apkidData[k] : []]);

  // Quark-Engine behaviour rules
  const quarkStep = staticResult?.steps?.quark;
  const quarkData = quarkStep?.status === "success" ? quarkStep.data : null;
  const quarkBehaviours: any[] = Array.isArray(quarkData?.top_behaviours) ? quarkData.top_behaviours : [];

  // Build IOCs from real data
  let iocsToUse: any[] = [];
  if (staticResult?.steps?.iocs?.data) {
    const iocData = staticResult.steps.iocs.data;
    const codeRefs = iocData.code_references || {};
    const allIocs: any[] = [];
    let iocId = 1;
    for (const url of iocData.urls || []) {
      allIocs.push({ id: iocId++, type: "url", value: url, context: "Java String Constant", confidence: 95, code_references: codeRefs[url] || [] });
    }
    for (const ip of iocData.ips || []) {
      allIocs.push({ id: iocId++, type: "ip", value: ip, context: "Decompiled Source", confidence: 85, code_references: codeRefs[ip] || [] });
    }
    for (const domain of iocData.domains || []) {
      allIocs.push({ id: iocId++, type: "domain", value: domain, context: "Decompiled Source", confidence: 75, code_references: codeRefs[domain] || [] });
    }
    for (const email of iocData.emails || []) {
      allIocs.push({ id: iocId++, type: "email", value: email, context: "Manifest / Source", confidence: 60, code_references: codeRefs[email] || [] });
    }
    for (const upi of iocData.upi_ids || []) {
      allIocs.push({ id: iocId++, type: "upi", value: upi, context: "Decompiled Source", confidence: 90, code_references: codeRefs[upi] || [] });
    }
    for (const key of iocData.api_keys || []) {
      allIocs.push({ id: iocId++, type: "api_key", value: key, context: "Decompiled Source", confidence: 95, code_references: codeRefs[key] || [] });
    }
    iocsToUse = allIocs;
  }

  const dangerousCount = permissionsToUse.filter((p) => p.protection_level === "dangerous").length;
  const criticalCount = permissionsToUse.filter((p) => p.risk === "critical").length;

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-panel border border-border-subtle p-4 flex flex-col items-center">
          <span className="text-xs font-mono text-primary/60 uppercase">Permissions</span>
          <span className="text-2xl font-bold">{permissionsToUse.length}</span>
        </div>
        <div className="bg-panel border border-border-subtle p-4 flex flex-col items-center">
          <span className="text-xs font-mono text-red-600/80 uppercase">Dangerous</span>
          <span className="text-2xl font-bold text-red-600">{dangerousCount}</span>
        </div>
        <div className="bg-panel border border-border-subtle p-4 flex flex-col items-center">
          <span className="text-xs font-mono text-orange-600/80 uppercase">Network Artifacts</span>
          <span className="text-2xl font-bold text-orange-600">{iocsToUse.length}</span>
        </div>
        <div className="bg-panel border border-border-subtle p-4 flex flex-col items-center">
          <span className="text-xs font-mono text-purple-600/80 uppercase">YARA Hits</span>
          <span className="text-2xl font-bold text-purple-600">{rawYaraMatches.length}</span>
          {yaraMatchesToUse.length > 0 && (
            <span className="text-[10px] font-mono text-primary/50">({yaraMatchesToUse.length} unique rules)</span>
          )}
        </div>
      </div>

      <div className="bg-panel border border-border-subtle p-4">
        <h3 className="font-display font-semibold text-sm mb-3 border-b border-border-subtle pb-2">
          Android Permissions
          <span className="ml-2 text-xs font-mono text-primary/60">
            Total: {permissionsToUse.length} | Dangerous: {dangerousCount} | Critical Risk: {criticalCount}
          </span>
        </h3>
        <div className="max-h-[400px] overflow-auto">
          <PermissionMatrix permissions={permissionsToUse} />
        </div>
      </div>

      <div className="bg-panel border border-border-subtle p-4">
        <div className="flex items-center justify-between mb-3 border-b border-border-subtle pb-2">
          <h3 className="font-display font-semibold text-sm">
            YARA Rule Matches
          </h3>
          <span className="text-xs font-mono text-primary/60">
            {yaraMatchesToUse.length} Unique Rules | {rawYaraMatches.length} Total Hits
          </span>
        </div>
        <div className="space-y-3">
          {yaraMatchesToUse.length === 0 ? (
            <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded text-sm flex items-center gap-2 font-medium shadow-sm">
              <span className="text-green-600 font-bold text-lg">✓</span> No malicious YARA signatures detected.
            </div>
          ) : (
            yaraMatchesToUse.map((match: any) => (
              <div
                key={match.rule_name}
                className={`p-3 border rounded ${
                  match.severity === "critical"
                    ? "border-red-300 bg-red-50/70"
                    : match.severity === "high"
                    ? "border-orange-300 bg-orange-50/70"
                    : "border-yellow-300 bg-yellow-50/70"
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-primary">{match.rule_name}</span>
                    {match.match_count > 1 && (
                      <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-purple-100 text-purple-800 border border-purple-200">
                        {match.match_count} hits
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                      match.severity === "critical" ? "bg-red-100 text-red-700 border-red-200" :
                      match.severity === "high" ? "bg-orange-100 text-orange-700 border-orange-200" :
                      "bg-yellow-100 text-yellow-800 border-yellow-200"
                    }`}>
                      {match.severity}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 bg-white border border-border-subtle rounded text-primary/70">
                      {match.category}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-primary/80 mb-2 leading-relaxed">{match.description}</p>
                
                {match.strings_matched && match.strings_matched.length > 0 && (
                  <div className="mt-2">
                    <div className="text-[10px] font-mono font-semibold text-primary/60 uppercase mb-1">Matched Patterns:</div>
                    <div className="flex flex-wrap gap-1">
                      {match.strings_matched.map((s: string, idx: number) => (
                        <span key={`${match.rule_name}-str-${idx}`} className="text-[11px] font-mono bg-white px-2 py-0.5 rounded border border-border-subtle text-primary/90 shadow-2xs">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {match.files && match.files.length > 0 && (
                  <details className="mt-2 text-xs">
                    <summary className="cursor-pointer text-[10px] font-mono text-primary/60 hover:text-primary transition-colors">
                      View matched files ({match.files.length})
                    </summary>
                    <ul className="mt-1 space-y-0.5 pl-3 list-disc text-[11px] font-mono text-primary/70 max-h-32 overflow-y-auto">
                      {match.files.map((f: string, fIdx: number) => (
                        <li key={fIdx} className="break-all">{f}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="bg-panel border border-border-subtle p-4">
        <div className="flex items-center justify-between mb-3 border-b border-border-subtle pb-2">
          <h3 className="font-display font-semibold text-sm">Packers &amp; Anti-Analysis (APKiD)</h3>
          {apkidData && (
            <span className={`text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
              apkidData.is_packed ? "bg-red-100 text-red-700 border-red-200" : "bg-green-100 text-green-700 border-green-200"
            }`}>
              {apkidData.is_packed ? "Packed" : "Not packed"}
            </span>
          )}
        </div>
        {!apkidData ? (
          <p className="text-xs text-primary/60 italic">
            {apkidStep?.error || apkidData?.error || "APKiD results not available for this case."}
          </p>
        ) : (
          <div className="space-y-3">
            {apkidGroups.every(([, , items]) => items.length === 0) ? (
              <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded text-sm flex items-center gap-2 font-medium shadow-sm">
                <span className="text-green-600 font-bold text-lg">✓</span> No packers, obfuscators or anti-analysis checks detected.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {apkidGroups.filter(([, , items]) => items.length > 0).map(([key, label, items]) => (
                  <div key={key} className="p-2 border border-border-subtle rounded bg-white/50">
                    <div className="text-[10px] font-mono font-semibold text-primary/60 uppercase mb-1">{label}</div>
                    <div className="flex flex-wrap gap-1">
                      {items.map((s: string, i: number) => (
                        <span key={`${key}-${i}`} className="text-[11px] font-mono bg-white px-2 py-0.5 rounded border border-border-subtle text-primary/90">{s}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
            {Array.isArray(apkidData.analyst_notes) && apkidData.analyst_notes.length > 0 && (
              <ul className="pl-4 list-disc text-xs text-primary/80 space-y-1">
                {apkidData.analyst_notes.map((n: string, i: number) => <li key={i}>{n}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>

      <div className="bg-panel border border-border-subtle p-4">
        <div className="flex items-center justify-between mb-3 border-b border-border-subtle pb-2">
          <h3 className="font-display font-semibold text-sm">Behaviour Rules (Quark-Engine)</h3>
          {quarkData?.available && (
            <span className="text-xs font-mono text-primary/60">
              {quarkData.threat_level} | Score: {quarkData.total_score} | {quarkData.high_confidence ?? 0} rules ≥80% / {quarkData.rules_total}
            </span>
          )}
        </div>
        {!quarkData || !quarkData.available || quarkData.error ? (
          <p className="text-xs text-primary/60 italic">
            {quarkStep?.error || quarkData?.error || "Quark-Engine results not available for this case."}
          </p>
        ) : quarkBehaviours.length === 0 ? (
          <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded text-sm flex items-center gap-2 font-medium shadow-sm">
            <span className="text-green-600 font-bold text-lg">✓</span> No behaviour rules matched.
          </div>
        ) : (
          <div className="space-y-1.5 max-h-[400px] overflow-auto">
            {quarkBehaviours.map((b: any) => (
              <div key={b.rule} className={`p-2 border rounded flex items-center justify-between gap-2 ${
                b.confidence >= 100 ? "border-red-300 bg-red-50/70" : b.confidence >= 80 ? "border-orange-300 bg-orange-50/70" : "border-yellow-300 bg-yellow-50/70"
              }`}>
                <div className="min-w-0">
                  <div className="text-xs text-primary/90">{b.crime}</div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    <span className="text-[10px] font-mono text-primary/50">{b.rule}</span>
                    {(b.labels || []).map((l: string) => (
                      <span key={l} className="text-[10px] font-mono px-1.5 rounded bg-white border border-border-subtle text-primary/70">{l}</span>
                    ))}
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border bg-white border-border-subtle whitespace-nowrap">
                  {b.confidence}%
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-panel border border-border-subtle p-4">
        <h3 className="font-display font-semibold text-sm mb-3 border-b border-border-subtle pb-2">
          Network Artifacts
        </h3>
        {iocsToUse.length === 0 ? (
          <p className="text-xs text-primary/60 italic">No IOCs detected in static analysis.</p>
        ) : (
          <IOCTable iocs={iocsToUse} />
        )}
      </div>
    </div>
  );
}
