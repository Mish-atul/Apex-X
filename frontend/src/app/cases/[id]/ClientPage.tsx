"use client";

import { useState, useMemo, useEffect } from "react";
import ThreatScore from "@/components/ThreatScore";
import BehaviorTimeline from "@/components/BehaviorTimeline";
import NetworkGraph from "@/components/NetworkGraph";
import PermissionMatrix from "@/components/PermissionMatrix";
import IOCTable from "@/components/IOCTable";
import VulnerabilityCard from "@/components/VulnerabilityCard";
import PhaseProgress from "@/components/PhaseProgress";
import CaseTabs from "./CaseTabs";
import { downloadReport, downloadEvidencePackage, getCaseDetail, getCaseResults } from "@/services/api";
import { FileText, Download, AlertTriangle, Shield, Activity, Network, Bug, FileDown, ArrowLeft } from "lucide-react";
import Link from "next/link";

const TABS = [
  { id: "overview", label: "Overview", icon: Shield },
  { id: "static", label: "Static Analysis", icon: FileText },
  { id: "dynamic", label: "Dynamic Analysis", icon: Activity },
  { id: "c2", label: "C2 & Attribution", icon: Network },
  { id: "vulns", label: "Vulnerabilities", icon: Bug },
  { id: "reports", label: "Reports", icon: FileDown },
] as const;

type TabId = (typeof TABS)[number]["id"];



export default function CaseDetailClient({ caseId }: { caseId: string }) {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [caseData, setCaseData] = useState<any>(null);
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [caseReports, setCaseReports] = useState<any[]>([]);

  useEffect(() => {
    async function loadData(isInitial = true) {
      if (isInitial) setIsLoading(true);
      
      const { data: detailData, error: detailError } = await getCaseDetail(caseId);
      if (detailError || !detailData) {
        if (isInitial) setError(detailError || "Failed to load case details");
        if (isInitial) setIsLoading(false);
        return;
      }
      
      setCaseData(detailData);
      
      // Fetch analysis results
      const { data: resultsData } = await getCaseResults(caseId);
      if (resultsData?.results) {
        // Convert dict {static: {...}, c2_intelligence: {...}} to array [{phase, result}]
        const resultsArray = Object.entries(resultsData.results).map(([phase, result]) => ({ phase, result }));
        setAnalysisResults(resultsArray);
        
        // Enrich caseData with derived metrics
        const staticResult = resultsArray.find((r: any) => r.phase === "static")?.result as any;
        if (staticResult) {
          const manifest = staticResult.steps?.manifest?.data || {};
          if (manifest.package_name && manifest.package_name !== "unknown") {
            detailData.package_name = manifest.package_name;
          }
          
          if (!detailData.threat_score || detailData.threat_score === 0) {
            let score = 0;
            const dangerousPerms = Object.values(manifest.permissions || {}).filter((v: any) => v.protection_level === "dangerous").length;
            const misconfigs = manifest.misconfigurations?.length || 0;
            const totalIocs = staticResult.steps?.iocs?.data?.total_indicators || 0;
            const yaraHits = staticResult.steps?.yara?.data?.total_matches || 0;
            
            score += dangerousPerms * 3;
            score += misconfigs * 5;
            score += totalIocs * 1;
            
            detailData.threat_score = Math.min(score + yaraHits * 25, 100);
          }

          // AGGREGATE THREAT SCORE ACROSS ALL PHASES
          let maxThreat = detailData.threat_score || 0;
          resultsArray.forEach((r: any) => {
            if (r.result?.threat_score && r.result.threat_score > maxThreat) {
              maxThreat = r.result.threat_score;
            }
            if (r.result?.risk_score && r.result.risk_score > maxThreat) {
              maxThreat = r.result.risk_score;
            }
          });
          detailData.threat_score = maxThreat;
          
          if (!detailData.verdict || detailData.verdict === "completed") {
             if (detailData.threat_score >= 74) detailData.verdict = "High Risk";
             else if (detailData.threat_score >= 40) detailData.verdict = "Medium Risk";
             else detailData.verdict = "Low Risk";
          }
          
          const duration = staticResult.duration_seconds || 0;
          let formattedTime = `${duration.toFixed(1)} s`;
          if (duration >= 60) {
            const mins = Math.floor(duration / 60);
            const secs = Math.floor(duration % 60);
            formattedTime = `${mins}m ${secs}s`;
          }
          detailData.analysis_time = formattedTime;
          detailData.engine_version = "APEX-X v2.1";
          detailData.decompiler = staticResult.steps?.jadx?.status === "success" ? "JADX + Androguard" : "Androguard";
        }
      }
      
      setCaseData(detailData);
      
      const langs = ["English", "Hindi", "Kannada", "Tamil", "Telugu"];
      const generatedReports = langs.map((lang, idx) => ({
        id: `rpt-${detailData.id}-${lang.toLowerCase()}`,
        case_id: detailData.id,
        case_number: detailData.case_number || `CASE-${detailData.id.slice(0, 8).toUpperCase()}`,
        title: `${detailData.apk_name || "APK"} — Investigation Report (${lang})`,
        type: "pdf",
        language: lang,
        generated_at: new Date().toISOString(),
        size_kb: 0,
      }));
      setCaseReports(generatedReports);
      
      if (isInitial) setIsLoading(false);
    }
    
    loadData();

    // Setup polling if the case is still analyzing
    const intervalId = setInterval(() => {
      setCaseData((currentCaseData: any) => {
        if (currentCaseData && currentCaseData.status === "analyzing") {
          loadData(false);
        }
        return currentCaseData;
      });
    }, 5000);

    return () => clearInterval(intervalId);
  }, [caseId]);

  if (isLoading) {
    return (
      <main className="flex-1 flex flex-col max-w-7xl mx-auto w-full p-6">
        <div className="h-4 w-32 bg-surface rounded animate-pulse mb-4" />
        <div className="bg-panel border border-border-subtle rounded-lg p-6 mb-6 animate-pulse">
          <div className="h-3 w-24 bg-surface rounded mb-3" />
          <div className="h-8 w-2/3 bg-surface rounded mb-2" />
          <div className="h-3 w-40 bg-surface rounded" />
        </div>
        <div className="flex gap-2 mb-4">
          {[...Array(6)].map((_, i) => <div key={i} className="h-8 w-28 bg-surface rounded animate-pulse" />)}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => <div key={i} className="h-32 bg-panel border border-border-subtle rounded-lg animate-pulse" />)}
        </div>
        <p className="sr-only">Loading case {caseId}</p>
      </main>
    );
  }
  
  if (error || !caseData) {
    return <div className="p-8 flex justify-center"><p className="font-mono text-red-600">{error || "Case not found"}</p></div>;
  }

  const phaseOf = (name: string) =>
    Array.isArray(analysisResults) ? analysisResults.find((r: any) => r.phase === name)?.result : undefined;
  const toStatus = (r: any): "pending" | "running" | "completed" | "failed" => {
    if (!r) return caseData.status === "analyzing" ? "running" : "pending";
    const st = r.status;
    if (st === "failed" || st === "error") return "failed";
    if (st === "running") return "running";
    if (st === "queued" || st === "pending") return "pending";
    return "completed";
  };
  const phaseStatus = [
    { phase: "Upload & Validation", r: { status: "completed", completed_at: caseData.created_at } },
    { phase: "Static Analysis", r: phaseOf("static") },
    { phase: "Dynamic Analysis", r: phaseOf("dynamic") },
    { phase: "C2 Intelligence", r: phaseOf("c2_intelligence") },
    { phase: "Vulnerability Scan", r: phaseOf("vulnerability") },
  ].map(({ phase, r }) => {
    const status = toStatus(r);
    return {
      phase,
      status,
      progress: status === "completed" || status === "failed" ? 100 : status === "running" ? 50 : 0,
      started_at: r?.started_at || null,
      completed_at: status === "completed" ? r?.completed_at || null : null,
    };
  });

  return (
    <main className="flex-1 flex flex-col max-w-7xl mx-auto w-full p-6">
      <Link href="/dashboard" className="flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-indigo-600 transition-colors mb-4">
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>
      
      {/* Case Header */}
      <div className="bg-panel border-l-4 border-l-primary shadow-lg p-6 mb-6 relative overflow-hidden group flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <span className="font-pixel text-sm font-bold tracking-widest text-primary bg-primary/10 px-2 py-1 border border-primary/30 shadow-[0_0_15px_rgba(79,70,229,0.2)] group-hover:animate-pulse">
              {caseData.case_number}
            </span>
          </div>
          <h1 className="font-display text-3xl sm:text-4xl font-bold mb-1 text-transparent bg-clip-text bg-gradient-to-r from-slate-800 to-slate-500">
            {caseData.apk_name}
          </h1>
          <p className="text-sm font-mono text-primary/80 bg-canvas inline-block px-2 py-0.5 border border-border-subtle rounded-sm">
            {caseData.package_name || "N/A"}
          </p>
        </div>
        <div className="relative z-10 flex flex-col md:items-end gap-2">
          <span
            className={`text-sm font-mono font-bold px-3 py-1 flex items-center gap-2 ${
              caseData.status === "completed"
                ? "bg-green-100 text-green-800 border border-green-300"
                : caseData.status === "analyzing"
                ? "bg-blue-100 text-blue-800 border border-blue-300"
                : "bg-gray-100 text-gray-800 border border-gray-300"
            }`}
          >
            {caseData.status === "analyzing" && (
              <svg className="animate-spin h-4 w-4 text-blue-700" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            )}
            {caseData.status.toUpperCase()}
          </span>
          {caseData.verdict && (
            <span className={`text-sm font-bold px-3 py-1 border shadow-sm ${
              caseData.verdict === "High Risk" || caseData.verdict === "Critical" ? "bg-red-100 text-red-800 border-red-300" :
              caseData.verdict === "Medium Risk" ? "bg-orange-100 text-orange-800 border-orange-300" :
              "bg-green-100 text-green-800 border-green-300"
            }`}>
              {caseData.verdict.toUpperCase()}
            </span>
          )}
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-border-subtle mb-4 overflow-x-auto">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              type="button"
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-primary text-primary"
                  : "border-transparent text-primary/50 hover:text-primary/80"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <CaseTabs
        activeTab={activeTab}
        caseData={caseData}
        phaseStatus={phaseStatus}
        caseReports={caseReports}
        analysisResults={analysisResults}
      />
    </main>
  );
}
