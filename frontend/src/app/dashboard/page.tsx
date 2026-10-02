"use client";

import { m, Variants } from "framer-motion";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ActivitySquare, CheckCircle2, Search, Filter } from "lucide-react";
import CaseCard from "@/components/CaseCard";
import PhaseProgress from "@/components/PhaseProgress";
import { getCases, CaseResponse } from "@/services/api";

// Pipeline stages shown while a case is being analysed (indeterminate progress)
const ANALYZING_PHASES = [
  { phase: "Static Analysis", status: "running" as const, progress: 60, started_at: null, completed_at: null },
  { phase: "Dynamic Analysis", status: "pending" as const, progress: 0, started_at: null, completed_at: null },
  { phase: "C2 Intelligence", status: "pending" as const, progress: 0, started_at: null, completed_at: null },
  { phase: "Vulnerability Scan", status: "pending" as const, progress: 0, started_at: null, completed_at: null },
];

const containerVariants: Variants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.1 },
  },
};

const itemVariants: Variants = {
  hidden: { opacity: 0, y: 15 },
  show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 100 } },
};

export default function Dashboard() {
  const router = useRouter();
  const [cases, setCases] = useState<CaseResponse[]>([]);
  
  useEffect(() => {
    getCases().then(({ data }) => {
      if (data) {
        setCases(data);
      }
    });
  }, []);

  const stats = {
    total: cases.length,
    critical: cases.filter((c) => (c.threat_score || 0) >= 75).length,
    analyzing: cases.filter((c) => c.status === "analyzing").length,
    completed: cases.filter((c) => c.status === "completed").length,
  };

  const recentActivities = cases.map((c) => {
    let action = "APK_UPLOADED";
    let details = `APK uploaded: ${c.apk_name}`;
    if (c.status === "completed") {
      action = "ANALYSIS_COMPLETED";
      details = `Static & Dynamic analysis completed for ${c.apk_name} — Threat Score: ${c.threat_score || 0}/100`;
    } else if (c.status === "analyzing") {
      action = "ANALYSIS_IN_PROGRESS";
      details = `Automated forensics pipeline analyzing ${c.apk_name}...`;
    }
    return {
      id: `act-${c.id}`,
      action,
      case_id: c.id,
      case_number: c.case_number || `CASE-${c.id.slice(0, 8).toUpperCase()}`,
      user: "APEX-X Engine",
      timestamp: c.updated_at || c.created_at || new Date().toISOString(),
      details,
    };
  });

  return (
    <main className="min-h-screen p-6 md:p-8 max-w-[1600px] mx-auto w-full flex flex-col gap-6">
      <m.header 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ type: "spring", stiffness: 200, damping: 20 }}
        className="flex flex-col md:flex-row md:items-end justify-between border-b border-border-subtle pb-8 gap-6"
      >
        <div>
          <m.h1 
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.1, type: "spring" }}
            className="text-4xl md:text-5xl font-display font-black flex items-center gap-4 tracking-tight"
          >
            <div className="w-14 h-14 bg-gradient-to-br from-indigo-500 via-purple-500 to-pink-500 rounded-2xl flex items-center justify-center shrink-0 shadow-lg shadow-indigo-500/20">
              <ActivitySquare className="w-7 h-7 text-white" />
            </div>
            <span className="bg-gradient-to-r from-slate-900 via-indigo-900 to-slate-900 bg-clip-text text-transparent">
              Analysis Results
            </span>
          </m.h1>
          <m.p 
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="text-base font-sans text-text-muted mt-4 flex items-center gap-2"
          >
            <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0" />
            These applications have been deeply scanned and analyzed. Click any card for comprehensive details.
          </m.p>
        </div>
        <m.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="flex gap-4 w-full md:w-auto"
        >
          <button 
            type="button"
            onClick={() => router.push("/upload")}
            className="w-full md:w-auto bg-gradient-to-r from-indigo-600 to-violet-600 text-white px-8 py-3.5 font-display font-bold text-sm tracking-wide hover:shadow-lg hover:shadow-indigo-500/30 hover:scale-105 transition-all rounded-2xl"
          >
            + Upload New APK
          </button>
        </m.div>
      </m.header>

      <m.div
        variants={containerVariants}
        initial="hidden"
        animate="show"
        className="grid grid-cols-1 lg:grid-cols-4 gap-6 flex-1 min-h-0"
      >
        {/* Left Column: Stats & Queue */}
        <div className="lg:col-span-1 flex flex-col gap-6">
          {/* Quick Stats */}
          <m.div variants={itemVariants} className="bg-panel border border-border-subtle p-4">
            <h3 className="font-display font-semibold text-sm mb-4 border-b border-border-subtle pb-2">
              Overview
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-canvas p-3 border border-border-subtle">
                <span className="block text-2xl font-display font-bold">{stats.total}</span>
                <span className="text-xs text-text-muted">Total Apps</span>
              </div>
              <div className="bg-red-50 p-3 border border-red-200">
                <span className="block text-2xl font-display font-bold text-red-700">{stats.critical}</span>
                <span className="text-xs font-mono text-red-600 uppercase">Critical</span>
              </div>
              <div className="bg-blue-50 p-3 border border-blue-200">
                <span className="block text-2xl font-display font-bold text-blue-700">{stats.analyzing}</span>
                <span className="text-xs font-mono text-blue-600 uppercase">Analyzing</span>
              </div>
              <div className="bg-green-50 p-3 border border-green-200">
                <span className="block text-2xl font-display font-bold text-green-700">{stats.completed}</span>
                <span className="text-xs font-mono text-green-600 uppercase">Completed</span>
              </div>
            </div>
          </m.div>

          {/* Active Analysis Queue */}
          <m.div variants={itemVariants} className="bg-panel border border-border-subtle p-4 flex-1">
            <h3 className="font-display font-semibold text-sm mb-4 border-b border-border-subtle pb-2">
              Active Analysis Queue
            </h3>
            {stats.analyzing > 0 ? (
              <div className="space-y-4">
                {cases.reduce<React.ReactNode[]>((acc, caseItem) => {
                  if (caseItem.status === "analyzing") {
                    acc.push(
                      <div key={caseItem.id} className="border border-border-subtle p-3">
                        <div className="flex justify-between items-center mb-2">
                          <span className="font-mono text-xs font-semibold">{caseItem.case_number}</span>
                        </div>
                        <p className="text-xs truncate mb-3">{caseItem.apk_name}</p>
                        <PhaseProgress phases={ANALYZING_PHASES} />
                      </div>
                    );
                  }
                  return acc;
                }, [])}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-40 text-center">
                <CheckCircle2 className="w-8 h-8 text-primary/20 mb-2" />
                <span className="text-sm text-primary/50">Queue is empty</span>
              </div>
            )}
          </m.div>
        </div>

        {/* Middle Column: Case List */}
        <m.div variants={itemVariants} className="lg:col-span-2 bg-panel border border-border-subtle p-4 flex flex-col">
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-4 border-b border-border-subtle pb-2 gap-3">
            <h3 className="font-display font-semibold text-sm">Analyzed Apps</h3>
            <div className="flex gap-2 w-full sm:w-auto">
              <div className="relative flex-1 sm:flex-none">
                <Search className="w-4 h-4 absolute left-2.5 top-2 text-primary/40" />
                <input 
                  type="text" 
                  placeholder="Search cases..." 
                  aria-label="Search cases"
                  className="w-full bg-canvas border border-border-subtle pl-8 pr-3 py-1.5 text-xs font-mono focus:outline-none focus:border-primary/50"
                />
              </div>
              <button type="button" className="bg-canvas border border-border-subtle p-1.5 hover:bg-border-subtle/50 transition-colors shrink-0">
                <Filter className="w-4 h-4" />
              </button>
            </div>
          </div>
          
          <div className="flex-1 overflow-y-auto pr-2 space-y-3">
            {cases.map((caseData) => (
              <CaseCard
                key={caseData.id}
                caseData={caseData}
                onDeleted={(deletedId) => setCases(cases.filter(c => c.id !== deletedId))}
              />
            ))}
          </div>
        </m.div>

        {/* Right Column: Activity Feed */}
        <m.div variants={itemVariants} className="lg:col-span-1 bg-panel border border-border-subtle p-4 flex flex-col">
          <h3 className="font-display font-semibold text-sm mb-4 border-b border-border-subtle pb-2">
            Recent Activity
          </h3>
          <div className="flex-1 overflow-y-auto space-y-4">
            {recentActivities.length === 0 && (
              <p className="text-xs text-text-muted font-mono py-6 text-center">
                No activity yet. Upload an APK to begin analysis.
              </p>
            )}
            {recentActivities.map((activity) => (
              <div key={activity.id} className="relative pl-4 border-l border-border-subtle">
                <div className="absolute w-2 h-2 bg-primary rounded-full -left-[4.5px] top-1" />
                <div className="mb-1">
                  <span className="text-xs font-mono text-primary/60 mr-2" suppressHydrationWarning>
                    {new Date(activity.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                  </span>
                  <span className="text-xs font-semibold">{activity.user}</span>
                </div>
                <p className="text-xs font-mono mb-1">{activity.action.replace(/_/g, " ")}</p>
                <div className="bg-canvas border border-border-subtle p-2 text-xs">
                  <span className="font-mono font-semibold block mb-1">{activity.case_number}</span>
                  <span className="text-primary/80">{activity.details}</span>
                </div>
              </div>
            ))}
          </div>
        </m.div>

      </m.div>
    </main>
  );
}
