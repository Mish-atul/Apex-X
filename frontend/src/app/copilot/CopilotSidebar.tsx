import Link from "next/link";
import { ArrowLeft, Zap } from "lucide-react";
import { CaseResponse } from "@/services/api";

// Static example prompts shown as clickable suggestions (UI affordance, not case data)
const SUGGESTED_QUERIES = [
  "What permissions does this APK request?",
  "Are there any exported components without protection?",
  "What hardcoded secrets were found?",
  "Summarize the OWASP vulnerabilities detected.",
  "What is the overall risk level and why?",
];

export default function CopilotSidebar({
  selectedCase,
  setSelectedCase,
  setInput,
  cases = [],
}: {
  selectedCase: string;
  setSelectedCase: (id: string) => void;
  setInput: (text: string) => void;
  cases: CaseResponse[];
}) {
  const currentCase = cases.find((c) => c.id === selectedCase);

  return (
    <div className="w-full md:w-80 flex md:flex-col gap-4 shrink-0">
      <Link href="/dashboard" className="flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-indigo-600 transition-colors mb-2">
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>
      
      {/* Case Selector */}
      <div className="bg-panel border border-border-subtle p-4">
        <label htmlFor="caseSelector" className="block text-xs font-mono text-primary/60 mb-2">
          ACTIVE CONTEXT
        </label>
        <select
          id="caseSelector"
          value={selectedCase}
          onChange={(e) => setSelectedCase(e.target.value)}
          className="w-full bg-canvas border border-border-subtle px-3 py-2 text-sm font-mono focus:outline-none focus:border-primary/50"
        >
          {cases.map((c) => (
            <option key={c.id} value={c.id}>
              {c.case_number} - {c.apk_name}
            </option>
          ))}
        </select>
        {currentCase && (
          <div className="mt-3 space-y-1">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-primary/60">Risk Score</span>
              <span
                className={`font-bold ${
                  (currentCase.threat_score || 0) > 40
                    ? "text-red-600"
                    : (currentCase.threat_score || 0) > 20
                    ? "text-orange-500"
                    : "text-green-600"
                }`}
              >
                {currentCase.threat_score || 0}/100
              </span>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono">
              <Zap className="w-3 h-3 text-emerald-500" />
              <span className="text-primary/60">
                Qwen 2.5 (Local)
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Suggested Queries */}
      <div className="bg-panel border border-border-subtle p-4 flex-1 overflow-y-auto hidden md:block">
        <h3 className="font-display font-semibold text-sm mb-3 border-b border-border-subtle pb-2">
          Suggested Queries
        </h3>
        <div className="space-y-2">
          {SUGGESTED_QUERIES.map((suggestion) => (
            <button
              type="button"
              key={suggestion}
              onClick={() => setInput(suggestion)}
              className="w-full text-left p-2 text-sm text-primary/80 hover:bg-canvas border border-transparent hover:border-border-subtle transition-colors"
            >
              {suggestion}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
