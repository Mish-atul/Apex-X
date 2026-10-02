"use client";

import { useState, useEffect } from "react";

interface SharedNode {
  type: string;
  value: string;
}

interface Correlation {
  case_id: string;
  related_package: string;
  shared_nodes: SharedNode[];
}

export default function SyndicateAlert({ caseId }: { caseId: string }) {
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "/api/v1";
    fetch(`${API_BASE_URL}/cases/${caseId}/correlations`)
      .then(async res => {
        if (!res.ok) throw new Error("API error");
        const text = await res.text();
        try {
          return JSON.parse(text);
        } catch {
          throw new Error("Invalid JSON response");
        }
      })
      .then(data => {
        if (data && data.correlations) {
          setCorrelations(data.correlations);
        }
      })
      .catch(err => {
        console.warn("Failed to fetch correlations:", err.message);
      })
      .finally(() => setLoading(false));
  }, [caseId]);

  if (loading || correlations.length === 0) return null;

  return (
    <div className="bg-red-50 border border-red-200 rounded-lg overflow-hidden mb-6">
      <div 
        className="p-4 flex items-center justify-between cursor-pointer hover:bg-red-100/50 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <span className="flex items-center justify-center w-8 h-8 rounded-full bg-red-100 text-red-600">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </span>
          <div>
            <h3 className="text-red-800 font-semibold text-sm font-display">Syndicate Alert</h3>
            <p className="text-red-600 text-xs">Found connections to {correlations.length} other known cases</p>
          </div>
        </div>
        <button className="text-red-500">
          {expanded ? "Collapse" : "View Connections"}
        </button>
      </div>

      {expanded && (
        <div className="p-4 border-t border-red-200 bg-white">
          <div className="space-y-4">
            {correlations.map(corr => (
              <div key={corr.case_id} className="border border-border-subtle rounded p-3">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-mono text-xs font-semibold text-primary">Case {corr.case_id.split('-')[0]}</span>
                  <span className="text-xs text-text-muted">{corr.related_package}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {corr.shared_nodes.map((node, idx) => (
                    <span key={idx} className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-surface text-[10px] font-mono text-text">
                      <span className="text-text-muted capitalize">{node.type}</span>
                      <span className="font-semibold">{node.value}</span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
