import React from "react";
import VulnerabilityCard from "@/components/VulnerabilityCard";

interface VulnsTabProps {
  caseData: any;
  analysisResults?: any;
  isMockCase: boolean;
}

export default function VulnsTab({ caseData, analysisResults, isMockCase }: VulnsTabProps) {
  // Find vulnerability phase result from the array structure
  const vulnResult = Array.isArray(analysisResults) 
    ? analysisResults.find((r: any) => r.phase === "vulnerability")?.result 
    : null;
    
  const vulnsToUse = vulnResult?.findings || [];
  
  return (
    <div className="space-y-4">
      <div className="flex gap-4 text-xs font-mono text-primary/60 mb-2">
        <span>
          Total: <strong className="text-primary">{vulnsToUse.length}</strong>
        </span>
        <span className="text-red-600">
          Critical: <strong>{vulnsToUse.filter((v: any) => v.severity === "critical").length}</strong>
        </span>
        <span className="text-orange-600">
          High: <strong>{vulnsToUse.filter((v: any) => v.severity === "high").length}</strong>
        </span>
      </div>
      {vulnsToUse.length === 0 ? (
        <div className="bg-panel border border-border-subtle p-4">
          <p className="text-xs text-primary/60 italic">No vulnerabilities found.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {vulnsToUse.map((vuln: any) => (
            <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
          ))}
        </div>
      )}
    </div>
  );
}
