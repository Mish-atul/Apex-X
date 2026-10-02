"use client";

import Link from "next/link";
import type { CaseResponse } from "@/services/api";
import { deleteCase } from "@/services/api";
import { ChevronRight, Trash2 } from "lucide-react";
import { useState } from "react";
import { useFeedback } from "@/components/Feedback";

interface CaseCardProps {
  caseData: CaseResponse;
  onDeleted?: (caseId: string) => void;
}

const statusConfig: Record<string, { bg: string; text: string; label: string }> = {
  completed: { bg: "bg-emerald-50", text: "text-emerald-700", label: "Done" },
  analyzing: { bg: "bg-blue-50", text: "text-blue-700", label: "Scanning..." },
  pending: { bg: "bg-gray-50", text: "text-gray-600", label: "Queued" },
  failed: { bg: "bg-red-50", text: "text-red-700", label: "Failed" },
};

function getScoreColor(score: number): string {
  if (score <= 25) return "text-emerald-600 bg-emerald-50";
  if (score <= 50) return "text-amber-600 bg-amber-50";
  if (score <= 75) return "text-orange-600 bg-orange-50";
  return "text-red-600 bg-red-50";
}

function getRiskLabel(score: number): string {
  if (score <= 25) return "Low Risk";
  if (score <= 50) return "Medium Risk";
  if (score <= 75) return "High Risk";
  return "Critical";
}

export default function CaseCard({ caseData, onDeleted }: CaseCardProps) {
  const status = statusConfig[caseData.status] || statusConfig.pending;
  const score = caseData.threat_score || 0;
  const [isDeleting, setIsDeleting] = useState(false);
  const { toast, confirm } = useFeedback();

  const handleDelete = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    const confirmed = await confirm({
      title: `Delete “${caseData.apk_name}”?`,
      message: "This permanently removes the case and all analysis results from the database and disk.",
      confirmLabel: "Delete case",
      tone: "danger",
    });
    if (!confirmed) return;

    try {
      setIsDeleting(true);
      await deleteCase(caseData.id);
      toast("success", "Case deleted", caseData.apk_name);
      if (onDeleted) {
        onDeleted(caseData.id);
      } else {
        window.location.reload();
      }
    } catch (err) {
      toast("error", "Failed to delete case", String(err));
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <Link prefetch={false} href={`/cases/${caseData.id}`}>
      <div className={`bg-white border border-border-subtle rounded-xl p-4 hover:border-primary/30 hover:shadow-md transition-all cursor-pointer group ${isDeleting ? 'opacity-50 pointer-events-none' : ''}`}>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-text-muted">
            {caseData.case_number}
          </span>
          <div className="flex items-center gap-2">
            <span
              className={`text-xs font-medium px-2.5 py-0.5 rounded-full ${status.bg} ${status.text}`}
            >
              {status.label}
            </span>
            <button
              onClick={handleDelete}
              disabled={isDeleting}
              title="Delete case"
              className="p-1 rounded-md text-gray-400 hover:text-red-500 hover:bg-red-50 transition-colors opacity-0 group-hover:opacity-100"
            >
              {isDeleting ? (
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              ) : (
                <Trash2 className="w-4 h-4" />
              )}
            </button>
          </div>
        </div>

        <h3 className="font-semibold text-sm mb-0.5 truncate">{caseData.apk_name}</h3>
        <p className="text-xs text-text-muted truncate mb-3">
          {caseData.package_name || "Unknown package"}
        </p>

        <div className="flex items-center justify-between pt-2 border-t border-border-subtle">
          {score > 0 ? (
            <span
              className={`text-xs font-semibold px-2.5 py-1 rounded-lg ${getScoreColor(score)}`}
            >
              {score}/100 · {getRiskLabel(score)}
            </span>
          ) : (
            <span className="text-xs text-text-muted">Not scored yet</span>
          )}
          <ChevronRight className="w-4 h-4 text-text-muted group-hover:text-primary transition-colors" />
        </div>
      </div>
    </Link>
  );
}
