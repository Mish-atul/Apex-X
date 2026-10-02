"use client";

import { FileText, Download, FileArchive, Search, ArrowLeft, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { getCases, CaseResponse, downloadReport, downloadEvidencePackage } from "@/services/api";
import { useFeedback } from "@/components/Feedback";

const LANGUAGES = ["English", "Hindi", "Kannada", "Tamil", "Telugu"];

function riskLabel(score: number) {
  if (score >= 75) return { label: "Critical", cls: "text-red-600 bg-red-50" };
  if (score >= 50) return { label: "High", cls: "text-orange-600 bg-orange-50" };
  if (score >= 25) return { label: "Medium", cls: "text-amber-600 bg-amber-50" };
  return { label: "Low", cls: "text-emerald-600 bg-emerald-50" };
}

export default function DocumentsClient() {
  const { toast } = useFeedback();
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    getCases().then(({ data }) => {
      if (data) setCases(data);
      setLoading(false);
    });
  }, []);

  const completed = cases.filter(
    (c) =>
      c.status === "completed" &&
      (search === "" ||
        c.apk_name?.toLowerCase().includes(search.toLowerCase()) ||
        c.case_number?.toLowerCase().includes(search.toLowerCase())),
  );

  const handlePDF = async (caseId: string, lang: string) => {
    setBusy(`${caseId}-${lang}`);
    try {
      await downloadReport(caseId, lang.toLowerCase());
      toast("success", `${lang} report downloaded`);
    } catch (e) {
      toast("error", "Report download failed", String(e));
    } finally {
      setBusy(null);
    }
  };

  const handleEvidence = async (caseId: string) => {
    setBusy(`${caseId}-evidence`);
    try {
      await downloadEvidencePackage(caseId);
      toast("success", "Evidence package downloaded");
    } catch (e) {
      toast("error", "Evidence download failed", String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="flex-1 flex flex-col max-w-6xl mx-auto w-full p-6">
      <Link href="/dashboard" className="flex items-center gap-2 text-sm font-medium text-text-muted hover:text-primary transition-colors mb-4">
        <ArrowLeft className="w-4 h-4" /> Back to Dashboard
      </Link>

      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-text">Investigation Reports</h1>
        <p className="text-sm text-text-muted mt-1">
          Download forensic reports and Section 65B evidence packages for completed cases.
        </p>
      </div>

      <div className="relative mb-5 max-w-md">
        <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by APK name or case number..."
          className="w-full pl-9 pr-3 py-2 text-sm bg-panel border border-border-subtle rounded-md focus:outline-none focus:ring-2 focus:ring-primary/30"
        />
      </div>

      {loading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-28 bg-panel border border-border-subtle rounded-lg animate-pulse" />
          ))}
        </div>
      ) : completed.length === 0 ? (
        <div className="bg-panel border border-border-subtle rounded-lg p-12 text-center">
          <FileText className="w-10 h-10 text-text-muted/50 mx-auto mb-3" />
          <p className="text-text-muted">No completed cases yet. Reports appear here once analysis finishes.</p>
          <Link href="/upload" className="inline-block mt-4 px-4 py-2 bg-primary text-white text-sm font-medium rounded-md hover:bg-primary/90 transition-colors">
            Upload an APK
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {completed.map((c) => {
            const risk = riskLabel(c.threat_score || 0);
            return (
              <div key={c.id} className="bg-panel border border-border-subtle rounded-lg p-4">
                <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-text-muted">{c.case_number}</span>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded ${risk.cls}`}>
                        {risk.label} · {c.threat_score || 0}/100
                      </span>
                    </div>
                    <Link href={`/cases/${c.id}`} className="font-display font-semibold text-text hover:text-primary transition-colors truncate block">
                      {c.apk_name}
                    </Link>
                  </div>
                  <button
                    onClick={() => handleEvidence(c.id)}
                    disabled={busy === `${c.id}-evidence`}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium border border-border-subtle rounded-md hover:bg-surface transition-colors disabled:opacity-50"
                  >
                    {busy === `${c.id}-evidence` ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileArchive className="w-3.5 h-3.5" />}
                    Evidence Package (65B)
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {LANGUAGES.map((lang) => (
                    <button
                      key={lang}
                      onClick={() => handlePDF(c.id, lang)}
                      disabled={busy === `${c.id}-${lang}`}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-surface hover:bg-primary/10 border border-border-subtle rounded-md transition-colors disabled:opacity-50"
                    >
                      {busy === `${c.id}-${lang}` ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                      {lang} PDF
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </main>
  );
}
