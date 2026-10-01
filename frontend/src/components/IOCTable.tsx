"use client";

import { useState, useMemo } from "react";
import type { IOCEntry } from "@/services/realData";
import { exportIOCsAsCSV, exportIOCsAsJSON, exportIOCsAsSTIX } from "@/services/api";

interface IOCTableProps {
  iocs: IOCEntry[];
}

const typeColors: Record<string, string> = {
  domain: "text-blue-600 bg-blue-50",
  ip: "text-green-600 bg-green-50",
  url: "text-purple-600 bg-purple-50",
  hash: "text-orange-600 bg-orange-50",
  email: "text-pink-600 bg-pink-50",
  phone: "text-red-600 bg-red-50",
  upi: "text-emerald-600 bg-emerald-50",
  bank_account: "text-teal-600 bg-teal-50",
};

type SortField = "type" | "value" | "confidence" | "first_seen";

const SortArrow = ({ field, currentSortField, sortAsc }: { field: SortField, currentSortField: SortField, sortAsc: boolean }) => {
  if (currentSortField !== field) return null;
  return <span className="ml-1">{sortAsc ? "↑" : "↓"}</span>;
};

export default function IOCTable({ iocs }: IOCTableProps) {
  const [search, setSearch] = useState("");
  const [sortField, setSortField] = useState<SortField>("confidence");
  const [sortAsc, setSortAsc] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const iocTypes = useMemo(() => ["all", "financial", ...Array.from(new Set(iocs.map((i) => i.type)))], [iocs]);

  const filtered = useMemo(() => {
    let result = [...iocs];

    // Type filter
    if (typeFilter !== "all") {
      if (typeFilter === "financial") {
        result = result.filter((i) => i.type === "upi" || i.type === "bank_account");
      } else {
        result = result.filter((i) => i.type === typeFilter);
      }
    }

    // Search
    if (search) {
      const lower = search.toLowerCase();
      result = result.filter(
        (i) =>
          i.value.toLowerCase().includes(lower) ||
          i.context.toLowerCase().includes(lower) ||
          i.type.toLowerCase().includes(lower)
      );
    }

    // Sort
    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === "confidence") cmp = a.confidence - b.confidence;
      else if (sortField === "first_seen") cmp = (a.first_seen || "").localeCompare(b.first_seen || "");
      else cmp = String(a[sortField]).localeCompare(String(b[sortField]));
      return sortAsc ? cmp : -cmp;
    });

    return result;
  }, [iocs, search, sortField, sortAsc, typeFilter]);

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  }


  const exportData = filtered.map((i) => ({
    type: i.type,
    value: i.value,
    context: i.context,
    confidence: i.confidence,
  }));

  return (
    <div className="flex flex-col h-full">
      {/* Controls */}
      <div className="flex flex-wrap gap-3 mb-4 items-center">
        <input
          type="text"
          aria-label="Search IOCs"
          placeholder="Search IOCs..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-canvas border border-border-subtle px-3 py-1.5 text-sm font-mono focus:outline-none focus:border-primary/50 flex-1 min-w-[200px]"
        />

        <select
          aria-label="Filter IOCs by type"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-canvas border border-border-subtle px-3 py-1.5 text-sm font-mono focus:outline-none"
        >
          {iocTypes.map((t) => {
            if (t === "all") return <option key={t} value={t}>All Types</option>;
            if (t === "financial") return <option key={t} value="financial">FINANCIAL (UPI/Bank)</option>;
            return (
              <option key={t} value={t}>
                {t.toUpperCase()}
              </option>
            );
          })}
        </select>
        
        {/* Statistics Cards */}
        <div className="flex gap-4 ml-4">
          <div className="flex flex-col items-center bg-canvas px-3 py-1 border border-border-subtle shadow-sm rounded">
            <span className="text-[10px] text-primary/50 uppercase tracking-widest">URLs</span>
            <span className="font-mono text-sm font-semibold">{iocs.filter(i => i.type === 'url').length}</span>
          </div>
          <div className="flex flex-col items-center bg-canvas px-3 py-1 border border-border-subtle shadow-sm rounded">
            <span className="text-[10px] text-primary/50 uppercase tracking-widest">Domains</span>
            <span className="font-mono text-sm font-semibold">{iocs.filter(i => i.type === 'domain').length}</span>
          </div>
          <div className="flex flex-col items-center bg-canvas px-3 py-1 border border-border-subtle shadow-sm rounded">
            <span className="text-[10px] text-primary/50 uppercase tracking-widest">IPs</span>
            <span className="font-mono text-sm font-semibold">{iocs.filter(i => i.type === 'ip').length}</span>
          </div>
        </div>

        {/* Export buttons */}
        <div className="flex gap-2 ml-auto">
          <button
            type="button"
            onClick={() => exportIOCsAsCSV(exportData)}
            className="px-3 py-1.5 text-xs font-mono font-medium border border-primary/30 rounded text-primary hover:bg-primary hover:text-white transition-colors"
          >
            CSV
          </button>
          <button
            type="button"
            onClick={() => exportIOCsAsJSON(exportData)}
            className="px-3 py-1.5 text-xs font-mono font-medium border border-primary/30 rounded text-primary hover:bg-primary hover:text-white transition-colors"
          >
            JSON
          </button>
          <button
            type="button"
            onClick={() => exportIOCsAsSTIX(exportData)}
            className="px-3 py-1.5 text-xs font-mono font-medium border border-primary/30 rounded text-primary hover:bg-primary hover:text-white transition-colors"
          >
            STIX
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border-subtle text-left">
              <th
                className="pb-2 font-mono text-xs text-primary/60 font-medium cursor-pointer hover:text-primary"
                onClick={() => handleSort("type")}
              >
                Type<SortArrow field="type" currentSortField={sortField} sortAsc={sortAsc} />
              </th>
              <th
                className="pb-2 font-mono text-xs text-primary/60 font-medium cursor-pointer hover:text-primary"
                onClick={() => handleSort("value")}
              >
                Value<SortArrow field="value" currentSortField={sortField} sortAsc={sortAsc} />
              </th>
              <th className="pb-2 font-mono text-xs text-primary/60 font-medium">Context</th>
              <th className="pb-2 font-mono text-xs text-primary/60 font-medium">Code Location</th>
              <th
                className="pb-2 font-mono text-xs text-primary/60 font-medium cursor-pointer hover:text-primary text-right"
                onClick={() => handleSort("confidence")}
              >
                Confidence<SortArrow field="confidence" currentSortField={sortField} sortAsc={sortAsc} />
              </th>
              <th
                className="pb-2 font-mono text-xs text-primary/60 font-medium cursor-pointer hover:text-primary"
                onClick={() => handleSort("first_seen")}
              >
                First Seen<SortArrow field="first_seen" currentSortField={sortField} sortAsc={sortAsc} />
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc) => {
              const refs = ioc.code_references || [];
              const primaryRef = refs[0];
              return (
                <tr key={ioc.id} className="border-b border-border-subtle/50 hover:bg-canvas/50 transition-colors">
                  <td className="py-2 pr-3">
                    <span className={`text-xs font-mono font-semibold px-2 py-0.5 ${typeColors[ioc.type] || ""}`}>
                      {ioc.type.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-2 pr-3 font-mono text-xs break-all max-w-[300px]">
                    {ioc.value}
                    {(ioc.type === "upi" || ioc.type === "bank_account") && (
                      <button
                        onClick={() => {
                          const text = `To: Nodal Officer\nRequest to freeze ${ioc.type === 'upi' ? 'UPI ID' : 'Bank Account'}:\n${ioc.value}\nContext: ${ioc.context}\nCase relates to cyber fraud.`;
                          navigator.clipboard.writeText(text);
                          alert("Freeze request block copied to clipboard");
                        }}
                        className="ml-2 px-1.5 py-0.5 text-[10px] bg-primary/10 hover:bg-primary/20 rounded border border-primary/20 cursor-pointer"
                        title="Copy freeze-request block"
                      >
                        Copy Freeze Block
                      </button>
                    )}
                  </td>
                  <td className="py-2 pr-3 text-xs text-primary/70 max-w-[200px]">
                    {ioc.type === 'url' ? 'Java String Constant' : (ioc.type === 'domain' || ioc.type === 'ip') ? 'Decompiled Source' : ioc.context}
                  </td>
                  <td className="py-2 pr-3 text-xs font-mono">
                    {primaryRef ? (
                      <div className="flex flex-col gap-0.5">
                        <span 
                          className="inline-flex items-center gap-1 text-[11px] font-mono text-amber-500 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20 max-w-[220px] truncate"
                          title={`${primaryRef.file}:${primaryRef.line}${primaryRef.context ? `\nCode: ${primaryRef.context}` : ''}`}
                        >
                          <span>⚡</span>
                          <span className="truncate">{primaryRef.file.split('/').pop()}</span>
                          <span className="text-amber-400 font-bold">:{primaryRef.line}</span>
                        </span>
                        {primaryRef.context && (
                          <span className="text-[10px] text-primary/50 font-mono italic truncate max-w-[200px]" title={primaryRef.context}>
                            {primaryRef.context}
                          </span>
                        )}
                        {refs.length > 1 && (
                          <span className="text-[9px] text-primary/40 font-mono">
                            +{refs.length - 1} more locations
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-primary/30 text-xs">—</span>
                    )}
                  </td>
                  <td className="py-2 pr-3 text-right">
                    <span
                      className={`text-xs font-mono font-semibold ${
                        ioc.confidence >= 80 ? "text-red-600" : ioc.confidence >= 60 ? "text-orange-600" : "text-green-600"
                      }`}
                    >
                      {ioc.confidence >= 80 ? "🔴 High" : ioc.confidence >= 60 ? "🟡 Medium" : "🟢 Low"}
                    </span>
                  </td>
                  <td className="py-2 text-xs font-mono text-primary/60 whitespace-nowrap">
                    {ioc.first_seen ? new Date(ioc.first_seen).toLocaleString() : "N/A"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="mt-2 text-xs font-mono text-primary/50">
        Showing {filtered.length} of {iocs.length} indicators
      </div>
    </div>
  );
}
