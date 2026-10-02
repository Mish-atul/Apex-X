"use client";

import { useState, useEffect, useMemo } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  Line,
} from "react-simple-maps";
import { Globe, Filter, MapPin } from "lucide-react";

const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface ThreatMarker {
  ip: string;
  lat: number;
  lng: number;
  country: string;
  city: string;
  org: string;
  classification: string;
  risk: string;
  case_name: string;
}

interface ThreatArc {
  from: { lat: number; lng: number };
  to: { lat: number; lng: number };
  case_name: string;
  classification: string;
}

interface ThreatMapData {
  markers: ThreatMarker[];
  arcs: ThreatArc[];
}

const CLASSIFICATION_COLORS: Record<string, string> = {
  malicious: "#ef4444",
  suspicious: "#f59e0b",
  benign: "#22c55e",
  unknown: "#6b7280",
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#22c55e",
};

export default function ThreatMapPage() {
  const [data, setData] = useState<ThreatMapData>({ markers: [], arcs: [] });
  const [loading, setLoading] = useState(true);
  const [hoveredMarker, setHoveredMarker] = useState<ThreatMarker | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [filterCase, setFilterCase] = useState<string>("all");
  const [filterClassification, setFilterClassification] = useState<string>("all");

  useEffect(() => {
    fetch(`${process.env.NEXT_PUBLIC_API_URL || "/api/v1"}/cases/threat-map`)
      .then((r) => r.json())
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const caseNames = useMemo(() => {
    const names = new Set(data.markers.map((m) => m.case_name));
    return Array.from(names);
  }, [data.markers]);

  const filtered = useMemo(() => {
    let markers = data.markers;
    let arcs = data.arcs;

    if (filterCase !== "all") {
      markers = markers.filter((m) => m.case_name === filterCase);
      arcs = arcs.filter((a) => a.case_name === filterCase);
    }
    if (filterClassification !== "all") {
      markers = markers.filter((m) => m.classification === filterClassification);
      arcs = arcs.filter((a) => a.classification === filterClassification);
    }
    return { markers, arcs };
  }, [data, filterCase, filterClassification]);

  const stats = useMemo(() => {
    const m = filtered.markers;
    return {
      total: m.length,
      malicious: m.filter((x) => x.classification === "malicious").length,
      suspicious: m.filter((x) => x.classification === "suspicious").length,
      benign: m.filter((x) => x.classification === "benign").length,
      countries: new Set(m.map((x) => x.country).filter(Boolean)).size,
    };
  }, [filtered.markers]);

  return (
    <main className="flex-1 p-4 md:p-6 flex flex-col h-[calc(100vh-70px)] max-w-[1600px] mx-auto w-full">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-4 border-b border-border-subtle pb-4 shrink-0 gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-orange-500 rounded-xl flex items-center justify-center">
            <Globe className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-display font-bold text-text">
              Global Threat Map
            </h1>
            <p className="text-xs text-text-muted">
              Real-time visualization of C2 infrastructure across analyzed APKs
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <select
            aria-label="Filter by APK"
            value={filterCase}
            onChange={(e) => setFilterCase(e.target.value)}
            className="bg-white border border-border-subtle px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/20"
          >
            <option value="all">All APKs</option>
            {caseNames.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by classification"
            value={filterClassification}
            onChange={(e) => setFilterClassification(e.target.value)}
            className="bg-white border border-border-subtle px-3 py-2 text-sm rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/20"
          >
            <option value="all">All Types</option>
            <option value="malicious">🔴 Malicious</option>
            <option value="suspicious">🟡 Suspicious</option>
            <option value="benign">🟢 Benign</option>
            <option value="unknown">⚪ Unknown</option>
          </select>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4 shrink-0">
        <div className="bg-panel border border-border-subtle p-3 rounded-lg">
          <div className="text-xs text-text-muted font-mono uppercase">Total IPs</div>
          <div className="text-lg font-bold mt-1">{stats.total}</div>
        </div>
        <div className="bg-panel border border-border-subtle p-3 rounded-lg">
          <div className="text-xs text-red-400 font-mono uppercase">Malicious</div>
          <div className="text-lg font-bold mt-1 text-red-400">{stats.malicious}</div>
        </div>
        <div className="bg-panel border border-border-subtle p-3 rounded-lg">
          <div className="text-xs text-yellow-400 font-mono uppercase">Suspicious</div>
          <div className="text-lg font-bold mt-1 text-yellow-400">{stats.suspicious}</div>
        </div>
        <div className="bg-panel border border-border-subtle p-3 rounded-lg">
          <div className="text-xs text-green-400 font-mono uppercase">Benign</div>
          <div className="text-lg font-bold mt-1 text-green-400">{stats.benign}</div>
        </div>
        <div className="bg-panel border border-border-subtle p-3 rounded-lg">
          <div className="text-xs text-text-muted font-mono uppercase">Countries</div>
          <div className="text-lg font-bold mt-1">{stats.countries}</div>
        </div>
      </div>

      {/* Map */}
      <div className="flex-1 bg-[#0a1628] border border-border-subtle rounded-xl min-h-0 relative overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-full text-text-muted">
            <div className="animate-pulse">Loading threat intelligence map...</div>
          </div>
        ) : filtered.markers.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-text-muted gap-2">
            <MapPin className="w-8 h-8 opacity-30" />
            <p className="text-sm">No IP geolocation data available yet.</p>
            <p className="text-xs opacity-60">Upload and analyze an APK to populate the map.</p>
          </div>
        ) : (
          <>
            <ComposableMap
              projection="geoMercator"
              projectionConfig={{ scale: 140, center: [30, 20] }}
              style={{ width: "100%", height: "100%" }}
            >
              {/* World geography */}
              <Geographies geography={GEO_URL}>
                {({ geographies }: { geographies: any[] }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="#1a2744"
                      stroke="#2a3f5f"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "#243656", outline: "none" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>

              {/* Arc lines from origin to IPs */}
              {filtered.arcs.map((arc, i) => (
                <Line
                  key={`arc-${i}`}
                  from={[arc.from.lng, arc.from.lat]}
                  to={[arc.to.lng, arc.to.lat]}
                  stroke={CLASSIFICATION_COLORS[arc.classification] || "#6b7280"}
                  strokeWidth={1}
                  strokeLinecap="round"
                  strokeOpacity={0.4}
                />
              ))}

              {/* IP Markers */}
              {filtered.markers.map((marker, i) => {
                const color =
                  RISK_COLORS[marker.risk] ||
                  CLASSIFICATION_COLORS[marker.classification] ||
                  "#6b7280";
                return (
                  <Marker
                    key={`marker-${i}`}
                    coordinates={[marker.lng, marker.lat]}
                    onMouseEnter={(e) => {
                      setHoveredMarker(marker);
                      setTooltipPos({ x: e.clientX, y: e.clientY });
                    }}
                    onMouseLeave={() => setHoveredMarker(null)}
                  >
                    {/* Outer pulse ring */}
                    <circle
                      r={8}
                      fill={color}
                      fillOpacity={0.15}
                      stroke={color}
                      strokeWidth={0.5}
                      strokeOpacity={0.3}
                    >
                      <animate
                        attributeName="r"
                        from="6"
                        to="14"
                        dur="2s"
                        repeatCount="indefinite"
                      />
                      <animate
                        attributeName="fill-opacity"
                        from="0.2"
                        to="0"
                        dur="2s"
                        repeatCount="indefinite"
                      />
                    </circle>
                    {/* Inner dot */}
                    <circle
                      r={4}
                      fill={color}
                      stroke="#0a1628"
                      strokeWidth={1}
                      style={{ cursor: "pointer" }}
                    />
                  </Marker>
                );
              })}
            </ComposableMap>

            {/* Tooltip */}
            {hoveredMarker && (
              <div
                className="fixed z-50 bg-[#0f1d32] border border-blue-500/30 rounded-lg p-3 shadow-xl pointer-events-none"
                style={{
                  left: tooltipPos.x + 12,
                  top: tooltipPos.y - 80,
                  minWidth: 220,
                }}
              >
                <div className="text-xs font-mono text-blue-300 font-bold mb-1">
                  {hoveredMarker.ip}
                </div>
                <div className="text-xs text-white/70 space-y-0.5">
                  <div>
                    📍 {[hoveredMarker.city, hoveredMarker.country].filter(Boolean).join(", ") || "Unknown"}
                  </div>
                  <div>🏢 {hoveredMarker.org || "Unknown ISP"}</div>
                  <div>📦 {hoveredMarker.case_name}</div>
                  <div className="flex gap-2 mt-1">
                    <span
                      className="px-1.5 py-0.5 rounded text-[10px] font-mono border"
                      style={{
                        color: CLASSIFICATION_COLORS[hoveredMarker.classification],
                        borderColor: CLASSIFICATION_COLORS[hoveredMarker.classification] + "40",
                        backgroundColor: CLASSIFICATION_COLORS[hoveredMarker.classification] + "15",
                      }}
                    >
                      {hoveredMarker.classification}
                    </span>
                    <span
                      className="px-1.5 py-0.5 rounded text-[10px] font-mono border"
                      style={{
                        color: RISK_COLORS[hoveredMarker.risk],
                        borderColor: RISK_COLORS[hoveredMarker.risk] + "40",
                        backgroundColor: RISK_COLORS[hoveredMarker.risk] + "15",
                      }}
                    >
                      {hoveredMarker.risk}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Legend */}
            <div className="absolute bottom-4 left-4 bg-[#0f1d32]/90 backdrop-blur border border-blue-500/20 rounded-lg p-3">
              <div className="text-[10px] font-mono text-white/50 uppercase mb-2">Legend</div>
              <div className="flex flex-col gap-1.5">
                {[
                  { label: "Malicious", color: "#ef4444" },
                  { label: "Suspicious", color: "#f59e0b" },
                  { label: "Benign", color: "#22c55e" },
                  { label: "Unknown", color: "#6b7280" },
                ].map((item) => (
                  <div key={item.label} className="flex items-center gap-2">
                    <div
                      className="w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-[10px] text-white/60">{item.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </main>
  );
}
