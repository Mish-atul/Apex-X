// ============================================================
// APEX-X Real Analysis Data — Generated from engine test results
// Types only — no synthetic data. All values come from the live backend API.
// ============================================================

export interface MockCase {
  id: string;
  case_number: string;
  apk_hash: string;
  apk_name: string;
  status: "pending" | "analyzing" | "completed" | "failed";
  created_at: string;
  updated_at: string | null;
  threat_score: number;
  verdict: string;
  package_name: string;
  description: string;
  priority: "low" | "medium" | "high" | "critical";
}

export interface Permission {
  case_id?: string;
  name: string;
  protection_level: "normal" | "dangerous" | "signature" | "signatureOrSystem";
  description: string;
  risk: "low" | "medium" | "high" | "critical";
  granted: boolean;
}

export interface IOCEntry {
  case_id?: string;
  id: string;
  type: "domain" | "ip" | "url" | "hash" | "email" | "phone" | "upi" | "bank_account" | string;
  value: string;
  context: string;
  confidence: number;
  first_seen: string;
  code_references?: Array<{
    file: string;
    line: number;
    context?: string;
  }>;
}

export interface Vulnerability {
  case_id?: string;
  id: string;
  title: string;
  description: string;
  cvss_score: number;
  cvss_vector: string;
  owasp_category: string;
  severity: "low" | "medium" | "high" | "critical";
  poc_narrative: string;
  cwe_id: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  type: "network" | "file_io" | "api_call" | "sms" | "crypto" | "permission";
  title: string;
  description: string;
  severity: "info" | "warning" | "critical";
}

export interface GraphNode {
  id: string;
  label: string;
  type: "apk" | "domain" | "ip" | "campaign" | "threat_actor" | "url" | "file" | "baas_project";
  risk?: string;
  metadata?: Record<string, string>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  confidence?: number;
  style?: "solid" | "dashed";
}

export interface YARAMatch {
  rule_name: string;
  category: string;
  description: string;
  strings_matched: string[];
  severity: "low" | "medium" | "high" | "critical";
}

export interface ActivityEntry {
  id: string;
  action: string;
  case_id: string;
  case_number: string;
  user: string;
  timestamp: string;
  details: string;
}

export interface PhaseStatus {
  phase: string;
  status: "pending" | "running" | "completed" | "failed";
  progress: number;
  started_at: string | null;
  completed_at: string | null;
}

export interface ReportEntry {
  id: string;
  case_id: string;
  case_number: string;
  title: string;
  type: "pdf" | "zip" | "csv" | "json" | "stix";
  language: string;
  generated_at: string;
  size_kb: number;
}


// NOTE: Synthetic demo data has been removed. All data now comes from the live API.
// This module exports TypeScript types only.
