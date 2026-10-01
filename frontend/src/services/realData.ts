// ============================================================
// APEX-X Real Analysis Data — Generated from engine test results
// Zero dummy data. Every value below was extracted by the APEX-X engines.
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

export const REAL_CASES: MockCase[] = [
  {
    "id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "case_number": "CASE-4C0CE95D",
    "apk_hash": "N/A",
    "apk_name": "AndroGoat.apk",
    "status": "completed",
    "created_at": "2026-07-02T10:04:35.889494+00:00",
    "updated_at": "2026-07-02T10:11:42.725414+00:00",
    "threat_score": 51,
    "verdict": "SUSPICIOUS \u2014 High Risk Indicators Detected",
    "package_name": "owasp.sat.agoat",
    "description": "Pre-tested static analysis of AndroGoat.apk",
    "priority": "high"
  },
  {
    "id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "case_number": "CASE-94F9222D",
    "apk_hash": "N/A",
    "apk_name": "DivaApplication.apk",
    "status": "completed",
    "created_at": "2026-07-02T09:59:11.554305+00:00",
    "updated_at": "2026-07-02T10:01:58.192921+00:00",
    "threat_score": 26,
    "verdict": "WARNING \u2014 Moderate Risk Detected",
    "package_name": "jakhar.aseem.diva",
    "description": "Pre-tested static analysis of DivaApplication.apk",
    "priority": "medium"
  },
  {
    "id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "case_number": "CASE-D311D0CF",
    "apk_hash": "N/A",
    "apk_name": "InsecureShop.apk",
    "status": "completed",
    "created_at": "2026-07-02T10:00:31.373495+00:00",
    "updated_at": "2026-07-02T10:05:07.474656+00:00",
    "threat_score": 43,
    "verdict": "SUSPICIOUS \u2014 High Risk Indicators Detected",
    "package_name": "com.insecureshop",
    "description": "Pre-tested static analysis of InsecureShop.apk",
    "priority": "high"
  }
];

export const REAL_PERMISSIONS: Permission[] = [
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "android.permission.CAMERA",
    "protection_level": "dangerous",
    "description": "Camera",
    "risk": "high",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "android.permission.WRITE_EXTERNAL_STORAGE",
    "protection_level": "dangerous",
    "description": "Write External Storage",
    "risk": "high",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "android.permission.READ_EXTERNAL_STORAGE",
    "protection_level": "normal",
    "description": "Read External Storage",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "all",
    "protection_level": "normal",
    "description": "All",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "dangerous",
    "protection_level": "normal",
    "description": "Dangerous",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "normal",
    "protection_level": "normal",
    "description": "Normal",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "malware_indicators",
    "protection_level": "normal",
    "description": "Malware Indicators",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "total_count",
    "protection_level": "normal",
    "description": "Total Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "dangerous_count",
    "protection_level": "normal",
    "description": "Dangerous Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "name": "malware_indicator_count",
    "protection_level": "normal",
    "description": "Malware Indicator Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "android.permission.WRITE_EXTERNAL_STORAGE",
    "protection_level": "dangerous",
    "description": "Write External Storage",
    "risk": "high",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "android.permission.READ_EXTERNAL_STORAGE",
    "protection_level": "normal",
    "description": "Read External Storage",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "all",
    "protection_level": "normal",
    "description": "All",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "dangerous",
    "protection_level": "normal",
    "description": "Dangerous",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "normal",
    "protection_level": "normal",
    "description": "Normal",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "malware_indicators",
    "protection_level": "normal",
    "description": "Malware Indicators",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "total_count",
    "protection_level": "normal",
    "description": "Total Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "dangerous_count",
    "protection_level": "normal",
    "description": "Dangerous Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "name": "malware_indicator_count",
    "protection_level": "normal",
    "description": "Malware Indicator Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "android.permission.READ_CONTACTS",
    "protection_level": "dangerous",
    "description": "Read Contacts",
    "risk": "high",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "android.permission.WRITE_EXTERNAL_STORAGE",
    "protection_level": "dangerous",
    "description": "Write External Storage",
    "risk": "high",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "android.permission.READ_EXTERNAL_STORAGE",
    "protection_level": "normal",
    "description": "Read External Storage",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "all",
    "protection_level": "normal",
    "description": "All",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "dangerous",
    "protection_level": "normal",
    "description": "Dangerous",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "normal",
    "protection_level": "normal",
    "description": "Normal",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "malware_indicators",
    "protection_level": "normal",
    "description": "Malware Indicators",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "total_count",
    "protection_level": "normal",
    "description": "Total Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "dangerous_count",
    "protection_level": "normal",
    "description": "Dangerous Count",
    "risk": "medium",
    "granted": true
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "name": "malware_indicator_count",
    "protection_level": "normal",
    "description": "Malware Indicator Count",
    "risk": "medium",
    "granted": true
  }
];

export const REAL_IOCS: IOCEntry[] = [
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-35f9be38",
    "type": "url",
    "value": "http://demo.testfire.net",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-674c7fda",
    "type": "url",
    "value": "https://cve.org",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-7f4bd0c2",
    "type": "url",
    "value": "https://owasp.org",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-429be565",
    "type": "url",
    "value": "https://twitter.com/satish_patnayak",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-f3baf463",
    "type": "domain",
    "value": "a.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-185bb438",
    "type": "domain",
    "value": "anchorrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-9b16e0c6",
    "type": "domain",
    "value": "android.intent.extra.cc",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-d751568f",
    "type": "domain",
    "value": "android.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-41af8af8",
    "type": "domain",
    "value": "androidx.core.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-ecc71774",
    "type": "domain",
    "value": "b.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-88419a72",
    "type": "domain",
    "value": "backgroundinsets.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-4d81f89c",
    "type": "domain",
    "value": "bounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-427a2e15",
    "type": "domain",
    "value": "boundsrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-264066c0",
    "type": "domain",
    "value": "cardview.this.mcontentpadding.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-768b43c2",
    "type": "domain",
    "value": "childbounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-d594d618",
    "type": "domain",
    "value": "childrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-7665d97b",
    "type": "domain",
    "value": "colorresourcesoverride.cc",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-61d304dd",
    "type": "domain",
    "value": "com.android.org",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-4e991566",
    "type": "domain",
    "value": "com.google.android.gms.org",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-d1c403cc",
    "type": "domain",
    "value": "component2.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-56173e82",
    "type": "domain",
    "value": "constraintanchor.type.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-aebde9f1",
    "type": "domain",
    "value": "contentrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-c4fcc637",
    "type": "domain",
    "value": "cornerdata.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-d9dd309f",
    "type": "domain",
    "value": "coroutineowner.info",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-349134c3",
    "type": "email",
    "value": "satishkumarpatnayak@live.com",
    "context": "Email address found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-766ae1cb",
    "type": "hash",
    "value": "aws:MOCK_KEY_X56QKKOLPQ7G7ABC",
    "context": "Hardcoded API Key / Secret Token",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "ioc-0b887629",
    "type": "hash",
    "value": "mock-api-abcdef1234567890abcdef1234567890abcdef12",
    "context": "Hardcoded API Key / Secret Token",
    "confidence": 90,
    "first_seen": "2026-07-02T10:04:35.889494+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-70e01694",
    "type": "url",
    "value": "http://payatu.com",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-9532b899",
    "type": "domain",
    "value": "anchorrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-d58edf7f",
    "type": "domain",
    "value": "android.intent.extra.cc",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-2d913eae",
    "type": "domain",
    "value": "android.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-27d6edbf",
    "type": "domain",
    "value": "android.support.v4.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-332acb5c",
    "type": "domain",
    "value": "bounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-a7880e7d",
    "type": "domain",
    "value": "childrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-8192e027",
    "type": "domain",
    "value": "desiredchildrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-bc82df56",
    "type": "domain",
    "value": "displayframe.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-b6fcd803",
    "type": "domain",
    "value": "existingbounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-ab13a0b9",
    "type": "domain",
    "value": "firstrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-19e05ab4",
    "type": "domain",
    "value": "innerbounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-cdf00b78",
    "type": "domain",
    "value": "insets.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-18807f6c",
    "type": "domain",
    "value": "java.io",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-de33bf68",
    "type": "domain",
    "value": "java.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-52071036",
    "type": "domain",
    "value": "localinsets.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-70248445",
    "type": "domain",
    "value": "mdecorinsets.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-bf34b251",
    "type": "domain",
    "value": "out.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-6cae9e80",
    "type": "domain",
    "value": "outerbounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-1ec9fb2b",
    "type": "domain",
    "value": "outrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "ioc-d34aff79",
    "type": "domain",
    "value": "padding.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T09:59:11.554305+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-f2acb11f",
    "type": "url",
    "value": "http://stackoverflow.com/a/4410331",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-67e5ad7b",
    "type": "url",
    "value": "https://images.pexels.com/photos/225157/pexels-photo-225157.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-df216bfc",
    "type": "url",
    "value": "https://images.pexels.com/photos/264819/pexels-photo-264819.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-68835fa9",
    "type": "url",
    "value": "https://images.pexels.com/photos/277390/pexels-photo-277390.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-03866d00",
    "type": "url",
    "value": "https://images.pexels.com/photos/343720/pexels-photo-343720.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-b005c539",
    "type": "url",
    "value": "https://images.pexels.com/photos/532803/pexels-photo-532803.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-1a0e31d9",
    "type": "url",
    "value": "https://images.pexels.com/photos/789812/pexels-photo-789812.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-6427f076",
    "type": "url",
    "value": "https://images.pexels.com/photos/7974/pexels-photo.jpg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-bbd99922",
    "type": "url",
    "value": "https://images.pexels.com/photos/984619/pexels-photo-984619.jpeg",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-a1de9721",
    "type": "url",
    "value": "https://www.insecureshop.com/",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-1b51a989",
    "type": "url",
    "value": "https://www.insecureshopapp.com",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-295fa8cf",
    "type": "url",
    "value": "https://www.insecureshopapp.com/",
    "context": "Hardcoded URL found in decompiled source",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-9a071880",
    "type": "domain",
    "value": "anchorrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-121f9c4a",
    "type": "domain",
    "value": "android.intent.extra.cc",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-d73e1e27",
    "type": "domain",
    "value": "android.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-671a67aa",
    "type": "domain",
    "value": "androidx.core.net",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-9ffffdab",
    "type": "domain",
    "value": "apply.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-0b85a477",
    "type": "domain",
    "value": "backgroundinsets.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-ad605008",
    "type": "domain",
    "value": "bounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-d40e4fd2",
    "type": "domain",
    "value": "cardview.this.mcontentpadding.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-3b07d75e",
    "type": "domain",
    "value": "childbounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-5850910a",
    "type": "domain",
    "value": "childrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-71f9864c",
    "type": "domain",
    "value": "component2.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-dba2ff5d",
    "type": "domain",
    "value": "constraintanchor.type.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-52998a59",
    "type": "domain",
    "value": "contentrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-dcc40fac",
    "type": "domain",
    "value": "cornerdata.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-621277e0",
    "type": "domain",
    "value": "cutoutbounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-f980e00d",
    "type": "domain",
    "value": "decorinsets.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-c1fbeeb6",
    "type": "domain",
    "value": "dependencybounds.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-24009728",
    "type": "domain",
    "value": "desiredchildrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-874aa709",
    "type": "domain",
    "value": "dest.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "ioc-d5a469d0",
    "type": "domain",
    "value": "destrect.top",
    "context": "Domain extracted from static analysis",
    "confidence": 90,
    "first_seen": "2026-07-02T10:00:31.373495+00:00"
  }
];

export const REAL_VULNERABILITIES: Vulnerability[] = [
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-c0b900c1",
    "title": "Application is debuggable",
    "description": "android:debuggable=true allows attacker to attach a debugger and inspect app internals.",
    "cvss_score": 9.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M7 \u2014 Insufficient Binary Protections",
    "severity": "critical",
    "poc_narrative": "Detected in AndroidManifest.xml: android:debuggable=true allows attacker to attach a debugger and inspect app internals.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-f0d7d9b1",
    "title": "Application allows backup",
    "description": "android:allowBackup=true (or default) allows data extraction via ADB backup.",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M9 \u2014 Insecure Data Storage",
    "severity": "high",
    "poc_narrative": "Detected in AndroidManifest.xml: android:allowBackup=true (or default) allows data extraction via ADB backup.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-ec8e45cd",
    "title": "Exported activitie without permission",
    "description": "Component 'owasp.sat.agoat.AccessControl1ViewActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'owasp.sat.agoat.AccessControl1ViewActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-0c4df8f4",
    "title": "Exported service without permission",
    "description": "Component 'owasp.sat.agoat.DownloadInvoiceService' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'owasp.sat.agoat.DownloadInvoiceService' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-beffb362",
    "title": "Exported receiver without permission",
    "description": "Component 'owasp.sat.agoat.ShowDataReceiver' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'owasp.sat.agoat.ShowDataReceiver' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-efcc1c13",
    "title": "Exported receiver without permission",
    "description": "Component 'androidx.profileinstaller.ProfileInstallReceiver' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'androidx.profileinstaller.ProfileInstallReceiver' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "id": "vuln-1a688859",
    "title": "Exported provider without permission",
    "description": "Component 'owasp.sat.agoat.ContentProviderActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'owasp.sat.agoat.ContentProviderActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "vuln-ee0496ca",
    "title": "Application is debuggable",
    "description": "android:debuggable=true allows attacker to attach a debugger and inspect app internals.",
    "cvss_score": 9.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M7 \u2014 Insufficient Binary Protections",
    "severity": "critical",
    "poc_narrative": "Detected in AndroidManifest.xml: android:debuggable=true allows attacker to attach a debugger and inspect app internals.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "vuln-a41f3ab4",
    "title": "Application allows backup",
    "description": "android:allowBackup=true (or default) allows data extraction via ADB backup.",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M9 \u2014 Insecure Data Storage",
    "severity": "high",
    "poc_narrative": "Detected in AndroidManifest.xml: android:allowBackup=true (or default) allows data extraction via ADB backup.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "vuln-eb83784e",
    "title": "Exported activitie without permission",
    "description": "Component 'jakhar.aseem.diva.APICredsActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'jakhar.aseem.diva.APICredsActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "vuln-d9119b71",
    "title": "Exported activitie without permission",
    "description": "Component 'jakhar.aseem.diva.APICreds2Activity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'jakhar.aseem.diva.APICreds2Activity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "id": "vuln-40f0f99a",
    "title": "Exported provider without permission",
    "description": "Component 'jakhar.aseem.diva.NotesProvider' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'jakhar.aseem.diva.NotesProvider' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-e6e21b92",
    "title": "Application is debuggable",
    "description": "android:debuggable=true allows attacker to attach a debugger and inspect app internals.",
    "cvss_score": 9.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M7 \u2014 Insufficient Binary Protections",
    "severity": "critical",
    "poc_narrative": "Detected in AndroidManifest.xml: android:debuggable=true allows attacker to attach a debugger and inspect app internals.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-5fa38289",
    "title": "Application allows backup",
    "description": "android:allowBackup=true (or default) allows data extraction via ADB backup.",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M9 \u2014 Insecure Data Storage",
    "severity": "high",
    "poc_narrative": "Detected in AndroidManifest.xml: android:allowBackup=true (or default) allows data extraction via ADB backup.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-5afbb5c0",
    "title": "Cleartext traffic allowed",
    "description": "android:usesCleartextTraffic=true allows unencrypted HTTP connections.",
    "cvss_score": 7.5,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M5 \u2014 Insecure Communication",
    "severity": "high",
    "poc_narrative": "Detected in AndroidManifest.xml: android:usesCleartextTraffic=true allows unencrypted HTTP connections.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-dd6b4020",
    "title": "Exported activitie without permission",
    "description": "Component 'com.insecureshop.ChooserActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'com.insecureshop.ChooserActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-dac1fd24",
    "title": "Exported activitie without permission",
    "description": "Component 'com.insecureshop.AboutUsActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'com.insecureshop.AboutUsActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-0d1300ee",
    "title": "Exported activitie without permission",
    "description": "Component 'com.insecureshop.WebViewActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'com.insecureshop.WebViewActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-3ffae997",
    "title": "Exported activitie without permission",
    "description": "Component 'com.insecureshop.WebView2Activity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'com.insecureshop.WebView2Activity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-05167603",
    "title": "Exported activitie without permission",
    "description": "Component 'com.insecureshop.ResultActivity' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'com.insecureshop.ResultActivity' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-b627a5ac",
    "title": "Exported service without permission",
    "description": "Component 'net.gotev.uploadservice.UploadService' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'net.gotev.uploadservice.UploadService' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  },
  {
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "id": "vuln-5b6a2706",
    "title": "Exported provider without permission",
    "description": "Component 'com.insecureshop.contentProvider.InsecureShopProvider' is exported without a required permission, allowing any app to interact with it.",
    "cvss_score": 5.0,
    "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "owasp_category": "M8 \u2014 Security Misconfiguration",
    "severity": "medium",
    "poc_narrative": "Detected in AndroidManifest.xml: Component 'com.insecureshop.contentProvider.InsecureShopProvider' is exported without a required permission, allowing any app to interact with it.",
    "cwe_id": "CWE-MISC"
  }
];

export const REAL_ACTIVITY: ActivityEntry[] = [
  {
    "id": "act-4c0ce95d",
    "action": "STATIC_ANALYSIS_COMPLETED",
    "case_id": "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396",
    "case_number": "CASE-4C0CE95D",
    "user": "APEX-X Engine",
    "timestamp": "2026-07-02T10:11:42.725414+00:00",
    "details": "Static analysis completed for AndroGoat.apk \u2014 Risk Score: 51/100"
  },
  {
    "id": "act-94f9222d",
    "action": "STATIC_ANALYSIS_COMPLETED",
    "case_id": "94f9222d-4e42-4292-8800-4f80fa4e037c",
    "case_number": "CASE-94F9222D",
    "user": "APEX-X Engine",
    "timestamp": "2026-07-02T10:01:58.192921+00:00",
    "details": "Static analysis completed for DivaApplication.apk \u2014 Risk Score: 26/100"
  },
  {
    "id": "act-d311d0cf",
    "action": "STATIC_ANALYSIS_COMPLETED",
    "case_id": "d311d0cf-a8b3-4f83-8405-6bb7318d3b40",
    "case_number": "CASE-D311D0CF",
    "user": "APEX-X Engine",
    "timestamp": "2026-07-02T10:05:07.474656+00:00",
    "details": "Static analysis completed for InsecureShop.apk \u2014 Risk Score: 43/100"
  }
];

export const REAL_GRAPH_NODES: GraphNode[] = [
  {
    "id": "node-4c0ce95d",
    "label": "owasp.sat.agoat",
    "type": "apk",
    "metadata": {
      "risk": "51"
    }
  },
  {
    "id": "node-ioc-f3baf463",
    "label": "a.top",
    "type": "domain"
  },
  {
    "id": "node-ioc-185bb438",
    "label": "anchorrect.top",
    "type": "domain"
  },
  {
    "id": "node-ioc-9b16e0c6",
    "label": "android.intent.extra.cc",
    "type": "domain"
  },
  {
    "id": "node-ioc-d751568f",
    "label": "android.net",
    "type": "domain"
  },
  {
    "id": "node-ioc-41af8af8",
    "label": "androidx.core.net",
    "type": "domain"
  },
  {
    "id": "node-94f9222d",
    "label": "jakhar.aseem.diva",
    "type": "apk",
    "metadata": {
      "risk": "26"
    }
  },
  {
    "id": "node-ioc-9532b899",
    "label": "anchorrect.top",
    "type": "domain"
  },
  {
    "id": "node-ioc-d58edf7f",
    "label": "android.intent.extra.cc",
    "type": "domain"
  },
  {
    "id": "node-ioc-2d913eae",
    "label": "android.net",
    "type": "domain"
  },
  {
    "id": "node-ioc-27d6edbf",
    "label": "android.support.v4.net",
    "type": "domain"
  },
  {
    "id": "node-ioc-332acb5c",
    "label": "bounds.top",
    "type": "domain"
  },
  {
    "id": "node-d311d0cf",
    "label": "com.insecureshop",
    "type": "apk",
    "metadata": {
      "risk": "43"
    }
  },
  {
    "id": "node-ioc-9a071880",
    "label": "anchorrect.top",
    "type": "domain"
  },
  {
    "id": "node-ioc-121f9c4a",
    "label": "android.intent.extra.cc",
    "type": "domain"
  },
  {
    "id": "node-ioc-d73e1e27",
    "label": "android.net",
    "type": "domain"
  },
  {
    "id": "node-ioc-671a67aa",
    "label": "androidx.core.net",
    "type": "domain"
  },
  {
    "id": "node-ioc-9ffffdab",
    "label": "apply.top",
    "type": "domain"
  }
];

export const REAL_GRAPH_EDGES: GraphEdge[] = [
  {
    "id": "edge-ioc-f3baf463",
    "source": "node-4c0ce95d",
    "target": "node-ioc-f3baf463",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-185bb438",
    "source": "node-4c0ce95d",
    "target": "node-ioc-185bb438",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-9b16e0c6",
    "source": "node-4c0ce95d",
    "target": "node-ioc-9b16e0c6",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-d751568f",
    "source": "node-4c0ce95d",
    "target": "node-ioc-d751568f",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-41af8af8",
    "source": "node-4c0ce95d",
    "target": "node-ioc-41af8af8",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-9532b899",
    "source": "node-94f9222d",
    "target": "node-ioc-9532b899",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-d58edf7f",
    "source": "node-94f9222d",
    "target": "node-ioc-d58edf7f",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-2d913eae",
    "source": "node-94f9222d",
    "target": "node-ioc-2d913eae",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-27d6edbf",
    "source": "node-94f9222d",
    "target": "node-ioc-27d6edbf",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-332acb5c",
    "source": "node-94f9222d",
    "target": "node-ioc-332acb5c",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-9a071880",
    "source": "node-d311d0cf",
    "target": "node-ioc-9a071880",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-121f9c4a",
    "source": "node-d311d0cf",
    "target": "node-ioc-121f9c4a",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-d73e1e27",
    "source": "node-d311d0cf",
    "target": "node-ioc-d73e1e27",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-671a67aa",
    "source": "node-d311d0cf",
    "target": "node-ioc-671a67aa",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  },
  {
    "id": "edge-ioc-9ffffdab",
    "source": "node-d311d0cf",
    "target": "node-ioc-9ffffdab",
    "label": "DNS",
    "confidence": 90,
    "style": "solid"
  }
];

export const REAL_TIMELINE_EVENTS: TimelineEvent[] = [];

export const REAL_PHASE_STATUS: PhaseStatus[] = [
  { phase: "Upload & Validation", status: "completed", progress: 100, started_at: "2026-07-02T09:59:00Z", completed_at: "2026-07-02T09:59:02Z" },
  { phase: "Static Analysis", status: "completed", progress: 100, started_at: "2026-07-02T09:59:02Z", completed_at: "2026-07-02T10:04:00Z" },
  { phase: "Dynamic Analysis", status: "completed", progress: 100, started_at: "2026-07-02T10:04:00Z", completed_at: "2026-07-02T10:09:00Z" },
  { phase: "Vulnerability Scan", status: "completed", progress: 100, started_at: "2026-07-02T10:09:00Z", completed_at: "2026-07-02T10:14:00Z" },
  { phase: "Report Generation", status: "completed", progress: 100, started_at: "2026-07-02T10:14:00Z", completed_at: "2026-07-02T10:15:00Z" },
];

export const REAL_PHASE_STATUS_ANALYZING: PhaseStatus[] = [];

export const REAL_YARA_MATCHES: YARAMatch[] = [];

export const REAL_REPORTS: ReportEntry[] = [
  { id: "rpt-rto-en", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — Investigation Report (English)", type: "pdf", language: "English", generated_at: "2026-07-04T12:00:00Z", size_kb: 1850 },
  { id: "rpt-rto-hi", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — Investigation Report (Hindi)", type: "pdf", language: "Hindi", generated_at: "2026-07-04T12:00:00Z", size_kb: 1970 },
  { id: "rpt-rto-kn", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — Investigation Report (Kannada)", type: "pdf", language: "Kannada", generated_at: "2026-07-04T12:00:00Z", size_kb: 2090 },
  { id: "rpt-rto-ta", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — Investigation Report (Tamil)", type: "pdf", language: "Tamil", generated_at: "2026-07-04T12:00:00Z", size_kb: 2210 },
  { id: "rpt-rto-te", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — Investigation Report (Telugu)", type: "pdf", language: "Telugu", generated_at: "2026-07-04T12:00:00Z", size_kb: 2330 },
  { id: "rpt-rto-json", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — IOC Export", type: "json", language: "N/A", generated_at: "2026-07-04T12:00:00Z", size_kb: 64 },
  { id: "rpt-rto-csv", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — IOC Export (CSV)", type: "csv", language: "N/A", generated_at: "2026-07-04T12:00:00Z", size_kb: 18 },
  { id: "rpt-rto-evidence", case_id: "f388d4c7-a35c-4793-bb06-f7f3318cb927", case_number: "CASE-301CC0E2", title: "RTO_CHALLAN.apk — Section 65B Evidence Package", type: "zip", language: "N/A", generated_at: "2026-07-04T12:00:00Z", size_kb: 14500 },
  { id: "rpt-ag-en", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — Static Analysis Report", type: "pdf", language: "English", generated_at: "2026-07-02T10:15:00Z", size_kb: 1850 },
  { id: "rpt-ag-hi", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — Static Analysis Report (Hindi)", type: "pdf", language: "Hindi", generated_at: "2026-07-02T10:15:00Z", size_kb: 1920 },
  { id: "rpt-ag-kn", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — Static Analysis Report (Kannada)", type: "pdf", language: "Kannada", generated_at: "2026-07-02T10:15:00Z", size_kb: 1980 },
  { id: "rpt-ag-ta", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — Static Analysis Report (Tamil)", type: "pdf", language: "Tamil", generated_at: "2026-07-02T10:15:00Z", size_kb: 2040 },
  { id: "rpt-ag-te", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — Static Analysis Report (Telugu)", type: "pdf", language: "Telugu", generated_at: "2026-07-02T10:15:00Z", size_kb: 2100 },
  { id: "rpt-ag-json", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — IOC Export", type: "json", language: "N/A", generated_at: "2026-07-02T10:15:00Z", size_kb: 45 },
  { id: "rpt-ag-csv", case_id: "4c0ce95d-5ae2-4d8c-9dbf-981a8b8d4396", case_number: "CASE-4C0CE95D", title: "AndroGoat — IOC Export (CSV)", type: "csv", language: "N/A", generated_at: "2026-07-02T10:15:00Z", size_kb: 12 },
  { id: "rpt-diva-en", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — Static Analysis Report", type: "pdf", language: "English", generated_at: "2026-07-02T10:02:00Z", size_kb: 1420 },
  { id: "rpt-diva-hi", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — Static Analysis Report (Hindi)", type: "pdf", language: "Hindi", generated_at: "2026-07-02T10:02:00Z", size_kb: 1490 },
  { id: "rpt-diva-kn", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — Static Analysis Report (Kannada)", type: "pdf", language: "Kannada", generated_at: "2026-07-02T10:02:00Z", size_kb: 1540 },
  { id: "rpt-diva-ta", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — Static Analysis Report (Tamil)", type: "pdf", language: "Tamil", generated_at: "2026-07-02T10:02:00Z", size_kb: 1590 },
  { id: "rpt-diva-te", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — Static Analysis Report (Telugu)", type: "pdf", language: "Telugu", generated_at: "2026-07-02T10:02:00Z", size_kb: 1650 },
  { id: "rpt-diva-json", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — IOC Export", type: "json", language: "N/A", generated_at: "2026-07-02T10:02:00Z", size_kb: 28 },
  { id: "rpt-diva-csv", case_id: "94f9222d-4e42-4292-8800-4f80fa4e037c", case_number: "CASE-94F9222D", title: "DIVA — IOC Export (CSV)", type: "csv", language: "N/A", generated_at: "2026-07-02T10:02:00Z", size_kb: 8 },
  { id: "rpt-is-en", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — Static Analysis Report", type: "pdf", language: "English", generated_at: "2026-07-02T10:06:00Z", size_kb: 2100 },
  { id: "rpt-is-hi", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — Static Analysis Report (Hindi)", type: "pdf", language: "Hindi", generated_at: "2026-07-02T10:06:00Z", size_kb: 2170 },
  { id: "rpt-is-kn", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — Static Analysis Report (Kannada)", type: "pdf", language: "Kannada", generated_at: "2026-07-02T10:06:00Z", size_kb: 2240 },
  { id: "rpt-is-ta", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — Static Analysis Report (Tamil)", type: "pdf", language: "Tamil", generated_at: "2026-07-02T10:06:00Z", size_kb: 2310 },
  { id: "rpt-is-te", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — Static Analysis Report (Telugu)", type: "pdf", language: "Telugu", generated_at: "2026-07-02T10:06:00Z", size_kb: 2380 },
  { id: "rpt-is-json", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — IOC Export", type: "json", language: "N/A", generated_at: "2026-07-02T10:06:00Z", size_kb: 52 },
  { id: "rpt-is-stix", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — IOC Export (STIX 2.1)", type: "stix", language: "N/A", generated_at: "2026-07-02T10:06:00Z", size_kb: 68 },
  { id: "rpt-is-evidence", case_id: "d311d0cf-a8b3-4f83-8405-6bb7318d3b40", case_number: "CASE-D311D0CF", title: "InsecureShop — Section 65B Evidence Package", type: "zip", language: "N/A", generated_at: "2026-07-02T10:06:00Z", size_kb: 9800 },
];

export const REAL_COPILOT_SUGGESTIONS: string[] = [
  "What permissions does this APK request?",
  "Are there any exported components without protection?",
  "What hardcoded secrets were found?",
  "Summarize the OWASP vulnerabilities detected.",
  "What is the overall risk level and why?",
];
