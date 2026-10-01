// API service wrapper for APEX-X backend
// Falls back to mock data when backend is unavailable

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "https://apex-x-backend.onrender.com/api/v1";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  const cookies = document.cookie.split("; ");
  const tokenCookie = cookies.find(row => row.startsWith("apex_token="));
  return tokenCookie ? tokenCookie.split("=")[1] : null;
}

async function apiFetch<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<{ data: T | null; error: string | null; status: number }> {
  const token = getToken();
  const headers: Record<string, string> = {
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Don't set Content-Type for FormData (browser sets it with boundary)
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = headers["Content-Type"] || "application/json";
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
      cache: "no-store",
    });

    if (!response.ok) {
      const errorBody = await response.text();
      return { data: null, error: errorBody || response.statusText, status: response.status };
    }

    const data = await response.json();
    return { data: data as T, error: null, status: response.status };
  } catch (err) {
    return { data: null, error: (err as Error).message, status: 0 };
  }
}

// ---- Auth ----

export async function loginAPI(username: string, password: string) {
  // Backend uses OAuth2PasswordRequestForm which expects form-urlencoded
  const formData = new URLSearchParams();
  formData.append("username", username);
  formData.append("password", password);

  return apiFetch<{ access_token: string; token_type: string }>("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData.toString(),
  });
}

// ---- Health / Ping ----

export async function pingAPI() {
  try {
    await fetch(`${API_BASE_URL}/health`);
  } catch {
    // Ignore errors for background ping
  }
}

export async function signupAPI(username: string, password: string) {
  return apiFetch<{ access_token: string; token_type: string }>("/auth/signup", {
    method: "POST",
    body: JSON.stringify({ username, password, role: "investigator" }),
  });
}

// ---- Cases ----

import { REAL_CASES } from "./realData";

export interface CaseResponse {
  id: string;
  case_number: string;
  apk_hash: string;
  apk_name: string;
  status: string;
  created_at: string;
  updated_at: string | null;
  threat_score?: number;
  verdict?: string;
  package_name?: string;
  priority?: string;
  analysis_time?: string;
  engine_version?: string;
  decompiler?: string;
  [key: string]: any;
}

export async function getCases(): Promise<{ data: CaseResponse[] | null; error: string | null; status: number }> {
  try {
    const response = await apiFetch<CaseResponse[]>("/cases");
    const realCasesList = response.data || [];
    // Append the 3 dummy mock cases for demonstration
    const combined = [...realCasesList, ...(REAL_CASES as unknown as CaseResponse[])];
    return { data: combined, error: response.error, status: 200 };
  } catch (error: any) {
    return { data: REAL_CASES as unknown as CaseResponse[], error: error.message, status: 500 };
  }
}

export async function getCaseDetail(caseId: string): Promise<{ data: CaseResponse | null; error: string | null; status: number }> {
  try {
    // Check if it's one of our mock cases first
    const mockCase = REAL_CASES.find((c) => c.id === caseId);
    if (mockCase) {
      return { data: mockCase as unknown as CaseResponse, error: null, status: 200 };
    }
    
    const response = await apiFetch<CaseResponse>(`/cases/${caseId}`);
    return { data: response.data, error: response.error, status: 200 };
  } catch (error: any) {
    return { data: null, error: error.message, status: 404 };
  }
}

// ---- Upload ----

export async function uploadAPK(
  file: File,
  onProgress?: (percent: number) => void
): Promise<{ data: CaseResponse | null; error: string | null }> {
  const token = getToken();
  
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append("file", file);

    xhr.upload.addEventListener("progress", (event) => {
      if (event.lengthComputable && onProgress) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    });

    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve({ data: JSON.parse(xhr.responseText), error: null });
        } catch {
          resolve({ data: null, error: "Invalid response from server" });
        }
      } else {
        resolve({ data: null, error: xhr.responseText || "Upload failed" });
      }
    });

    xhr.addEventListener("error", () => {
      resolve({ data: null, error: "Network error during upload" });
    });

    xhr.open("POST", `${API_BASE_URL}/cases/upload/`);
    if (token) {
      xhr.setRequestHeader("Authorization", `Bearer ${token}`);
    }
    xhr.send(formData);
  });
}

// ---- Results ----

export async function getCaseResults(caseId: string, phase?: string) {
  const query = phase ? `?phase=${phase}` : "";
  return apiFetch<Record<string, unknown>>(`/cases/${caseId}/results${query}`);
}

// ---- Reports ----

export async function downloadReport(caseId: string, language: string): Promise<void> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const response = await fetch(
      `${API_BASE_URL}/reports/${caseId}/download?language=${language}`,
      { headers }
    );

    if (!response.ok) throw new Error("Download failed");

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report_${caseId}_${language}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Report download error:", err);
    alert("Report download failed. The backend may not be running.");
  }
}

export async function downloadEvidencePackage(caseId: string): Promise<void> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const response = await fetch(
      `${API_BASE_URL}/reports/${caseId}/evidence-package`,
      { headers }
    );

    if (!response.ok) throw new Error("Download failed");

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evidence_package_${caseId}.zip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Evidence package download error:", err);
    alert("Evidence package download failed. The backend may not be running.");
  }
}

// ---- IOC Export ----

export function exportIOCsAsCSV(iocs: { type: string; value: string; context: string; confidence: number }[]): void {
  const header = "Type,Value,Context,Confidence\n";
  const rows = iocs.map(
    (ioc) => `"${ioc.type}","${ioc.value}","${ioc.context}",${ioc.confidence}`
  ).join("\n");
  
  const blob = new Blob([header + rows], { type: "text/csv" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "iocs_export.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export function exportIOCsAsJSON(iocs: { type: string; value: string; context: string; confidence: number }[]): void {
  const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "iocs_export.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

export async function runDynamicAnalysis(caseId: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  
  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/dynamic/run`, {
    method: "POST",
    headers,
  });
  if (!response.ok) throw new Error("Failed to start dynamic analysis");
  return response.json();
}

export async function deleteCase(caseId: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}`, {
    method: "DELETE",
    headers,
  });
  if (!response.ok) throw new Error("Failed to delete case");
  return response.json();
}

export function exportIOCsAsSTIX(iocs: { type: string; value: string; context: string; confidence: number }[]): void {
  const stixBundle = {
    type: "bundle",
    id: `bundle--${crypto.randomUUID()}`,
    spec_version: "2.1",
    created: new Date().toISOString(),
    objects: iocs.map((ioc) => ({
      type: "indicator",
      id: `indicator--${crypto.randomUUID()}`,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: `${ioc.type}: ${ioc.value}`,
      description: ioc.context,
      pattern: getSTIXPattern(ioc.type, ioc.value),
      pattern_type: "stix",
      valid_from: new Date().toISOString(),
      confidence: ioc.confidence,
    })),
  };

  const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: "application/json" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "iocs_export_stix21.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

function getSTIXPattern(type: string, value: string): string {
  switch (type) {
    case "domain": return `[domain-name:value = '${value}']`;
    case "ip": return `[ipv4-addr:value = '${value}']`;
    case "url": return `[url:value = '${value}']`;
    case "hash": return `[file:hashes.MD5 = '${value}']`;
    case "email": return `[email-addr:value = '${value}']`;
    default: return `[artifact:payload_bin = '${value}']`;
  }
}

// ── Manual Penetration Testing APIs ────────────────────────────────

export async function scanPentestDevices(caseId: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/pentest/devices`, {
    method: "GET",
    headers,
  });
  if (!response.ok) throw new Error("Failed to scan devices");
  return response.json();
}

export async function startPentestSession(caseId: string, deviceSerial: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/pentest/start`, {
    method: "POST",
    headers,
    body: JSON.stringify({ device_serial: deviceSerial }),
  });
  if (!response.ok) throw new Error("Failed to start pentest session");
  return response.json();
}

export async function getPentestStatus(caseId: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/pentest/status`, {
    method: "GET",
    headers,
  });
  if (!response.ok) throw new Error("Failed to get pentest status");
  return response.json();
}

export async function stopPentestSession(caseId: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/pentest/stop`, {
    method: "POST",
    headers,
  });
  if (!response.ok) throw new Error("Failed to stop pentest session");
  return response.json();
}

export async function cleanPentestDevice(caseId: string, deviceSerial?: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/pentest/clean`, {
    method: "POST",
    headers,
    body: JSON.stringify(deviceSerial ? { device_serial: deviceSerial } : {}),
  });
  if (!response.ok) throw new Error("Failed to clean device");
  return response.json();
}

export async function uninstallPackageFromDevice(caseId: string, packageName: string, deviceSerial?: string): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await fetch(`${API_BASE_URL}/cases/${caseId}/pentest/uninstall-package`, {
    method: "POST",
    headers,
    body: JSON.stringify({ package_name: packageName, ...(deviceSerial ? { device_serial: deviceSerial } : {}) }),
  });
  if (!response.ok) throw new Error(`Failed to uninstall package ${packageName}`);
  return response.json();
}



