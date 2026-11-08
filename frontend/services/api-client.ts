import type { HealthResponse, IdentityResult, IntelligenceIndicator, IntelligenceOverview, MessageAnalysis, QrAnalysis, ScamDnaGraph, ScanEvent, ScanFinding, ScanRecord, ScanReport, SecurityHeadersResult, TlsResult, UrlScanStatus } from "@/types/api";
import { API_BASE_URL } from "@/lib/runtime-config";

type BackendHealthResult =
  | { ok: true; data: HealthResponse }
  | { ok: false; error: string };

export type AcceptedUrlScan = { scan_id: string; status: "queued"; status_url: string };
export type ScanProgress = { scan_id: string; status: UrlScanStatus; risk_level: string; risk_score: number; summary: string };

async function authenticatedRequest<T>(path: string, accessToken: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: "GET",
      cache: "no-store",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    throw new Error("Could not reach the THREATLENS API. Check that the backend is running.");
  }
  return parseApiResponse<T>(response);
}

async function parseApiResponse<T>(response: Response): Promise<T> {
  let payload: unknown;
  try { payload = await response.json(); } catch { payload = null; }
  if (!response.ok) {
    const detail = isRecord(payload) && typeof payload.detail === "string" ? payload.detail : `The API returned HTTP ${response.status}.`;
    throw new Error(detail);
  }
  if (payload === null) throw new Error("The API returned an empty response.");
  return payload as T;
}

export async function submitUrlScan(url: string, accessToken: string): Promise<AcceptedUrlScan> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/scans/url`, {
      method: "POST",
      cache: "no-store",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    throw new Error("Could not reach the THREATLENS API. Check that the backend is running.");
  }
  const result = await parseApiResponse<unknown>(response);
  if (!isRecord(result) || typeof result.scan_id !== "string" || result.status !== "queued") {
    throw new Error("The API returned an unexpected scan response.");
  }
  return result as AcceptedUrlScan;
}

export async function getUrlScanStatus(scanId: string, accessToken: string): Promise<ScanProgress> {
  const result = await authenticatedRequest<unknown>(`/scans/${encodeURIComponent(scanId)}/status`, accessToken);
  if (!isRecord(result) || typeof result.scan_id !== "string" || typeof result.status !== "string") {
    throw new Error("The API returned an unexpected scan status.");
  }
  return result as ScanProgress;
}

export async function getUrlScanReport(scanId: string, accessToken: string): Promise<ScanReport> {
  const [scan, findings, events] = await Promise.all([
    authenticatedRequest<unknown>(`/scans/${encodeURIComponent(scanId)}`, accessToken),
    authenticatedRequest<unknown>(`/scans/${encodeURIComponent(scanId)}/findings`, accessToken),
    authenticatedRequest<unknown>(`/scans/${encodeURIComponent(scanId)}/events`, accessToken),
  ]);
  if (!isScanRecord(scan) || !Array.isArray(findings) || !Array.isArray(events)) {
    throw new Error("The API returned an incomplete scan report.");
  }
  return {
    scan,
    findings: findings as ScanFinding[],
    events: events as ScanEvent[],
  };
}

export async function analyzeWebsiteIdentity(url: string, accessToken: string, scanId?: string): Promise<IdentityResult> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/analyze/identity`, {
      method: "POST", cache: "no-store",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ url, ...(scanId ? { scan_id: scanId } : {}) }), signal: AbortSignal.timeout(10000),
    });
  } catch { throw new Error("Could not reach the THREATLENS API. Check that the backend is running."); }
  const result = await parseApiResponse<unknown>(response);
  if (!isRecord(result) || typeof result.actual_domain !== "string" || typeof result.detection_category !== "string") {
    throw new Error("The API returned an unexpected identity analysis response.");
  }
  return result as IdentityResult;
}

async function postAnalysis<T>(path: string, url: string, accessToken: string, scanId?: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { method: "POST", cache: "no-store", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ url, ...(scanId ? { scan_id: scanId } : {}) }), signal: AbortSignal.timeout(15000) });
  } catch { throw new Error("Could not reach the THREATLENS API. Check that the backend is running."); }
  return parseApiResponse<T>(response);
}

export function analyzeTls(url: string, accessToken: string, scanId?: string): Promise<TlsResult> {
  return postAnalysis<TlsResult>("/analyze/tls", url, accessToken, scanId);
}

export function analyzeSecurityHeaders(url: string, accessToken: string, scanId?: string): Promise<SecurityHeadersResult> {
  return postAnalysis<SecurityHeadersResult>("/analyze/security-headers", url, accessToken, scanId);
}

export async function analyzeMessage(content: string, accessToken: string, allowLlm = false): Promise<MessageAnalysis> {
  let response: Response;
  try { response = await fetch(`${API_BASE_URL}/analyze/message`, { method: "POST", cache: "no-store", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify({ content, allow_llm: allowLlm }), signal: AbortSignal.timeout(15000) }); }
  catch { throw new Error("Could not reach the THREATLENS API. Check that the backend is running."); }
  return parseApiResponse<MessageAnalysis>(response);
}

export async function analyzeQr(file: File, accessToken: string): Promise<QrAnalysis> {
  const form = new FormData(); form.append("file", file);
  let response: Response;
  try { response = await fetch(`${API_BASE_URL}/analyze/qr`, { method: "POST", cache: "no-store", headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" }, body: form, signal: AbortSignal.timeout(20000) }); }
  catch { throw new Error("Could not reach the THREATLENS API. Check that the backend is running."); }
  return parseApiResponse<QrAnalysis>(response);
}

export function getIntelligenceOverview(accessToken: string): Promise<IntelligenceOverview> { return authenticatedRequest<IntelligenceOverview>("/intelligence/overview", accessToken); }
export async function getIntelligenceIndicators(accessToken: string, search = ""): Promise<IntelligenceIndicator[]> { const result = await authenticatedRequest<{ items: IntelligenceIndicator[] }>(`/intelligence/indicators?page=1&page_size=50${search ? `&search=${encodeURIComponent(search)}` : ""}`, accessToken); return result.items; }
export function getScamDna(scanId: string, accessToken: string): Promise<ScamDnaGraph> { return authenticatedRequest<ScamDnaGraph>(`/scam-dna/${encodeURIComponent(scanId)}`, accessToken); }
export function analyzeScamDna(scanId: string, accessToken: string): Promise<ScamDnaGraph> { return postJson<ScamDnaGraph>(`/scam-dna/${encodeURIComponent(scanId)}/analyze`, {}, accessToken); }

async function postJson<T>(path: string, body: unknown, accessToken: string): Promise<T> {
  let response: Response;
  try { response = await fetch(`${API_BASE_URL}${path}`, { method: "POST", cache: "no-store", headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000) }); }
  catch { throw new Error("Could not reach the THREATLENS API. Check that the backend is running."); }
  return parseApiResponse<T>(response);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScanRecord(value: unknown): value is ScanRecord {
  return isRecord(value) && typeof value.id === "string" && typeof value.target === "string" &&
    typeof value.status === "string" && typeof value.risk_level === "string" && typeof value.risk_score === "number";
}

export function getApiDocsUrl(): string {
  return `${API_BASE_URL.replace(/\/api\/v1$/, "")}/docs`;
}

export async function getBackendHealth(): Promise<BackendHealthResult> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });

    if (!response.ok) {
      return { ok: false, error: `Health check returned HTTP ${response.status}.` };
    }

    const data: unknown = await response.json();
    if (!isHealthResponse(data)) {
      return { ok: false, error: "The backend returned an unexpected health response." };
    }

    return { ok: true, data };
  } catch {
    return {
      ok: false,
      error: "Could not reach FastAPI. Check that the backend is running on the configured API URL.",
    };
  }
}

function isHealthResponse(value: unknown): value is HealthResponse {
  return (
    typeof value === "object" &&
    value !== null &&
    "status" in value && value.status === "ok" &&
    "service" in value && typeof value.service === "string" &&
    "supabase_configured" in value && typeof value.supabase_configured === "boolean"
    && (!("scan_persistence_configured" in value) || typeof value.scan_persistence_configured === "boolean")
  );
}

