export type HealthResponse = {
  status: "ok";
  service: string;
  supabase_configured: boolean;
  scan_persistence_configured?: boolean;
};

export type UrlScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type IdentityResult = {
  scan_id: string | null;
  claimed_brand: string | null;
  actual_domain: string;
  similarity_score: number;
  suspicious_characters: string[];
  detection_category: string;
  evidence: string[];
  confidence: number;
  explanation: string;
  brand_domain: string | null;
};

export type TlsResult = {
  scan_id: string | null;
  url: string;
  available: boolean;
  certificate: Record<string, unknown> | null;
  reason?: string | null;
  limitations: string[];
};

export type SecurityHeadersResult = {
  scan_id: string | null;
  url: string;
  available: boolean;
  http_status: number;
  headers: Record<string, string>;
  missing: string[];
  findings?: { header: string; status: string; remediation: string }[];
  mixed_content: { available: boolean; detail: string };
  limitations: string[];
};

export type ScanRecord = {
  id: string;
  user_id: string;
  scan_type: string;
  target: string;
  normalized_target: string;
  status: UrlScanStatus;
  risk_level: string;
  risk_score: number;
  summary: string;
  started_at: string;
  completed_at: string | null;
  created_at: string;
};

export type ScanFinding = {
  id: string;
  scan_id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  evidence: Record<string, unknown>;
  source: string;
  confidence: number;
  created_at: string;
};

export type ScanEvent = {
  id: string;
  scan_id: string;
  event_type: string;
  title: string;
  description: string;
  event_data: Record<string, unknown>;
  occurred_at: string;
};

export type ScanReport = {
  scan: ScanRecord;
  findings: ScanFinding[];
  events: ScanEvent[];
};

export type MessageAnalysis = {
  analysis_id: string;
  risk_level: string;
  risk_score: number;
  detected_tactics: string[];
  highlighted_phrases: string[];
  extracted_indicators: Record<string, string[]>;
  evidence: string[];
  explanation: string;
  recommended_actions: string[];
  source: string;
};

export type QrAnalysis = {
  analysis_id: string;
  decoded: boolean;
  content_type: string;
  extracted_content: string | null;
  url_scan_id: string | null;
  risk_level: string | null;
  risk_score: number | null;
  evidence: string[];
  explanation: string;
};

export type IntelligenceIndicator = { id: string; indicator_type: string; indicator_value: string; source: string; threat_category: string; confidence: number; first_seen?: string | null; last_seen?: string | null; metadata?: Record<string, unknown> };
export type IntelligenceOverview = { indicator_count: number; source_count: number; sources: string[]; categories: Record<string, number>; types: Record<string, number>; last_updated?: string | null };
export type ScamDnaGraph = { scan_id: string; nodes: { id: string; node_type: string; label: string; metadata: Record<string, unknown> }[]; edges: { id: string; source: string; target: string; relationship_type: string; confidence: number; evidence: Record<string, unknown> }[]; relationships: { id?: string | null; source_scan_id: string; related_scan_id: string; relationship_type: string; confidence: number; evidence: Record<string, unknown> }[]; deterministic_summary: string; ai_interpretation?: Record<string, unknown> | null };

