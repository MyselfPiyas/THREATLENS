"use client";

import { useEffect, useState } from "react";
import { API_BASE_URL } from "@/lib/runtime-config";

export function PublicPassportVerifier() {
  const [id, setId] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const sharedToken = new URLSearchParams(window.location.search).get("token");
    if (sharedToken) {
      const timer = window.setTimeout(() => setId(sharedToken), 0);
      return () => window.clearTimeout(timer);
    }
  }, []);
  async function verify() {
    setLoading(true); setError(""); setResult(null);
    try {
      const response = await fetch(`${API_BASE_URL}/public/passports/${encodeURIComponent(id.trim())}/verify`, { cache: "no-store" });
      const payload = await response.json().catch(() => null);
      if (!response.ok) throw new Error(typeof payload?.detail === "string" ? payload.detail : `Verification returned HTTP ${response.status}.`);
      setResult(payload);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Verification failed."); }
    finally { setLoading(false); }
  }
  return <div className="space-y-3">
    <label htmlFor="passport-id" className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Public share token</label>
    <div className="flex flex-col gap-2 sm:flex-row"><input id="passport-id" value={id} onChange={(event) => setId(event.target.value)} placeholder="Paste the share token from its owner" className="min-h-10 flex-1 rounded-lg border border-border bg-background/60 px-3 text-[11px] outline-none focus:border-accent" /><button type="button" disabled={loading || !id.trim()} onClick={verify} className="min-h-10 rounded-lg bg-accent px-4 text-[10px] font-semibold text-slate-950 disabled:cursor-not-allowed disabled:opacity-50">{loading ? "Checking…" : "Verify shared passport"}</button></div>
    {error ? <p role="alert" className="rounded-lg border border-warning/25 bg-warning/[0.06] p-3 text-[10px] text-warning">{error}</p> : null}
    {result ? <div className="rounded-lg border border-border bg-background/40 p-3 text-[10px] text-muted-foreground"><p className="font-semibold text-foreground">{String(result.verification_status)}</p><p className="mt-1 break-all font-mono">SHA-256 · {String(result.report_hash)}</p><p className="mt-2">{String(result.detail)}</p></div> : null}
  </div>;
}
