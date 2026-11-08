"use client";

import { useCallback, useEffect, useState } from "react";
import { Copy, Download, RefreshCw, ShieldCheck, Upload } from "lucide-react";
import { EmptyState, ErrorNotice } from "@/components/dashboard/ui";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";

type Passport = { id: string; scan_id: string; report_hash: string; verification_status: string; created_at: string; public_sharing_enabled: boolean };
type Scan = { id: string; target: string; status: string; created_at: string };

const API = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001/api/v1").replace(/\/+$/, "");

export function TrustPassportManager() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [passports, setPassports] = useState<Passport[]>([]);
  const [selectedScan, setSelectedScan] = useState("");
  const [shareLinks, setShareLinks] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const request = useCallback(async (path: string, init: RequestInit = {}) => {
    const supabase = createSupabaseBrowserClient();
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.access_token) throw new Error("Your session expired. Sign in again.");
    const response = await fetch(`${API}${path}`, { ...init, headers: { ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json" }), Authorization: `Bearer ${session.access_token}`, ...init.headers }, cache: "no-store" });
    const payload = await response.json().catch(() => null);
    if (!response.ok) throw new Error(typeof payload?.detail === "string" ? payload.detail : `Request failed (${response.status}).`);
    return payload;
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true); setError("");
    try {
      const [records, scanRows] = await Promise.all([request("/passports?limit=50"), (async () => {
        const supabase = createSupabaseBrowserClient();
        const { data: { session } } = await supabase.auth.getSession();
        if (!session?.access_token) return [];
        const { data, error: queryError } = await supabase.from("scans").select("id,target,status,created_at").order("created_at", { ascending: false }).limit(100);
        if (queryError) throw new Error("Saved scans could not be loaded. Check the database connection.");
        return data ?? [];
      })()]);
      setPassports(records); setScans(scanRows as Scan[]);
      if (!selectedScan && scanRows.length) setSelectedScan(scanRows.find((scan: Scan) => ["completed", "complete"].includes(scan.status))?.id ?? "");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Trust passports could not be loaded."); }
    finally { setLoading(false); }
  }, [request, selectedScan]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  async function createPassport() {
    if (!selectedScan) return;
    setBusy("create"); setError(""); setNotice("");
    try { await request("/passports", { method: "POST", body: JSON.stringify({ scan_id: selectedScan }) }); setNotice("Off-chain passport created and stored."); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Passport creation failed."); }
    finally { setBusy(""); }
  }

  async function verify(id: string) {
    setBusy(id); setError(""); setNotice("");
    try { const result = await request(`/passports/${id}/verify`, { method: "POST" }); setNotice(result.detail); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Verification failed."); }
    finally { setBusy(""); }
  }

  async function verifyUpload(id: string, file: File) {
    const isJson = file.type === "application/json" || file.name.toLowerCase().endsWith(".json");
    if (!isJson) { setError("Choose a JSON passport report."); return; }
    if (file.size > 1024 * 1024) { setError("Passport JSON must be 1 MB or smaller."); return; }
    setBusy(`upload-${id}`); setError(""); setNotice("");
    try {
      const form = new FormData();
      form.append("file", file, file.name);
      const result = await request(`/passports/${id}/verify-upload`, { method: "POST", body: form });
      setNotice(result.integrity_match ? "Uploaded report matches the stored SHA-256 reference." : "Tamper detected: uploaded report does not match the stored SHA-256 reference.");
      await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Uploaded report verification failed."); }
    finally { setBusy(""); }
  }

  async function share(id: string, enabled: boolean) {
    setBusy(id); setError(""); setNotice("");
    try {
      if (enabled) {
        const result = await request(`/passports/${id}/share`, { method: "POST" });
        const link = `${window.location.origin}/verify?token=${encodeURIComponent(result.public_token)}`;
        setShareLinks((previous) => ({ ...previous, [id]: link })); setNotice("A revocable public verification link is ready. It exposes only integrity metadata.");
      } else {
        await request(`/passports/${id}/share`, { method: "DELETE" });
        setShareLinks((previous) => { const next = { ...previous }; delete next[id]; return next; }); setNotice("Public link revoked.");
      }
      await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Sharing update failed."); }
    finally { setBusy(""); }
  }

  async function download(id: string, format: "json" | "pdf") {
    setBusy(id); setError("");
    try {
      const supabase = createSupabaseBrowserClient();
      const { data: { session } } = await supabase.auth.getSession();
      const response = await fetch(`${API}/passports/${id}/download?format=${format}`, { headers: { Authorization: `Bearer ${session?.access_token ?? ""}` }, cache: "no-store" });
      if (!response.ok) { const payload = await response.json().catch(() => null); throw new Error(payload?.detail || `Download failed (${response.status}).`); }
      const blob = await response.blob(); const href = URL.createObjectURL(blob); const anchor = document.createElement("a"); anchor.href = href; anchor.download = `threatlens-passport-${id}.${format}`; anchor.click(); URL.revokeObjectURL(href);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Download failed."); }
    finally { setBusy(""); }
  }

  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); setNotice("Verification link copied."); }
    catch { setError("Could not copy link. Select and copy it manually."); }
  }

  const eligibleScans = scans.filter((scan) => ["completed", "complete"].includes(scan.status));
  return <div className="space-y-4">
    <section className="rounded-xl border border-border bg-background/35 p-4">
      <h3 className="text-[12px] font-semibold">Create an off-chain passport</h3>
      <p className="mt-1 text-[10px] leading-4 text-muted-foreground">Select a completed investigation. A canonical report snapshot and SHA-256 digest will be stored in Supabase.</p>
      <div className="mt-3 flex flex-col gap-2 sm:flex-row">
        <select aria-label="Completed investigation" value={selectedScan} onChange={(event) => setSelectedScan(event.target.value)} className="min-h-10 min-w-0 flex-1 rounded-lg border border-border bg-background px-3 text-[10px]">
          <option value="">Select a completed investigation</option>
          {eligibleScans.map((scan) => <option key={scan.id} value={scan.id}>{scan.target} · {new Date(scan.created_at).toLocaleDateString()}</option>)}
        </select>
        <button type="button" onClick={createPassport} disabled={!selectedScan || !!busy || loading} className="min-h-10 rounded-lg bg-accent px-4 text-[10px] font-semibold text-slate-950 disabled:opacity-50">{busy === "create" ? "Creating…" : "Create passport"}</button>
      </div>
      {!loading && eligibleScans.length === 0 ? <p className="mt-2 text-[9px] text-muted-foreground">No completed scans are available yet.</p> : null}
    </section>
    {error ? <ErrorNotice detail={error} /> : null}
    {notice ? <p role="status" className="rounded-xl border border-accent/20 bg-accent/[0.06] p-3 text-[10px] text-accent">{notice}</p> : null}
    {loading ? <div role="status" className="rounded-xl border border-border p-6 text-center text-[10px] text-muted-foreground">Loading your passports…</div> : passports.length ? <div className="space-y-3">{passports.map((record) => <article key={record.id} className="rounded-xl border border-border bg-background/35 p-4">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div className="min-w-0"><p className="text-[10px] font-semibold">Off-chain report integrity record</p><p className="mt-1 break-all font-mono text-[9px] text-muted-foreground">SHA-256 · {record.report_hash}</p><p className="mt-1 break-all text-[9px] text-muted-foreground">Passport {record.id} · Scan {record.scan_id}</p></div><span className="w-fit rounded-full border border-border px-2.5 py-1 text-[8px] uppercase tracking-wide text-muted-foreground">{record.verification_status}</span></div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button onClick={() => verify(record.id)} disabled={!!busy} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-3 text-[9px] hover:border-accent/40 disabled:opacity-50"><RefreshCw className="size-3" /> Verify</button>
        <button onClick={() => download(record.id, "json")} disabled={!!busy} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-3 text-[9px] disabled:opacity-50"><Download className="size-3" /> JSON</button>
        <button onClick={() => download(record.id, "pdf")} disabled={!!busy} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border px-3 text-[9px] disabled:opacity-50"><Download className="size-3" /> PDF</button>
        <label className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded-lg border border-border px-3 text-[9px] hover:border-accent/40 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-50" aria-label="Verify a downloaded JSON report">
          <Upload className="size-3" /> {busy === `upload-${record.id}` ? "Checking…" : "Verify JSON"}
          <input type="file" accept=".json,application/json" className="sr-only" disabled={!!busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; if (file) void verifyUpload(record.id, file); }} />
        </label>
        {record.public_sharing_enabled ? <><button onClick={() => share(record.id, true)} disabled={!!busy} className="h-8 rounded-lg border border-accent/30 px-3 text-[9px] text-accent disabled:opacity-50">{shareLinks[record.id] ? "Rotate link" : "Generate link"}</button><button onClick={() => share(record.id, false)} disabled={!!busy} className="h-8 rounded-lg border border-warning/30 px-3 text-[9px] text-warning disabled:opacity-50">Revoke public link</button></> : <button onClick={() => share(record.id, true)} disabled={!!busy} className="h-8 rounded-lg border border-accent/30 px-3 text-[9px] text-accent disabled:opacity-50">Enable public link</button>}
      </div>
      {shareLinks[record.id] ? <div className="mt-3 flex flex-col gap-2 sm:flex-row"><input aria-label="Public verification link" readOnly value={shareLinks[record.id]} className="min-h-9 min-w-0 flex-1 rounded-lg border border-border bg-background px-2 text-[9px]"/><button onClick={() => void copy(shareLinks[record.id])} className="inline-flex h-9 items-center justify-center gap-1.5 rounded-lg border border-border px-3 text-[9px]"><Copy className="size-3"/> Copy link</button></div> : null}
    </article>)}</div> : <EmptyState icon={ShieldCheck} title="No report passports yet" detail="No demo or synthetic passport records are shown. Create one from a completed saved investigation." />}
  </div>;
}
