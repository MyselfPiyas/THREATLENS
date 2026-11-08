"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import Link from "next/link";
import Image from "next/image";
import { AlertCircle, ArrowRight, FileImage, Globe2, Link2, LoaderCircle, LockKeyhole, ScanLine, UploadCloud } from "lucide-react";
import { FindingCards, InvestigationTimeline } from "@/components/dashboard/investigation-sections";
import { ErrorNotice, PageHeading, Panel, RiskBadge, ScoreIndicator } from "@/components/dashboard/ui";
import { useUrlScan } from "@/hooks/use-url-scan";
import { createSupabaseBrowserClient } from "@/lib/supabase/client";
import { analyzeMessage, analyzeQr } from "@/services/api-client";
import type { MessageAnalysis, QrAnalysis } from "@/types/api";
import { IdentityPanel } from "@/components/dashboard/identity-panel";

type Mode = "url" | "message" | "qr";

const copy: Record<Mode, { eyebrow: string; title: string; description: string; label: string; placeholder: string; helper: string; button: string }> = {
  url: { eyebrow: "Investigation tools / URL scanner", title: "Inspect a suspicious link", description: "Run a bounded URL investigation with DNS pinning, redirect checks, and evidence-based risk scoring.", label: "Website address", placeholder: "https://example.com/path", helper: "Public HTTP and HTTPS targets on standard ports only. URLs with credentials or authentication tokens are rejected.", button: "Start URL scan" },
  message: { eyebrow: "Investigation tools / Message analyzer", title: "Review a suspicious message", description: "Analyze untrusted text for social-engineering tactics and extract indicators without following its instructions.", label: "Message text", placeholder: "Paste suspicious content here…", helper: "Avoid passwords, API keys, or private information. Submitted content is analyzed as untrusted data.", button: "Analyze message" },
  qr: { eyebrow: "Investigation tools / QR scanner", title: "Inspect a QR code", description: "Decode a QR image locally through the backend. Destinations are not automatically visited.", label: "QR code image", placeholder: "Choose an image file", helper: "PNG, JPEG, or WEBP up to 5 MB. A decoded URL can be investigated separately.", button: "Decode QR code" },
};

const progressCopy: Record<string, string> = {
  authenticating: "Checking your signed-in session…",
  queued: "The scan is queued for an investigation worker…",
  running: "Checking DNS, response headers, redirects, and trusted indicators…",
};

export function ScannerWorkbench({ mode }: { mode: Mode }) {
  const [value, setValue] = useState("");
  const [notice, setNotice] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const previewUrlRef = useRef<string | null>(null);
  const [messageResult, setMessageResult] = useState<MessageAnalysis | null>(null);
  const [qrResult, setQrResult] = useState<QrAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [allowLlm, setAllowLlm] = useState(false);
  const { flow, submit, reset } = useUrlScan();
  const content = copy[mode];
  const isQr = mode === "qr";
  const isMessage = mode === "message";
  const isUrl = mode === "url";
  const Icon = isQr ? FileImage : isMessage ? ScanLine : Globe2;
  const busy = analyzing || flow.status === "authenticating" || flow.status === "queued" || flow.status === "running";

  useEffect(() => () => { if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current); }, []);

  function updateSelectedFile(file: File | null) {
    if (previewUrlRef.current) URL.revokeObjectURL(previewUrlRef.current);
    previewUrlRef.current = file ? URL.createObjectURL(file) : null;
    setImagePreview(previewUrlRef.current);
    setSelectedFile(file);
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!value.trim()) {
      setNotice("Add an item first.");
      return;
    }
    setNotice(""); setMessageResult(null); setQrResult(null);
    if (isUrl) {
      void submit(value.trim());
      return;
    }
    void runAnalysis();
  }

  async function runAnalysis() {
    setAnalyzing(true);
    try {
      const { data, error } = await createSupabaseBrowserClient().auth.getSession();
      const token = data.session?.access_token;
      if (error || !token) throw new Error("Your session has expired. Sign in again before analyzing content.");
      if (isMessage) setMessageResult(await analyzeMessage(value, token, allowLlm));
      else if (selectedFile) setQrResult(await analyzeQr(selectedFile, token));
      else throw new Error("Choose a QR image first.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "The analysis could not be completed."); }
    finally { setAnalyzing(false); }
  }

  return (
    <>
      <PageHeading eyebrow={content.eyebrow} title={content.title} description={content.description} />
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(260px,0.65fr)]">
        <Panel className="overflow-hidden">
          <div className="border-b border-border/80 bg-gradient-to-r from-accent/[0.06] to-transparent px-5 py-4 sm:px-7">
            <div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-xl border border-accent/15 bg-accent/[0.08] text-accent"><Icon className="size-4" /></span><div><h2 className="text-[12px] font-semibold">New investigation</h2><p className="mt-1 text-[9px] text-muted-foreground">{isUrl ? "Authenticated URL inspection" : isMessage ? "Authenticated message analysis" : "Authenticated QR decoding"}</p></div><span className="ml-auto rounded-full border border-accent/20 bg-accent/[0.06] px-2.5 py-1 text-[8px] font-semibold uppercase tracking-[0.11em] text-accent">Implemented</span></div>
          </div>
          <form onSubmit={handleSubmit} className="p-5 sm:p-7">
            <label htmlFor="scan-input" className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">{content.label}</label>
            {isQr ? (
              <label htmlFor="scan-input" className="mt-2 flex min-h-44 cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-border bg-background/50 px-5 text-center transition hover:border-accent/35">
                {imagePreview ? <Image src={imagePreview} alt="Selected QR code preview" width={320} height={160} unoptimized className="max-h-40 max-w-full rounded-lg object-contain" /> : <span className="grid size-11 place-items-center rounded-xl border border-border bg-panel-raised text-accent"><UploadCloud className="size-5" /></span>}
                <span className="mt-3 text-[11px] font-medium">Choose a QR image</span><span className="mt-1 text-[9px] text-muted-foreground">PNG, JPG, or WEBP · local preview only</span>
                <input id="scan-input" type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" onChange={(event) => { const file = event.currentTarget.files?.[0] ?? null; updateSelectedFile(file); setValue(file?.name ?? ""); setNotice(""); }} />
              </label>
            ) : isMessage ? (
              <textarea id="scan-input" value={value} onChange={(event) => { setValue(event.target.value); setNotice(""); }} maxLength={12000} rows={8} placeholder={content.placeholder} className="mt-2 w-full resize-y rounded-xl border border-border bg-background/75 px-4 py-3 text-[12px] leading-5 text-foreground outline-none placeholder:text-muted-foreground/55 focus:border-accent/50 focus:ring-2 focus:ring-accent/10" />
            ) : (
              <div className="mt-2 flex h-12 items-center gap-3 rounded-xl border border-border bg-background/75 px-3 focus-within:border-accent/50 focus-within:ring-2 focus-within:ring-accent/10"><Link2 className="size-4 shrink-0 text-muted-foreground" /><input id="scan-input" type="url" inputMode="url" value={value} disabled={busy} onChange={(event) => { setValue(event.target.value); setNotice(""); reset(); }} maxLength={2048} placeholder={content.placeholder} className="h-full min-w-0 flex-1 bg-transparent text-[12px] outline-none placeholder:text-muted-foreground/55 disabled:opacity-50" /></div>
            )}
            <p className="mt-2 text-[9px] leading-4 text-muted-foreground">{content.helper}</p>
            {isMessage ? <label className="mt-3 flex items-start gap-2 text-[9px] leading-4 text-muted-foreground"><input type="checkbox" checked={allowLlm} onChange={(event) => setAllowLlm(event.target.checked)} className="mt-0.5 accent-sky-400" />Allow the optional configured AI provider to review the submitted message. The backend redacts email addresses and phone numbers first; this is off by default.</label> : null}
            <div className="mt-5 flex flex-col gap-3 border-t border-border/70 pt-5 sm:flex-row sm:items-center sm:justify-between">
              <span className="inline-flex items-center gap-2 text-[9px] text-muted-foreground"><LockKeyhole className="size-3.5 text-positive" /> No credentials or cookies are sent to the target</span>
              <button type="submit" disabled={busy} className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-accent px-4 text-[10px] font-bold text-[#06111c] transition hover:bg-[#80cbff] disabled:cursor-wait disabled:opacity-60">{busy ? "Analyzing…" : content.button}{busy ? <LoaderCircle className="size-3.5 animate-spin" /> : <ArrowRight className="size-3.5" />}</button>
            </div>
            {notice ? <p role="status" aria-live="polite" className="mt-4 flex items-start gap-2 rounded-lg border border-warning/20 bg-warning/[0.05] px-3 py-2.5 text-[10px] leading-4 text-warning"><AlertCircle className="mt-0.5 size-3.5 shrink-0" />{notice}</p> : null}
            {flow.status === "error" ? <div className="mt-4"><ErrorNotice detail={flow.error ?? "The scan could not be completed."} />{flow.scanId ? <Link className="mt-2 inline-block text-[9px] font-semibold text-accent" href="/scan-history">Open scan history</Link> : null}</div> : null}
            {busy ? <div role="status" aria-live="polite" className="mt-4 flex items-center gap-3 rounded-lg border border-accent/15 bg-accent/[0.04] px-3 py-3 text-[10px] text-muted-foreground"><LoaderCircle className="size-4 animate-spin text-accent" />{progressCopy[flow.status]}</div> : null}
          </form>
        </Panel>

        <div className="space-y-4">
          <Panel className="p-5">
            <p className="text-[9px] font-semibold uppercase tracking-[0.15em] text-muted-foreground">What happens next</p>
            <div className="mt-4 space-y-4">
              {["Validate the URL and destination", "Inspect DNS and bounded response metadata", "Review evidence and risk classification"].map((step, index) => <div key={step} className="flex gap-3"><span className="grid size-6 shrink-0 place-items-center rounded-full border border-border bg-panel-raised text-[9px] font-semibold text-muted-foreground">0{index + 1}</span><div className="pt-1"><p className="text-[10px] font-medium">{step}</p><p className="mt-1 text-[9px] leading-4 text-muted-foreground">{isUrl ? "Each redirect is revalidated before a connection." : "Available when this analyzer is connected."}</p></div></div>)}
            </div>
          </Panel>
          <div className="rounded-xl border border-warning/15 bg-warning/[0.035] p-4"><div className="flex gap-2.5"><AlertCircle className="mt-0.5 size-4 shrink-0 text-warning" /><p className="text-[9px] leading-4 text-muted-foreground"><strong className="font-semibold text-warning">Evidence has limits.</strong> Findings are review signals, not proof of maliciousness. QR destinations are never automatically visited.</p></div></div>
        </div>
      </div>

      {messageResult ? <AnalysisResult result={messageResult} /> : null}
      {qrResult ? <QrResultPanel result={qrResult} /> : null}

      {flow.report ? <section className="mt-5 space-y-4" aria-live="polite">
        <Panel className="p-5 sm:p-6"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="text-[9px] uppercase tracking-[0.15em] text-muted-foreground">Completed URL investigation</p><h2 className="mt-2 break-all text-[15px] font-semibold">{flow.report.scan.target}</h2><p className="mt-2 max-w-3xl text-[10px] leading-5 text-muted-foreground">{flow.report.scan.summary}</p></div><Link href={`/scan/${encodeURIComponent(flow.report.scan.id)}`} className="rounded-lg border border-border bg-panel-raised px-3 py-2 text-[9px] font-semibold text-accent hover:border-accent/30">Open saved report</Link></div><div className="mt-4 flex flex-wrap items-center gap-5 border-t border-border/70 pt-4"><div><p className="text-[8px] uppercase tracking-[0.12em] text-muted-foreground">Risk classification</p><div className="mt-2"><RiskBadge level={flow.report.scan.risk_level} /></div></div><div><p className="text-[8px] uppercase tracking-[0.12em] text-muted-foreground">Score</p><div className="mt-2"><ScoreIndicator score={flow.report.scan.risk_score} /></div></div><p className="max-w-lg text-[9px] leading-4 text-muted-foreground">This automated assessment is based on available DNS, HTTP, URL-pattern, and trusted-feed signals. Review the evidence before acting.</p></div></Panel>
        <div className="grid gap-4 xl:grid-cols-2"><FindingCards findings={flow.report.findings} /><InvestigationTimeline events={flow.report.events} /></div>
        <IdentityPanel url={flow.report.scan.target} scanId={flow.report.scan.id} />
      </section> : null}
    </>
  );
}

function AnalysisResult({ result }: { result: MessageAnalysis }) {
  return <Panel className="mt-5 p-5 sm:p-6" aria-live="polite"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-[9px] uppercase tracking-[0.15em] text-muted-foreground">Completed message analysis</p><h2 className="mt-2 text-[15px] font-semibold">{result.risk_level} · score {result.risk_score}</h2></div><RiskBadge level={result.risk_level} /></div><p className="mt-3 text-[10px] leading-5 text-muted-foreground">{result.explanation}</p><div className="mt-5 grid gap-4 md:grid-cols-2"><div><h3 className="text-[10px] font-semibold">Detected tactics</h3><div className="mt-2 flex flex-wrap gap-2">{result.detected_tactics.length ? result.detected_tactics.map((item) => <span key={item} className="rounded-full border border-warning/20 bg-warning/[0.05] px-2 py-1 text-[9px] text-warning">{item}</span>) : <span className="text-[10px] text-muted-foreground">No configured tactics observed.</span>}</div><h3 className="mt-4 text-[10px] font-semibold">Highlighted phrases</h3><div className="mt-2 flex flex-wrap gap-2">{result.highlighted_phrases.length ? result.highlighted_phrases.map((item) => <mark key={item} className="rounded bg-warning/15 px-2 py-1 text-[9px] text-warning">{item}</mark>) : <span className="text-[10px] text-muted-foreground">No phrases highlighted.</span>}</div></div><div><h3 className="text-[10px] font-semibold">Extracted indicators</h3><div className="mt-2 space-y-1 text-[10px] text-muted-foreground">{Object.entries(result.extracted_indicators).map(([kind, values]) => <p key={kind}><span className="text-foreground">{kind}:</span> {values.join(" · ") || "none"}</p>)}</div><h3 className="mt-4 text-[10px] font-semibold">Evidence</h3><ul className="mt-2 space-y-1 text-[10px] leading-5 text-muted-foreground">{result.evidence.map((item) => <li key={item}>• {item}</li>)}</ul></div></div><div className="mt-5"><h3 className="text-[10px] font-semibold">Recommended actions</h3><ul className="mt-2 space-y-1 text-[10px] leading-5 text-muted-foreground">{result.recommended_actions.map((item) => <li key={item}>• {item}</li>)}</ul></div></Panel>;
}

function QrResultPanel({ result }: { result: QrAnalysis }) {
  return <Panel className="mt-5 p-5 sm:p-6" aria-live="polite"><p className="text-[9px] uppercase tracking-[0.15em] text-muted-foreground">QR decode result</p><h2 className="mt-2 text-[15px] font-semibold">{result.decoded ? "QR content decoded" : "QR code not decoded"}</h2><p className="mt-3 break-all rounded-lg border border-border bg-background/50 p-3 text-[10px] text-foreground">{result.extracted_content ?? "No content"}</p>{result.url_scan_id ? <Link href={`/scan/${encodeURIComponent(result.url_scan_id)}`} className="mt-3 inline-block rounded-lg border border-accent/20 px-3 py-2 text-[10px] font-semibold text-accent">Open URL investigation</Link> : null}<p className="mt-3 text-[10px] leading-5 text-muted-foreground">{result.explanation}</p><div className="mt-4 space-y-1 text-[10px] text-muted-foreground">{result.evidence.map((item) => <p key={item}>• {item}</p>)}</div></Panel>;
}
