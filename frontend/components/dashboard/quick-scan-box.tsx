"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { ArrowRight, Globe2, LoaderCircle, LockKeyhole } from "lucide-react";
import { RiskBadge } from "@/components/dashboard/ui";
import { useUrlScan } from "@/hooks/use-url-scan";

export function QuickScanBox() {
  const [url, setUrl] = useState("");
  const [emptyMessage, setEmptyMessage] = useState("");
  const { flow, submit, reset } = useUrlScan();
  const busy = flow.status === "authenticating" || flow.status === "queued" || flow.status === "running";

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!url.trim()) {
      setEmptyMessage("Enter a URL to start an investigation.");
      return;
    }
    setEmptyMessage("");
    void submit(url.trim());
  }

  return (
    <div>
      <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-2.5 sm:flex-row">
        <label htmlFor="quick-url" className="sr-only">URL to scan</label>
        <div className="flex h-11 min-w-0 flex-1 items-center gap-2.5 rounded-lg border border-border bg-background/70 px-3.5 focus-within:border-accent/50"><Globe2 className="size-4 shrink-0 text-muted-foreground" /><input id="quick-url" type="url" inputMode="url" maxLength={2048} placeholder="Paste a URL to inspect" value={url} disabled={busy} onChange={(event) => { setUrl(event.target.value); setEmptyMessage(""); reset(); }} className="h-full min-w-0 flex-1 bg-transparent text-[11px] outline-none placeholder:text-muted-foreground/60 disabled:opacity-50" /></div>
        <button type="submit" disabled={busy} className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-accent px-4 text-[10px] font-bold text-[#06111c] transition hover:bg-[#80cbff] disabled:cursor-wait disabled:opacity-60">{busy ? "Scanning…" : "Quick scan"}{busy ? <LoaderCircle className="size-3.5 animate-spin" /> : <ArrowRight className="size-3.5" />}</button>
      </form>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[9px] text-muted-foreground"><span className="inline-flex items-center gap-1.5"><LockKeyhole className="size-3 text-positive" /> No credentials are sent to targets</span><Link href="/url-scanner" className="font-semibold text-accent hover:text-foreground">Open URL scanner</Link></div>
      {emptyMessage ? <p role="status" aria-live="polite" className="mt-3 text-[9px] text-warning">{emptyMessage}</p> : null}
      {flow.status === "error" ? <div role="alert" className="mt-3 rounded-lg border border-warning/20 bg-warning/[0.05] px-3 py-2 text-[9px] leading-4 text-warning">{flow.error}{flow.scanId ? <> <Link href="/scan-history" className="font-semibold underline">Open history</Link></> : null}</div> : null}
      {flow.status === "queued" || flow.status === "running" || flow.status === "authenticating" ? <p role="status" aria-live="polite" className="mt-3 flex items-center gap-2 text-[9px] text-muted-foreground"><LoaderCircle className="size-3 animate-spin text-accent" />{flow.status === "queued" ? "Investigation queued…" : flow.status === "running" ? "Inspecting DNS, response metadata, and redirects…" : "Checking signed-in session…"}</p> : null}
      {flow.report ? <div role="status" className="mt-3 rounded-lg border border-border bg-background/40 px-3 py-2.5"><div className="flex flex-wrap items-center gap-2"><RiskBadge level={flow.report.scan.risk_level} /><span className="text-[9px] text-muted-foreground">Score {flow.report.scan.risk_score}</span><Link href={`/scan/${encodeURIComponent(flow.report.scan.id)}`} className="ml-auto text-[9px] font-semibold text-accent hover:text-foreground">Open report</Link></div><p className="mt-2 text-[9px] leading-4 text-muted-foreground">{flow.report.scan.summary}</p></div> : null}
    </div>
  );
}
