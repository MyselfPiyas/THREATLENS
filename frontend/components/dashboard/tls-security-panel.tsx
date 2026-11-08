"use client";

import { CheckCircle2, CircleAlert, LoaderCircle, LockKeyhole } from "lucide-react";
import { useTlsAnalysis } from "@/hooks/use-tls-analysis";
import { ErrorNotice, Panel, PanelTitle } from "@/components/dashboard/ui";

function value(record: Record<string, unknown> | null, key: string): string {
  const item = record?.[key];
  return typeof item === "string" || typeof item === "number" || typeof item === "boolean" ? String(item) : "Not available";
}

function chainValue(record: Record<string, unknown> | null): string {
  const chain = record?.chain;
  if (!chain || typeof chain !== "object") return "Not available";
  const subjects = (chain as { subjects?: unknown }).subjects;
  return Array.isArray(subjects) && subjects.length ? `${subjects.length} certificates observed` : "Not available";
}

export function TlsSecurityPanel({ url, scanId }: { url: string; scanId?: string }) {
  const { tls, headers, busy, error, analyze } = useTlsAnalysis();
  return <Panel id="tls-security-analysis" className="mt-4 p-5 sm:p-6">
    <PanelTitle title="TLS and website security" detail="Passive certificate and HTTP header observations" />
    {!tls && !error ? <div className="mt-4 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-dashed border-border p-4"><div className="flex items-start gap-3"><span className="grid size-9 place-items-center rounded-xl border border-accent/15 bg-accent/[0.08] text-accent"><LockKeyhole className="size-4" /></span><p className="max-w-xl text-[10px] leading-5 text-muted-foreground">Inspect publicly observable TLS metadata and response security headers. A valid certificate does not establish that a website is trustworthy.</p></div><button type="button" onClick={() => void analyze(url, scanId)} disabled={busy} className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-[10px] font-bold text-[#06111c] disabled:opacity-60">{busy ? <LoaderCircle className="size-3.5 animate-spin" /> : <LockKeyhole className="size-3.5" />} {busy ? "Inspecting…" : "Analyze TLS"}</button></div> : null}
    {error ? <div className="mt-4"><ErrorNotice detail={error} /></div> : null}
    {tls ? <div className="mt-4 space-y-4">
      <div className="grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-border bg-background/35 p-3"><p className="text-[8px] uppercase tracking-[0.12em] text-muted-foreground">Certificate</p><p className="mt-2 text-[11px] font-semibold">{tls.available ? "Observed" : "Unavailable"}</p></div><div className="rounded-xl border border-border bg-background/35 p-3"><p className="text-[8px] uppercase tracking-[0.12em] text-muted-foreground">Hostname match</p><p className="mt-2 text-[11px] font-semibold">{value(tls.certificate, "hostname_matching")}</p></div><div className="rounded-xl border border-border bg-background/35 p-3"><p className="text-[8px] uppercase tracking-[0.12em] text-muted-foreground">Expiry</p><p className={`mt-2 text-[11px] font-semibold ${tls.certificate?.expired === true || tls.certificate?.expires_soon === true ? "text-warning" : "text-positive"}`}>{value(tls.certificate, "validity_end")} {tls.certificate?.expired === true ? "· expired" : tls.certificate?.expires_soon === true ? "· soon" : ""}</p></div></div>
      <div className="grid gap-3 text-[10px] sm:grid-cols-2"><div className="rounded-xl border border-border bg-background/35 p-4"><p className="font-semibold">Certificate details</p>{tls.certificate ? <dl className="mt-3 space-y-2 text-muted-foreground"><div className="flex justify-between gap-4"><dt>Issuer</dt><dd className="max-w-[65%] text-right text-foreground">{value(tls.certificate, "issuer")}</dd></div><div className="flex justify-between gap-4"><dt>Key</dt><dd className="text-right text-foreground">{value(tls.certificate, "key_algorithm")} · {value(tls.certificate, "key_size")} bits</dd></div><div className="flex justify-between gap-4"><dt>Signature</dt><dd className="text-right text-foreground">{value(tls.certificate, "signature_algorithm")}</dd></div><div className="flex justify-between gap-4"><dt>Protocol</dt><dd className="text-right text-foreground">{value(tls.certificate, "tls_version")}</dd></div><div className="flex justify-between gap-4"><dt>Chain</dt><dd className="text-right text-foreground">{chainValue(tls.certificate)}</dd></div><div className="flex justify-between gap-4"><dt>CT source</dt><dd className="text-right text-foreground">{value((tls.certificate.certificate_transparency as Record<string, unknown> | undefined) ?? null, "source")}</dd></div></dl> : <p className="mt-3 text-muted-foreground">Certificate details are unavailable because the TLS handshake was not safely verified.</p>}</div><div className="rounded-xl border border-border bg-background/35 p-4"><p className="font-semibold">Security headers</p>{headers ? <ul className="mt-3 space-y-2">{Object.entries(headers.headers).map(([name, state]) => <li key={name} className="flex items-center justify-between gap-3 text-muted-foreground"><span>{name}</span><span className={state === "present" ? "text-positive" : "text-warning"}>{state === "present" ? <CheckCircle2 className="inline size-3.5" /> : <CircleAlert className="inline size-3.5" />} {state}</span></li>)}{headers.findings?.filter((item) => item.status !== "present").map((item) => <li key={`${item.header}-remediation`} className="border-t border-border pt-2 text-[9px] text-muted-foreground">{item.header}: {item.remediation}</li>)}</ul> : <p className="mt-3 text-muted-foreground">Header inspection unavailable.</p>}</div></div>
      <p className="text-[9px] leading-4 text-muted-foreground">Certificate metadata is observational. Revocation and Certificate Transparency were not claimed unless explicitly available from a configured source.</p>
    </div> : null}
  </Panel>;
}
