import { Check, Clock3 } from "lucide-react";
import { Panel, PanelTitle, RiskBadge, formatDate } from "@/components/dashboard/ui";

export type FindingRecord = { id: string; category: string; title: string; description: string; severity: string; source: string; confidence: number; created_at: string };
export type TimelineEvent = { id: string; event_type: string; title: string; description: string; event_data?: Record<string, unknown>; occurred_at: string };

export function WebsiteIdentityAnalysis({ events }: { events: TimelineEvent[] }) {
  const evidence = events.find((event) => event.event_type === "domain_inspected")?.event_data ?? {};
  const host = typeof evidence.host === "string" ? evidence.host : null;
  const labelCount = typeof evidence.label_count === "number" ? evidence.label_count : null;
  const hasPunycode = typeof evidence.idn_punycode === "boolean" ? evidence.idn_punycode : null;

  return (
    <Panel id="website-identity" className="p-5 sm:p-6">
      <PanelTitle title="Website identity analysis" detail="Hostname structure recorded by this investigation" />
      <dl className="grid gap-3 sm:grid-cols-2">
        <IdentityValue label="Hostname" value={host ?? "No hostname evidence recorded"} />
        <IdentityValue label="Hostname labels" value={labelCount === null ? "Not available" : String(labelCount)} />
        <IdentityValue label="IDN punycode marker" value={hasPunycode === null ? "Not recorded" : hasPunycode ? "Observed" : "Not observed"} />
        <IdentityValue label="Registration age and owner" value="Not queried" />
      </dl>
      <p className="mt-4 rounded-lg border border-border bg-background/35 px-3 py-2.5 text-[9px] leading-4 text-muted-foreground">
        Hostname structure does not establish domain ownership or legitimacy. Registration data was not available to this scanner.
      </p>
    </Panel>
  );
}

export function TlsAnalysis({ target, events }: { target: string; events: TimelineEvent[] }) {
  const tlsEvents = events.filter((event) => event.event_type === "tls_inspected");
  const targetUsesHttps = target.toLowerCase().startsWith("https://");

  return (
    <Panel id="tls-analysis" className="p-5 sm:p-6">
      <PanelTitle title="TLS analysis" detail="Transport observations recorded during the scan" />
      {tlsEvents.length ? (
        <ul className="space-y-2">
          {tlsEvents.map((event) => {
            const host = typeof event.event_data?.host === "string" ? event.event_data.host : "Unknown host";
            return <li key={event.id} className="rounded-lg border border-border bg-background/35 p-3"><p className="text-[10px] font-medium">TLS handshake completed · {host}</p><p className="mt-1 text-[9px] leading-4 text-muted-foreground">The HTTPS connection completed its handshake. Certificate identity and expiry details were not collected.</p></li>;
          })}
        </ul>
      ) : (
        <p className="rounded-lg border border-dashed border-border p-4 text-[9px] leading-4 text-muted-foreground">
          {targetUsesHttps ? "No successful TLS handshake was recorded. TLS status is unknown." : "This target used HTTP; no TLS handshake was attempted."}
        </p>
      )}
      <p className="mt-4 text-[9px] leading-4 text-muted-foreground">TLS observations do not prove a website is safe.</p>
    </Panel>
  );
}

function IdentityValue({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0 rounded-lg border border-border bg-background/35 p-3"><dt className="text-[8px] uppercase tracking-[0.12em] text-muted-foreground">{label}</dt><dd className="mt-1 break-all text-[10px] font-medium">{value}</dd></div>;
}

export function FindingCards({ findings }: { findings: FindingRecord[] }) {
  return (
    <Panel className="p-5 sm:p-6"><PanelTitle title="Findings" detail="Evidence linked to this saved scan" />{findings.length ? <div className="space-y-3">{findings.map((finding) => <article key={finding.id} className="rounded-xl border border-border bg-background/35 p-4"><div className="flex flex-wrap items-center gap-2"><span className="text-[10px] font-semibold">{finding.title}</span><RiskBadge level={finding.severity} /></div><p className="mt-2 text-[9px] leading-4 text-muted-foreground">{finding.description}</p><div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[8px] text-muted-foreground"><span>Category · {finding.category}</span><span>Source · {finding.source}</span><span>Confidence · {Math.round(finding.confidence * 100)}%</span></div></article>)}</div> : <div className="rounded-xl border border-dashed border-border p-5 text-[9px] leading-4 text-muted-foreground">No findings are stored for this scan. This does not establish that the target is safe.</div>}</Panel>
  );
}

export function InvestigationTimeline({ events }: { events: TimelineEvent[] }) {
  return (
    <Panel className="p-5 sm:p-6"><PanelTitle title="Investigation timeline" detail="Events recorded by the scan service" />{events.length ? <ol className="space-y-0">{events.map((event, index) => <li key={event.id} className="relative flex gap-3 pb-5 last:pb-0"><span className="relative z-10 mt-0.5 grid size-6 shrink-0 place-items-center rounded-full border border-accent/15 bg-accent/[0.07] text-accent">{index === events.length - 1 ? <Check className="size-3" /> : <Clock3 className="size-3" />}</span>{index < events.length - 1 ? <span className="absolute bottom-0 left-3 top-6 w-px bg-border" /> : null}<div><p className="text-[10px] font-medium">{event.title}</p><p className="mt-1 text-[9px] leading-4 text-muted-foreground">{event.description}</p><p className="mt-1.5 text-[8px] text-muted-foreground">{formatDate(event.occurred_at)} · {event.event_type}</p></div></li>)}</ol> : <div className="rounded-xl border border-dashed border-border p-5 text-[9px] leading-4 text-muted-foreground">No timeline events are stored for this scan.</div>}</Panel>
  );
}
