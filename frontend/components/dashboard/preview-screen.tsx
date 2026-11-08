import Link from "next/link";
import { Activity, CircleDot, Fingerprint, Globe2, Network, Radar, ShieldCheck, Sparkles, type LucideIcon } from "lucide-react";
import { DemoTag, EmptyState, PageHeading, Panel, PanelTitle } from "@/components/dashboard/ui";

export function ThreatIntelligenceScreen() {
  return (
    <>
      <PageHeading eyebrow="Intelligence / Threat feeds" title="Threat intelligence" description="A source-aware view of indicators and emerging threats. Feed ingestion is not connected in this build." action={<DemoTag />} />
      <div className="grid gap-4 md:grid-cols-3">
        {[{ label: "Active sources", value: "—", icon: Radar }, { label: "Indicators indexed", value: "—", icon: CircleDot }, { label: "Updated", value: "—", icon: Activity }].map((item) => <div key={item.label} className="rounded-xl border border-border bg-panel/75 p-5"><div className="flex items-center justify-between text-[10px] text-muted-foreground"><span>{item.label}</span><item.icon className="size-4 text-accent" /></div><p className="mt-4 text-2xl font-semibold">{item.value}</p><p className="mt-1 text-[9px] text-muted-foreground">No live threat feed is connected</p></div>)}
      </div>
      <Panel className="mt-4 p-5 sm:p-6"><PanelTitle title="Indicator explorer" detail="Results will include source, confidence, and last-seen timestamps." /><EmptyState icon={Radar} title="No intelligence sources connected" detail="No indicators are available yet. This screen will populate from controlled backend feeds; no sample threat indicators are being shown." /></Panel>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <InfoCard icon={ShieldCheck} title="Source provenance" detail="Each future indicator will show where it came from and how confidence was assigned." />
        <InfoCard icon={Sparkles} title="Freshness signals" detail="Indicator recency and source status will be visible when feed ingestion is enabled." />
      </div>
    </>
  );
}

export function ScamDnaScreen() {
  return (
    <>
      <PageHeading eyebrow="Intelligence / Scam DNA" title="Scam DNA" description="Explore shared patterns across investigated targets. Pattern matching is not connected yet." action={<DemoTag />} />
      <Panel className="dashboard-grid overflow-hidden p-5 sm:p-8">
        <div className="mx-auto max-w-xl py-5 text-center">
          <span className="mx-auto grid size-14 place-items-center rounded-2xl border border-accent/20 bg-accent/[0.08] text-accent"><Fingerprint className="size-6" /></span>
          <h2 className="mt-4 text-[15px] font-semibold">Build an evidence-backed pattern map</h2>
          <p className="mx-auto mt-2 max-w-md text-[10px] leading-5 text-muted-foreground">Related indicators, infrastructure, and message patterns will be grouped here after real investigations exist. No synthetic clusters are displayed.</p>
          <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-warning/20 bg-warning/[0.06] px-3 py-1.5 text-[8px] font-semibold uppercase tracking-[0.12em] text-warning"><CircleDot className="size-3" /> Waiting for scan data</div>
        </div>
      </Panel>
      <div className="mt-4 grid gap-4 md:grid-cols-3">
        {[{ title: "Infrastructure links", detail: "Domains and hosting indicators grouped with evidence.", icon: Network }, { title: "Campaign patterns", detail: "Shared language and themes from analyzed content.", icon: Sparkles }, { title: "Confidence trail", detail: "How related entities were connected and assessed.", icon: ShieldCheck }].map((item) => <div key={item.title} className="rounded-xl border border-border bg-panel/75 p-5"><item.icon className="size-4 text-accent" /><h3 className="mt-4 text-[11px] font-semibold">{item.title}</h3><p className="mt-1.5 text-[9px] leading-4 text-muted-foreground">{item.detail}</p></div>)}
      </div>
    </>
  );
}

export function SettingsScreen() {
  return (
    <>
      <PageHeading eyebrow="Workspace / Preferences" title="Settings" description="Workspace preferences and connected service status." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(280px,0.72fr)]">
        <Panel className="p-5 sm:p-6"><PanelTitle title="Workspace preferences" detail="These controls are presented as a preview and do not change account settings." />
          <div className="divide-y divide-border/80">
            {[{ title: "Investigation notifications", detail: "Receive an alert when a saved investigation is ready.", state: "Not configured" }, { title: "Report retention", detail: "Retention policy for stored scan reports.", state: "Managed by workspace" }, { title: "Default scan visibility", detail: "Your scans are scoped to your signed-in account by database policies.", state: "Private" }].map((item) => <div key={item.title} className="flex flex-col gap-3 py-4 first:pt-0 sm:flex-row sm:items-center sm:justify-between"><div><p className="text-[11px] font-medium">{item.title}</p><p className="mt-1 text-[9px] leading-4 text-muted-foreground">{item.detail}</p></div><span className="w-fit rounded-full border border-border bg-background/60 px-2.5 py-1 text-[8px] font-medium text-muted-foreground">{item.state}</span></div>)}
          </div>
        </Panel>
        <Panel className="p-5 sm:p-6"><PanelTitle title="Connected services" detail="Readiness for this workspace" />
          <div className="space-y-3">{[{ title: "Supabase Auth", state: "Connected", icon: ShieldCheck, color: "text-positive" }, { title: "Scan service", state: "Not connected", icon: Globe2, color: "text-warning" }, { title: "Threat feeds", state: "Not connected", icon: Radar, color: "text-warning" }].map((item) => <div key={item.title} className="flex items-center gap-3 rounded-lg border border-border/80 bg-background/35 p-3"><item.icon className={`size-4 ${item.color}`} /><span className="flex-1 text-[10px] font-medium">{item.title}</span><span className={`text-[8px] ${item.color}`}>{item.state}</span></div>)}</div>
        </Panel>
      </div>
      <div className="mt-4"><p className="text-[9px] text-muted-foreground">For your profile details, use <Link href="/profile" className="font-semibold text-accent hover:text-foreground">account profile</Link>.</p></div>
    </>
  );
}

function InfoCard({ icon: Icon, title, detail }: { icon: LucideIcon; title: string; detail: string }) {
  return <div className="rounded-xl border border-border bg-panel/70 p-5"><Icon className="size-4 text-accent" /><h3 className="mt-3 text-[11px] font-semibold">{title}</h3><p className="mt-1.5 text-[9px] leading-4 text-muted-foreground">{detail}</p></div>;
}
