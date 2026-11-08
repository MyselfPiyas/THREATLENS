import Link from "next/link";
import { Activity, ArrowRight, ArrowUpRight, CircleAlert, Fingerprint, Globe2, MessageSquareText, QrCode, ScanSearch, ShieldCheck, Sparkles, type LucideIcon } from "lucide-react";
import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { requireAuthenticatedUser } from "@/lib/supabase/require-user";
import { ActionLink, DemoTag, EmptyState, ErrorNotice, PageHeading, Panel, PanelTitle, ScanRow, type ScanSummary } from "@/components/dashboard/ui";
import { QuickScanBox } from "@/components/dashboard/quick-scan-box";
import { DEMO_RISK_DISTRIBUTION } from "@/lib/demo/dashboard-demo";

function Metric({ title, value, note, icon: Icon, tone = "blue" }: { title: string; value: string; note: string; icon: LucideIcon; tone?: "blue" | "orange" | "red" | "green" | "neutral" }) {
  const tones = { blue: "bg-accent/10 text-accent", orange: "bg-warning/10 text-warning", red: "bg-negative/10 text-negative", green: "bg-positive/10 text-positive", neutral: "bg-panel-raised text-muted-foreground" };
  return <div className="glass-panel glass-interactive rounded-xl border border-border/90 bg-panel/75 p-4 sm:p-5"><div className="flex items-start justify-between gap-2"><span className="text-[10px] font-medium text-muted-foreground">{title}</span><span className={`grid size-8 place-items-center rounded-lg ${tones[tone]}`}><Icon className="size-4" /></span></div><p className="mt-4 text-[26px] font-semibold tracking-[-0.04em] tabular-nums">{value}</p><p className="mt-1 text-[9px] leading-4 text-muted-foreground">{note}</p></div>;
}

export default async function DashboardPage() {
  const user = await requireAuthenticatedUser();
  let recentScans: ScanSummary[] = [];
  let totalScans = 0;
  let highRiskCount = 0;
  let suspiciousUrlCount = 0;
  let confirmedMaliciousCount = 0;
  let dataUnavailable = !getSupabaseEnvironmentStatus();

  if (!dataUnavailable) {
    try {
      const supabase = await createSupabaseServerClient();
      const [total, high, suspicious, confirmed, recent] = await Promise.all([
        supabase.from("scans").select("id", { count: "exact", head: true }).eq("user_id", user.id),
        supabase.from("scans").select("id", { count: "exact", head: true }).eq("user_id", user.id).in("risk_level", ["high", "critical", "HIGH_RISK", "CONFIRMED_MALICIOUS"]),
        supabase.from("scans").select("id", { count: "exact", head: true }).eq("user_id", user.id).eq("scan_type", "url").in("risk_level", ["medium", "high", "critical", "SUSPICIOUS", "HIGH_RISK", "CONFIRMED_MALICIOUS"]),
        supabase.from("scans").select("id", { count: "exact", head: true }).eq("user_id", user.id).eq("risk_level", "CONFIRMED_MALICIOUS"),
        supabase.from("scans").select("id,target,scan_type,status,risk_level,risk_score,summary,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(6),
      ]);
      if (total.error || high.error || suspicious.error || confirmed.error || recent.error) {
        dataUnavailable = true;
      } else {
        totalScans = total.count ?? 0;
        highRiskCount = high.count ?? 0;
        suspiciousUrlCount = suspicious.count ?? 0;
        confirmedMaliciousCount = confirmed.count ?? 0;
        recentScans = (recent.data ?? []) as ScanSummary[];
      }
    } catch {
      dataUnavailable = true;
    }
  }

  return (
    <div className="animate-rise-in">
      <PageHeading eyebrow="Security workspace / Overview" title="Good to see you." description="A focused view of your investigation activity and trust signals." action={<span className="inline-flex items-center gap-2 rounded-full border border-positive/15 bg-positive/[0.05] px-3 py-2 text-[9px] font-medium text-positive"><span className="size-1.5 rounded-full bg-positive" /> Account protected</span>} />

      {dataUnavailable ? <div className="mb-5"><ErrorNotice detail="Your scan records could not be loaded. Metrics are shown as unavailable; no security verdicts are inferred." /></div> : null}

      <section aria-label="Scan metrics" className="grid grid-cols-2 gap-3 xl:grid-cols-4 xl:gap-4">
        <Metric title="Total scans" value={dataUnavailable ? "—" : String(totalScans)} note="Your stored investigations" icon={ScanSearch} tone="blue" />
        <Metric title="High-risk detections" value={dataUnavailable ? "—" : String(highRiskCount)} note="Recorded as high or critical" icon={CircleAlert} tone="red" />
        <Metric title="Suspicious websites" value={dataUnavailable ? "—" : String(suspiciousUrlCount)} note="URL scans marked medium or above" icon={Globe2} tone="orange" />
        <Metric title="Confirmed malicious" value={dataUnavailable ? "—" : String(confirmedMaliciousCount)} note="Trusted high-confidence feed match" icon={ShieldCheck} tone={confirmedMaliciousCount ? "red" : "neutral"} />
      </section>

      <section className="mt-5 grid gap-4 xl:grid-cols-[minmax(0,1.45fr)_minmax(300px,0.75fr)]">
        <Panel className="dashboard-grid relative overflow-hidden p-5 sm:p-6">
          <div className="absolute -right-16 -top-24 size-64 rounded-full bg-accent/[0.035] blur-3xl" />
          <div className="relative"><div className="flex items-start justify-between gap-3"><div><p className="text-[9px] font-semibold uppercase tracking-[0.16em] text-accent">Start an investigation</p><h2 className="mt-2 text-[16px] font-semibold tracking-tight">Check a link before you trust it</h2><p className="mt-1.5 text-[10px] leading-4 text-muted-foreground">Run a bounded URL inspection and review its saved evidence.</p></div><span className="grid size-10 place-items-center rounded-xl border border-accent/15 bg-accent/[0.08] text-accent"><Globe2 className="size-5" /></span></div><QuickScanBox /></div>
        </Panel>

        <Panel className="p-5 sm:p-6">
          <PanelTitle title="Scan categories" detail="Choose an investigation workspace" />
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Website", href: "/url-scanner", icon: Globe2 },
              { label: "Message", href: "/message-analyzer", icon: MessageSquareText },
              { label: "QR code", href: "/qr-scanner", icon: QrCode },
            ].map(({ label, href, icon: Icon }) => <Link key={href} href={href} className="group flex min-h-[78px] flex-col justify-between rounded-lg border border-border bg-background/40 p-3 transition hover:border-accent/25 hover:bg-accent/[0.04]"><Icon className="size-4 text-muted-foreground transition group-hover:text-accent" /><span className="flex items-center justify-between text-[9px] font-medium">{label}<ArrowUpRight className="size-3 text-muted-foreground group-hover:text-accent" /></span></Link>)}
          </div>
          <div className="mt-3 rounded-lg border border-warning/15 bg-warning/[0.035] px-3 py-2.5 text-[9px] leading-4 text-muted-foreground"><span className="font-semibold text-warning">URL scan workflow implemented.</span> Live results need backend Supabase write access. Message and QR analysis remain preview only.</div>
        </Panel>
      </section>

      <section className="mt-5 grid gap-4 xl:grid-cols-2">
        <Panel className="p-5 sm:p-6">
          <PanelTitle title="Risk distribution" detail="Illustrative chart for visual preview" action={<DemoTag />} />
          <div className="rounded-lg border border-warning/10 bg-warning/[0.025] px-3 py-2 text-[9px] leading-4 text-warning">Demo visualization only · these values are not scan results.</div>
          <div className="mt-5 space-y-3.5" aria-label="Illustrative demo distribution">
            {DEMO_RISK_DISTRIBUTION.map((item) => <div key={item.label} className="grid grid-cols-[72px_1fr_28px] items-center gap-3"><span className="text-[9px] text-muted-foreground">{item.label}</span><div className="h-1.5 overflow-hidden rounded-full bg-panel-raised"><div className={`h-full rounded-full ${item.color}`} style={{ width: `${item.value}%` }} /></div><span className="text-right text-[9px] tabular-nums text-muted-foreground">{item.value}%</span></div>)}
          </div>
          <p className="mt-4 text-[8px] text-muted-foreground">Example proportions are decorative and do not represent Threatlens activity.</p>
        </Panel>

        <Panel className="p-5 sm:p-6">
          <PanelTitle title="Recent investigations" detail="Private to your account" action={<ActionLink href="/scan-history">View history</ActionLink>} />
          {dataUnavailable ? <ErrorNotice detail="History is temporarily unavailable. Retry later to reload your account records." /> : recentScans.length ? <div>{recentScans.map((scan) => <ScanRow key={scan.id} scan={scan} />)}</div> : <EmptyState icon={Fingerprint} title="Your investigation history is empty" detail="Completed and queued URL scans will appear here. No sample findings are shown." action={<Link href="/url-scanner" className="inline-flex items-center gap-1.5 text-[9px] font-semibold text-accent hover:text-foreground">Open URL scanner <ArrowRight className="size-3" /></Link>} />}
        </Panel>
      </section>

      <section className="mt-5 grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(300px,0.75fr)]">
        <Panel className="p-5 sm:p-6">
          <PanelTitle title="Recent threat activity" detail="Evidence-backed activity from your saved investigations" />
          <EmptyState icon={Activity} title="No threat activity recorded" detail="This area will show real scan events once scanner services are connected. It does not display sample detections." />
        </Panel>
        <Panel className="relative overflow-hidden p-5 sm:p-6">
          <div className="absolute -right-8 -top-9 size-36 rounded-full bg-accent/[0.06] blur-2xl" />
          <div className="relative flex items-start gap-3"><span className="grid size-9 place-items-center rounded-xl border border-accent/15 bg-accent/[0.08] text-accent"><Sparkles className="size-4" /></span><div><p className="text-[12px] font-semibold">Your trust workspace</p><p className="mt-1.5 text-[10px] leading-4 text-muted-foreground">Investigation history stays scoped to your authenticated account. Scanner verdicts and threat feeds will appear when those services are connected.</p></div></div>
          <div className="mt-5 flex flex-wrap gap-2"><span className="rounded-full border border-positive/15 bg-positive/[0.04] px-2.5 py-1 text-[8px] text-positive">Account scoped</span><span className="rounded-full border border-border bg-background/40 px-2.5 py-1 text-[8px] text-muted-foreground">No mock findings</span><span className="rounded-full border border-border bg-background/40 px-2.5 py-1 text-[8px] text-muted-foreground">Evidence first</span></div>
          <Link href="/settings" className="mt-5 inline-flex items-center gap-1.5 text-[9px] font-semibold text-accent hover:text-foreground">Review workspace settings <ArrowRight className="size-3" /></Link>
        </Panel>
      </section>
    </div>
  );
}
