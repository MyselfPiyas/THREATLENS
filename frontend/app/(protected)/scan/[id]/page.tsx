import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ExternalLink, FileText } from "lucide-react";
import { requireAuthenticatedUser } from "@/lib/supabase/require-user";
import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { ErrorNotice, PageHeading, Panel, PanelTitle, RiskBadge, ScoreIndicator, formatDate } from "@/components/dashboard/ui";
import { FindingCards, InvestigationTimeline, TlsAnalysis, WebsiteIdentityAnalysis, type FindingRecord, type TimelineEvent } from "@/components/dashboard/investigation-sections";
import { IdentityPanel } from "@/components/dashboard/identity-panel";
import { TlsSecurityPanel } from "@/components/dashboard/tls-security-panel";

export default async function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const user = await requireAuthenticatedUser();
  const { id } = await params;
  if (!getSupabaseEnvironmentStatus()) return <main><PageHeading eyebrow="Investigation / Details" title="Investigation unavailable" description="Database configuration is missing." /></main>;

  let scan: { id: string; target: string; normalized_target: string; scan_type: string; status: string; risk_level: string; risk_score: number; summary: string; started_at: string; completed_at: string | null; created_at: string } | null = null;
  let findings: FindingRecord[] = [];
  let events: TimelineEvent[] = [];
  let unavailable = false;
  try {
    const supabase = await createSupabaseServerClient();
    const result = await supabase.from("scans").select("id,user_id,target,normalized_target,scan_type,status,risk_level,risk_score,summary,started_at,completed_at,created_at").eq("id", id).eq("user_id", user.id).maybeSingle();
    if (result.error) unavailable = true;
    else if (!result.data) notFound();
    else {
      scan = result.data;
      const [findingResult, eventResult] = await Promise.all([
        supabase.from("scan_findings").select("id,category,title,description,severity,source,confidence,created_at").eq("scan_id", id).order("created_at", { ascending: false }),
        supabase.from("scan_events").select("id,event_type,title,description,event_data,occurred_at").eq("scan_id", id).order("occurred_at", { ascending: true }),
      ]);
      if (findingResult.error || eventResult.error) unavailable = true;
      else {
        findings = (findingResult.data ?? []) as FindingRecord[];
        events = (eventResult.data ?? []) as TimelineEvent[];
      }
    }
  } catch {
    unavailable = true;
  }

  if (!scan) return <><PageHeading eyebrow="Investigation / Details" title="Investigation unavailable" description="The record could not be loaded." />{unavailable ? <ErrorNotice detail="Try again after confirming the database connection." /> : null}</>;

  return (
    <>
      <PageHeading eyebrow={`Investigation / ${scan.scan_type}`} title={scan.target} description={scan.summary || "No summary was saved with this record."} action={<Link href="/scan-history" className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-panel px-3 text-[9px] font-semibold text-muted-foreground transition hover:text-foreground"><ArrowLeft className="size-3.5" /> History</Link>} />
      {unavailable ? <div className="mb-4"><ErrorNotice detail="Some investigation details could not be loaded. The scan record is shown without the missing sections." /></div> : null}
      <div className="grid gap-4 md:grid-cols-3">
        <Panel className="p-4"><p className="text-[9px] uppercase tracking-[0.12em] text-muted-foreground">Recorded risk level</p><div className="mt-3"><RiskBadge level={scan.risk_level} /></div><p className="mt-2 text-[8px] text-muted-foreground">This value reflects the stored scan record.</p></Panel>
        <Panel className="p-4"><p className="text-[9px] uppercase tracking-[0.12em] text-muted-foreground">Risk score</p><div className="mt-3"><ScoreIndicator score={scan.risk_score} /></div><p className="mt-2 text-[8px] text-muted-foreground">Score recorded by the scan service.</p></Panel>
        <Panel className="p-4"><p className="text-[9px] uppercase tracking-[0.12em] text-muted-foreground">Investigation status</p><p className="mt-3 text-[13px] font-semibold capitalize">{scan.status}</p><p className="mt-2 text-[8px] text-muted-foreground">Created {formatDate(scan.created_at)}</p></Panel>
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <FindingCards findings={findings} />
        <InvestigationTimeline events={events} />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <WebsiteIdentityAnalysis events={events} />
        <TlsAnalysis target={scan.normalized_target} events={events} />
      </div>
      <div className="mt-4"><IdentityPanel url={scan.normalized_target} scanId={scan.id} /></div>
      <TlsSecurityPanel url={scan.normalized_target} scanId={scan.id} />
      <Panel className="mt-4 p-5"><PanelTitle title="Target metadata" detail="Stored target strings from the scan record" /><div className="grid gap-3 text-[9px] sm:grid-cols-2"><div><p className="text-muted-foreground">Submitted target</p><p className="mt-1 break-all font-mono">{scan.target}</p></div><div><p className="text-muted-foreground">Normalized target</p><p className="mt-1 break-all font-mono">{scan.normalized_target}</p></div><div><p className="text-muted-foreground">Started</p><p className="mt-1">{formatDate(scan.started_at)}</p></div><div><p className="text-muted-foreground">Completed</p><p className="mt-1">{scan.completed_at ? formatDate(scan.completed_at) : "Not recorded"}</p></div></div><div className="mt-4 flex items-center gap-2 text-[8px] text-muted-foreground"><FileText className="size-3.5" /> Record ID · {scan.id}<ExternalLink className="ml-auto size-3" /></div></Panel>
    </>
  );
}
