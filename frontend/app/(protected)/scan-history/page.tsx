import Link from "next/link";
import { Archive, ArrowUpRight, Fingerprint } from "lucide-react";
import { requireAuthenticatedUser } from "@/lib/supabase/require-user";
import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { EmptyState, ErrorNotice, PageHeading, Panel, ScanRow, type ScanSummary } from "@/components/dashboard/ui";

export default async function ScanHistoryPage() {
  const user = await requireAuthenticatedUser();
  let scans: ScanSummary[] = [];
  let unavailable = !getSupabaseEnvironmentStatus();

  if (!unavailable) {
    try {
      const supabase = await createSupabaseServerClient();
      const { data, error } = await supabase.from("scans").select("id,target,scan_type,status,risk_level,risk_score,summary,created_at").eq("user_id", user.id).order("created_at", { ascending: false }).limit(100);
      if (error) unavailable = true;
      else scans = (data ?? []) as ScanSummary[];
    } catch {
      unavailable = true;
    }
  }

  return (
    <>
      <PageHeading eyebrow="Investigations / Archive" title="Scan history" description="Your saved investigations, isolated to your signed-in account." action={<span className="inline-flex items-center gap-2 rounded-lg border border-border bg-panel px-3 py-2 text-[9px] text-muted-foreground"><Archive className="size-3.5" /> {unavailable ? "—" : scans.length} records</span>} />
      <Panel className="p-5 sm:p-6">
        <div className="mb-4 hidden grid-cols-[minmax(0,1fr)_100px_88px_80px] border-b border-border pb-3 text-[8px] font-semibold uppercase tracking-[0.12em] text-muted-foreground sm:grid"><span>Investigation</span><span>Status</span><span>Risk</span><span /></div>
        {unavailable ? <ErrorNotice detail="Scan history could not be loaded. Check your connection and try again." /> : scans.length ? <div>{scans.map((scan) => <ScanRow key={scan.id} scan={scan} />)}</div> : <EmptyState icon={Fingerprint} title="No saved investigations yet" detail="No URL scan records are available for this account." action={<Link href="/url-scanner" className="inline-flex items-center gap-1.5 text-[9px] font-semibold text-accent hover:text-foreground">Open URL scanner <ArrowUpRight className="size-3" /></Link>} />}
      </Panel>
      <p className="mt-3 text-[9px] leading-4 text-muted-foreground">Risk labels here come from stored scan records. An empty history is not a safety assessment of any website.</p>
    </>
  );
}
