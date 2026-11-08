import Link from "next/link";
import { Fingerprint } from "lucide-react";
import { requireAuthenticatedUser } from "@/lib/supabase/require-user";
import { PageHeading, Panel, PanelTitle } from "@/components/dashboard/ui";
import { TrustPassportManager } from "@/components/trust-passport-manager";

export default async function TrustPassportsPage() {
  await requireAuthenticatedUser();
  return <>
    <PageHeading eyebrow="Trust layer / Reports" title="Trust passports" description="Canonical report downloads and off-chain SHA-256 integrity verification. No wallet or blockchain connection is required." action={<Link href="/verify" className="rounded-lg border border-border px-3 py-1.5 text-[8px] font-semibold text-accent hover:border-accent/30">Public verification</Link>} />
    <Panel className="p-5 sm:p-6">
      <PanelTitle title="Report registry" detail="The backend stores the original canonical report and its digest. Verification re-hashes that snapshot; it does not claim protection from privileged database tampering." />
      <TrustPassportManager />
    </Panel>
    <div className="mt-4 flex items-start gap-3 rounded-xl border border-accent/10 bg-accent/[0.035] p-4"><span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent/[0.08] text-accent"><Fingerprint className="size-4" /></span><p className="pt-0.5 text-[9px] leading-4 text-muted-foreground">A passport attests to report integrity only. It does not prove that a website is safe, and it must not contain passwords, API keys, private messages, or sensitive data that does not belong in a scan report.</p></div>
    <p className="mt-4 rounded-xl border border-border bg-panel/50 p-3 text-[9px] text-muted-foreground">Part 9 is off-chain only. No blockchain registration, wallet, transaction, or chain confirmation is represented.</p>
  </>;
}
