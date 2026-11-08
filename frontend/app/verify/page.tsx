import Link from "next/link";
import { ArrowLeft, ShieldCheck } from "lucide-react";
import { PageHeading, Panel, PanelTitle } from "@/components/dashboard/ui";
import { PublicPassportVerifier } from "@/components/public-passport-verifier";

export default function PublicVerificationPage() {
  return (
    <main className="mx-auto min-h-screen w-full max-w-5xl px-5 py-10 sm:px-8 sm:py-14">
      <PageHeading
        eyebrow="Trust passport / Public verification"
        title="Public report verification"
        description="Use an owner-created share token to verify report integrity metadata. Private scan evidence is never disclosed here."
        action={<span className="rounded-full border border-accent/20 bg-accent/[0.06] px-3 py-1.5 text-[8px] font-semibold uppercase tracking-[0.11em] text-accent">Public metadata only</span>}
      />
      <Panel className="mt-6 p-5 sm:p-7">
        <PanelTitle title="Public verification" detail="The passport owner creates a revocable share link. Public checks return only the report hash, version, and integrity status." />
        <PublicPassportVerifier />
        <div className="mt-5 flex items-center gap-2 text-[9px] text-muted-foreground"><ShieldCheck className="size-4 text-accent" /> Public verification never certifies that a website is safe.</div>
        <Link href="/" className="mt-4 inline-flex items-center gap-2 text-[9px] font-semibold text-accent hover:text-foreground"><ArrowLeft className="size-3" /> Return to THREATLENS</Link>
      </Panel>
    </main>
  );
}
