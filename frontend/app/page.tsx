import { ArrowUpRight, Check, CircleDashed, Database, Fingerprint, Shield, ShieldCheck, Wifi } from "lucide-react";
import Link from "next/link";
import { getApiDocsUrl, getBackendHealth } from "@/services/api-client";
import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { StatusCard } from "@/components/status-card";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const [api, authConfigured] = await Promise.all([
    getBackendHealth(),
    Promise.resolve(getSupabaseEnvironmentStatus()),
  ]);

  const apiConnected = api.ok;
  const backendSupabaseConfigured = api.ok && api.data.supabase_configured;
  const scanPersistenceConfigured = api.ok && api.data.scan_persistence_configured === true;
  const readyCount = Number(apiConnected) + Number(authConfigured) + Number(backendSupabaseConfigured) + Number(scanPersistenceConfigured);

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-[1440px] flex-col px-5 sm:px-8 lg:px-12">
      <header className="flex h-[76px] items-center justify-between border-b border-border/80">
        <a href="#overview" className="group flex items-center gap-3" aria-label="THREATLENS home">
          <span className="grid size-9 place-items-center rounded-xl border border-accent/25 bg-accent/10 text-accent shadow-[0_0_28px_rgba(89,183,255,0.12)]">
            <Shield className="size-[18px]" aria-hidden="true" />
          </span>
          <span className="text-[13px] font-bold tracking-[0.2em] text-foreground">THREATLENS</span>
        </a>
        <div className="flex items-center gap-4">
          <div className="hidden items-center gap-3 rounded-full border border-border bg-panel/80 px-3.5 py-2 sm:flex">
            <span className="relative flex size-2">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-accent opacity-30" />
              <span className="relative inline-flex size-2 rounded-full bg-accent" />
            </span>
            <span className="text-[11px] font-medium tracking-wide text-muted-foreground">URL INVESTIGATION · LOCAL</span>
          </div>
          <Link href="/auth/login" className="text-xs font-medium text-muted-foreground transition hover:text-foreground">Sign in</Link>
          <Link href="/auth/sign-up" className="rounded-lg bg-accent px-3.5 py-2.5 text-xs font-semibold text-[#06111c] transition hover:bg-[#80cbff]">Create account</Link>
        </div>
      </header>

      <section id="overview" className="grid flex-1 content-center py-14 sm:py-20">
        <div className="mx-auto w-full max-w-5xl">
          <div className="mb-8 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
            <span className="h-px w-7 bg-accent/70" />
            Platform readiness
          </div>

          <div className="grid gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-end">
            <div>
              <h1 className="max-w-2xl text-4xl font-semibold leading-[1.12] tracking-[-0.045em] sm:text-6xl">
                Trust, made <span className="text-accent">observable.</span>
              </h1>
              <p className="mt-5 max-w-xl text-base leading-7 text-muted-foreground sm:text-lg">
                Your threat intelligence workspace connects URL investigations with account-scoped evidence and clear risk explanations.
              </p>
            </div>
            <div className="rounded-2xl border border-border bg-panel/70 p-5 sm:p-6">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-xs font-medium text-muted-foreground">READY CHECKS</p>
                  <p className="mt-2 text-3xl font-semibold tracking-tight">{readyCount}<span className="text-muted-foreground"> / 4</span></p>
                </div>
                <div className="grid size-12 place-items-center rounded-xl bg-accent/10 text-accent">
                  {readyCount === 4 ? <ShieldCheck className="size-6" aria-hidden="true" /> : <CircleDashed className="size-6" aria-hidden="true" />}
                </div>
              </div>
              <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-panel-raised">
                <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${(readyCount / 4) * 100}%` }} />
              </div>
              <p className="mt-3 text-xs text-muted-foreground">
                {readyCount === 4 ? "FastAPI, Supabase Auth, and secure scan persistence are configured." : "Finish the backend credentials and scan storage setup."}
              </p>
            </div>
          </div>

          <div className="mt-12 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <StatusCard
              icon={<Wifi className="size-[18px]" aria-hidden="true" />}
              title="FastAPI"
              detail={api.ok ? `Health check succeeded · ${api.data.service}` : api.error}
              status={api.ok ? "online" : "offline"}
              statusLabel={api.ok ? "Connected" : "Unavailable"}
            />
            <StatusCard
              icon={<Fingerprint className="size-[18px]" aria-hidden="true" />}
              title="Supabase Auth"
              detail={authConfigured ? "Frontend Auth client credentials are present." : "Add the project URL and publishable key to frontend/.env.local."}
              status={authConfigured ? "ready" : "setup"}
              statusLabel={authConfigured ? "Configured" : "Needs setup"}
            />
            <StatusCard
              icon={<Database className="size-[18px]" aria-hidden="true" />}
              title="Supabase API"
              detail={backendSupabaseConfigured ? "Backend Supabase public credentials are present." : "Add the project URL and publishable key to backend/.env."}
              status={backendSupabaseConfigured ? "ready" : "setup"}
              statusLabel={backendSupabaseConfigured ? "Configured" : "Needs setup"}
            />
            <StatusCard
              icon={<Database className="size-[18px]" aria-hidden="true" />}
              title="URL scan storage"
              detail={scanPersistenceConfigured ? "Backend-only database access is ready for scan records." : "Add SUPABASE_SECRET_KEY to backend/.env to enable secure scan writes."}
              status={scanPersistenceConfigured ? "ready" : "setup"}
              statusLabel={scanPersistenceConfigured ? "Configured" : "Needs setup"}
            />
          </div>

          <div className="mt-7 flex flex-col gap-4 rounded-xl border border-border/80 bg-panel/80 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-5">
            <div className="flex items-start gap-3">
              <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-lg bg-accent/10 text-accent">
                <Check className="size-4" aria-hidden="true" />
              </span>
              <div>
                <p className="text-sm font-medium">URL investigation is ready to connect</p>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">URL scans use bounded network inspection and save evidence to your account. Message and QR analysis are still preview-only.</p>
              </div>
            </div>
            <a className="inline-flex shrink-0 items-center gap-2 text-xs font-semibold text-accent transition hover:text-foreground" href={getApiDocsUrl()} target="_blank" rel="noreferrer">
              Open API docs <ArrowUpRight className="size-3.5" aria-hidden="true" />
            </a>
          </div>
        </div>
      </section>

      <footer className="flex min-h-14 items-center justify-between border-t border-border/70 text-[11px] text-muted-foreground">
        <span>THREATLENS · TRUST INTELLIGENCE</span>
        <span>URL SCAN BUILD</span>
      </footer>
    </main>
  );
}

