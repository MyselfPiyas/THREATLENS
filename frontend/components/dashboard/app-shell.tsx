"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import {
  Archive, ChevronDown, ChevronLeft, Fingerprint,
  Globe2, LayoutDashboard, Menu, QrCode, ScanLine, Settings2, Shield,
  ShieldAlert, Sparkles, UserRound, X, LogOut,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { signOutAction } from "@/app/auth/actions";
import { getBackendHealth } from "@/services/api-client";

const navigation: Array<{ label: string; href: string; icon: LucideIcon; soon?: boolean }> = [
  { label: "Overview", href: "/dashboard", icon: LayoutDashboard },
  { label: "URL Scanner", href: "/url-scanner", icon: Globe2 },
  { label: "Message Analyzer", href: "/message-analyzer", icon: ScanLine },
  { label: "QR Scanner", href: "/qr-scanner", icon: QrCode },
  { label: "Threat Intelligence", href: "/threat-intelligence", icon: ShieldAlert },
  { label: "Scam DNA", href: "/scam-dna", icon: Fingerprint },
  { label: "Trust Passports", href: "/trust-passports", icon: Shield },
  { label: "Scan History", href: "/scan-history", icon: Archive },
  { label: "Settings", href: "/settings", icon: Settings2 },
];

function SidebarContent({ pathname, close, scanStorageReady }: { pathname: string; close?: () => void; scanStorageReady: boolean | null }) {
  return (
    <>
      <Link href="/dashboard" onClick={close} className="flex items-center gap-3 px-2 py-1.5">
        <span className="grid size-9 place-items-center rounded-xl border border-accent/20 bg-accent/10 text-accent shadow-[0_0_24px_rgba(89,183,255,0.1)]">
          <Shield className="size-[18px]" aria-hidden="true" />
        </span>
        <span>
          <span className="block text-[12px] font-bold tracking-[0.19em]">THREATLENS</span>
          <span className="mt-0.5 block text-[9px] font-medium uppercase tracking-[0.17em] text-muted-foreground">Trust intelligence</span>
        </span>
      </Link>

      <div className="mt-9 px-3 text-[9px] font-semibold uppercase tracking-[0.2em] text-muted-foreground/75">Workspace</div>
      <nav aria-label="Main navigation" className="mt-2 space-y-1">
        {navigation.map(({ label, href, icon: Icon, soon }) => {
          const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(`${href}/`));
          return (
            <Link
              key={href}
              href={href}
              onClick={close}
              aria-current={active ? "page" : undefined}
              className={`group flex min-h-10 items-center gap-3 rounded-lg border px-3 text-[12px] font-medium transition ${active ? "border-accent/15 bg-accent/[0.09] text-foreground shadow-[inset_2px_0_0_#59b7ff]" : "border-transparent text-muted-foreground hover:border-border/70 hover:bg-panel-raised/60 hover:text-foreground"}`}
            >
              <Icon className={`size-4 shrink-0 ${active ? "text-accent" : "text-muted-foreground group-hover:text-foreground"}`} strokeWidth={1.8} aria-hidden="true" />
              <span className="flex-1">{label}</span>
              {soon ? <span className="rounded border border-border px-1.5 py-0.5 text-[8px] uppercase tracking-wide text-muted-foreground">Preview</span> : null}
            </Link>
          );
        })}
      </nav>

      <div className="mt-auto pt-8">
        <div className="rounded-xl border border-accent/10 bg-gradient-to-br from-accent/[0.08] to-transparent p-3.5">
          <div className="flex items-center gap-2 text-[11px] font-semibold"><Sparkles className="size-3.5 text-accent" /> Workspace status</div>
          <p className="mt-2 text-[10px] leading-4 text-muted-foreground">URL, message, and QR analyses use bounded backend workflows when storage is available.</p>
          <div role="status" aria-live="polite" className={`mt-3 flex items-center gap-2 text-[9px] font-medium ${scanStorageReady === true ? "text-positive" : scanStorageReady === false ? "text-warning" : "text-muted-foreground"}`}>
            <span className={`size-1.5 rounded-full ${scanStorageReady === true ? "bg-positive" : scanStorageReady === false ? "bg-warning" : "bg-muted-foreground"}`} />
            {scanStorageReady === true ? "Secure scan storage ready" : scanStorageReady === false ? "Scan storage unavailable" : "Checking scan storage…"}
          </div>
        </div>
        <Link href="/profile" onClick={close} className="mt-4 flex items-center gap-3 rounded-xl border border-border/80 bg-background/40 p-3 transition hover:bg-panel-raised">
          <span className="grid size-8 place-items-center rounded-full border border-border bg-panel-raised text-muted-foreground"><UserRound className="size-4" /></span>
          <span className="min-w-0 flex-1"><span className="block text-[11px] font-semibold">My account</span><span className="mt-0.5 block text-[9px] text-muted-foreground">Profile & security</span></span>
          <ChevronDown className="size-3.5 text-muted-foreground" />
        </Link>
        <form action={signOutAction} className="mt-2 lg:hidden">
          <button type="submit" className="flex h-10 w-full items-center gap-3 rounded-lg px-3 text-[11px] font-medium text-muted-foreground transition hover:bg-panel-raised hover:text-foreground"><LogOut className="size-4" /> Sign out</button>
        </form>
      </div>
    </>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scanStorageReady, setScanStorageReady] = useState<boolean | null>(null);
  const title = navigation.find((item) => item.href === pathname)?.label ?? (pathname.startsWith("/scan/") ? "Investigation detail" : "Workspace");

  useEffect(() => {
    let active = true;
    void getBackendHealth().then((result) => {
      if (active) setScanStorageReady(result.ok && result.data.scan_persistence_configured === true);
    });
    return () => { active = false; };
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="glass-panel fixed inset-y-0 left-0 z-30 hidden w-[248px] flex-col overflow-y-auto border-r border-border/80 px-4 py-5 lg:flex">
        <SidebarContent pathname={pathname} scanStorageReady={scanStorageReady} />
      </aside>

      {mobileOpen ? (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button className="absolute inset-0 bg-black/65" aria-label="Close navigation menu" onClick={() => setMobileOpen(false)} />
          <aside className="glass-panel absolute inset-y-0 left-0 flex w-[min(84vw,290px)] flex-col overflow-y-auto border-r border-border px-4 py-5 shadow-2xl">
            <button className="mb-5 ml-auto grid size-9 place-items-center rounded-lg border border-border text-muted-foreground" aria-label="Close menu" onClick={() => setMobileOpen(false)}><X className="size-4" /></button>
            <SidebarContent pathname={pathname} scanStorageReady={scanStorageReady} close={() => setMobileOpen(false)} />
          </aside>
        </div>
      ) : null}

      <div className="min-h-screen lg:pl-[248px]">
        <header className="glass-panel sticky top-0 z-20 flex h-[66px] items-center justify-between border-b border-border/80 bg-background/75 px-4 backdrop-blur-xl sm:px-7 lg:px-9">
          <div className="flex min-w-0 items-center gap-3">
            <button onClick={() => setMobileOpen(true)} className="grid size-9 shrink-0 place-items-center rounded-lg border border-border text-muted-foreground lg:hidden" aria-label="Open navigation menu"><Menu className="size-4" /></button>
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground"><span className="hidden sm:inline">THREATLENS</span><ChevronLeft className="hidden size-3 rotate-180 sm:block" /><span className="truncate text-foreground">{title}</span></div>
              <div className="mt-1 hidden items-center gap-1.5 text-[9px] font-medium uppercase tracking-[0.12em] text-muted-foreground sm:flex"><span className="size-1.5 rounded-full bg-positive" /> Private workspace</div>
            </div>
          </div>
          <div className="flex items-center gap-2 sm:gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-border bg-panel/70 px-3 py-1.5 text-[9px] font-medium text-muted-foreground md:inline-flex"><span className="size-1.5 rounded-full bg-positive" /> Account protected</span>
            <Link href="/profile" aria-label="Open profile" className="grid size-9 place-items-center rounded-lg border border-border bg-panel/60 text-muted-foreground transition hover:text-foreground"><UserRound className="size-4" /></Link>
            <form action={signOutAction}>
              <button type="submit" className="hidden h-9 items-center gap-2 rounded-lg border border-border px-3 text-[10px] font-medium text-muted-foreground transition hover:bg-panel-raised hover:text-foreground sm:inline-flex"><LogOut className="size-3.5" /> Sign out</button>
            </form>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1560px] px-4 py-6 sm:px-7 sm:py-8 lg:px-9 lg:py-9">{children}</main>
      </div>
    </div>
  );
}
