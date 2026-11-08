import type { ReactNode } from "react";
import Link from "next/link";
import { ArrowUpRight, Fingerprint, type LucideIcon } from "lucide-react";

export type ScanSummary = {
  id: string;
  target: string;
  scan_type: string;
  status: string;
  risk_level: string;
  risk_score: number;
  summary?: string;
  created_at: string;
};

export function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="mb-7 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <p className="text-[9px] font-semibold uppercase tracking-[0.2em] text-accent">{eyebrow}</p>
        <h1 className="mt-2 text-[28px] font-semibold tracking-[-0.04em] sm:text-[34px]">{title}</h1>
        <p className="mt-2 max-w-2xl text-[12px] leading-5 text-muted-foreground sm:text-[13px]">{description}</p>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

export function Panel({ children, className = "", id }: { children: ReactNode; className?: string; id?: string }) {
  return <section id={id} className={`glass-panel glass-interactive rounded-2xl border border-border/90 bg-panel/80 ${className}`}>{children}</section>;
}

export function PanelTitle({ title, detail, action }: { title: string; detail?: string; action?: ReactNode }) {
  return <div className="mb-5 flex items-start justify-between gap-4"><div><h2 className="text-[13px] font-semibold">{title}</h2>{detail ? <p className="mt-1 text-[10px] leading-4 text-muted-foreground">{detail}</p> : null}</div>{action}</div>;
}

export function DemoTag() {
  return <span className="inline-flex items-center gap-1.5 rounded-full border border-warning/20 bg-warning/[0.07] px-2 py-1 text-[8px] font-semibold uppercase tracking-[0.13em] text-warning"><span className="size-1 rounded-full bg-warning" /> Demo visualization</span>;
}

export function EmptyState({ icon: Icon = Fingerprint, title, detail, action }: { icon?: LucideIcon; title: string; detail: string; action?: ReactNode }) {
  return (
    <div className="flex min-h-[180px] flex-col items-center justify-center rounded-xl border border-dashed border-border/90 px-5 py-8 text-center">
      <span className="grid size-10 place-items-center rounded-xl border border-border bg-panel-raised text-muted-foreground"><Icon className="size-[18px]" /></span>
      <p className="mt-3 text-[12px] font-semibold">{title}</p>
      <p className="mt-1.5 max-w-md text-[10px] leading-4 text-muted-foreground">{detail}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function RiskBadge({ level }: { level: string }) {
  const normalized = level.toLowerCase();
  const styles: Record<string, string> = {
    critical: "border-negative/25 bg-negative/[0.08] text-negative",
    high: "border-negative/20 bg-negative/[0.06] text-negative",
    medium: "border-warning/25 bg-warning/[0.07] text-warning",
    low: "border-positive/20 bg-positive/[0.06] text-positive",
    info: "border-accent/20 bg-accent/[0.06] text-accent",
    unknown: "border-border bg-panel-raised text-muted-foreground",
    low_risk: "border-positive/20 bg-positive/[0.06] text-positive",
    suspicious: "border-warning/25 bg-warning/[0.07] text-warning",
    high_risk: "border-negative/20 bg-negative/[0.06] text-negative",
    confirmed_malicious: "border-negative/30 bg-negative/[0.11] text-negative",
    inconclusive: "border-border bg-panel-raised text-muted-foreground",
  };
  return <span className={`inline-flex items-center rounded-full border px-2 py-1 text-[8px] font-semibold uppercase tracking-[0.1em] ${styles[normalized] ?? styles.unknown}`}>{level || "unknown"}</span>;
}

export function ScoreIndicator({ score }: { score: number | null | undefined }) {
  const value = typeof score === "number" && Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : null;
  const color = value === null ? "bg-border" : value >= 75 ? "bg-negative" : value >= 45 ? "bg-warning" : "bg-positive";
  return (
    <div className="flex min-w-[82px] items-center gap-2">
      <span className="h-1.5 w-12 overflow-hidden rounded-full bg-panel-raised"><span className={`block h-full rounded-full ${color}`} style={{ width: `${value ?? 0}%` }} /></span>
      <span className="text-[10px] tabular-nums text-muted-foreground">{value === null ? "—" : value}</span>
    </div>
  );
}

export function ScanRow({ scan }: { scan: ScanSummary }) {
  return (
    <Link href={`/scan/${encodeURIComponent(scan.id)}`} className="group grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-b border-border/70 py-3.5 last:border-0 last:pb-0 hover:bg-white/[0.015] sm:grid-cols-[minmax(0,1fr)_100px_88px_80px]">
      <div className="flex min-w-0 items-center gap-3">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg border border-border bg-panel-raised text-muted-foreground"><Fingerprint className="size-4" /></span>
        <div className="min-w-0"><p className="truncate text-[11px] font-medium group-hover:text-accent">{scan.target}</p><p className="mt-1 truncate text-[9px] text-muted-foreground">{scan.scan_type} · {formatDate(scan.created_at)}</p></div>
      </div>
      <span className="hidden text-[9px] capitalize text-muted-foreground sm:block">{scan.status}</span>
      <span className="hidden sm:block"><RiskBadge level={scan.risk_level} /></span>
      <span className="flex items-center justify-end gap-1 text-[9px] text-muted-foreground"><span className="sm:hidden"><RiskBadge level={scan.risk_level} /></span><ArrowUpRight className="hidden size-3.5 group-hover:text-accent sm:block" /></span>
    </Link>
  );
}

export function ErrorNotice({ detail }: { detail: string }) {
  return <div role="alert" className="rounded-xl border border-warning/25 bg-warning/[0.06] px-4 py-3 text-[11px] leading-5 text-warning">{detail}</div>;
}

export function formatDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Date unavailable";
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" }).format(date);
}

export function ActionLink({ href, children }: { href: string; children: ReactNode }) {
  return <Link href={href} className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-panel-raised/70 px-3 text-[10px] font-semibold text-foreground transition hover:border-accent/30 hover:text-accent">{children}<ArrowUpRight className="size-3.5" /></Link>;
}
