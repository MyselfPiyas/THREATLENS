import type { ReactNode } from "react";

type Status = "online" | "ready" | "offline" | "setup";

const statusStyles: Record<Status, { dot: string; text: string }> = {
  online: { dot: "bg-positive shadow-[0_0_10px_rgba(165,242,118,0.6)]", text: "text-positive" },
  ready: { dot: "bg-positive", text: "text-positive" },
  offline: { dot: "bg-negative", text: "text-negative" },
  setup: { dot: "bg-warning", text: "text-warning" },
};

export function StatusCard({
  icon,
  title,
  detail,
  status,
  statusLabel,
}: {
  icon: ReactNode;
  title: string;
  detail: string;
  status: Status;
  statusLabel: string;
}) {
  const styles = statusStyles[status];

  return (
    <article className="group rounded-2xl border border-border bg-panel/75 p-5 transition duration-200 hover:-translate-y-0.5 hover:border-[#35443c] hover:bg-panel">
      <div className="flex items-start justify-between">
        <span className="grid size-9 place-items-center rounded-xl border border-border bg-panel-raised text-muted-foreground transition group-hover:text-foreground">
          {icon}
        </span>
        <span className={`inline-flex items-center gap-2 rounded-full border border-border/80 bg-background/60 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.08em] ${styles.text}`}>
          <span className={`size-1.5 rounded-full ${styles.dot}`} />
          {statusLabel}
        </span>
      </div>
      <h2 className="mt-5 text-sm font-semibold">{title}</h2>
      <p className="mt-2 min-h-10 text-xs leading-5 text-muted-foreground">{detail}</p>
    </article>
  );
}

