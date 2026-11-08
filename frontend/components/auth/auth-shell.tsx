import Link from "next/link";
import { ArrowLeft, Shield } from "lucide-react";
import type { ReactNode } from "react";

type AuthShellProps = {
  eyebrow: string;
  title: string;
  description: string;
  children: ReactNode;
  footer?: ReactNode;
};

export function AuthShell({ eyebrow, title, description, children, footer }: AuthShellProps) {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-5 py-12 sm:px-8">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_50%_5%,rgba(89,183,255,0.09),transparent_44%)]" />
      <div className="relative w-full max-w-[480px]">
        <Link href="/" className="mb-9 inline-flex items-center gap-3" aria-label="THREATLENS home">
          <span className="grid size-10 place-items-center rounded-xl border border-accent/25 bg-accent/10 text-accent">
            <Shield className="size-[19px]" aria-hidden="true" />
          </span>
          <span className="text-[13px] font-bold tracking-[0.2em] text-foreground">THREATLENS</span>
        </Link>

        <section className="rounded-2xl border border-border bg-panel/90 p-6 shadow-[0_24px_100px_rgba(0,0,0,0.28)] sm:p-9">
          <div className="mb-7">
            <p className="mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-accent">{eyebrow}</p>
            <h1 className="text-3xl font-semibold tracking-[-0.04em] text-foreground">{title}</h1>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">{description}</p>
          </div>
          {children}
          {footer ? <div className="mt-6 border-t border-border pt-5 text-center text-sm text-muted-foreground">{footer}</div> : null}
        </section>

        <Link href="/" className="mt-6 inline-flex items-center gap-2 text-xs text-muted-foreground transition hover:text-foreground">
          <ArrowLeft className="size-3.5" aria-hidden="true" />
          Back to platform status
        </Link>
      </div>
    </main>
  );
}
