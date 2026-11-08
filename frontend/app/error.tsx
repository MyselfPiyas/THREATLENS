"use client";

import { AlertTriangle, RotateCcw } from "lucide-react";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="grid min-h-screen place-items-center bg-background px-6 text-foreground">
      <section className="w-full max-w-md rounded-2xl border border-border bg-panel p-8 text-center">
        <AlertTriangle className="mx-auto mb-4 size-8 text-warning" aria-hidden="true" />
        <h1 className="text-xl font-semibold">The workspace could not load</h1>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">
          The page hit an unexpected error while checking service readiness. Try loading it again.
        </p>
        <button
          className="mt-6 inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-[#101512] transition hover:bg-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          onClick={reset}
          type="button"
        >
          <RotateCcw className="size-4" aria-hidden="true" />
          Retry
        </button>
      </section>
    </main>
  );
}

