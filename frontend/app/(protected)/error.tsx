"use client";

export default function ProtectedError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main className="mx-auto max-w-3xl px-5 py-16 sm:px-8" role="alert">
      <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-negative">Workspace unavailable</p>
      <h1 className="mt-3 text-3xl font-semibold">We could not load this account view.</h1>
      <p className="mt-3 text-sm leading-6 text-muted-foreground">Your session and data remain protected. Try loading the page again.</p>
      <button onClick={reset} className="mt-6 rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-[#0b100e]">Try again</button>
    </main>
  );
}
