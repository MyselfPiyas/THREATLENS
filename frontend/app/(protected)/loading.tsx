export default function ProtectedLoading() {
  return (
    <section aria-live="polite" aria-busy="true" className="animate-pulse">
      <div className="h-2 w-32 rounded bg-panel-raised" />
      <div className="mt-3 h-9 w-64 max-w-full rounded bg-panel-raised" />
      <div className="mt-3 h-3 w-[min(500px,100%)] rounded bg-panel-raised" />
      <div className="mt-7 grid grid-cols-2 gap-3 xl:grid-cols-4">{Array.from({ length: 4 }, (_, index) => <div key={index} className="h-28 rounded-xl border border-border bg-panel/70" />)}</div>
      <div className="mt-4 grid gap-4 xl:grid-cols-2"><div className="h-72 rounded-2xl border border-border bg-panel/70" /><div className="h-72 rounded-2xl border border-border bg-panel/70" /></div>
      <p className="sr-only">Loading your private workspace…</p>
    </section>
  );
}
