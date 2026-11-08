import type { AuthActionState } from "@/types/auth";

export function AuthFeedback({ state }: { state: AuthActionState }) {
  if (!state.message) {
    return <div aria-live="polite" className="sr-only" />;
  }

  const isSuccess = state.kind === "success";
  return (
    <p
      role={isSuccess ? "status" : "alert"}
      aria-live="polite"
      className={
        "rounded-lg border px-3.5 py-3 text-sm leading-5 " +
        (isSuccess
          ? "border-accent/25 bg-accent/5 text-accent"
          : "border-negative/25 bg-negative/5 text-negative")
      }
    >
      {state.message}
    </p>
  );
}
