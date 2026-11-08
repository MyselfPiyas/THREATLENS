"use client";

import { useFormStatus } from "react-dom";

type AuthSubmitButtonProps = {
  children: string;
  pendingLabel?: string;
};

export function AuthSubmitButton({ children, pendingLabel = "Working…" }: AuthSubmitButtonProps) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 text-sm font-semibold text-[#06111c] transition hover:bg-[#80cbff] disabled:cursor-not-allowed disabled:opacity-60"
    >
      {pending ? pendingLabel : children}
    </button>
  );
}
