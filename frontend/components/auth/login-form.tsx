"use client";

import Link from "next/link";
import { useActionState } from "react";

import { signInAction } from "@/app/auth/actions";
import { AuthFeedback } from "@/components/auth/auth-feedback";
import { AuthField } from "@/components/auth/auth-field";
import { AuthSubmitButton } from "@/components/auth/auth-submit-button";
import { initialAuthActionState } from "@/types/auth";

type LoginFormProps = {
  nextPath: string;
  notice?: string;
};

export function LoginForm({ nextPath, notice }: LoginFormProps) {
  const [state, action] = useActionState(signInAction, initialAuthActionState);
  return (
    <form action={action} className="space-y-5">
      <input type="hidden" name="next" value={nextPath} />
      {notice ? <p role="alert" className="rounded-lg border border-warning/25 bg-warning/5 px-3.5 py-3 text-sm text-warning">{notice}</p> : null}
      <AuthField label="Email address" name="email" type="email" autoComplete="email" required maxLength={320} />
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3">
          <label htmlFor="password" className="text-xs font-medium text-foreground">Password</label>
          <Link href="/auth/forgot-password" className="text-xs text-accent transition hover:text-foreground">Forgot password?</Link>
        </div>
          <AuthField label="" name="password" id="password" type="password" autoComplete="current-password" required maxLength={128} />
      </div>
      <AuthFeedback state={state} />
      <AuthSubmitButton>Sign in</AuthSubmitButton>
    </form>
  );
}
