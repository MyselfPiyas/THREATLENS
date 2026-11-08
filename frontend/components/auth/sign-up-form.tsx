"use client";

import { useActionState } from "react";

import { signUpAction } from "@/app/auth/actions";
import { AuthFeedback } from "@/components/auth/auth-feedback";
import { AuthField } from "@/components/auth/auth-field";
import { AuthSubmitButton } from "@/components/auth/auth-submit-button";
import { initialAuthActionState } from "@/types/auth";

export function SignUpForm({ nextPath }: { nextPath: string }) {
  const [state, action] = useActionState(signUpAction, initialAuthActionState);
  return (
    <form action={action} className="space-y-5">
      <input type="hidden" name="next" value={nextPath} />
      <AuthField label="Full name" name="full_name" autoComplete="name" required minLength={2} maxLength={160} />
      <AuthField label="Email address" name="email" type="email" autoComplete="email" required maxLength={320} />
      <AuthField
        label="Password"
        name="password"
        type="password"
        autoComplete="new-password"
        required
        minLength={12}
        maxLength={128}
        hint="Use 12 to 128 characters."
      />
      <AuthFeedback state={state} />
      <AuthSubmitButton pendingLabel="Creating account…">Create account</AuthSubmitButton>
      <p className="text-center text-[11px] leading-5 text-muted-foreground">
        By creating an account, you agree to use THREATLENS responsibly. Live URL scans require backend Supabase scan storage; message and QR analysis remain previews.
      </p>
    </form>
  );
}
