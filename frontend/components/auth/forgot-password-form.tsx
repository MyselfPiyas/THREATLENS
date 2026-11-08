"use client";

import { useActionState } from "react";

import { requestPasswordResetAction } from "@/app/auth/actions";
import { AuthFeedback } from "@/components/auth/auth-feedback";
import { AuthField } from "@/components/auth/auth-field";
import { AuthSubmitButton } from "@/components/auth/auth-submit-button";
import { initialAuthActionState } from "@/types/auth";

export function ForgotPasswordForm() {
  const [state, action] = useActionState(requestPasswordResetAction, initialAuthActionState);
  return (
    <form action={action} className="space-y-5">
      <AuthField label="Email address" name="email" type="email" autoComplete="email" required maxLength={320} />
      <AuthFeedback state={state} />
      <AuthSubmitButton pendingLabel="Sending secure link…">Send reset link</AuthSubmitButton>
    </form>
  );
}
