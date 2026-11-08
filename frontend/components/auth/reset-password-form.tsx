"use client";

import { useActionState } from "react";

import { resetPasswordAction } from "@/app/auth/actions";
import { AuthFeedback } from "@/components/auth/auth-feedback";
import { AuthField } from "@/components/auth/auth-field";
import { AuthSubmitButton } from "@/components/auth/auth-submit-button";
import { initialAuthActionState } from "@/types/auth";

export function ResetPasswordForm() {
  const [state, action] = useActionState(resetPasswordAction, initialAuthActionState);
  return (
    <form action={action} className="space-y-5">
      <AuthField
        label="New password"
        name="password"
        type="password"
        autoComplete="new-password"
        required
        minLength={12}
        maxLength={128}
        hint="Use 12 to 128 characters."
      />
      <AuthField
        label="Confirm new password"
        name="confirm_password"
        type="password"
        autoComplete="new-password"
        required
        minLength={12}
        maxLength={128}
      />
      <AuthFeedback state={state} />
      <AuthSubmitButton pendingLabel="Updating password…">Update password</AuthSubmitButton>
    </form>
  );
}
