"use client";

import { useActionState } from "react";

import { updateProfileAction } from "@/app/auth/actions";
import { AuthFeedback } from "@/components/auth/auth-feedback";
import { AuthField } from "@/components/auth/auth-field";
import { AuthSubmitButton } from "@/components/auth/auth-submit-button";
import { initialAuthActionState } from "@/types/auth";

type ProfileFormProps = {
  fullName: string;
  avatarUrl: string;
};

export function ProfileForm({ fullName, avatarUrl }: ProfileFormProps) {
  const [state, action] = useActionState(updateProfileAction, initialAuthActionState);
  return (
    <form action={action} className="space-y-5">
      <AuthField label="Full name" name="full_name" defaultValue={fullName} required minLength={2} maxLength={160} />
      <AuthField
        label="Avatar URL"
        name="avatar_url"
        type="url"
        defaultValue={avatarUrl}
        maxLength={2048}
        placeholder="https://…"
        hint="Optional. Use a secure HTTPS address."
      />
      <AuthFeedback state={state} />
      <AuthSubmitButton pendingLabel="Saving profile…">Save changes</AuthSubmitButton>
    </form>
  );
}
