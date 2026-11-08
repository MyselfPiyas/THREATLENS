import Link from "next/link";

import { AuthShell } from "@/components/auth/auth-shell";
import { ResetPasswordForm } from "@/components/auth/reset-password-form";
import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { getAuthenticatedUser } from "@/lib/supabase/require-user";

export const dynamic = "force-dynamic";

export default async function ResetPasswordPage() {
  const isConfigured = getSupabaseEnvironmentStatus();
  const user = isConfigured ? await getAuthenticatedUser() : null;

  return (
    <AuthShell
      eyebrow="Account recovery"
      title="Choose a new password"
      description="Use the secure reset link from your email to update your password."
      footer={<>Need another link? <Link href="/auth/forgot-password" className="font-medium text-accent hover:text-foreground">Request a new reset</Link></>}
    >
      {!isConfigured ? (
        <p role="alert" className="rounded-lg border border-warning/25 bg-warning/5 px-3.5 py-3 text-sm leading-5 text-warning">
          Supabase Auth is not configured. Add the project URL and publishable key to the frontend environment.
        </p>
      ) : user ? (
        <ResetPasswordForm />
      ) : (
        <p role="alert" className="rounded-lg border border-warning/25 bg-warning/5 px-3.5 py-3 text-sm leading-5 text-warning">
          This reset link is invalid or expired. Request a new link and open it from the same browser.
        </p>
      )}
    </AuthShell>
  );
}
