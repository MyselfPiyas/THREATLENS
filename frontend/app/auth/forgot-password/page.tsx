import Link from "next/link";

import { AuthShell } from "@/components/auth/auth-shell";
import { ForgotPasswordForm } from "@/components/auth/forgot-password-form";

export default function ForgotPasswordPage() {
  return (
    <AuthShell
      eyebrow="Account recovery"
      title="Reset your password"
      description="Enter your account email. If it can receive a reset link, we'll send instructions to your inbox."
      footer={<>Remembered it? <Link href="/auth/login" className="font-medium text-accent hover:text-foreground">Return to sign in</Link></>}
    >
      <ForgotPasswordForm />
    </AuthShell>
  );
}
