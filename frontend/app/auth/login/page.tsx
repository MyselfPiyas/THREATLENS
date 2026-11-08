import Link from "next/link";

import { AuthShell } from "@/components/auth/auth-shell";
import { LoginForm } from "@/components/auth/login-form";
import { getSafeRedirectPath } from "@/lib/supabase/safe-redirect";

type LoginPageProps = {
  searchParams: Promise<{ next?: string; error?: string }>;
};

function getNotice(error: string | undefined): string | undefined {
  if (error === "auth_callback") {
    return "That confirmation or recovery link is invalid or has expired. Request a new email to continue.";
  }
  if (error === "configuration") {
    return "Dashboard access requires Supabase credentials. Configure the frontend project URL and publishable key.";
  }
  return undefined;
}

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const params = await searchParams;
  const nextPath = getSafeRedirectPath(params.next);
  return (
    <AuthShell
      eyebrow="Secure access"
      title="Welcome back"
      description="Sign in to view your private THREATLENS workspace."
      footer={<>New to THREATLENS? <Link href="/auth/sign-up" className="font-medium text-accent hover:text-foreground">Create an account</Link></>}
    >
      <LoginForm nextPath={nextPath} notice={getNotice(params.error)} />
    </AuthShell>
  );
}
