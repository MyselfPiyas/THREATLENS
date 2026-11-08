import Link from "next/link";

import { AuthShell } from "@/components/auth/auth-shell";
import { SignUpForm } from "@/components/auth/sign-up-form";
import { getSafeRedirectPath } from "@/lib/supabase/safe-redirect";

type SignUpPageProps = {
  searchParams: Promise<{ next?: string }>;
};

export default async function SignUpPage({ searchParams }: SignUpPageProps) {
  const params = await searchParams;
  return (
    <AuthShell
      eyebrow="Create your account"
      title="Start with trust"
      description="Create a private workspace for your digital trust intelligence."
      footer={<>Already registered? <Link href="/auth/login" className="font-medium text-accent hover:text-foreground">Sign in</Link></>}
    >
      <SignUpForm nextPath={getSafeRedirectPath(params.next)} />
    </AuthShell>
  );
}
