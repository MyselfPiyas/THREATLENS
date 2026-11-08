import { NextResponse, type NextRequest } from "next/server";

import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { getSafeRedirectPath } from "@/lib/supabase/safe-redirect";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { getSiteUrl } from "@/lib/supabase/site-url";

export async function GET(request: NextRequest) {
  const siteUrl = getSiteUrl();
  const callbackUrl = new URL("/auth/login?error=auth_callback", siteUrl);

  if (!getSupabaseEnvironmentStatus()) {
    return NextResponse.redirect(new URL("/auth/login?error=configuration", siteUrl));
  }

  const code = request.nextUrl.searchParams.get("code");
  const destination = getSafeRedirectPath(request.nextUrl.searchParams.get("next"));
  if (!code) {
    return NextResponse.redirect(callbackUrl);
  }

  try {
    const supabase = await createSupabaseServerClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return NextResponse.redirect(new URL(destination, siteUrl));
    }
  } catch {
    // Do not include provider or token details in the redirect.
  }

  return NextResponse.redirect(callbackUrl);
}
