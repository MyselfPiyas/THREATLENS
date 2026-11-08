import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";

function isProtectedRoute(pathname: string): boolean {
  const protectedBases = [
    "/dashboard",
    "/profile",
    "/url-scanner",
    "/message-analyzer",
    "/qr-scanner",
    "/threat-intelligence",
    "/scam-dna",
    "/trust-passports",
    "/scan-history",
    "/settings",
    "/scan",
  ];
  return protectedBases.some((base) => pathname === base || pathname.startsWith(base + "/"));
}

function isGuestRoute(pathname: string): boolean {
  return ["/auth/login", "/auth/sign-up", "/auth/forgot-password"].includes(pathname);
}

function redirectPreservingCookies(url: URL, response: NextResponse): NextResponse {
  const redirectResponse = NextResponse.redirect(url);
  for (const cookie of response.cookies.getAll()) {
    redirectResponse.cookies.set(cookie);
  }
  return redirectResponse;
}

export async function proxy(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  if (!getSupabaseEnvironmentStatus()) {
    if (isProtectedRoute(pathname)) {
      const loginUrl = new URL("/auth/login", request.url);
      loginUrl.searchParams.set("next", pathname + request.nextUrl.search);
      return NextResponse.redirect(loginUrl);
    }
    return NextResponse.next({ request });
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const supabaseApiKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY?.trim() ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY?.trim();
  if (!supabaseUrl || !supabaseApiKey) {
    if (isProtectedRoute(pathname)) {
      const loginUrl = new URL("/auth/login", request.url);
      loginUrl.searchParams.set("next", pathname + request.nextUrl.search);
      return NextResponse.redirect(loginUrl);
    }
    return NextResponse.next({ request });
  }

  let response = NextResponse.next({ request });
  const supabase = createServerClient(supabaseUrl, supabaseApiKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) {
          request.cookies.set(name, value);
        }
        response = NextResponse.next({ request });
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });

  let userIsAuthenticated = false;
  try {
    const { data, error } = await supabase.auth.getClaims();
    userIsAuthenticated = !error && typeof data?.claims?.sub === "string";
  } catch {
    userIsAuthenticated = false;
  }

  if (isProtectedRoute(pathname) && !userIsAuthenticated) {
    const loginUrl = new URL("/auth/login", request.url);
    loginUrl.searchParams.set("next", pathname + request.nextUrl.search);
    return redirectPreservingCookies(loginUrl, response);
  }

  if (isGuestRoute(pathname) && userIsAuthenticated) {
    return redirectPreservingCookies(new URL("/dashboard", request.url), response);
  }

  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"],
};
