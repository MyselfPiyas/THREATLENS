import { redirect } from "next/navigation";

import { getSupabaseEnvironmentStatus } from "@/lib/supabase/config";
import { createSupabaseServerClient } from "@/lib/supabase/server";

export type AuthenticatedUser = {
  id: string;
};

export async function getAuthenticatedUser(): Promise<AuthenticatedUser | null> {
  if (!getSupabaseEnvironmentStatus()) {
    return null;
  }

  try {
    const supabase = await createSupabaseServerClient();
    const { data, error } = await supabase.auth.getClaims();
    const userId = data?.claims?.sub;
    if (error || typeof userId !== "string" || !userId) {
      return null;
    }
    return { id: userId };
  } catch {
    return null;
  }
}

export async function requireAuthenticatedUser(nextPath = "/dashboard"): Promise<AuthenticatedUser> {
  const user = await getAuthenticatedUser();
  if (!user) {
    const loginUrl = new URLSearchParams({ next: nextPath });
    redirect("/auth/login?" + loginUrl.toString());
  }
  return user;
}
