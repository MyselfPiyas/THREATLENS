import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { getSupabasePublicCredentials } from "@/lib/supabase/config";

export async function createSupabaseServerClient() {
  const { url, apiKey } = getSupabasePublicCredentials();
  const cookieStore = await cookies();

  return createServerClient(url, apiKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Server Components cannot write cookies; the proxy handles session refreshes.
        }
      },
    },
  });
}

