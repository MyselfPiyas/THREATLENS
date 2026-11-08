import { requireAuthenticatedUser } from "@/lib/supabase/require-user";
import { AppShell } from "@/components/dashboard/app-shell";

export const dynamic = "force-dynamic";

export default async function ProtectedLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  await requireAuthenticatedUser();
  return <AppShell>{children}</AppShell>;
}
