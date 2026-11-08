import { LoaderCircle } from "lucide-react";

export default function Loading() {
  return (
    <main className="grid min-h-screen place-items-center bg-background text-foreground">
      <div className="flex items-center gap-3 text-sm text-muted-foreground" role="status">
        <LoaderCircle className="size-4 animate-spin text-accent" aria-hidden="true" />
        Checking platform connections…
      </div>
    </main>
  );
}

