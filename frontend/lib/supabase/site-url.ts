export function getSiteUrl(): string {
  const configuredUrl =
    process.env.NEXT_PUBLIC_SITE_URL?.trim() ||
    (process.env.NODE_ENV === "production" ? "" : "http://localhost:3000");

  if (!configuredUrl) {
    throw new Error("Set NEXT_PUBLIC_SITE_URL to the public THREATLENS origin.");
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(configuredUrl);
  } catch {
    throw new Error("NEXT_PUBLIC_SITE_URL must be a valid HTTP(S) origin.");
  }

  if (
    !["http:", "https:"].includes(parsedUrl.protocol) ||
    !parsedUrl.hostname ||
    parsedUrl.username ||
    parsedUrl.password ||
    parsedUrl.pathname !== "/" ||
    parsedUrl.search ||
    parsedUrl.hash
  ) {
    throw new Error("NEXT_PUBLIC_SITE_URL must be an HTTP(S) origin without a path or credentials.");
  }

  if (process.env.NODE_ENV === "production" && parsedUrl.protocol !== "https:") {
    throw new Error("NEXT_PUBLIC_SITE_URL must use HTTPS in production.");
  }

  return parsedUrl.origin;
}
