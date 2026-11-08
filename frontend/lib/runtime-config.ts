/** Public, non-secret runtime URLs used by browser-facing features. */
export const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL?.trim() || "http://127.0.0.1:8001/api/v1"
).replace(/\/+$/, "");
