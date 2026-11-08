import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  distDir: process.env.THREATLENS_NEXT_DIST_DIR?.trim() || ".next",
};

export default nextConfig;

