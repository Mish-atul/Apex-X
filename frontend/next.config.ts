import type { NextConfig } from "next";

const BACKEND_INTERNAL_URL = process.env.BACKEND_INTERNAL_URL || "http://127.0.0.1:8080";

const nextConfig: NextConfig = {
  // output: "export", // Disabled for local dev because middleware is used
  // FastAPI routes use trailing slashes (e.g. /cases/); keep them intact for the proxy.
  skipTrailingSlashRedirect: true,
  images: {
    unoptimized: true,
  },
  experimental: {
    // Allow large APK uploads (~200 MB) to pass through proxy/middleware buffering.
    proxyClientMaxBodySize: "250mb",
  },
  async rewrites() {
    return [
      // Preserve trailing slashes (FastAPI redirects /cases -> /cases/ with an internal host).
      {
        source: "/api/v1/:path*/",
        destination: `${BACKEND_INTERNAL_URL}/api/v1/:path*/`,
      },
      {
        source: "/api/v1/:path*",
        destination: `${BACKEND_INTERNAL_URL}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
