import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // Allow the sandbox preview panel + local origins to load Next.js dev assets.
  allowedDevOrigins: [
    "preview-chat-cfef58b1-7ad8-4628-9951-7afe337139fb.space-z.ai",
    "*.space-z.ai",
    "localhost",
    "127.0.0.1",
  ],
};

export default nextConfig;
