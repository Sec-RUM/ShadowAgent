import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1", "localhost", "192.168.12.1"],
  outputFileTracingRoot: __dirname,
};

export default nextConfig;
