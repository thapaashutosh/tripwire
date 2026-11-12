import type { NextConfig } from "next";

// Static export: `npm run build` writes plain HTML/JS to out/, which can be served from S3.
const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
};

export default nextConfig;
