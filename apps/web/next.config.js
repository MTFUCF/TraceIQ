/** @type {import('next').NextConfig} */
const nextConfig = {
  // Standalone output bundles only what's needed — perfect for Container Apps.
  // The resulting `.next/standalone` folder contains a self-contained Node app.
  output: "standalone",
  reactStrictMode: true,
};
module.exports = nextConfig;
