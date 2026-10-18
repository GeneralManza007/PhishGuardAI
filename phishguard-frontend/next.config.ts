import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  /* config options here */
  // Fix the workspace root warning
  turbopack: {
    root: process.cwd(),
  },
  // Allow network access in dev (fixes the cross-origin warning)
  allowedDevOrigins: ['192.168.1.129', 'localhost', '127.0.0.1'],
};

export default nextConfig;