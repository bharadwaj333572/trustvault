/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverComponentsExternalPackages: ['@node-rs/argon2', '@electric-sql/pglite', 'pg'],
  },
  webpack: (config, { isServer }) => {
    if (isServer) {
      config.externals = [...(config.externals || []), '@node-rs/argon2'];
    }
    return config;
  },
};

export default nextConfig;
