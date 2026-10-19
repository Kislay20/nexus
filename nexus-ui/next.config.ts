import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
    // Tera local cloudflare fix
    allowedDevOrigins: ["*.trycloudflare.com"], 
    
    async rewrites() {
        return [
            {
                source: '/api/gateway/:path*',
                destination: process.env.BACKEND_URL 
                    ? `${process.env.BACKEND_URL}/v1/:path*` 
                    : 'http://127.0.0.1:8000/v1/:path*'
            }
        ];
    },
};

export default nextConfig;