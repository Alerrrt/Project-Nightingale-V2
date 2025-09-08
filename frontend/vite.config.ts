

import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  // Use backend service name for Docker-internal access, fallback to localhost for local dev
  // Default to local dev backend on 8000; Docker sets VITE_API_URL to http://backend:9000
  const apiTarget = env.VITE_API_URL || 'http://localhost:8000'
  // Derive ws target explicitly to ensure WebSocket proxying works reliably
  const wsTarget = apiTarget.replace(/^http/, 'ws')
  
  console.log('Vite config - API target:', apiTarget, 'WS target:', wsTarget)
  
  return {
    plugins: [react()],
    server: {
      host: true,
      port: 3003,
      proxy: {
        // Explicit WS proxy to avoid upgrade issues with some environments
        '/api/ws': {
          target: wsTarget,
          changeOrigin: true,
          ws: true,
          secure: false,
          configure: (proxy, options) => {
            proxy.on('error', (err, req, res) => {
              console.log('[WS] proxy error', err);
            });
            proxy.on('proxyReqWs', (proxyReq, req, socket, options, head) => {
              console.log('[WS] Upgrading WebSocket for:', req.url);
            });
          },
        },
        // HTTP API proxy
        '/api': {
          target: apiTarget,
          changeOrigin: true,
          ws: true,
          configure: (proxy, options) => {
            proxy.on('error', (err, req, res) => {
              console.log('proxy error', err);
            });
            proxy.on('proxyReq', (proxyReq, req, res) => {
              console.log('Sending Request to the Target:', req.method, req.url);
            });
            proxy.on('proxyRes', (proxyRes, req, res) => {
              console.log('Received Response from the Target:', proxyRes.statusCode, req.url);
            });
          },
        },
      },
    },
  }
})
