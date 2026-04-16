import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: ['gentle-emu-commonly.ngrok-free.app'],
    // Proxy all /api calls to the Flask backend.
    // This means the frontend NEVER calls localhost:8001 directly —
    // it calls /api/... which Vite forwards. Works both locally and
    // through the Ngrok tunnel since the backend always runs on the HOST PC.
    proxy: {
      '/api': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
    },
  },
})
