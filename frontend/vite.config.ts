import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // Core vendor chunks
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-ui': ['react-toastify', 'lucide-react'],
          'vendor-state': ['zustand', '@tanstack/react-query'],
          // Heavy libraries
          'vendor-charts': ['recharts'],
        },
      },
    },
    // Increase chunk size warning limit slightly since we have code splitting now
    chunkSizeWarningLimit: 600,
  },
})
