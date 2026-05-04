import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

/** @type {import('vite').UserConfig} */
export default defineConfig({
  plugins: [svelte()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://backend:5000', // Adjust the target to match your backend service URL or just use 'http://localhost:5000' if running locally
        changeOrigin: true,
      }
    }
  }
})
