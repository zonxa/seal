import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/aggregator/v1': {
        target: 'https://aggregator.walrus-testnet.walrus.space',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/aggregator/, ''),
      },
      '/publisher/v1': {
        target: 'https://publisher.walrus-testnet.walrus.space',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/publisher/, '')
      }
    }
  }
})
