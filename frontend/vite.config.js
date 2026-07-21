import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Geliştirmede: Vite 5173'te çalışır, /api istekleri 3000'deki backend'e
// proxy'lenir (CORS gerekmez).
// Üretimde: `npm run build` çıktısı ../src/api/public'e yazılır, Express
// aynı porttan (3000) servis eder.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:3000",
    },
  },
  build: {
    outDir: "../src/api/public",
    emptyOutDir: true,
  },
});
