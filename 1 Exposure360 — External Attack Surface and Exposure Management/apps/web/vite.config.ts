import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiTarget = process.env.PLAYWRIGHT_API_URL ?? "http://api:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": apiTarget,
      "/health": apiTarget,
    },
  },
});
