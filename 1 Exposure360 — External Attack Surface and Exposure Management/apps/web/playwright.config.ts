import { existsSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

const systemChromium = ["/usr/bin/chromium", "/usr/bin/chromium-browser"].find(existsSync);

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    browserName: "chromium",
    ...devices["Desktop Chrome"],
    launchOptions: systemChromium ? { executablePath: systemChromium } : undefined,
  },
  webServer: {
    command: "pnpm exec vite --host 127.0.0.1 --port 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: true,
  },
});
