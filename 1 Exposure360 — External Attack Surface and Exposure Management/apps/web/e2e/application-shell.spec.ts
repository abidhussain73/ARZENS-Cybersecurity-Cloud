import { expect, test } from "@playwright/test";

test("renders the Phase 1 application shell and organization context", async ({ page }) => {
  await page.route("**/api/v1/system/info", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ name: "Exposure360", version: "0.1.0", phase: 1, api_version: "v1" }),
    });
  });
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Phase 1 Foundation" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in securely" })).toBeVisible();
  await page.getByLabel("Current organization").selectOption({ label: "ORG-A" });
  await expect(page.getByText("Selected context: ORG-A")).toBeVisible();
  await expect(page.getByText("Server validation required")).toBeVisible();
});
