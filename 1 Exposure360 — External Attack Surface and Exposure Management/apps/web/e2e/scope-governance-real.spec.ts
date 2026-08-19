import { expect, test } from "@playwright/test";

test("runs the required scope lifecycle through the real local FastAPI governance backend", async ({ page }) => {
  const organizationId = "00000000-0000-4000-8000-00000000a001";

  await page.goto("/settings/scopes");
  await page.getByLabel("Organization ID").fill(organizationId);
  await page.getByLabel("Access token").fill("deterministic-browser-fixture-token");
  await page.getByRole("button", { name: "Load scopes" }).click();
  await page.getByLabel("Name").fill("Real browser acceptance scope");
  await page.getByLabel("Description").fill("A deterministic real API browser acceptance record");
  await page.getByRole("button", { name: "Create draft" }).click();

  await page.getByLabel("Seeds input").fill("EXAMPLE.COM.");
  await expect(page.getByText("EXAMPLE.COM. → example.com")).toBeVisible();
  await page.getByRole("button", { name: "Add seed" }).click();
  await page.getByLabel("Exclusions input").fill("hidden.example.com");
  await page.getByLabel("Exclusion reason").fill("Real browser acceptance exclusion");
  await page.getByRole("button", { name: "Add exclusion" }).click();
  await page.getByRole("button", { name: "Save policy" }).click();
  await page.getByRole("button", { name: "Validate draft" }).click();
  await expect(page.getByText("READY FOR APPROVAL")).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await page.getByLabel("Decision reason").fill("Real browser acceptance approval");
  await page.getByRole("button", { name: "Approve version" }).click();

  await expect(page.getByText("Approved version is read-only.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create new draft from this version" })).toBeVisible();
  await expect(page.getByLabel("Seeds input")).toBeDisabled();
});
