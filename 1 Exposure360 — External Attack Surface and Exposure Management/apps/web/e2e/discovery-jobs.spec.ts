import { expect, test } from "@playwright/test";

const states = ["QUEUED", "RUNNING", "PARTIAL", "DEGRADED", "COMPLETED", "CANCELLING", "CANCELLED", "FAILED"];
const firstJobId = "00000000-0000-4000-8000-000000000001";

function job(state: string, index: number) {
  return {
    id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    state,
    scope_id: "scope-id",
    scope_version_id: "version-id",
    approval_id: "approval-id",
    current_stage: "HTTP_METADATA",
    counts: { processed: 4, succeeded: 3, failed: 1, skipped: 0, queued: 0 },
    known_total: null,
    indeterminate: true,
    degraded_sources: [],
    created_at: "2026-08-19T00:00:00Z",
    started_at: "2026-08-19T00:01:00Z",
    updated_at: "2026-08-19T00:02:00Z",
    finished_at: null,
    links: {},
  };
}

test("renders discovery lifecycle and cancellation state in the browser", async ({ page }) => {
  const jobs = states.map(job);
  await page.route("**/api/v1/discovery/jobs", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({ contentType: "application/json", body: JSON.stringify(jobs) });
      return;
    }
    await route.continue();
  });
  await page.route(`**/api/v1/discovery/jobs/${firstJobId}`, async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(jobs[0]) });
  });
  await page.route(`**/api/v1/discovery/jobs/${firstJobId}/stages`, async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify([{ stage: "HTTP_METADATA", state: "RUNNING", processed: 4, succeeded: 3, failed: 1, skipped: 0, queued: 0, known_total: null, indeterminate: true, last_error_code: null, started_at: null, finished_at: null }]) });
  });
  await page.route(`**/api/v1/discovery/jobs/${firstJobId}/events`, async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify([{ id: "event-id", event_type: "stage.started", stage: "HTTP_METADATA", details: {}, correlation_id: "browser-test", created_at: "2026-08-19T00:00:00Z" }]) });
  });
  await page.route(`**/api/v1/discovery/jobs/${firstJobId}/dead-letters`, async (route) => {
    await route.fulfill({ contentType: "application/json", body: "[]" });
  });
  await page.route(`**/api/v1/discovery/jobs/${firstJobId}/cancel`, async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ ...jobs[0], state: "CANCELLING" }) });
  });

  await page.goto("/discovery/jobs");
  await page.getByLabel("Organization ID").fill("org-browser-test");
  await page.getByLabel("Access token").fill("deterministic-browser-fixture-token");
  await page.getByRole("button", { name: "Load discovery jobs" }).click();

  for (const state of states) await expect(page.getByText(state).first()).toBeVisible();
  await expect(page.getByText(/Progress is indeterminate/)).toBeVisible();
  await expect(page.getByText("Stage progress")).toBeVisible();
  await page.getByRole("button", { name: "Cancel discovery job" }).click();
  await expect(page.getByText("Cancellation requested")).toBeVisible();
});
