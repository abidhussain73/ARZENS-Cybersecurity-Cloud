import { expect, test } from "@playwright/test";

const connection = { organizationId: "org-phase5-browser", accessToken: "browser-fixture-token" };
const finding = {
  id: "finding-phase5-1",
  asset_id: "asset-phase5-1",
  asset_display_name: "fixture.example.test",
  rule_id: "exposure.http.missing_hsts",
  rule_version: 1,
  title: "Missing HSTS",
  category: "HTTP_SECURITY_HEADER",
  severity: "MEDIUM",
  confidence: 0.9,
  state: "OPEN",
  first_seen: "2026-08-20T00:00:00Z",
  last_seen: "2026-08-20T01:00:00Z",
};
const change = {
  id: "change-phase5-1",
  asset_id: "asset-phase5-1",
  asset_display_name: "fixture.example.test",
  change_type: "CERTIFICATE",
  summary: "CERTIFICATE: certificate",
  state: "EXPECTED",
  significance_score: 55,
  significance_model_version: "change-significance-v1",
  approved_change_id: "approval-phase5-1",
  first_seen: "2026-08-20T00:00:00Z",
  last_seen: "2026-08-20T01:00:00Z",
};

test("reviews a finding evidence trail and an expected change in the browser", async ({ page }) => {
  await page.route("**/api/v1/findings?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ items: [finding], page: { offset: 0, limit: 25, total: 1 } }),
    });
  });
  await page.route(`**/api/v1/findings/${finding.id}`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...finding,
        description: "HSTS is absent from recorded HTTP metadata.",
        service_asset_id: null,
        rule_hash: "a".repeat(64),
        asset: { display_name: finding.asset_display_name, canonical_key: "domain:fixture.example.test" },
        service_asset: null,
        evidence_links: [],
        evaluation_history: [],
        state_history: [],
        exception: null,
      }),
    });
  });
  await page.route(`**/api/v1/findings/${finding.id}/evidence`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: "finding-evidence-link-1",
          evidence_id: "evidence-phase5-1",
          observation_id: null,
          evidence_type: "HTTP_RESPONSE",
          sha256: "b".repeat(64),
          size_bytes: 10,
          media_type: "application/json",
          collected_at: finding.last_seen,
          stored_at: finding.last_seen,
        },
      ]),
    });
  });
  await page.route(`**/api/v1/findings/${finding.id}/history?**`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        items: [{ id: "history-phase5-1", event_type: "EVALUATION", occurred_at: finding.last_seen }],
        page: { offset: 0, limit: 100, total: 1 },
      }),
    });
  });
  await page.route("**/api/v1/changes?**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ items: [change], page: { offset: 0, limit: 25, total: 1 } }),
    });
  });
  await page.route(`**/api/v1/changes/${change.id}`, async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ...change,
        from_snapshot_id: "snapshot-previous",
        to_snapshot_id: "snapshot-current",
        details: { component_key: "certificate", old: "old-cert", new: "new-cert" },
        significance_factors: [{ factor: "CERTIFICATE_CHANGE", points: 55 }],
        approved_change: {
          id: "approval-phase5-1",
          name: "Certificate rotation",
          reason: "Authorized maintenance",
          starts_at: "2026-08-20T00:00:00Z",
          ends_at: "2026-08-20T02:00:00Z",
          approved_by_user_id: "user-phase5-1",
          status: "ACTIVE",
        },
      }),
    });
  });

  await page.goto("/findings");
  await page.getByLabel("Organization ID").fill(connection.organizationId);
  await page.getByLabel("Access token").fill(connection.accessToken);
  await page.getByLabel("Finding state").selectOption("OPEN");
  await page.getByRole("button", { name: "Load findings" }).click();
  await page.getByRole("button", { name: "Missing HSTS" }).click();
  await expect(page.getByRole("heading", { name: "Missing HSTS" })).toBeVisible();
  await expect(page.getByText("HTTP_RESPONSE")).toBeVisible();
  await expect(page.getByRole("button", { name: "Request authorized download" })).toBeVisible();
  await expect(page.getByText("EVALUATION")).toBeVisible();

  await page.goto("/changes");
  await page.getByLabel("Organization ID").fill(connection.organizationId);
  await page.getByLabel("Access token").fill(connection.accessToken);
  await page.getByRole("button", { name: "Load changes" }).click();
  await expect(page.locator("strong").filter({ hasText: "EXPECTED" })).toBeVisible();
  await page.getByRole("button", { name: /CERTIFICATE.*certificate/ }).click();
  await expect(page.getByText("old-cert")).toBeVisible();
  await expect(page.getByText("new-cert")).toBeVisible();
  await expect(page.getByText("CERTIFICATE_CHANGE: +55 points")).toBeVisible();
  await expect(page.getByText(/Certificate rotation.*Authorized maintenance/)).toBeVisible();
});
