import { expect, test } from "@playwright/test";

test("creates, validates, submits, approves, and locks a scope version", async ({ page }) => {
  const organizationId = "00000000-0000-4000-8000-000000000001";
  const scopeId = "00000000-0000-4000-8000-000000000010";
  const versionId = "00000000-0000-4000-8000-000000000020";
  const version = {
    id: versionId,
    scope_id: scopeId,
    organization_id: organizationId,
    version_number: 1,
    state: "DRAFT",
    change_summary: "Initial draft",
    created_by_user_id: "00000000-0000-4000-8000-000000000030",
    supersedes_version_id: null,
    content_hash: null,
    created_at: "2026-08-19T00:00:00Z",
    seeds: [] as Array<Record<string, unknown>>,
    exclusions: [] as Array<Record<string, unknown>>,
    policy: null as Record<string, unknown> | null,
    approvals: [] as Array<Record<string, unknown>>,
  };

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const method = request.method();
    const url = new URL(request.url());
    const respond = (payload: unknown, status = 200) => route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(payload),
    });

    if (url.pathname === "/api/v1/scopes" && method === "GET") return respond([]);
    if (url.pathname === "/api/v1/scopes" && method === "POST") return respond(version, 201);
    if (url.pathname.endsWith("/versions") && method === "GET") return respond([version]);
    if (url.pathname.endsWith(`/versions/${versionId}`) && method === "GET") return respond(version);
    if (url.pathname.endsWith("/seeds") && method === "POST") {
      const seed = { id: "seed-1", target_type: "DOMAIN", raw_value: "EXAMPLE.COM.", canonical_value: "example.com", match_mode: "EXACT", warning: "Normalized to example.com", reason: null, created_at: "2026-08-19T00:00:00Z" };
      version.seeds = [seed];
      return respond(seed, 201);
    }
    if (url.pathname.endsWith("/exclusions") && method === "POST") {
      const exclusion = { id: "exclusion-1", target_type: "DOMAIN", raw_value: "hidden.example.com", canonical_value: "hidden.example.com", match_mode: "EXACT", warning: null, reason: "Reserved documentation host", created_at: "2026-08-19T00:00:00Z" };
      version.exclusions = [exclusion];
      return respond(exclusion, 201);
    }
    if (url.pathname.endsWith("/policy") && method === "PUT") {
      version.policy = { id: "policy-1", allowed_protocols: ["HTTPS"], max_requests_per_second: 1, max_concurrent_targets: 1, max_concurrent_requests: 1, schedule_timezone: "UTC", schedule_windows: [], connect_timeout_seconds: 10, request_timeout_seconds: 30, active_scanning_enabled: false, updated_at: "2026-08-19T00:00:00Z" };
      return respond(version.policy);
    }
    if (url.pathname.endsWith("/validate") && method === "POST") return respond({ approvable: true, errors: [], warnings: [], content_hash: "test-content-hash" });
    if (url.pathname.endsWith("/submit") && method === "POST") {
      version.state = "SUBMITTED";
      version.content_hash = "test-content-hash";
      return respond(version);
    }
    if (url.pathname.endsWith("/approve") && method === "POST") {
      version.state = "APPROVED";
      version.approvals = [{ id: "approval-1", decision: "APPROVED", decision_reason: "Test approval", approved_by_user_id: "00000000-0000-4000-8000-000000000030", approved_at: "2026-08-19T00:00:00Z", expires_at: null, content_hash: "test-content-hash" }];
      return respond(version.approvals[0]);
    }
    return respond({ error: "Unhandled test route" }, 500);
  });

  await page.goto("/settings/scopes");
  await page.getByLabel("Organization ID").fill(organizationId);
  await page.getByLabel("Access token").fill("fixture-token");
  await page.getByRole("button", { name: "Load scopes" }).click();
  await page.getByLabel("Name").fill("Documentation targets");
  await page.getByRole("button", { name: "Create draft" }).click();

  await page.getByLabel("Seeds input").fill("EXAMPLE.COM.");
  await expect(page.getByText("EXAMPLE.COM. → example.com")).toBeVisible();
  await page.getByRole("button", { name: "Add seed" }).click();
  await page.getByLabel("Exclusions input").fill("hidden.example.com");
  await page.getByLabel("Exclusion reason").fill("Reserved documentation host");
  await page.getByRole("button", { name: "Add exclusion" }).click();
  await page.getByRole("button", { name: "Save policy" }).click();
  await page.getByRole("button", { name: "Validate draft" }).click();
  await expect(page.getByText("READY FOR APPROVAL")).toBeVisible();
  await page.getByRole("button", { name: "Submit for approval" }).click();
  await page.getByRole("button", { name: "Approve version" }).click();

  await expect(page.getByText("Approved version is read-only.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Create new draft from this version" })).toBeVisible();
  await expect(page.getByLabel("Seeds input")).toBeDisabled();
});
