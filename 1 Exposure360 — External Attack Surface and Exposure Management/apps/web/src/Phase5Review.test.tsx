import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ApprovedChanges } from "./ApprovedChanges";
import { Changes } from "./Changes";
import { Findings } from "./Findings";
import type { FindingsApi } from "./findingsApi";

const connection = { organizationId: "org-1", accessToken: "token" };
const finding = {
  id: "finding-1", asset_id: "asset-1", asset_display_name: "fixture.example.test",
  rule_id: "exposure.http.missing_hsts", rule_version: 1, title: "Missing HSTS",
  category: "HTTP_SECURITY_HEADER", severity: "MEDIUM", confidence: 0.9, state: "OPEN",
  first_seen: "2026-08-20T00:00:00Z", last_seen: "2026-08-20T01:00:00Z",
};
const change = {
  id: "change-1", asset_id: "asset-1", asset_display_name: "fixture.example.test",
  change_type: "CERTIFICATE", summary: "CERTIFICATE: certificate", state: "EXPECTED",
  significance_score: 55, significance_model_version: "change-significance-v1", approved_change_id: "approval-1",
  first_seen: "2026-08-20T00:00:00Z", last_seen: "2026-08-20T01:00:00Z",
};
const approval = {
  id: "approval-1", name: "Certificate rotation", description: "Fixture maintenance", asset_id: "asset-1",
  allowed_change_types: ["CERTIFICATE"], component_selector: { component_key: "certificate" },
  starts_at: "2026-08-20T00:00:00Z", ends_at: "2026-08-20T02:00:00Z", reason: "Authorized maintenance",
  ticket_reference: "CHG-1", approved_by_user_id: "user-1", created_by_user_id: "user-1", status: "ACTIVE",
};

function mockApi(): FindingsApi {
  return {
    listFindings: vi.fn().mockResolvedValue({ items: [finding], page: { offset: 0, limit: 25, total: 1 } }),
    getFinding: vi.fn().mockResolvedValue({ ...finding, description: "HSTS is absent.", service_asset_id: null, rule_hash: "a".repeat(64), asset: { display_name: finding.asset_display_name, canonical_key: "domain:fixture.example.test" }, service_asset: null, evidence_links: [], evaluation_history: [], state_history: [], exception: null }),
    listFindingEvidence: vi.fn().mockResolvedValue([{ id: "link-1", evidence_id: "evidence-1", observation_id: null, evidence_type: "HTTP_RESPONSE", sha256: "b".repeat(64), size_bytes: 10, media_type: "application/json", collected_at: finding.last_seen, stored_at: finding.last_seen }]),
    getFindingHistory: vi.fn().mockResolvedValue({ items: [{ id: "history-1", event_type: "EVALUATION", occurred_at: finding.last_seen, matched: true }], page: { offset: 0, limit: 100, total: 1 } }),
    transitionFinding: vi.fn().mockResolvedValue({ ...finding, state: "EXCEPTION", description: "HSTS is absent.", service_asset_id: null, rule_hash: "a".repeat(64), asset: { display_name: finding.asset_display_name, canonical_key: "domain:fixture.example.test" }, service_asset: null, evidence_links: [], evaluation_history: [], state_history: [], exception: { reason: "Accepted maintenance", expires_at: null, created_at: finding.last_seen } }),
    authorizeEvidenceDownload: vi.fn().mockRejectedValue(new Error("Evidence integrity check failed.")),
    listChanges: vi.fn().mockResolvedValue({ items: [change], page: { offset: 0, limit: 25, total: 1 } }),
    getChange: vi.fn().mockResolvedValue({ ...change, from_snapshot_id: "snapshot-1", to_snapshot_id: "snapshot-2", details: { component_key: "certificate", old: "old-cert", new: "new-cert" }, significance_factors: [{ factor: "CERTIFICATE_CHANGE", points: 55 }], approved_change: { id: approval.id, name: approval.name, reason: approval.reason, starts_at: approval.starts_at, ends_at: approval.ends_at, approved_by_user_id: approval.approved_by_user_id, status: "ACTIVE" } }),
    listApprovedChanges: vi.fn().mockResolvedValue({ items: [approval], page: { offset: 0, limit: 25, total: 1 } }),
    createApprovedChange: vi.fn().mockResolvedValue(approval),
    disableApprovedChange: vi.fn().mockResolvedValue({ ...approval, status: "DISABLED" }),
  };
}

describe("Phase 5 analyst review UI", () => {
  it("filters a finding, exposes state actions, and displays evidence authorization errors", async () => {
    const user = userEvent.setup(); const api = mockApi(); window.history.replaceState({}, "", "/findings");
    render(<Findings api={api} defaultConnection={connection} />);
    await screen.findByText("Missing HSTS");
    await user.selectOptions(screen.getByLabelText("Finding state"), "OPEN");
    await user.click(screen.getByRole("button", { name: "Load findings" }));
    expect(api.listFindings).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({ state: "OPEN" }));
    await user.click(screen.getByRole("button", { name: "Missing HSTS" }));
    await screen.findByRole("heading", { name: "Missing HSTS" });
    await user.type(screen.getByLabelText("Exception reason"), "Temporary maintenance");
    expect(screen.getByRole("button", { name: "Create exception" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Request authorized download" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Evidence integrity check failed.");
  });

  it("renders change before/after, expected state, and significance explanation", async () => {
    const user = userEvent.setup(); const api = mockApi(); window.history.replaceState({}, "", "/changes");
    render(<Changes api={api} defaultConnection={connection} />);
    await screen.findByText("CERTIFICATE: certificate");
    expect(screen.getByText("EXPECTED", { selector: "strong" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /CERTIFICATE.*certificate/ }));
    expect(api.getChange).toHaveBeenCalledWith(expect.anything(), "change-1");
    await screen.findByText("old-cert");
    expect(screen.getByText("new-cert")).toBeInTheDocument();
    expect(screen.getByText("CERTIFICATE_CHANGE: +55 points")).toBeInTheDocument();
    expect(screen.getByText(/Certificate rotation.*Authorized maintenance/)).toBeInTheDocument();
  });

  it("keeps approval creation and disable controls restricted to privileged roles", async () => {
    const user = userEvent.setup(); const api = mockApi(); window.history.replaceState({}, "", "/settings/approved-changes");
    const { rerender } = render(<ApprovedChanges api={api} defaultConnection={connection} role="viewer" />);
    await screen.findByText("Certificate rotation");
    expect(screen.queryByRole("button", { name: "Create approved change" })).not.toBeInTheDocument();
    rerender(<ApprovedChanges api={api} defaultConnection={connection} role="reviewer" />);
    await screen.findByRole("button", { name: "Create approved change" });
    await user.click(screen.getByRole("button", { name: "Disable" }));
    expect(api.disableApprovedChange).toHaveBeenCalledWith(expect.anything(), "approval-1");
  });
});
