import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Assets } from "./Assets";
import type { AssetsApi } from "./assetsApi";

const asset = { id: "asset-1", asset_type: "DOMAIN" as const, canonical_key: "domain:fixture.example.test", display_name: "fixture.example.test", lifecycle_state: "STALE" as const, first_seen: "2026-01-20T00:00:00Z", last_seen: "2026-01-21T00:00:00Z", primary_owner: null, top_technologies: [{ id: "tech-1", product: "FixtureWeb", category: "web_server", version_value: "1.2.3", confidence: 0.8, rule_id: "tech.fixture", rule_version: 1 }] };

function mockApi(): AssetsApi { return { listAssets: vi.fn().mockResolvedValue({ items: [asset], page: { offset: 0, limit: 25, total: 1 } }), getAsset: vi.fn().mockResolvedValue({ ...asset, subtype: null, identifiers: [], ownership_claims: [], technology_fingerprints: asset.top_technologies, observation_count: 1, evidence_count: 1 }), listObservations: vi.fn().mockResolvedValue({ items: [], page: { offset: 0, limit: 25, total: 0 } }), listEvidence: vi.fn().mockResolvedValue([{ id: "evidence-1", observation_id: null, evidence_type: "HTTP_RESPONSE", sha256: "abc", size_bytes: 10, media_type: "application/json", collected_at: asset.last_seen, stored_at: asset.last_seen, sensitivity_class: "INTERNAL_METADATA", collector_name: "fixture", collector_version: "1" }]), getOwnership: vi.fn().mockResolvedValue({ primary: null, claims: [] }), getTimeline: vi.fn().mockResolvedValue([{ event_type: "OBSERVATION", occurred_at: asset.last_seen, resource_id: "observation-1", summary: "HTTP_RESPONSE" }]), getRelationships: vi.fn().mockResolvedValue([{ relationship_type: "RESOLVES_TO", target_asset_id: "ip-1", source_observation_id: null, observed_at: asset.last_seen }]), authorizeEvidenceDownload: vi.fn().mockRejectedValue(new Error("Evidence download is not authorized.")) }; }

describe("Assets", () => {
  beforeEach(() => { window.history.replaceState({}, "", "/assets"); });

  it("loads a filtered asset inventory and drills into metadata-only detail", async () => {
    const user = userEvent.setup(); const api = mockApi(); render(<Assets api={api} defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await screen.findByText("fixture.example.test"); expect(screen.getByText("STALE", { selector: "span" })).toBeInTheDocument(); expect(screen.getByText("FixtureWeb 1.2.3 · 80%")).toBeInTheDocument();
    await user.click(screen.getByText("fixture.example.test")); await screen.findByRole("heading", { name: "fixture.example.test" }); expect(screen.getByText("Direct relationships")).toBeInTheDocument(); expect(screen.queryByText("object_store_key")).not.toBeInTheDocument();
  });

  it("keeps server-side filter controls and evidence authorization failures visible", async () => {
    const user = userEvent.setup(); const api = mockApi(); render(<Assets api={api} defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await screen.findByText("fixture.example.test"); await user.selectOptions(screen.getByLabelText("Asset type"), "DOMAIN"); await user.click(screen.getByRole("button", { name: "Load assets" })); expect(api.listAssets).toHaveBeenLastCalledWith(expect.anything(), expect.objectContaining({ assetType: "DOMAIN" })); await user.click(screen.getByRole("button", { name: /fixture\.example\.test/ })); await screen.findByText("Evidence metadata"); await user.click(screen.getByRole("button", { name: "Request authorized download" })); expect(await screen.findByRole("alert")).toHaveTextContent("Evidence download is not authorized.");
  });
});
