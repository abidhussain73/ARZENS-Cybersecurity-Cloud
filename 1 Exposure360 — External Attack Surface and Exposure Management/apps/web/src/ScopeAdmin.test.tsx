import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ScopeAdmin } from "./ScopeAdmin";
import {
  type ScopeGovernanceApi,
  type ScopeSummary,
  type ScopeVersion,
} from "./scopeApi";

const scope: ScopeSummary = {
  id: "scope-1",
  organization_id: "org-1",
  name: "Documentation scope",
  description: "Reserved documentation targets",
  status: "ACTIVE",
  created_by_user_id: "user-1",
  created_at: "2026-08-19T00:00:00Z",
  updated_at: "2026-08-19T00:00:00Z",
  disabled_at: null,
  disabled_by_user_id: null,
};

function version(state: ScopeVersion["state"] = "DRAFT"): ScopeVersion {
  return {
    id: "version-1",
    scope_id: "scope-1",
    organization_id: "org-1",
    version_number: 1,
    state,
    change_summary: "Initial draft",
    created_by_user_id: "user-1",
    supersedes_version_id: null,
    content_hash: state === "APPROVED" ? "approved-content-hash" : null,
    created_at: "2026-08-19T00:00:00Z",
    seeds: [],
    exclusions: [],
    policy: null,
    approvals: [],
  };
}

function apiWith(overrides: Partial<ScopeGovernanceApi> = {}): ScopeGovernanceApi {
  const draft = version();
  return {
    listScopes: vi.fn().mockResolvedValue([scope]),
    createScope: vi.fn(),
    updateScope: vi.fn(),
    listVersions: vi.fn().mockResolvedValue([draft]),
    getVersion: vi.fn().mockResolvedValue(draft),
    createVersion: vi.fn().mockResolvedValue(draft),
    addSeed: vi.fn(),
    addExclusion: vi.fn(),
    putPolicy: vi.fn(),
    validate: vi.fn().mockResolvedValue({ approvable: true, errors: [], warnings: [], content_hash: "hash" }),
    submit: vi.fn().mockResolvedValue({ ...draft, state: "SUBMITTED" }),
    approve: vi.fn(),
    reject: vi.fn(),
    disable: vi.fn(),
    enable: vi.fn(),
    stop: vi.fn().mockResolvedValue({ active: true, level: "SCOPE", stop_generation: 1 }),
    resume: vi.fn().mockResolvedValue({ active: false, level: null, stop_generation: 0 }),
    ...overrides,
  };
}

async function selectTestScope(): Promise<void> {
  fireEvent.click(await screen.findByRole("button", { name: /documentation scope/i }));
  await screen.findByRole("heading", { name: "Documentation scope" });
}

describe("ScopeAdmin", () => {
  it("shows the raw-to-canonical normalization preview before a seed is saved", async () => {
    render(<ScopeAdmin api={apiWith()} defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await selectTestScope();

    fireEvent.change(screen.getByLabelText("Seeds input"), { target: { value: "EXAMPLE.COM." } });

    expect(screen.getByText(/EXAMPLE\.COM\. → example\.com/)).toBeInTheDocument();
  });

  it("displays explicit blocking conflict status returned by validation", async () => {
    render(<ScopeAdmin api={apiWith({
      validate: vi.fn().mockResolvedValue({
        approvable: false,
        content_hash: null,
        errors: [{ severity: "ERROR", code: "DUPLICATE", message: "Duplicate seed example.com" }],
        warnings: [],
      }),
    })} defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await selectTestScope();

    fireEvent.click(screen.getByRole("button", { name: "Validate draft" }));

    expect(await screen.findByText("BLOCKING ERROR")).toBeInTheDocument();
    expect(screen.getByText(/DUPLICATE: Duplicate seed example\.com/)).toBeInTheDocument();
  });

  it("makes an approved version read-only and offers a new-draft action", async () => {
    render(<ScopeAdmin api={apiWith({ listVersions: vi.fn().mockResolvedValue([version("APPROVED")]) })} defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await selectTestScope();

    expect(screen.getByText("Approved version is read-only.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create new draft from this version" })).toBeInTheDocument();
    expect(screen.getByLabelText("Seeds input")).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Add seed" })).not.toBeInTheDocument();
  });

  it("limits emergency stop to administrators and owners", async () => {
    render(<ScopeAdmin api={apiWith()} role="analyst" defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await selectTestScope();

    expect(screen.queryByRole("button", { name: "Emergency stop scope" })).not.toBeInTheDocument();
  });

  it("renders a safe error summary when a target mutation fails", async () => {
    render(<ScopeAdmin api={apiWith({ addSeed: vi.fn().mockRejectedValue(new Error("Seed rejected by policy")) })} defaultConnection={{ organizationId: "org-1", accessToken: "token" }} />);
    await selectTestScope();
    fireEvent.change(screen.getByLabelText("Seeds input"), { target: { value: "example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add seed" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Seed rejected by policy"));
  });
});
