import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DiscoveryJobs } from "./DiscoveryJobs";
import type { DiscoveryApi, DiscoveryJob, DiscoveryJobState } from "./discoveryApi";
import type { GovernanceConnection } from "./scopeApi";

const states: DiscoveryJobState[] = [
  "QUEUED", "RUNNING", "PARTIAL", "DEGRADED", "COMPLETED", "CANCELLING", "CANCELLED", "FAILED",
];

function job(state: DiscoveryJobState, index = 0): DiscoveryJob {
  return {
    id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
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

function apiWith(jobs: DiscoveryJob[]): DiscoveryApi {
  return {
    listJobs: vi.fn().mockResolvedValue(jobs),
    getJob: vi.fn().mockImplementation(async (_connection: GovernanceConnection, jobId: string) => jobs.find((item) => item.id === jobId) ?? jobs[0]),
    cancelJob: vi.fn().mockImplementation(async (_connection: GovernanceConnection, jobId: string) => ({ ...jobs.find((item) => item.id === jobId)!, state: "CANCELLING" })),
    listStages: vi.fn().mockResolvedValue([{ stage: "HTTP_METADATA", state: "RUNNING", processed: 4, succeeded: 3, failed: 1, skipped: 0, queued: 0, known_total: null, indeterminate: true, last_error_code: null, started_at: null, finished_at: null }]),
    listEvents: vi.fn().mockResolvedValue([{ id: "event-id", event_type: "stage.started", stage: "HTTP_METADATA", details: {}, correlation_id: "test", created_at: "2026-08-19T00:00:00Z" }]),
    listDeadLetters: vi.fn().mockResolvedValue([]),
  };
}

describe("DiscoveryJobs", () => {
  it("renders all required lifecycle badges and truthful indeterminate progress", async () => {
    render(<DiscoveryJobs api={apiWith(states.map((state, index) => job(state, index)))} defaultConnection={{ organizationId: "org", accessToken: "token" }} />);

    for (const state of states) {
      expect((await screen.findAllByText(state)).length).toBeGreaterThan(0);
    }
    expect(await screen.findByText(/Progress is indeterminate/)).toBeInTheDocument();
    expect(screen.getByText("Stage progress")).toBeInTheDocument();
  });

  it("changes the visible job state to cancelling after an authorized cancel action", async () => {
    const api = apiWith([job("RUNNING")]);
    render(<DiscoveryJobs api={api} defaultConnection={{ organizationId: "org", accessToken: "token" }} />);

    fireEvent.click(await screen.findByRole("button", { name: "Cancel discovery job" }));

    await waitFor(() => expect(screen.getAllByText("CANCELLING")).not.toHaveLength(0));
    expect(api.cancelJob).toHaveBeenCalledTimes(1);
  });
});
