import { ApiError } from "./api";
import type { GovernanceConnection } from "./scopeApi";

export type DiscoveryJobState =
  | "QUEUED"
  | "RUNNING"
  | "PARTIAL"
  | "DEGRADED"
  | "COMPLETED"
  | "CANCELLING"
  | "CANCELLED"
  | "FAILED";

export type DiscoveryJob = {
  id: string;
  state: DiscoveryJobState;
  scope_id: string;
  scope_version_id: string;
  approval_id: string;
  current_stage: string | null;
  counts: { processed: number; succeeded: number; failed: number; skipped: number; queued: number };
  known_total: number | null;
  indeterminate: boolean;
  degraded_sources: Array<Record<string, unknown>>;
  created_at: string | null;
  started_at: string | null;
  updated_at: string | null;
  finished_at: string | null;
  links: Record<string, string>;
};

export type DiscoveryStage = {
  stage: string;
  state: string;
  processed: number;
  succeeded: number;
  failed: number;
  skipped: number;
  queued: number;
  known_total: number | null;
  indeterminate: boolean;
  last_error_code: string | null;
  started_at: string | null;
  finished_at: string | null;
};

export type DiscoveryEvent = {
  id: string;
  event_type: string;
  stage: string | null;
  details: Record<string, unknown>;
  correlation_id: string | null;
  created_at: string | null;
};

export type DiscoveryDeadLetter = {
  id: string;
  candidate_id: string | null;
  stage: string;
  operation_key: string;
  attempts: number;
  error_class: string;
  safe_message: string;
  state: string;
  first_failed_at: string;
  last_failed_at: string;
};

async function request<T>(path: string, connection: GovernanceConnection, method = "GET"): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${connection.accessToken}`,
      "Content-Type": "application/json",
      "X-Organization-ID": connection.organizationId,
    },
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: { error?: { message?: string } } } | null;
    throw new ApiError(response.status, payload?.detail?.error?.message ?? "The discovery service could not complete the request.");
  }
  return (await response.json()) as T;
}

export interface DiscoveryApi {
  listJobs(connection: GovernanceConnection): Promise<DiscoveryJob[]>;
  getJob(connection: GovernanceConnection, jobId: string): Promise<DiscoveryJob>;
  cancelJob(connection: GovernanceConnection, jobId: string): Promise<DiscoveryJob>;
  listStages(connection: GovernanceConnection, jobId: string): Promise<DiscoveryStage[]>;
  listEvents(connection: GovernanceConnection, jobId: string): Promise<DiscoveryEvent[]>;
  listDeadLetters(connection: GovernanceConnection, jobId: string): Promise<DiscoveryDeadLetter[]>;
}

export const discoveryApi: DiscoveryApi = {
  listJobs: (connection) => request("/api/v1/discovery/jobs", connection),
  getJob: (connection, jobId) => request(`/api/v1/discovery/jobs/${jobId}`, connection),
  cancelJob: (connection, jobId) => request(`/api/v1/discovery/jobs/${jobId}/cancel`, connection, "POST"),
  listStages: (connection, jobId) => request(`/api/v1/discovery/jobs/${jobId}/stages`, connection),
  listEvents: (connection, jobId) => request(`/api/v1/discovery/jobs/${jobId}/events`, connection),
  listDeadLetters: (connection, jobId) => request(`/api/v1/discovery/jobs/${jobId}/dead-letters`, connection),
};
