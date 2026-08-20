import { ApiError } from "./api";
import type { GovernanceConnection } from "./scopeApi";

export type Page = { offset: number; limit: number; total: number };
export type FindingSummary = {
  id: string; asset_id: string; asset_display_name: string; rule_id: string; rule_version: number;
  title: string; category: string; severity: string; confidence: number; state: string;
  first_seen: string; last_seen: string;
};
export type FindingDetail = FindingSummary & {
  description: string; service_asset_id: string | null; rule_hash: string;
  asset: Record<string, unknown>; service_asset: Record<string, unknown> | null;
  evidence_links: Array<Record<string, unknown>>; evaluation_history: TimelineEntry[];
  state_history: TimelineEntry[]; exception: { reason: string | null; expires_at: string | null; created_at: string | null } | null;
};
export type FindingEvidence = {
  id: string; evidence_id: string; observation_id: string | null; evidence_type: string; sha256: string;
  size_bytes: number; media_type: string; collected_at: string; stored_at: string;
};
export type TimelineEntry = { id: string; event_type: string; occurred_at: string; [key: string]: unknown };
export type FindingFilters = {
  state?: string; severity?: string; category?: string; ruleId?: string; assetId?: string;
  confidenceMin?: string; confidenceMax?: string; search?: string; offset?: number; limit?: number;
};
export type ChangeSummary = {
  id: string; asset_id: string; asset_display_name: string; change_type: string; summary: string;
  state: string; significance_score: number | null; significance_model_version: string | null;
  approved_change_id: string | null; first_seen: string; last_seen: string;
};
export type ChangeDetail = ChangeSummary & {
  from_snapshot_id: string | null; to_snapshot_id: string | null; details: Record<string, unknown>;
  significance_factors: Array<{ factor: string; points: number }>;
  approved_change: { id: string; name: string; reason: string; starts_at: string; ends_at: string; approved_by_user_id: string; status: string } | null;
};
export type ChangeFilters = {
  changeType?: string; state?: string; expected?: string; significanceMin?: string; significanceMax?: string;
  offset?: number; limit?: number;
};
export type ApprovedChange = {
  id: string; name: string; description: string; asset_id: string | null; allowed_change_types: string[];
  component_selector: Record<string, unknown> | null; starts_at: string; ends_at: string; reason: string;
  ticket_reference: string | null; approved_by_user_id: string; created_by_user_id: string; status: string;
};
export type TransitionPayload = { reason?: string; expires_at?: string; verification_reference?: string };
export type ApprovedChangePayload = {
  name: string; description: string; asset_id: string; allowed_change_types: string[]; starts_at: string;
  ends_at: string; reason: string; ticket_reference?: string; component_selector?: Record<string, unknown>;
};

async function request<T>(path: string, connection: GovernanceConnection, method = "GET", payload?: unknown): Promise<T> {
  const body = payload === undefined ? {} : { body: JSON.stringify(payload) };
  const response = await fetch(path, {
    method,
    headers: { Authorization: `Bearer ${connection.accessToken}`, "Content-Type": "application/json", "X-Organization-ID": connection.organizationId },
    ...body,
  });
  if (!response.ok) {
    const value = (await response.json().catch(() => null)) as { detail?: { message?: string } } | null;
    throw new ApiError(response.status, value?.detail?.message ?? "The Exposure360 request could not be completed.");
  }
  return (await response.json()) as T;
}

function query(filters: Record<string, string | number | undefined>): string {
  const values = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== "") values.set(key, String(value)); });
  return values.toString();
}

export interface FindingsApi {
  listFindings(connection: GovernanceConnection, filters: FindingFilters): Promise<{ items: FindingSummary[]; page: Page }>;
  getFinding(connection: GovernanceConnection, findingId: string): Promise<FindingDetail>;
  listFindingEvidence(connection: GovernanceConnection, findingId: string): Promise<FindingEvidence[]>;
  getFindingHistory(connection: GovernanceConnection, findingId: string): Promise<{ items: TimelineEntry[]; page: Page }>;
  transitionFinding(connection: GovernanceConnection, findingId: string, action: string, payload: TransitionPayload): Promise<FindingDetail>;
  authorizeEvidenceDownload(connection: GovernanceConnection, evidenceId: string): Promise<{ url: string; filename: string }>;
  listChanges(connection: GovernanceConnection, filters: ChangeFilters): Promise<{ items: ChangeSummary[]; page: Page }>;
  getChange(connection: GovernanceConnection, changeId: string): Promise<ChangeDetail>;
  listApprovedChanges(connection: GovernanceConnection, offset?: number, limit?: number): Promise<{ items: ApprovedChange[]; page: Page }>;
  createApprovedChange(connection: GovernanceConnection, payload: ApprovedChangePayload): Promise<ApprovedChange>;
  disableApprovedChange(connection: GovernanceConnection, approvalId: string): Promise<ApprovedChange>;
}

export const findingsApi: FindingsApi = {
  listFindings: (connection, filters) => request(`/api/v1/findings?${query({ state: filters.state, severity: filters.severity, category: filters.category, rule_id: filters.ruleId, asset_id: filters.assetId, confidence_min: filters.confidenceMin, confidence_max: filters.confidenceMax, search: filters.search, offset: filters.offset ?? 0, limit: filters.limit ?? 25 })}`, connection),
  getFinding: (connection, findingId) => request(`/api/v1/findings/${findingId}`, connection),
  listFindingEvidence: (connection, findingId) => request(`/api/v1/findings/${findingId}/evidence`, connection),
  getFindingHistory: (connection, findingId) => request(`/api/v1/findings/${findingId}/history?offset=0&limit=100`, connection),
  transitionFinding: (connection, findingId, action, payload) => request(`/api/v1/findings/${findingId}/${action}`, connection, "POST", payload),
  authorizeEvidenceDownload: (connection, evidenceId) => request(`/api/v1/evidence/${evidenceId}/download`, connection, "POST"),
  listChanges: (connection, filters) => request(`/api/v1/changes?${query({ change_type: filters.changeType, state: filters.state, expected: filters.expected, significance_min: filters.significanceMin, significance_max: filters.significanceMax, offset: filters.offset ?? 0, limit: filters.limit ?? 25 })}`, connection),
  getChange: (connection, changeId) => request(`/api/v1/changes/${changeId}`, connection),
  listApprovedChanges: (connection, offset = 0, limit = 25) => request(`/api/v1/approved-changes?offset=${offset}&limit=${limit}`, connection),
  createApprovedChange: (connection, payload) => request("/api/v1/approved-changes", connection, "POST", payload),
  disableApprovedChange: (connection, approvalId) => request(`/api/v1/approved-changes/${approvalId}/disable`, connection, "POST"),
};
