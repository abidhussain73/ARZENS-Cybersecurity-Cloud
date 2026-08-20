import { ApiError } from "./api";
import type { GovernanceConnection } from "./scopeApi";

export type AssetSummary = {
  id: string;
  asset_type: "DOMAIN" | "IP" | "ASN" | "ENDPOINT" | "SERVICE";
  canonical_key: string;
  display_name: string;
  lifecycle_state: "ACTIVE" | "STALE" | "RETIRED";
  first_seen: string;
  last_seen: string;
  primary_owner: OwnerSummary | null;
  top_technologies: TechnologySummary[];
};

export type OwnerSummary = {
  id: string;
  owner_type: string;
  owner_reference: string;
  owner_display_name: string | null;
  claim_type: string;
  confidence: number;
};

export type TechnologySummary = {
  id: string;
  product: string;
  category: string;
  version_value: string | null;
  confidence: number;
  rule_id: string;
  rule_version: number;
};

export type AssetPage = { offset: number; limit: number; total: number };
export type AssetListResponse = { items: AssetSummary[]; page: AssetPage };

export type AssetDetail = AssetSummary & {
  subtype: Record<string, unknown> | null;
  identifiers: Array<{
    id: string;
    identifier_type: string;
    canonical_value: string;
    is_primary: boolean;
    source: string;
    first_seen: string;
    last_seen: string;
  }>;
  ownership_claims: OwnerSummary[];
  technology_fingerprints: TechnologySummary[];
  observation_count: number;
  evidence_count: number;
};

export type AssetObservation = {
  id: string;
  observation_type: string;
  source_type: string;
  source_key: string;
  observed_at: string;
  collected_at: string;
  confidence: number | null;
  state: string;
  payload_hash: string;
};

export type AssetEvidence = {
  id: string;
  observation_id: string | null;
  evidence_type: string;
  sha256: string;
  size_bytes: number;
  media_type: string;
  collected_at: string;
  stored_at: string;
  sensitivity_class: string;
  collector_name: string;
  collector_version: string;
};

export type TimelineItem = { event_type: string; occurred_at: string; resource_id: string | null; summary: string };
export type AssetRelationship = {
  relationship_type: string;
  target_asset_id: string;
  source_observation_id: string | null;
  observed_at: string | null;
};
export type DownloadReference = { method: string; url: string; expires_at: string; filename: string };

export type AssetListFilters = {
  assetType?: string;
  lifecycleState?: string;
  search?: string;
  owner?: string;
  technology?: string;
  offset?: number;
  limit?: number;
};

async function assetRequest<T>(path: string, connection: GovernanceConnection, method = "GET"): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${connection.accessToken}`,
      "Content-Type": "application/json",
      "X-Organization-ID": connection.organizationId,
    },
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { detail?: { message?: string } } | null;
    throw new ApiError(response.status, payload?.detail?.message ?? "The asset inventory request could not be completed.");
  }
  return (await response.json()) as T;
}

function query(filters: AssetListFilters): string {
  const params = new URLSearchParams();
  if (filters.assetType) params.set("asset_type", filters.assetType);
  if (filters.lifecycleState) params.set("lifecycle_state", filters.lifecycleState);
  if (filters.search) params.set("search", filters.search);
  if (filters.owner) params.set("owner", filters.owner);
  if (filters.technology) params.set("technology", filters.technology);
  params.set("offset", String(filters.offset ?? 0));
  params.set("limit", String(filters.limit ?? 25));
  return params.toString();
}

export interface AssetsApi {
  listAssets(connection: GovernanceConnection, filters: AssetListFilters): Promise<AssetListResponse>;
  getAsset(connection: GovernanceConnection, assetId: string): Promise<AssetDetail>;
  listObservations(connection: GovernanceConnection, assetId: string): Promise<{ items: AssetObservation[]; page: AssetPage }>;
  listEvidence(connection: GovernanceConnection, assetId: string): Promise<AssetEvidence[]>;
  getOwnership(connection: GovernanceConnection, assetId: string): Promise<{ primary: OwnerSummary | null; claims: OwnerSummary[] }>;
  getTimeline(connection: GovernanceConnection, assetId: string): Promise<TimelineItem[]>;
  getRelationships(connection: GovernanceConnection, assetId: string): Promise<AssetRelationship[]>;
  authorizeEvidenceDownload(connection: GovernanceConnection, evidenceId: string): Promise<DownloadReference>;
}

export const assetsApi: AssetsApi = {
  listAssets: (connection, filters) => assetRequest(`/api/v1/assets?${query(filters)}`, connection),
  getAsset: (connection, assetId) => assetRequest(`/api/v1/assets/${assetId}`, connection),
  listObservations: (connection, assetId) => assetRequest(`/api/v1/assets/${assetId}/observations?offset=0&limit=25`, connection),
  listEvidence: (connection, assetId) => assetRequest(`/api/v1/assets/${assetId}/evidence`, connection),
  getOwnership: (connection, assetId) => assetRequest(`/api/v1/assets/${assetId}/ownership`, connection),
  getTimeline: (connection, assetId) => assetRequest(`/api/v1/assets/${assetId}/timeline`, connection),
  getRelationships: (connection, assetId) => assetRequest(`/api/v1/assets/${assetId}/relationships`, connection),
  authorizeEvidenceDownload: (connection, evidenceId) => assetRequest(`/api/v1/evidence/${evidenceId}/download`, connection, "POST"),
};
