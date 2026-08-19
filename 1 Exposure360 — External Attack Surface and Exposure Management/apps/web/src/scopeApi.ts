import { ApiError } from "./api";

export type ScopeStatus = "ACTIVE" | "DISABLED" | "ARCHIVED";
export type VersionState = "DRAFT" | "SUBMITTED" | "APPROVED" | "REJECTED" | "SUPERSEDED";
export type TargetType = "DOMAIN" | "CIDR" | "IP" | "ASN";
export type MatchMode = "EXACT" | "DOMAIN_AND_SUBDOMAINS";
export type GovernanceRole = "viewer" | "analyst" | "reviewer" | "admin" | "owner";

export type GovernanceConnection = {
  organizationId: string;
  accessToken: string;
};

export type ScopeSummary = {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  status: ScopeStatus;
  created_by_user_id: string;
  created_at: string | null;
  updated_at: string | null;
  disabled_at: string | null;
  disabled_by_user_id: string | null;
};

export type ScopeTarget = {
  id: string;
  target_type: TargetType;
  raw_value: string;
  canonical_value: string;
  match_mode: MatchMode;
  warning: string | null;
  reason: string | null;
  created_at: string | null;
};

export type ScanPolicy = {
  id: string;
  allowed_protocols: string[];
  max_requests_per_second: number;
  max_concurrent_targets: number;
  max_concurrent_requests: number;
  schedule_timezone: string;
  schedule_windows: Array<{ days: string[]; start: string; end: string }>;
  connect_timeout_seconds: number;
  request_timeout_seconds: number;
  active_scanning_enabled: boolean;
  updated_at: string | null;
};

export type ScopeApproval = {
  id: string;
  decision: "APPROVED" | "REJECTED";
  decision_reason: string | null;
  approved_by_user_id: string;
  approved_at: string | null;
  expires_at: string | null;
  content_hash: string;
};

export type ScopeVersion = {
  id: string;
  scope_id: string;
  organization_id: string;
  version_number: number;
  state: VersionState;
  change_summary: string | null;
  created_by_user_id: string;
  supersedes_version_id: string | null;
  content_hash: string | null;
  created_at: string | null;
  seeds: ScopeTarget[];
  exclusions: ScopeTarget[];
  policy: ScanPolicy | null;
  approvals: ScopeApproval[];
};

export type ValidationFinding = {
  severity: "ERROR" | "WARNING" | "INFO";
  code: string;
  message: string;
};

export type ScopeValidation = {
  approvable: boolean;
  errors: ValidationFinding[];
  warnings: ValidationFinding[];
  content_hash: string | null;
};

export type StopState = {
  active: boolean;
  level: "ORGANIZATION" | "SCOPE" | null;
  stop_generation: number;
};

export type TargetInput = {
  target_type: TargetType;
  raw_value: string;
  match_mode: MatchMode;
  reason?: string;
};

export type PolicyInput = Omit<ScanPolicy, "id" | "updated_at">;

async function governanceRequest<T>(
  path: string,
  connection: GovernanceConnection,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const init: RequestInit = {
    method,
    headers: {
      Authorization: `Bearer ${connection.accessToken}`,
      "Content-Type": "application/json",
      "X-Organization-ID": connection.organizationId,
    },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as {
      detail?: { error?: { message?: string } };
    } | null;
    throw new ApiError(
      response.status,
      payload?.detail?.error?.message ?? "The governance service could not complete the request.",
    );
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export interface ScopeGovernanceApi {
  listScopes(connection: GovernanceConnection): Promise<ScopeSummary[]>;
  createScope(connection: GovernanceConnection, input: { name: string; description?: string }): Promise<ScopeVersion>;
  updateScope(connection: GovernanceConnection, scopeId: string, input: { name?: string; description?: string }): Promise<ScopeSummary>;
  listVersions(connection: GovernanceConnection, scopeId: string): Promise<ScopeVersion[]>;
  getVersion(connection: GovernanceConnection, scopeId: string, versionId: string): Promise<ScopeVersion>;
  createVersion(connection: GovernanceConnection, scopeId: string, cloneFromVersionId?: string): Promise<ScopeVersion>;
  addSeed(connection: GovernanceConnection, scopeId: string, versionId: string, input: TargetInput): Promise<ScopeTarget>;
  addExclusion(connection: GovernanceConnection, scopeId: string, versionId: string, input: TargetInput): Promise<ScopeTarget>;
  putPolicy(connection: GovernanceConnection, scopeId: string, versionId: string, input: PolicyInput): Promise<ScanPolicy>;
  validate(connection: GovernanceConnection, scopeId: string, versionId: string): Promise<ScopeValidation>;
  submit(connection: GovernanceConnection, scopeId: string, versionId: string): Promise<ScopeVersion>;
  approve(connection: GovernanceConnection, scopeId: string, versionId: string, reason?: string, expiresAt?: string): Promise<ScopeApproval>;
  reject(connection: GovernanceConnection, scopeId: string, versionId: string, reason?: string): Promise<ScopeApproval>;
  disable(connection: GovernanceConnection, scopeId: string): Promise<ScopeSummary>;
  enable(connection: GovernanceConnection, scopeId: string): Promise<ScopeSummary>;
  stop(connection: GovernanceConnection, scopeId: string, reason: string): Promise<StopState>;
  resume(connection: GovernanceConnection, scopeId: string): Promise<StopState>;
}

export const scopeGovernanceApi: ScopeGovernanceApi = {
  listScopes: (connection) => governanceRequest("/api/v1/scopes", connection),
  createScope: (connection, input) => governanceRequest("/api/v1/scopes", connection, "POST", input),
  updateScope: (connection, scopeId, input) => governanceRequest(`/api/v1/scopes/${scopeId}`, connection, "PATCH", input),
  listVersions: (connection, scopeId) => governanceRequest(`/api/v1/scopes/${scopeId}/versions`, connection),
  getVersion: (connection, scopeId, versionId) => governanceRequest(`/api/v1/scopes/${scopeId}/versions/${versionId}`, connection),
  createVersion: (connection, scopeId, cloneFromVersionId) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions`,
    connection,
    "POST",
    cloneFromVersionId ? { clone_from_version_id: cloneFromVersionId } : {},
  ),
  addSeed: (connection, scopeId, versionId, input) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/seeds`, connection, "POST", input,
  ),
  addExclusion: (connection, scopeId, versionId, input) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/exclusions`, connection, "POST", input,
  ),
  putPolicy: (connection, scopeId, versionId, input) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/policy`, connection, "PUT", input,
  ),
  validate: (connection, scopeId, versionId) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/validate`, connection, "POST",
  ),
  submit: (connection, scopeId, versionId) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/submit`, connection, "POST",
  ),
  approve: (connection, scopeId, versionId, reason, expiresAt) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/approve`, connection, "POST", {
      decision_reason: reason || undefined,
      expires_at: expiresAt || undefined,
    },
  ),
  reject: (connection, scopeId, versionId, reason) => governanceRequest(
    `/api/v1/scopes/${scopeId}/versions/${versionId}/reject`, connection, "POST", {
      decision_reason: reason || undefined,
    },
  ),
  disable: (connection, scopeId) => governanceRequest(`/api/v1/scopes/${scopeId}/disable`, connection, "POST"),
  enable: (connection, scopeId) => governanceRequest(`/api/v1/scopes/${scopeId}/enable`, connection, "POST"),
  stop: (connection, scopeId, reason) => governanceRequest(
    `/api/v1/scopes/${scopeId}/emergency-stop`, connection, "POST", { reason },
  ),
  resume: (connection, scopeId) => governanceRequest(`/api/v1/scopes/${scopeId}/resume`, connection, "POST"),
};
