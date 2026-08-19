import { FormEvent, useEffect, useMemo, useState } from "react";
import {
  type GovernanceConnection,
  type GovernanceRole,
  type MatchMode,
  type PolicyInput,
  type ScopeGovernanceApi,
  type ScopeStatus,
  type ScopeSummary,
  type ScopeTarget,
  type ScopeValidation,
  type ScopeVersion,
  type StopState,
  type TargetType,
  scopeGovernanceApi,
} from "./scopeApi";

type ScopeAdminProps = {
  api?: ScopeGovernanceApi;
  defaultConnection?: GovernanceConnection;
  role?: GovernanceRole;
};

type TargetDraft = {
  rawValue: string;
  targetType: TargetType;
  matchMode: MatchMode;
  reason: string;
};

const initialTarget: TargetDraft = {
  rawValue: "",
  targetType: "DOMAIN",
  matchMode: "EXACT",
  reason: "",
};

const initialPolicy: PolicyInput = {
  allowed_protocols: ["HTTPS"],
  max_requests_per_second: 1,
  max_concurrent_targets: 1,
  max_concurrent_requests: 1,
  schedule_timezone: "UTC",
  schedule_windows: [],
  connect_timeout_seconds: 10,
  request_timeout_seconds: 30,
  active_scanning_enabled: false,
};

function normalizePreview(targetType: TargetType, rawValue: string): string {
  const value = rawValue.trim();
  if (targetType === "DOMAIN") {
    return value.replace(/\.$/, "").toLowerCase();
  }
  if (targetType === "CIDR") {
    const [address, prefixText] = value.split("/");
    const prefix = Number(prefixText);
    const octets = address?.split(".").map(Number);
    if (octets?.length === 4 && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32) {
      const number = octets.reduce((result, octet) => (result << 8) + octet, 0) >>> 0;
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const network = number & mask;
      return `${[24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join(".")}/${prefix}`;
    }
  }
  return value;
}

function canEdit(role: GovernanceRole): boolean {
  return role !== "viewer";
}

function canApprove(role: GovernanceRole): boolean {
  return role === "admin" || role === "owner";
}

function toErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function ScopeAdmin({
  api = scopeGovernanceApi,
  defaultConnection,
  role = "admin",
}: ScopeAdminProps) {
  const [connection, setConnection] = useState<GovernanceConnection>(
    defaultConnection ?? { organizationId: "", accessToken: "" },
  );
  const [connected, setConnected] = useState(Boolean(defaultConnection));
  const [scopes, setScopes] = useState<ScopeSummary[]>([]);
  const [selectedScope, setSelectedScope] = useState<ScopeSummary | null>(null);
  const [versions, setVersions] = useState<ScopeVersion[]>([]);
  const [version, setVersion] = useState<ScopeVersion | null>(null);
  const [validation, setValidation] = useState<ScopeValidation | null>(null);
  const [stopState, setStopState] = useState<StopState | null>(null);
  const [filter, setFilter] = useState<"all" | "active" | "disabled" | "draft">("all");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);

  async function loadScopes(): Promise<void> {
    setLoading(true);
    setError("");
    try {
      setScopes(await api.listScopes(connection));
      setConnected(true);
      setNotice("Scope list refreshed from the governance API.");
    } catch (requestError) {
      setError(toErrorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (defaultConnection) {
      void loadScopes();
    }
  }, []);

  async function selectScope(scope: ScopeSummary): Promise<void> {
    setLoading(true);
    setError("");
    try {
      const loadedVersions = await api.listVersions(connection, scope.id);
      setSelectedScope(scope);
      setVersions(loadedVersions);
      setVersion(loadedVersions[0] ?? null);
      setValidation(null);
      setStopState(null);
    } catch (requestError) {
      setError(toErrorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  async function refreshVersion(nextVersion: ScopeVersion): Promise<void> {
    const refreshed = await api.getVersion(connection, nextVersion.scope_id, nextVersion.id);
    setVersion(refreshed);
    setVersions((items) => items.map((item) => (item.id === refreshed.id ? refreshed : item)));
  }

  async function createScope(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = String(form.get("scope-name") ?? "").trim();
    const description = String(form.get("scope-description") ?? "").trim();
    if (!name) {
      setError("Scope name is required.");
      return;
    }
    setLoading(true);
    try {
      const scopeInput = description ? { name, description } : { name };
      const created = await api.createScope(connection, scopeInput);
      const summary: ScopeSummary = {
        id: created.scope_id,
        organization_id: created.organization_id,
        name,
        description: description || null,
        status: "ACTIVE",
        created_by_user_id: created.created_by_user_id,
        created_at: created.created_at,
        updated_at: created.created_at,
        disabled_at: null,
        disabled_by_user_id: null,
      };
      setScopes((items) => [summary, ...items]);
      setSelectedScope(summary);
      setVersions([created]);
      setVersion(created);
      setValidation(null);
      setNotice("Scope created as version 1 draft.");
      event.currentTarget.reset();
    } catch (requestError) {
      setError(toErrorMessage(requestError));
    } finally {
      setLoading(false);
    }
  }

  const filteredScopes = useMemo(
    () => scopes.filter((scope) => {
      if (filter === "active") return scope.status === "ACTIVE";
      if (filter === "disabled") return scope.status === "DISABLED";
      if (filter === "draft") return versions.some((item) => item.scope_id === scope.id && item.state === "DRAFT");
      return true;
    }),
    [filter, scopes, versions],
  );

  return (
    <main className="governance-shell">
      <header className="governance-header">
        <div>
          <p className="eyebrow">Exposure360 · Phase 2</p>
          <h1>Scope Governance</h1>
          <p className="header-copy">Authorize only documented external targets. This workspace does not start network scans.</p>
        </div>
        <a href="/">Return to foundation shell</a>
      </header>

      <section className="connection-panel panel" aria-labelledby="connection-heading">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Secure context</p>
            <h2 id="connection-heading">Organization API connection</h2>
          </div>
          <span className={connected ? "status-pill active" : "status-pill"}>{connected ? "Connected" : "Not connected"}</span>
        </div>
        <div className="connection-grid">
          <label>Organization ID<input aria-label="Organization ID" value={connection.organizationId} onChange={(event) => setConnection({ ...connection, organizationId: event.target.value })} placeholder="Organization UUID" /></label>
          <label>Access token<input aria-label="Access token" type="password" value={connection.accessToken} onChange={(event) => setConnection({ ...connection, accessToken: event.target.value })} placeholder="Bearer access token" /></label>
          <label>Current role<select aria-label="Current role" value={role} disabled><option value={role}>{role}</option></select></label>
        </div>
        <div className="action-row"><button onClick={() => void loadScopes()} disabled={loading || !connection.organizationId || !connection.accessToken}>Load scopes</button></div>
      </section>

      <p className="sr-status" aria-live="polite">{notice}</p>
      {error && <section className="error-summary" role="alert"><strong>Request could not be completed.</strong><p>{error}</p></section>}

      {connected && (
        <section className="governance-layout">
          <aside className="scope-list panel" aria-labelledby="scope-list-heading">
            <div className="section-heading"><div><p className="eyebrow">Inventory</p><h2 id="scope-list-heading">Scopes</h2></div></div>
            <label>Filter scopes<select aria-label="Filter scopes" value={filter} onChange={(event) => setFilter(event.target.value as typeof filter)}><option value="all">All scopes</option><option value="active">Active</option><option value="disabled">Disabled</option><option value="draft">Draft pending</option></select></label>
            <div className="scope-rows">
              {filteredScopes.length === 0 && <p className="empty-state">No scopes match this filter.</p>}
              {filteredScopes.map((scope) => <button className={`scope-row ${selectedScope?.id === scope.id ? "selected" : ""}`} key={scope.id} onClick={() => void selectScope(scope)}><span>{scope.name}</span><small>{scope.status} · {formatTime(scope.updated_at)}</small></button>)}
            </div>
            {canEdit(role) && <form className="create-scope-form" onSubmit={(event) => void createScope(event)}><h3>Create scope</h3><label>Name<input name="scope-name" required /></label><label>Description<textarea name="scope-description" rows={2} /></label><button disabled={loading}>Create draft</button></form>}
          </aside>
          <section className="scope-workspace" aria-label="Scope editor">
            {selectedScope && version ? <VersionEditor api={api} connection={connection} role={role} scope={selectedScope} version={version} versions={versions} validation={validation} stopState={stopState} onVersionChange={setVersion} onVersionsChange={setVersions} onValidationChange={setValidation} onStopStateChange={setStopState} onScopeChange={(scope) => { setSelectedScope(scope); setScopes((items) => items.map((item) => item.id === scope.id ? scope : item)); }} onError={setError} onNotice={setNotice} onRefresh={refreshVersion} /> : <section className="panel empty-workspace"><p className="eyebrow">Select a scope</p><h2>Review and authorize scope versions</h2><p>Create or select an organization scope to review its draft content, policy, validation status, approval summary, and incident controls.</p></section>}
          </section>
        </section>
      )}
    </main>
  );
}

type VersionEditorProps = {
  api: ScopeGovernanceApi;
  connection: GovernanceConnection;
  role: GovernanceRole;
  scope: ScopeSummary;
  version: ScopeVersion;
  versions: ScopeVersion[];
  validation: ScopeValidation | null;
  stopState: StopState | null;
  onVersionChange(version: ScopeVersion): void;
  onVersionsChange(versions: ScopeVersion[]): void;
  onValidationChange(validation: ScopeValidation | null): void;
  onStopStateChange(state: StopState | null): void;
  onScopeChange(scope: ScopeSummary): void;
  onError(message: string): void;
  onNotice(message: string): void;
  onRefresh(version: ScopeVersion): Promise<void>;
};

function VersionEditor(props: VersionEditorProps) {
  const { api, connection, role, scope, version } = props;
  const [seed, setSeed] = useState<TargetDraft>(initialTarget);
  const [exclusion, setExclusion] = useState<TargetDraft>(initialTarget);
  const [policy, setPolicy] = useState<PolicyInput>(version.policy ? { ...version.policy } : initialPolicy);
  const [approvalReason, setApprovalReason] = useState("");
  const [approvalExpiry, setApprovalExpiry] = useState("");
  const [stopDialogOpen, setStopDialogOpen] = useState(false);
  const [stopReason, setStopReason] = useState("");
  const editable = version.state === "DRAFT" && canEdit(role);
  const preview = normalizePreview(seed.targetType, seed.rawValue);
  const validation = props.validation;
  const stopState = props.stopState;
  const latestApproval = version.approvals.at(0);

  useEffect(() => {
    setPolicy(version.policy ? { ...version.policy } : initialPolicy);
  }, [version.id, version.policy]);

  async function addTarget(kind: "seed" | "exclusion"): Promise<void> {
    const draft = kind === "seed" ? seed : exclusion;
    if (!editable || !draft.rawValue.trim()) return;
    if (kind === "exclusion" && !draft.reason.trim()) {
      props.onError("An exclusion reason is required.");
      return;
    }
    try {
      if (kind === "seed") await api.addSeed(connection, scope.id, version.id, { target_type: draft.targetType, raw_value: draft.rawValue, match_mode: draft.matchMode });
      else await api.addExclusion(connection, scope.id, version.id, { target_type: draft.targetType, raw_value: draft.rawValue, match_mode: draft.matchMode, reason: draft.reason });
      await props.onRefresh(version);
      if (kind === "seed") {
        setSeed(initialTarget);
      } else {
        setExclusion(initialTarget);
      }
      props.onNotice(`${kind === "seed" ? "Seed" : "Exclusion"} added to the draft.`);
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function savePolicy(): Promise<void> {
    if (!editable) return;
    try {
      await api.putPolicy(connection, scope.id, version.id, { ...policy, active_scanning_enabled: false });
      await props.onRefresh(version);
      props.onNotice("Policy saved. Active network scanning remains disabled in Phase 2.");
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function validateVersion(): Promise<void> {
    try {
      const result = await api.validate(connection, scope.id, version.id);
      props.onValidationChange(result);
      props.onNotice(result.approvable ? "Validation passed with no blocking errors." : "Validation found items requiring review.");
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function submitVersion(): Promise<void> {
    try {
      const submitted = await api.submit(connection, scope.id, version.id);
      props.onVersionChange(submitted);
      props.onVersionsChange(props.versions.map((item) => item.id === submitted.id ? submitted : item));
      props.onNotice("Draft submitted for approval. Content is now immutable.");
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function approve(decision: "approve" | "reject"): Promise<void> {
    try {
      if (decision === "approve") await api.approve(connection, scope.id, version.id, approvalReason, approvalExpiry || undefined);
      else await api.reject(connection, scope.id, version.id, approvalReason);
      await props.onRefresh(version);
      props.onNotice(`Version ${decision === "approve" ? "approved" : "rejected"}.`);
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function createDraft(): Promise<void> {
    try {
      const created = await api.createVersion(connection, scope.id, version.id);
      props.onVersionsChange([created, ...props.versions]);
      props.onVersionChange(created);
      props.onValidationChange(null);
      props.onNotice("New draft created from the selected approved version.");
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function changeScopeStatus(nextStatus: ScopeStatus): Promise<void> {
    try {
      const updated = nextStatus === "DISABLED" ? await api.disable(connection, scope.id) : await api.enable(connection, scope.id);
      props.onScopeChange(updated);
      props.onNotice(`Scope ${nextStatus === "DISABLED" ? "disabled" : "enabled"}.`);
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function confirmStop(): Promise<void> {
    if (!stopReason.trim()) { props.onError("Emergency stop reason is required."); return; }
    try {
      props.onStopStateChange(await api.stop(connection, scope.id, stopReason));
      setStopDialogOpen(false);
      setStopReason("");
      props.onNotice("Emergency stop is active for this scope.");
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  async function resume(): Promise<void> {
    try {
      props.onStopStateChange(await api.resume(connection, scope.id));
      props.onNotice("Emergency stop has been explicitly resumed.");
    } catch (requestError) { props.onError(toErrorMessage(requestError)); }
  }

  return <div className="editor-stack">
    <section className="panel scope-overview"><div><p className="eyebrow">Scope detail</p><h2>{scope.name}</h2><p>{scope.description || "No description supplied."}</p></div><div className="status-group"><span className={`status-pill ${scope.status === "ACTIVE" ? "active" : "disabled"}`}>{scope.status}</span><span className={`status-pill ${version.state.toLowerCase()}`}>Version {version.version_number} · {version.state}</span></div></section>
    <nav className="section-nav" aria-label="Scope editor sections"><a href="#seeds">Seeds</a><a href="#exclusions">Exclusions</a><a href="#policy">Policy</a><a href="#validation">Validation</a><a href="#approval">Approval</a><a href="#history">History</a></nav>
    {version.state === "APPROVED" && <section className="read-only-banner" role="status"><strong>Approved version is read-only.</strong><span>Create a new draft to change any target or policy value.</span>{canEdit(role) && <button onClick={() => void createDraft()}>Create new draft from this version</button>}</section>}
    <TargetSection id="seeds" title="Seeds" help="Explicit in-scope targets. Canonicalization is shown before save." draft={seed} setDraft={setSeed} preview={preview} targets={version.seeds} editable={editable} submitLabel="Add seed" onSubmit={() => void addTarget("seed")} />
    <TargetSection id="exclusions" title="Exclusions" help="Exclusions take precedence over matching seeds and require a reason." draft={exclusion} setDraft={setExclusion} preview={normalizePreview(exclusion.targetType, exclusion.rawValue)} targets={version.exclusions} editable={editable} exclusion submitLabel="Add exclusion" onSubmit={() => void addTarget("exclusion")} />
    <section id="policy" className="panel"><p className="eyebrow">Policy</p><h2>Execution boundaries</h2><p>Phase 2 records authorization policy only. No active network scanning is enabled.</p><div className="policy-grid"><label>Allowed protocol<select aria-label="Allowed protocol" disabled={!editable} value={policy.allowed_protocols[0] || "HTTPS"} onChange={(event) => setPolicy({ ...policy, allowed_protocols: [event.target.value] })}><option>DNS</option><option>TCP</option><option>TLS</option><option>HTTP</option><option>HTTPS</option></select></label><label>Requests per second<input aria-label="Requests per second" type="number" min="1" disabled={!editable} value={policy.max_requests_per_second} onChange={(event) => setPolicy({ ...policy, max_requests_per_second: Number(event.target.value) })} /></label><label>Concurrent targets<input aria-label="Concurrent targets" type="number" min="1" disabled={!editable} value={policy.max_concurrent_targets} onChange={(event) => setPolicy({ ...policy, max_concurrent_targets: Number(event.target.value) })} /></label><label>Concurrent requests<input aria-label="Concurrent requests" type="number" min="1" disabled={!editable} value={policy.max_concurrent_requests} onChange={(event) => setPolicy({ ...policy, max_concurrent_requests: Number(event.target.value) })} /></label><label>Schedule timezone<input aria-label="Schedule timezone" disabled={!editable} value={policy.schedule_timezone} onChange={(event) => setPolicy({ ...policy, schedule_timezone: event.target.value })} /></label></div>{editable && <button onClick={() => void savePolicy()}>Save policy</button>}</section>
    <section id="validation" className="panel"><p className="eyebrow">Validation</p><h2>Conflict analysis</h2><p>Validation checks duplicate or redundant scope seeds, exclusions, and policy completeness before approval.</p><button onClick={() => void validateVersion()}>Validate draft</button>{validation && <ValidationResults validation={validation} />}</section>
    <section id="approval" className="panel"><p className="eyebrow">Approval</p><h2>Authorization summary</h2><div className="approval-summary"><span>Scope<strong>{scope.name}</strong></span><span>Version<strong>{version.version_number}</strong></span><span>Seeds<strong>{version.seeds.length}</strong></span><span>Exclusions<strong>{version.exclusions.length}</strong></span><span>Protocols<strong>{version.policy?.allowed_protocols.join(", ") || "Not configured"}</strong></span><span>Rate<strong>{version.policy ? `${version.policy.max_requests_per_second}/s` : "Not configured"}</strong></span><span>Concurrency<strong>{version.policy ? `${version.policy.max_concurrent_targets} targets / ${version.policy.max_concurrent_requests} requests` : "Not configured"}</strong></span><span>Schedule<strong>{version.policy?.schedule_timezone || "Not configured"}</strong></span><span>Content hash<strong className="hash">{version.content_hash || validation?.content_hash || "Pending validation"}</strong></span></div>{version.state === "DRAFT" && editable && <button disabled={validation !== null && !validation.approvable} onClick={() => void submitVersion()}>Submit for approval</button>}{version.state === "SUBMITTED" && <div className="approval-actions"><label>Decision reason<textarea aria-label="Decision reason" value={approvalReason} onChange={(event) => setApprovalReason(event.target.value)} /></label><label>Approval expiry (UTC)<input aria-label="Approval expiry" type="datetime-local" value={approvalExpiry} onChange={(event) => setApprovalExpiry(event.target.value)} /></label>{canApprove(role) ? <><button onClick={() => void approve("approve")}>Approve version</button><button className="secondary" onClick={() => void approve("reject")}>Reject version</button></> : <p className="permission-note">Only an administrator or owner may approve or reject this submitted version.</p>}</div>}{latestApproval && <p className="approval-record">Latest decision: <strong>{latestApproval.decision}</strong> by {latestApproval.approved_by_user_id} at {formatTime(latestApproval.approved_at)}. Expires: {formatTime(latestApproval.expires_at)}.</p>}</section>
    <section className="incident-panel panel"><p className="eyebrow">Incident control</p><h2>Emergency stop</h2><p>{stopState?.active ? `STOP ACTIVE · ${stopState.level} level · generation ${stopState.stop_generation}` : "No emergency stop recorded in this editor session."}</p>{(role === "admin" || role === "owner") && <div className="action-row">{stopState?.active ? <button className="secondary" onClick={() => void resume()}>Resume scope activity</button> : <button className="danger" onClick={() => setStopDialogOpen(true)}>Emergency stop scope</button>}</div>}</section>
    <section id="history" className="panel"><p className="eyebrow">History</p><h2>Version history and audit trail</h2><div className="version-history">{props.versions.map((item) => <button key={item.id} className={item.id === version.id ? "selected" : ""} onClick={() => props.onVersionChange(item)}>v{item.version_number} · {item.state} · {formatTime(item.created_at)}</button>)}</div><p>Lifecycle actions are recorded with their correlation IDs in the organization audit event store.</p>{scope.status === "ACTIVE" && canApprove(role) && <button className="secondary" onClick={() => void changeScopeStatus("DISABLED")}>Disable scope</button>}{scope.status === "DISABLED" && canApprove(role) && <button onClick={() => void changeScopeStatus("ACTIVE")}>Enable scope</button>}</section>
    {stopDialogOpen && <div className="modal-backdrop" role="presentation"><section className="stop-dialog" role="dialog" aria-modal="true" aria-labelledby="stop-dialog-title"><h2 id="stop-dialog-title">Confirm emergency stop</h2><p>This immediately invalidates permitted work for this scope. Provide an incident reason before confirming.</p><label>Stop reason<textarea aria-label="Stop reason" value={stopReason} onChange={(event) => setStopReason(event.target.value)} autoFocus /></label><div className="action-row"><button className="danger" onClick={() => void confirmStop()}>Confirm emergency stop</button><button className="secondary" onClick={() => setStopDialogOpen(false)}>Cancel</button></div></section></div>}
  </div>;
}

type TargetSectionProps = {
  id: string;
  title: string;
  help: string;
  draft: TargetDraft;
  setDraft(draft: TargetDraft): void;
  preview: string;
  targets: ScopeTarget[];
  editable: boolean;
  exclusion?: boolean;
  submitLabel: string;
  onSubmit(): void;
};

function TargetSection({ id, title, help, draft, setDraft, preview, targets, editable, exclusion = false, submitLabel, onSubmit }: TargetSectionProps) {
  return <section id={id} className="panel"><p className="eyebrow">{title}</p><h2>{title === "Seeds" ? "Authorized targets" : "Targets explicitly excluded"}</h2><p>{help}</p><div className="target-grid"><label>Type<select aria-label={`${title} type`} disabled={!editable} value={draft.targetType} onChange={(event) => setDraft({ ...draft, targetType: event.target.value as TargetType })}><option value="DOMAIN">Domain</option><option value="CIDR">CIDR</option><option value="IP">IP</option><option value="ASN">ASN</option></select></label><label>Match mode<select aria-label={`${title} match mode`} disabled={!editable} value={draft.matchMode} onChange={(event) => setDraft({ ...draft, matchMode: event.target.value as MatchMode })}><option value="EXACT">Exact</option><option value="DOMAIN_AND_SUBDOMAINS">Domain and subdomains</option></select></label><label className="wide">Input<input aria-label={`${title} input`} disabled={!editable} value={draft.rawValue} onChange={(event) => setDraft({ ...draft, rawValue: event.target.value })} placeholder={draft.targetType === "DOMAIN" ? "EXAMPLE.COM." : "192.0.2.10/24"} /></label>{exclusion && <label className="wide">Exclusion reason<textarea aria-label="Exclusion reason" disabled={!editable} value={draft.reason} onChange={(event) => setDraft({ ...draft, reason: event.target.value })} /></label>}</div><div className="normalization-preview" aria-live="polite"><span>Normalization preview</span><strong>{draft.rawValue || "Enter a target"} → {preview || "—"}</strong></div>{editable && <button onClick={onSubmit}>{submitLabel}</button>}<TargetTable targets={targets} /></section>;
}

function TargetTable({ targets }: { targets: ScopeTarget[] }) {
  return <div className="table-wrap"><table><thead><tr><th>Input</th><th>Canonical value</th><th>Type</th><th>Match mode</th><th>State</th></tr></thead><tbody>{targets.length === 0 ? <tr><td colSpan={5}>No entries yet.</td></tr> : targets.map((target) => <tr key={target.id}><td>{target.raw_value}</td><td>{target.canonical_value}</td><td>{target.target_type}</td><td>{target.match_mode}</td><td>{target.warning || "Valid"}{target.reason ? ` · ${target.reason}` : ""}</td></tr>)}</tbody></table></div>;
}

function ValidationResults({ validation }: { validation: ScopeValidation }) {
  const findings = [...validation.errors, ...validation.warnings];
  return <div className="validation-results" aria-live="polite"><p><strong>{validation.approvable ? "READY FOR APPROVAL" : "REQUIRES REVIEW"}</strong> · {validation.content_hash || "Policy or target data incomplete"}</p>{findings.length === 0 ? <p>No conflicts or warnings reported.</p> : findings.map((finding) => <article className={`finding ${finding.severity.toLowerCase()}`} key={`${finding.code}-${finding.message}`}><strong>{finding.severity === "ERROR" ? "BLOCKING ERROR" : finding.severity}</strong><span>{finding.code}: {finding.message}</span></article>)}</div>;
}
