import { useEffect, useState } from "react";
import {
  assetsApi,
  type AssetDetail,
  type AssetEvidence,
  type AssetListFilters,
  type AssetRelationship,
  type AssetSummary,
  type AssetsApi,
  type TimelineItem,
} from "./assetsApi";
import type { GovernanceConnection } from "./scopeApi";

type AssetsProps = { api?: AssetsApi; defaultConnection?: GovernanceConnection };
type AssetBundle = {
  asset: AssetDetail;
  observations: string;
  evidence: AssetEvidence[];
  timeline: TimelineItem[];
  relationships: AssetRelationship[];
};

function message(error: unknown): string { return error instanceof Error ? error.message : "The asset inventory could not be reached."; }
function time(value: string | null): string { return value ? new Date(value).toLocaleString() : "—"; }
function percent(value: number): string { return `${Math.round(value * 100)}%`; }

function Status({ value }: { value: string }) {
  return <span className={`status-pill ${value.toLowerCase()}`}>{value}</span>;
}

export function Assets({ api = assetsApi, defaultConnection }: AssetsProps) {
  const [connection, setConnection] = useState<GovernanceConnection>(defaultConnection ?? { organizationId: "", accessToken: "" });
  const [filters, setFilters] = useState<AssetListFilters>({ offset: 0, limit: 25 });
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [bundle, setBundle] = useState<AssetBundle | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function loadAssets(nextFilters = filters): Promise<void> {
    setLoading(true); setError("");
    try {
      const response = await api.listAssets(connection, nextFilters);
      setAssets(response.items); setTotal(response.page.total);
      setNotice(`Loaded ${response.page.total} asset${response.page.total === 1 ? "" : "s"}.`);
      const routeAssetId = window.location.pathname.match(/^\/assets\/([^/]+)$/)?.[1];
      if (routeAssetId) await selectAsset(routeAssetId);
    } catch (requestError) { setError(message(requestError)); } finally { setLoading(false); }
  }

  async function selectAsset(assetId: string): Promise<void> {
    setSelected(assetId); setBundle(null); setError("");
    try {
      const [asset, observations, evidence, timeline, relationships] = await Promise.all([
        api.getAsset(connection, assetId), api.listObservations(connection, assetId), api.listEvidence(connection, assetId), api.getTimeline(connection, assetId), api.getRelationships(connection, assetId),
      ]);
      setBundle({ asset, observations: `${observations.items.length} loaded observations`, evidence, timeline, relationships });
      window.history.replaceState({}, "", `/assets/${assetId}`);
    } catch (requestError) { setError(message(requestError)); }
  }

  useEffect(() => { if (defaultConnection) void loadAssets(); }, []);
  const currentOffset = filters.offset ?? 0;
  const canPrevious = currentOffset > 0;
  const canNext = currentOffset + (filters.limit ?? 25) < total;

  return <main className="governance-shell assets-shell">
    <header className="governance-header"><div><p className="eyebrow">Exposure360 · Phase 5</p><h1>Canonical asset inventory</h1><p className="header-copy">Review organization-scoped canonical facts, evidence metadata, history, and direct one-hop relationships. This view does not calculate security risk.</p></div><a href="/discovery/jobs">Discovery operations</a></header>
    <section className="panel connection-panel"><div className="section-heading"><div><p className="eyebrow">Connection</p><h2>Organization context</h2></div><span className="foundation-note">API verified</span></div><div className="connection-grid"><label>Organization ID<input aria-label="Organization ID" value={connection.organizationId} onChange={(event) => setConnection({ ...connection, organizationId: event.target.value })} /></label><label className="wide">Access token<input aria-label="Access token" type="password" value={connection.accessToken} onChange={(event) => setConnection({ ...connection, accessToken: event.target.value })} /></label></div></section>
    <section className="panel" aria-labelledby="asset-filter-heading"><div className="section-heading"><div><p className="eyebrow">Inventory</p><h2 id="asset-filter-heading">Filters</h2></div><span className="foundation-note">Server-side</span></div><div className="connection-grid"><label className="wide">Search<input aria-label="Search assets" value={filters.search ?? ""} onChange={(event) => setFilters({ ...filters, search: event.target.value, offset: 0 })} /></label><label>Asset type<select aria-label="Asset type" value={filters.assetType ?? ""} onChange={(event) => setFilters({ ...filters, assetType: event.target.value, offset: 0 })}><option value="">All types</option>{["DOMAIN", "IP", "ASN", "ENDPOINT", "SERVICE"].map((type) => <option key={type}>{type}</option>)}</select></label><label>Lifecycle<select aria-label="Lifecycle state" value={filters.lifecycleState ?? ""} onChange={(event) => setFilters({ ...filters, lifecycleState: event.target.value, offset: 0 })}><option value="">All states</option>{["ACTIVE", "STALE", "RETIRED"].map((state) => <option key={state}>{state}</option>)}</select></label><label>Owner<input aria-label="Owner filter" value={filters.owner ?? ""} onChange={(event) => setFilters({ ...filters, owner: event.target.value, offset: 0 })} /></label><label>Technology<input aria-label="Technology filter" value={filters.technology ?? ""} onChange={(event) => setFilters({ ...filters, technology: event.target.value, offset: 0 })} /></label></div><div className="action-row"><button onClick={() => void loadAssets()} disabled={loading || !connection.organizationId || !connection.accessToken}>{loading ? "Loading…" : "Load assets"}</button></div></section>
    <p aria-live="polite" className="sr-status">{notice}</p>{error && <div className="error-summary" role="alert"><strong>Request not completed</strong><p>{error}</p></div>}
    <section className="panel" aria-labelledby="asset-list-heading"><div className="section-heading"><div><p className="eyebrow">Inventory</p><h2 id="asset-list-heading">Assets</h2></div><span className="foundation-note">{total} result{total === 1 ? "" : "s"}</span></div>{assets.length === 0 ? <p className="empty-state">No canonical assets match the selected organization and filters.</p> : <div className="table-wrap"><table><thead><tr><th>Asset</th><th>Lifecycle</th><th>Owner</th><th>Technologies</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>{assets.map((asset) => <tr key={asset.id}><td><button className="link-button" onClick={() => void selectAsset(asset.id)}><strong>{asset.display_name}</strong><small>{asset.asset_type} · {asset.canonical_key}</small></button></td><td><Status value={asset.lifecycle_state} /></td><td>{asset.primary_owner?.owner_display_name ?? asset.primary_owner?.owner_reference ?? "Unassigned"}</td><td>{asset.top_technologies.length ? asset.top_technologies.map((technology) => <span className="technology-tag" key={technology.id}>{technology.product}{technology.version_value ? ` ${technology.version_value}` : ""} · {percent(technology.confidence)}</span>) : "—"}</td><td>{time(asset.first_seen)}</td><td>{time(asset.last_seen)}</td></tr>)}</tbody></table></div>}<div className="action-row"><button className="secondary" disabled={!canPrevious || loading} onClick={() => { const next = { ...filters, offset: Math.max(0, currentOffset - (filters.limit ?? 25)) }; setFilters(next); void loadAssets(next); }}>Previous</button><button className="secondary" disabled={!canNext || loading} onClick={() => { const next = { ...filters, offset: currentOffset + (filters.limit ?? 25) }; setFilters(next); void loadAssets(next); }}>Next</button></div></section>
    {selected && <AssetDetail bundle={bundle} api={api} connection={connection} onError={setError} onNotice={setNotice} />}
  </main>;
}

function AssetDetail({ bundle, api, connection, onError, onNotice }: { bundle: AssetBundle | null; api: AssetsApi; connection: GovernanceConnection; onError: (value: string) => void; onNotice: (value: string) => void }) {
  if (!bundle) return <section className="panel"><h2>Loading asset detail</h2><p aria-live="polite">Retrieving organization-authorized metadata.</p></section>;
  const { asset, evidence, timeline, relationships } = bundle;
  async function download(evidenceItem: AssetEvidence): Promise<void> { try { const reference = await api.authorizeEvidenceDownload(connection, evidenceItem.id); onNotice(`Authorized evidence download: ${reference.filename}.`); window.open(reference.url, "_blank", "noopener,noreferrer"); } catch (requestError) { onError(message(requestError)); } }
  return <section className="panel asset-detail" aria-labelledby="asset-detail-heading"><div className="section-heading"><div><p className="eyebrow">Asset detail</p><h2 id="asset-detail-heading">{asset.display_name}</h2></div><Status value={asset.lifecycle_state} /></div><dl className="profile-grid"><div><dt>Canonical identity</dt><dd>{asset.canonical_key}</dd></div><div><dt>First seen</dt><dd>{time(asset.first_seen)}</dd></div><div><dt>Last seen</dt><dd>{time(asset.last_seen)}</dd></div><div><dt>Observation count</dt><dd>{asset.observation_count}</dd></div></dl><details open><summary>Identifiers</summary><ul>{asset.identifiers.map((item) => <li key={item.id}>{item.identifier_type}: {item.canonical_value} · {item.source}</li>) || <li>No identifiers are recorded.</li>}</ul></details><details open><summary>Ownership</summary><ul>{asset.ownership_claims.map((claim) => <li key={claim.id}>{claim.owner_display_name ?? claim.owner_reference} · {claim.claim_type} · {percent(claim.confidence)}</li>) || <li>Unassigned.</li>}</ul></details><details open><summary>Technologies</summary><ul>{asset.technology_fingerprints.map((technology) => <li key={technology.id}>{technology.product}{technology.version_value ? ` ${technology.version_value}` : ""} · {percent(technology.confidence)} · {technology.rule_id} v{technology.rule_version}</li>) || <li>No technology fingerprint is recorded.</li>}</ul></details><details open><summary>Observations</summary><p>{bundle.observations}</p></details><details open><summary>Evidence metadata</summary>{evidence.length === 0 ? <p>No evidence metadata is recorded.</p> : <ul>{evidence.map((item) => <li key={item.id}><strong>{item.evidence_type}</strong> · {item.media_type} · {item.size_bytes} bytes · SHA-256 {item.sha256}<button className="secondary" onClick={() => void download(item)}>Request authorized download</button></li>)}</ul>}</details><details open><summary>History</summary><ul>{timeline.map((event) => <li key={`${event.event_type}-${event.resource_id}`}>{time(event.occurred_at)} · {event.event_type} · {event.summary}</li>) || <li>No historical events are recorded.</li>}</ul></details><details open><summary>Direct relationships</summary><ul>{relationships.map((relationship) => <li key={`${relationship.relationship_type}-${relationship.target_asset_id}`}>{relationship.relationship_type} → {relationship.target_asset_id}</li>) || <li>No direct relationships are recorded.</li>}</ul></details></section>;
}
