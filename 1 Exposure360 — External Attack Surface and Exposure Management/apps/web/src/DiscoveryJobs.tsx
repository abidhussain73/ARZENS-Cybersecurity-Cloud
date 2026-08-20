import { useEffect, useState } from "react";
import { DiscoveryJobDetail } from "./DiscoveryJobDetail";
import { discoveryApi, type DiscoveryApi, type DiscoveryJob } from "./discoveryApi";
import type { GovernanceConnection } from "./scopeApi";

type DiscoveryJobsProps = { api?: DiscoveryApi; defaultConnection?: GovernanceConnection };

function errorMessage(error: unknown): string { return error instanceof Error ? error.message : "The discovery service could not be reached."; }
function stateClass(state: string): string { return `status-pill discovery-state ${state.toLowerCase()}`; }
function time(value: string | null): string { return value ? new Date(value).toLocaleString() : "—"; }

export function DiscoveryJobs({ api = discoveryApi, defaultConnection }: DiscoveryJobsProps) {
  const [connection, setConnection] = useState<GovernanceConnection>(defaultConnection ?? { organizationId: "", accessToken: "" });
  const [connected, setConnected] = useState(Boolean(defaultConnection));
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [selected, setSelected] = useState<DiscoveryJob | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refresh(): Promise<void> {
    setLoading(true); setError("");
    try {
      const loaded = await api.listJobs(connection);
      setJobs(loaded); setSelected((current) => loaded.find((job) => job.id === current?.id) ?? loaded[0] ?? null);
      setConnected(true); setNotice(`Loaded ${loaded.length} discovery job${loaded.length === 1 ? "" : "s"}.`);
    } catch (requestError) { setError(errorMessage(requestError)); } finally { setLoading(false); }
  }

  useEffect(() => { if (defaultConnection) void refresh(); }, []);
  function updateJob(job: DiscoveryJob): void { setSelected(job); setJobs((items) => items.map((item) => item.id === job.id ? job : item)); }

  return <main className="governance-shell discovery-shell">
    <header className="governance-header"><div><p className="eyebrow">Exposure360 · Phase 3</p><h1>Discovery operations</h1><p className="header-copy">Review asynchronous discovery jobs, truthful progress, collection stages, recovery signals, and cancellation state. Results remain version-scoped discovery evidence, not canonical assets.</p></div><a href="/settings/scopes">Scope administration</a></header>
    <section className="panel connection-panel"><div className="section-heading"><div><p className="eyebrow">Connection</p><h2>Organization context</h2></div><span className="foundation-note">API verified</span></div><div className="connection-grid"><label>Organization ID<input aria-label="Organization ID" value={connection.organizationId} onChange={(event) => setConnection({ ...connection, organizationId: event.target.value })} /></label><label className="wide">Access token<input aria-label="Access token" type="password" value={connection.accessToken} onChange={(event) => setConnection({ ...connection, accessToken: event.target.value })} /></label></div><div className="action-row"><button onClick={() => void refresh()} disabled={loading || !connection.organizationId || !connection.accessToken}>{loading ? "Refreshing…" : "Load discovery jobs"}</button></div></section>
    <p aria-live="polite" className="sr-status">{notice}</p>{error && <div className="error-summary" role="alert"><strong>Request not completed</strong><p>{error}</p></div>}
    {connected && <div className="discovery-layout"><section className="panel discovery-list" aria-labelledby="discovery-list-heading"><div className="section-heading"><div><p className="eyebrow">Jobs</p><h2 id="discovery-list-heading">Discovery queue</h2></div><span className="foundation-note">{jobs.length} total</span></div>{jobs.length === 0 ? <p className="empty-state">No discovery jobs are recorded for this organization.</p> : <div className="job-rows">{jobs.map((job) => <button className={`job-row ${selected?.id === job.id ? "selected" : ""}`} key={job.id} onClick={() => setSelected(job)}><span className={stateClass(job.state)}>{job.state}</span><strong>{job.current_stage ?? "Waiting for worker"}</strong><small>{job.counts.processed} processed · {time(job.created_at)}</small></button>)}</div>}</section>{selected ? <DiscoveryJobDetail api={api} connection={connection} job={selected} onJobChange={updateJob} onError={setError} /> : <section className="panel"><h2>Choose a discovery job</h2><p>Load jobs, then select one to inspect progress and guarded collection evidence.</p></section>}</div>}
  </main>;
}
