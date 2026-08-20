import { useEffect, useState } from "react";
import type { GovernanceConnection } from "./scopeApi";
import type { DiscoveryApi, DiscoveryDeadLetter, DiscoveryEvent, DiscoveryJob, DiscoveryStage } from "./discoveryApi";

type DiscoveryJobDetailProps = {
  api: DiscoveryApi;
  connection: GovernanceConnection;
  job: DiscoveryJob;
  onJobChange: (job: DiscoveryJob) => void;
  onError: (message: string) => void;
};

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The discovery request could not be completed.";
}

function dateTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function stateClass(state: string): string {
  return `status-pill discovery-state ${state.toLowerCase()}`;
}

export function DiscoveryJobDetail({ api, connection, job, onJobChange, onError }: DiscoveryJobDetailProps) {
  const [stages, setStages] = useState<DiscoveryStage[]>([]);
  const [events, setEvents] = useState<DiscoveryEvent[]>([]);
  const [deadLetters, setDeadLetters] = useState<DiscoveryDeadLetter[]>([]);
  const [loading, setLoading] = useState(true);
  const [cancelling, setCancelling] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    void Promise.all([api.getJob(connection, job.id), api.listStages(connection, job.id), api.listEvents(connection, job.id), api.listDeadLetters(connection, job.id)])
      .then(([loadedJob, loadedStages, loadedEvents, loadedDeadLetters]) => {
        if (!active) return;
        onJobChange(loadedJob);
        setStages(loadedStages);
        setEvents(loadedEvents);
        setDeadLetters(loadedDeadLetters);
      })
      .catch((error: unknown) => active && onError(errorMessage(error)))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [api, connection, job.id]);

  async function cancel(): Promise<void> {
    setCancelling(true);
    try {
      onJobChange(await api.cancelJob(connection, job.id));
    } catch (error) {
      onError(errorMessage(error));
    } finally {
      setCancelling(false);
    }
  }

  const cancellable = job.state === "QUEUED" || job.state === "RUNNING" || job.state === "CANCELLING";
  return (
    <section className="panel discovery-detail" aria-labelledby="discovery-detail-heading">
      <div className="section-heading">
        <div><p className="eyebrow">Discovery job</p><h2 id="discovery-detail-heading">Job progress</h2></div>
        <span className={stateClass(job.state)}>{job.state}</span>
      </div>
      <p className="job-identifier">{job.id}</p>
      <div className="discovery-summary">
        <span><small>Current stage</small><strong>{job.current_stage ?? "Waiting for worker"}</strong></span>
        <span><small>Processed</small><strong>{job.counts.processed}</strong></span>
        <span><small>Failures</small><strong>{job.counts.failed}</strong></span>
        <span><small>Started</small><strong>{dateTime(job.started_at)}</strong></span>
      </div>
      {job.indeterminate ? (
        <p className="indeterminate-progress" role="status">Progress is indeterminate because this source does not provide a known total. {job.counts.processed} items have been processed.</p>
      ) : (
        <progress aria-label="Discovery progress" max={job.known_total ?? 0} value={job.counts.processed} />
      )}
      <div className="action-row">
        <button className="danger" onClick={() => void cancel()} disabled={!cancellable || cancelling || job.state === "CANCELLING"}>
          {job.state === "CANCELLING" ? "Cancellation requested" : "Cancel discovery job"}
        </button>
      </div>
      {loading ? <p aria-live="polite">Loading job evidence…</p> : (
        <>
          <h3>Stage progress</h3>
          <div className="table-wrap"><table><thead><tr><th>Stage</th><th>State</th><th>Processed</th><th>Successful</th><th>Failed</th><th>Queued</th></tr></thead><tbody>
            {stages.map((stage) => <tr key={stage.stage}><td>{stage.stage}</td><td><span className={stateClass(stage.state)}>{stage.state}</span></td><td>{stage.processed}</td><td>{stage.succeeded}</td><td>{stage.failed}</td><td>{stage.indeterminate ? "—" : stage.queued}</td></tr>)}
          </tbody></table></div>
          {deadLetters.length > 0 && <div className="error-summary"><strong>Recovery attention required</strong>{deadLetters.map((item) => <p key={item.id}>{item.stage}: {item.safe_message} ({item.attempts} attempts)</p>)}</div>}
          <details className="event-log"><summary>Event log ({events.length})</summary><ul>{events.map((event) => <li key={event.id}>{dateTime(event.created_at)} — {event.event_type}{event.stage ? ` (${event.stage})` : ""}</li>)}</ul></details>
        </>
      )}
    </section>
  );
}
