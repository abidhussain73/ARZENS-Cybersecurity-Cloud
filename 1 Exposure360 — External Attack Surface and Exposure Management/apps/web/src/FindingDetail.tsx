import { useState } from "react";
import type { GovernanceConnection } from "./scopeApi";
import type { FindingDetail as FindingDetailRecord, FindingEvidence, FindingsApi, TimelineEntry } from "./findingsApi";

type Props = { finding: FindingDetailRecord; evidence: FindingEvidence[]; history: TimelineEntry[]; api: FindingsApi; connection: GovernanceConnection; onRefresh: () => Promise<void>; onError: (value: string) => void; };
const time = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : "—";
const percent = (value: number) => `${Math.round(value * 100)}%`;
const value = (input: unknown) => Array.isArray(input) ? input.join(", ") : typeof input === "object" ? "Structured metadata" : String(input ?? "—");

function actions(state: string): Array<[string, string]> {
  if (state === "OPEN") return [["acknowledge", "Acknowledge"], ["start", "Start work"], ["exception", "Create exception"]];
  if (state === "ACKNOWLEDGED") return [["start", "Start work"], ["reopen", "Reopen"], ["exception", "Create exception"]];
  if (state === "IN_PROGRESS") return [["resolve-pending-verification", "Resolve pending verification"], ["reopen", "Reopen"], ["exception", "Create exception"]];
  if (state === "RESOLVED_PENDING_VERIFICATION") return [["close", "Close with verification"], ["reopen", "Reopen"]];
  if (state === "EXCEPTION") return [["reopen", "Reopen"], ["start", "Start work"]];
  return state === "CLOSED" ? [["reopen", "Reopen"]] : [];
}

export function FindingDetail({ finding, evidence, history, api, connection, onRefresh, onError }: Props) {
  const [reason, setReason] = useState(""); const [expiry, setExpiry] = useState(""); const [verification, setVerification] = useState(""); const [working, setWorking] = useState(false);
  async function transition(action: string): Promise<void> {
    setWorking(true);
    const payload = { ...(reason ? { reason } : {}), ...(expiry ? { expires_at: expiry } : {}), ...(verification ? { verification_reference: verification } : {}) };
    try { await api.transitionFinding(connection, finding.id, action, payload); await onRefresh(); }
    catch (error) { onError(error instanceof Error ? error.message : "Finding workflow action was not completed."); } finally { setWorking(false); }
  }
  async function download(evidenceItem: FindingEvidence): Promise<void> {
    try { const reference = await api.authorizeEvidenceDownload(connection, evidenceItem.evidence_id); window.open(reference.url, "_blank", "noopener,noreferrer"); }
    catch (error) { onError(error instanceof Error ? error.message : "Evidence integrity or authorization check failed."); }
  }
  return <section className="panel asset-detail" aria-labelledby="finding-detail-heading"><div className="section-heading"><div><p className="eyebrow">Finding detail</p><h2 id="finding-detail-heading">{finding.title}</h2></div><span className={`status-pill ${finding.state.toLowerCase()}`}>{finding.state}</span></div><dl className="profile-grid"><div><dt>Severity</dt><dd>{finding.severity}</dd></div><div><dt>Confidence</dt><dd>{percent(finding.confidence)}</dd></div><div><dt>First seen</dt><dd>{time(finding.first_seen)}</dd></div><div><dt>Last seen</dt><dd>{time(finding.last_seen)}</dd></div></dl><details open><summary>Overview</summary><p>{finding.description}</p></details><details open><summary>Affected Asset</summary><p>{String(finding.asset.display_name)} · {String(finding.asset.canonical_key)}</p></details><details open><summary>Rule</summary><p>{finding.rule_id} v{finding.rule_version} · {finding.category}</p><p className="foundation-note">Rule hash: {finding.rule_hash}</p></details><details open><summary>Evidence</summary>{evidence.length ? <ul>{evidence.map(item => <li key={item.id}><strong>{item.evidence_type}</strong> · {item.media_type} · SHA-256 {item.sha256}<button className="secondary" onClick={() => void download(item)}>Request authorized download</button></li>)}</ul> : <p>No evidence metadata is available.</p>}</details><details open><summary>History</summary><ul>{history.map(item => <li key={item.id}>{time(item.occurred_at)} · {item.event_type} · {value(item.to_state ?? item.matched)}</li>) || <li>No history is available.</li>}</ul></details><details open><summary>Exception</summary>{finding.exception ? <p>{finding.exception.reason ?? "No reason supplied"} · expires {time(finding.exception.expires_at)}</p> : <p>No active exception.</p>}<label>Exception reason<textarea aria-label="Exception reason" value={reason} onChange={event => setReason(event.target.value)} /></label><label>Exception expiry<input aria-label="Exception expiry" type="datetime-local" value={expiry} onChange={event => setExpiry(event.target.value)} /></label></details><section aria-label="Finding workflow actions"><label>Verification reference<input aria-label="Verification reference" value={verification} onChange={event => setVerification(event.target.value)} /></label><div className="action-row">{actions(finding.state).map(([action, label]) => <button key={action} className={action === "exception" ? "secondary" : ""} disabled={working || (action === "exception" && (!reason || !expiry)) || (action === "close" && !verification)} onClick={() => void transition(action)}>{label}</button>)}</div></section></section>;
}
