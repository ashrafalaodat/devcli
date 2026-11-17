import type {ClusterHealth as Health} from '../types';
import {Pill, date} from './ui';

export function healthStateLabel(health?: Health): string {
  if (!health || health.mode === 'disabled') return 'Monitoring off';
  return {UNKNOWN: 'Not checked', RECOVERING: 'Confirming recovery', PASSING: 'Checks passing', FAILING: 'Check failed', STALE: 'Checks stale'}[health.state] || 'Not checked';
}

export function ClusterHealth({health, detail = false}: {health?: Health; detail?: boolean}) {
  const enabled = health && health.mode !== 'disabled';
  const tone = enabled && health.state === 'PASSING' ? 'success' : enabled && ['FAILING', 'STALE'].includes(health.state) ? 'warning' : 'neutral';
  return <div className="cluster-health">
    <Pill tone={tone}>{healthStateLabel(health)}</Pill>
    {enabled ? <>
      <small>{health.mode === 'observe' ? 'Observe only · placement unchanged' : 'Checks required for new bookings'}</small>
      <small>{health.check_pending ? 'Check queued or running' : health.checked_at ? `Checked ${date(health.checked_at)}` : 'Awaiting a completed check'}</small>
      {health.reason_code && health.reason_code !== 'checks_passed' && <small className="health-reason">{health.reason_code.replaceAll('_', ' ')}</small>}
      {detail && <>
        <small>{health.profile === 'discovery-only.v1' ? 'API discovery · readiness not checked' : 'API discovery and readiness'}</small>
        <small>{health.duration_ms} ms · {health.max_age_seconds}s freshness window</small>
        <small>Identity and workload permissions are not verified by these checks.</small>
        {health.last_success_at && <small>Last successful cycle: {date(health.last_success_at)}</small>}
      </>}
    </> : <small>Cluster connectivity has not been validated by monitoring.</small>}
  </div>;
}
