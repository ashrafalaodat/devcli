import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { PageProps, Session } from '../types';
import { Button, Contact, DataTable, Pill, date } from '../components/ui';
import { parseLabels } from '../lib/labels';

export default function Overview({
  data,
  api,
  refresh,
  notify,
  navigate,
  selectedBookingCluster,
  bookingRequestVersion,
}: PageProps) {
  const [selectedCluster, setSelectedCluster] = useState('');
  const [selector, setSelector] = useState('');
  const [booking, setBooking] = useState(false);
  const requestKey = useRef<string | null>(null);
  const { profile, clusters, sessions, session } = data;
  const primary = profile.primary_session;
  const ownSessions = sessions.filter(item => item.owner === session.owner_id);
  const activeSessions = ownSessions.filter(item => item.state === 'ACTIVE');
  const teamSessions = sessions.filter(item => item.state === 'ACTIVE');
  const blocked = profile.active_bookings >= profile.max_bookings;
  const cluster = (id: string) => clusters.find(item => item.id === id);
  const clusterName = (id: string) => cluster(id)?.name || id;

  useEffect(() => {
    if (selectedBookingCluster !== undefined) {
      setSelectedCluster(selectedBookingCluster);
      requestKey.current = null;
    }
  }, [selectedBookingCluster, bookingRequestVersion]);

  // Deregistration may remove a previously chosen entry during a refresh.
  useEffect(() => {
    if (selectedCluster && !clusters.some(item => item.id === selectedCluster)) {
      setSelectedCluster('');
      requestKey.current = null;
    }
  }, [clusters, selectedCluster]);

  async function book(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (booking || blocked) return;
    setBooking(true);
    try {
      const body = { cluster: selectedCluster, selector: parseLabels(selector) };
      const key = requestKey.current || crypto.randomUUID();
      requestKey.current = key;
      const result = await api<Session>('/v1/sessions', {
        method: 'POST',
        body,
        headers: { 'Idempotency-Key': key },
      });
      if (requestKey.current === key) requestKey.current = null;
      await refresh();
      notify(`Booked ${clusterName(result.cluster)}. Session ${result.id}.`);
    } catch (error) {
      notify(error instanceof Error ? error.message : 'The booking could not be completed.', true);
    } finally {
      setBooking(false);
    }
  }

  async function selectPrimary(item: Session) {
    if (!window.confirm(`Use ${clusterName(item.cluster)} as your primary cluster on all devices? Open connections to the previous primary will close.`)) return;
    await api('/v1/primary', { method: 'POST', body: { cluster: item.cluster } });
    await refresh();
    notify(`Primary cluster changed to ${clusterName(item.cluster)}. Keep using the same kubeconfig.`);
  }

  async function share(item: Session, shareable: boolean) {
    await api(`/v1/sessions/${encodeURIComponent(item.id)}/share`, {
      method: 'POST',
      body: { shareable: !shareable },
    });
    await refresh();
    notify(shareable ? 'New shared bookings are now disabled.' : 'Sharing enabled. Other developers can join this cluster.');
  }

  async function stop(item: Session) {
    if (!window.confirm(`Release your booking on ${clusterName(item.cluster)}? If it is primary, your oldest remaining booking becomes primary. A token with automatic booking enabled can reserve again on its next Kubernetes request. Kubernetes workloads will remain.`)) return;
    await api(`/v1/sessions/${encodeURIComponent(item.id)}/stop`, { method: 'POST' });
    await refresh();
    notify('Booking released. Personal tokens and workloads were retained; enabled automatic booking tokens can reserve again on their next Kubernetes request.');
  }

  const metrics = [
    ['Your bookings / limit', `${profile.active_bookings} / ${profile.max_bookings}`, '◫'],
    ['Available clusters', clusters.filter(item => item.available).length, '◇'],
    ['Team members active', new Set(teamSessions.map(item => item.owner)).size, '↗'],
  ] as const;

  return <>
    <div className="page-heading">
      <div><div className="eyebrow">WORKSPACE</div><h1 id="overview-title">Your environments</h1><p>Reserve a whole cluster. Share it when you choose.</p></div>
      <Button id="refresh-overview" className="button secondary" onClick={refresh} notify={notify}>↻ Refresh</Button>
    </div>
    <div id="metrics" className="metrics">
      {metrics.map(([label, count, icon]) => <div className="metric" key={label}>
        <div><div className="metric-label">{label}</div><div className="metric-value">{count}</div></div>
        <div className="metric-icon">{icon}</div>
      </div>)}
    </div>
    <section id="primary-summary" className="panel primary-summary" aria-label="Primary cluster">
      <div className="section-heading"><h2>Your primary cluster</h2><Pill tone={primary ? 'success' : 'neutral'}>{primary ? 'Selected' : 'No cluster booked'}</Pill></div>
      {primary ? <><h3>{clusterName(primary.cluster)}</h3><p>Your kubeconfig routes to this cluster. Switching primary affects new commands in every terminal and device; open connections to the previous primary are closed.</p></> : <p>No cluster is booked. Book an available cluster to start using kubectl. Your first booking becomes primary automatically.</p>}
      <Button className="button secondary" onClick={() => navigate('access')}>Get reusable kubeconfig</Button>
    </section>
    <section className="panel booking-panel" aria-labelledby="booking-title">
      <div><h2 id="booking-title">Book a cluster</h2><p>A free cluster is exclusive to you. Existing holders must enable sharing before anyone can join.</p></div>
      <form id="booking-form" className="form-grid" onSubmit={book} onChange={() => { requestKey.current = null; }}>
        <label>Cluster<select id="booking-cluster" name="cluster" value={selectedCluster} onChange={event => setSelectedCluster(event.target.value)}>
          <option value="">Choose automatically</option>
          {clusters.map(item => <option key={item.id} value={item.id}>{item.name}{item.maintenance ? ' · maintenance' : !item.available ? ' · reserved' : ''}</option>)}
        </select></label>
        <label>Required labels<input name="selector" placeholder="region=eu,type=test" autoComplete="off" value={selector} onChange={event => setSelector(event.target.value)} /><span className="field-help">Optional, comma-separated key=value pairs</span></label>
        <button id="booking-submit" className="button primary align-start" type="submit" disabled={blocked || booking} data-limit-blocked={String(blocked)}>Book cluster <span aria-hidden="true">→</span></button>
      </form>
      <p id="booking-limit-help" className="field-help" aria-live="polite">{blocked
        ? `You hold ${profile.active_bookings} of ${profile.max_bookings} allowed clusters. Release a booking or ask an administrator to increase your limit.`
        : `You can hold up to ${profile.max_bookings} cluster${profile.max_bookings === 1 ? '' : 's'}. Your first booking becomes primary; additional bookings do not change it.`}</p>
      <p className="field-help">Using a cluster keeps that booking reserved. After activity stops, it is released after the administrator’s inactivity period. Only the cluster being used is extended; workloads remain.</p>
    </section>
    <div className="section-heading"><h2>Your active bookings</h2><span id="booking-count" className="pill neutral">{activeSessions.length} / {profile.max_bookings} held</span></div>
    <div id="my-bookings" className="booking-list">
      {!activeSessions.length && <div className="empty"><strong>No cluster is booked.</strong><span>Book an available cluster above. Your first booking becomes primary.</span></div>}
      {activeSessions.map(item => {
        const selected = primary?.id === item.id;
        const registeredCluster = cluster(item.cluster);
        const shareable = registeredCluster?.shareable || false;
        return <article key={item.id} data-session-id={item.id} className={`booking-card${selected ? ' primary-booking' : ''}`}>
          <div className="card-top">
            <div className="card-title"><span className="cluster-mark">◇</span><div><h3>{clusterName(item.cluster)}</h3><small>{item.cluster}</small></div></div>
            <div className="labels">{selected && <Pill tone="success">Primary</Pill>}<Pill tone={shareable ? 'warning' : 'neutral'}>{shareable ? 'Shared' : 'Exclusive'}</Pill></div>
          </div>
          <div className="details">
            <div><span className="detail-label">Auto-release</span><span className="text-break booking-auto-release">{date(item.expires_at)}</span></div>
            <div><span className="detail-label">Last activity</span><span className="text-break booking-last-activity">{item.last_activity_at ? date(item.last_activity_at) : 'No requests yet'}</span></div>
          </div>
          <div className="card-actions">
            {!selected && <Button className="button primary small" onClick={() => selectPrimary(item)} notify={notify}>Make primary</Button>}
            {registeredCluster?.controller_session === item.id && <Button className="button secondary small" onClick={() => share(item, shareable)} notify={notify}>{shareable ? 'Disable sharing' : 'Allow sharing'}</Button>}
            <Button className="button danger small" onClick={() => stop(item)} notify={notify}>Stop</Button>
          </div>
          <span className="mono booking-id">{item.id}</span>
        </article>;
      })}
    </div>
    <div className="section-heading"><h2>Team bookings</h2><span className="subtle">Reach out before sharing an environment</span></div>
    <div id="team-bookings" className="panel table-wrap"><DataTable
      headers={['Cluster', 'Developer / contact', 'Access', 'Auto-release']}
      rows={teamSessions.map(item => [clusterName(item.cluster), <Contact person={item} />, <Pill tone={cluster(item.cluster)?.shareable ? 'warning' : 'neutral'}>{cluster(item.cluster)?.shareable ? 'Shared' : 'Exclusive'}</Pill>, date(item.expires_at)])}
      emptyText="No active team bookings."
    /></div>
    <details className="panel history"><summary>Booking history</summary><div id="booking-history" className="table-wrap"><DataTable
      headers={['Cluster', 'Booking', 'State', 'Ended']}
      rows={ownSessions.filter(item => item.state !== 'ACTIVE').slice().reverse().map(item => [clusterName(item.cluster), item.id, <Pill>{item.state}</Pill>, date(item.ended_at)])}
      emptyText="No previous bookings."
    /></div></details>
  </>;
}
