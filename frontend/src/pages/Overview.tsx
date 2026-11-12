import {useEffect, useRef, useState} from 'react';
import type {FormEvent} from 'react';
import type {PageProps, Session} from '../types';
import {Button, Contact, DataTable, FormError, Pill, errorMessage} from '../components/ui';
import {Dialog, useConfirm} from '../components/Dialog';
import {Icon} from '../components/Icon';
import {parseLabels} from '../lib/labels';
import {allocation, ClusterName, Labels, relative, timestamp} from './developer-utils';

export default function Overview({data, api, refresh, notify, navigate, selectedBookingCluster, bookingRequestVersion}: PageProps) {
  const [selectedCluster, setSelectedCluster] = useState('');
  const [selector, setSelector] = useState('');
  const [bookingOpen, setBookingOpen] = useState(false);
  const [booking, setBooking] = useState(false);
  const [error, setError] = useState('');
  const [selectorError, setSelectorError] = useState('');
  const requestKey = useRef<string | null>(null);
  const submitting = useRef(false);
  const confirm = useConfirm();
  const {profile, clusters, sessions, session} = data;
  const primary = profile.primary_session;
  const ownSessions = sessions.filter(item => item.owner === session.owner_id);
  const activeSessions = ownSessions.filter(item => item.state === 'ACTIVE');
  const teamSessions = sessions.filter(item => item.state === 'ACTIVE' && item.owner !== session.owner_id);
  const blocked = profile.active_bookings >= profile.max_bookings;
  const cluster = (id: string) => clusters.find(item => item.id === id);
  const clusterName = (id: string) => cluster(id)?.name || id;
  const primaryCluster = primary ? cluster(primary.cluster) : undefined;
  const requestedCluster = cluster(selectedCluster);
  const joining = Boolean(requestedCluster?.participants?.length);

  useEffect(() => {
    if (!bookingRequestVersion) return;
    setSelectedCluster(selectedBookingCluster ?? '');
    setSelector('');
    setError('');
    setSelectorError('');
    requestKey.current = null;
    setBookingOpen(true);
  }, [selectedBookingCluster, bookingRequestVersion]);

  useEffect(() => {
    if (selectedCluster && !clusters.some(item => item.id === selectedCluster)) {
      setSelectedCluster('');
      requestKey.current = null;
      setError('That cluster is no longer registered. Choose another cluster or select automatically.');
    }
  }, [clusters, selectedCluster]);

  function openBooking() {
    setError('');
    setSelectorError('');
    setBookingOpen(true);
  }

  function changeBooking() {
    requestKey.current = null;
    setError('');
    setSelectorError('');
  }

  async function book(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current || blocked) return;
    let labels: Record<string, string>;
    try {labels = parseLabels(selector);} catch (problem) {
      const message = errorMessage(problem);
      setSelectorError(message);
      setError('Check the required labels and try again.');
      return;
    }
    submitting.current = true;
    setBooking(true);
    setError('');
    setSelectorError('');
    const key = requestKey.current || crypto.randomUUID();
    requestKey.current = key;
    try {
      const result = await api<Session>('/v1/sessions', {method: 'POST', body: {cluster: selectedCluster, selector: labels}, headers: {'Idempotency-Key': key}});
      if (requestKey.current === key) requestKey.current = null;
      // A successful allocation must never be retried because its follow-up
      // read failed. Close first and report refresh failure separately.
      setBookingOpen(false);
      setSelectedCluster('');
      setSelector('');
      try {await refresh();} catch {
        notify(`Booked ${clusterName(result.cluster)}. Refresh the workspace to load its latest status.`, true);
        return;
      }
      notify(`Booked ${clusterName(result.cluster)}. Session ${result.id}.`);
    } catch (problem) {
      setError(errorMessage(problem));
      // The same key is retained for an unchanged retry, including a response
      // lost after the backend already committed the reservation.
      try {await refresh();} catch { /* Preserve the allocation error. */ }
    } finally {
      submitting.current = false;
      setBooking(false);
    }
  }

  async function selectPrimary(item: Session) {
    if (!await confirm({title: `Use ${clusterName(item.cluster)} as primary?`, description: 'New Kubernetes commands will use this cluster in every terminal and device using your identity.', confirmLabel: 'Switch primary', children: <div className="notice"><Icon name="info"/><p>Open watch, exec and port-forward connections to the previous primary will close. Existing Kubernetes operations and workloads are not migrated.</p></div>})) return;
    await api('/v1/primary', {method: 'POST', body: {cluster: item.cluster}});
    await refresh();
    notify(`Primary cluster changed to ${clusterName(item.cluster)}. Your kubeconfig stays the same.`);
  }

  async function share(item: Session, shareable: boolean) {
    const registered = cluster(item.cluster);
    if (!await confirm({title: shareable ? `Disable new joins on ${clusterName(item.cluster)}?` : `Allow sharing on ${clusterName(item.cluster)}?`, description: shareable ? 'Existing holders keep their bookings. New developers will no longer be able to join.' : `Other approved developers may join, up to ${registered?.max_participants ?? 2} holders in total. They will see your name and contact details for coordination.`, confirmLabel: shareable ? 'Disable sharing' : 'Allow sharing'})) return;
    await api(`/v1/sessions/${encodeURIComponent(item.id)}/share`, {method: 'POST', body: {shareable: !shareable}});
    await refresh();
    notify(shareable ? 'New shared bookings are disabled. Current holders retain access.' : 'Sharing enabled. Other developers can join this cluster.');
  }

  async function stop(item: Session) {
    if (!await confirm({title: `Release ${clusterName(item.cluster)}?`, description: 'Your gateway access to this booking ends. If it is primary, your oldest remaining active booking becomes primary.', confirmLabel: 'Release booking', danger: true, children: <ul className="consequence-list"><li>Kubernetes workloads and data remain.</li><li>Your personal tokens remain valid.</li><li>A token with automatic booking enabled can reserve again on its next Kubernetes request.</li></ul>})) return;
    await api(`/v1/sessions/${encodeURIComponent(item.id)}/stop`, {method: 'POST'});
    await refresh();
    notify('Booking released. Personal tokens and workloads remain; an enabled automatic-booking token can reserve again.');
  }

  return <>
    <div className="page-title page-heading"><div><div className="eyebrow">YOUR WORKSPACE</div><h1 id="overview-title">Ready for your next build.</h1><p>Your clusters, access and team activity in one place.</p></div><Button className="button primary" onClick={openBooking} disabled={blocked} aria-describedby={blocked ? 'booking-limit-help' : undefined}><Icon name="plus"/>Book a cluster</Button></div>
    <div className="workspace-layout workspace-grid">
      <section id="primary-summary" className="panel primary-panel" aria-label="Primary cluster">
        <div className="panel-top"><span className="eyebrow">CURRENT PRIMARY</span><Pill tone={primaryCluster?.shareable ? 'brand' : 'neutral'}>{primary ? allocation(primaryCluster) : 'No cluster booked'}</Pill></div>
        {primary ? <>
          <div className="primary-name"><Icon name="cluster"/><div><h2>{clusterName(primary.cluster)}</h2><Labels cluster={primaryCluster}/></div><Pill tone="brand">Your primary</Pill></div>
          <p className="primary-description">Your kubectl commands route here, across all terminals and devices.</p>
          <div className="primary-details"><div><small>Auto-release if activity stops</small><strong className="booking-auto-release">{relative(primary.expires_at, true)} <span>· {timestamp(primary.expires_at)}</span></strong></div><div><small>Last activity</small><strong className="booking-last-activity">{relative(primary.last_activity_at)} <span>· {timestamp(primary.last_activity_at)}</span></strong></div></div>
          <div className="panel-bottom primary-actions"><Button className="button primary" onClick={() => navigate('access')}><Icon name="key"/>Get kubeconfig</Button>{primaryCluster?.controller_session === primary.id && <Button onClick={() => share(primary, primaryCluster.shareable)} notify={notify}><Icon name="people"/>{primaryCluster.shareable ? 'Disable sharing' : 'Allow sharing'}</Button>}<span className="small muted">{primaryCluster?.controller_session === primary.id ? 'You control new shared joins.' : 'Sharing is controlled by the current holder.'}</span></div>
        </> : <div className="primary-empty"><Icon name="cluster"/><h2>Your workspace is waiting.</h2><p>Book an available cluster to start. Your first booking becomes primary automatically.</p><Button className="button primary" onClick={openBooking} disabled={blocked}>Book your first cluster</Button><Button className="button subtle" onClick={() => navigate('access')}>Set up access first</Button></div>}
      </section>
      <aside className="panel getting-started" aria-labelledby="booking-limit-title"><span className="eyebrow" id="booking-limit-title">YOUR BOOKING LIMIT</span><div className="limit-value">{profile.active_bookings}<span> / {profile.max_bookings}</span></div><p>clusters currently held</p><div className="limit-bars" aria-hidden="true">{Array.from({length: Math.min(profile.max_bookings, 10)}, (_, index) => <i key={index} className={index < profile.active_bookings ? '' : 'empty'}/>)}</div><p id="booking-limit-help" className={blocked ? 'small limit-warning' : 'small'}>{blocked ? 'Your limit is reached. Release a booking or ask an administrator to increase your limit.' : profile.max_bookings_override == null ? `Your current booking limit is ${profile.max_bookings}.` : `Your administrator has set your limit to ${profile.max_bookings}.`}</p><div className="divider"/><div className="micro-heading">One config. Your primary.</div><p className="small">Use the CLI or a personal kubeconfig to connect with stock kubectl.</p><Button className="button subtle text-link" onClick={() => navigate('access')}>View connection options <Icon name="arrow"/></Button></aside>
    </div>
    <div className="section-title section-heading"><div><h2>Your bookings</h2><p>Only the cluster being used gets its inactivity deadline extended.</p></div><div className="row-actions"><span id="booking-count" className="meta-count">{activeSessions.length} / {profile.max_bookings} held</span><Button id="refresh-overview" className="button subtle" onClick={refresh} notify={notify} aria-label="Refresh workspace"><Icon name="refresh"/>Refresh</Button></div></div>
    <section id="my-bookings" className="panel flush table-wrap mobile-records">
      {!activeSessions.length ? <div className="empty"><strong>No cluster is booked.</strong><p>Book an available cluster. Your first booking becomes primary.</p><Button className="button primary" onClick={openBooking} disabled={blocked}>Book a cluster</Button></div> : <table className="mobile-records"><thead><tr>{['Cluster', 'Access', 'Auto-release if inactive', 'Actions'].map(header => <th scope="col" key={header}>{header}</th>)}</tr></thead><tbody>{activeSessions.map(item => {
        const selected = primary?.id === item.id;
        const registered = cluster(item.cluster);
        return <tr key={item.id} data-session-id={item.id} className={selected ? 'primary-booking' : ''}><td data-label="Cluster"><ClusterName cluster={registered} fallback={item.cluster}/><small className="mono booking-id">{item.id}</small></td><td data-label="Access">{selected && <Pill tone="brand">Primary</Pill>}<Pill>{allocation(registered)}</Pill></td><td data-label="Auto-release if inactive"><strong className="booking-auto-release">{timestamp(item.expires_at)}</strong><small className="booking-last-activity">Last activity: {relative(item.last_activity_at)}</small></td><td data-label="Actions"><div className="row-actions">{!selected && <Button className="button secondary" onClick={() => selectPrimary(item)} notify={notify}>Make primary</Button>}{registered?.controller_session === item.id && <Button className="button subtle" onClick={() => share(item, registered.shareable)} notify={notify}>{registered.shareable ? 'Disable sharing' : 'Allow sharing'}</Button>}<Button className="button danger-text" onClick={() => stop(item)} notify={notify}>Release booking</Button></div></td></tr>;
      })}</tbody></table>}
    </section>
    <div className="section-title section-heading"><div><h2>Around your team</h2><p>See who is using a cluster before coordinating a shared booking.</p></div><Button className="button subtle" onClick={() => navigate('clusters')}>Browse clusters <Icon name="arrow"/></Button></div>
    <div id="team-bookings" className="panel flush table-wrap mobile-records"><DataTable headers={['Cluster', 'Developer / contact', 'Access', 'Auto-release']} rows={teamSessions.map(item => [<ClusterName cluster={cluster(item.cluster)} fallback={item.cluster}/>, <Contact person={item}/>, <Pill>{allocation(cluster(item.cluster))}</Pill>, timestamp(item.expires_at)])} emptyText="No other team bookings right now."/></div>
    <div className="quiet-note"><Icon name="info"/>Inactivity releases the booking and gateway access. Kubernetes workloads and data remain.</div>
    <details className="panel history"><summary>Booking history</summary><div id="booking-history" className="table-wrap mobile-records"><DataTable headers={['Cluster', 'Booking', 'State', 'Ended']} rows={ownSessions.filter(item => item.state !== 'ACTIVE').slice().reverse().map(item => [clusterName(item.cluster), item.id, <Pill>{item.state}</Pill>, timestamp(item.ended_at)])} emptyText="No previous bookings."/></div></details>
    <Dialog open={bookingOpen} busy={booking} onClose={() => {if (!submitting.current) setBookingOpen(false);}} title="Book a cluster" description="Reserve a whole cluster. Your first booking becomes primary; additional bookings keep your current primary selected." id="booking-dialog">
      <form id="booking-form" className="drawer-form" onSubmit={book} onChange={changeBooking}>
        <div className="drawer-content"><FormError message={error} fields={selectorError ? [{id: 'booking-selector', message: selectorError}] : undefined}/>
          <label className="field">Cluster<select id="booking-cluster" name="cluster" value={selectedCluster} disabled={booking} onChange={event => setSelectedCluster(event.target.value)}><option value="">Choose automatically</option>{clusters.map(item => <option key={item.id} value={item.id} disabled={item.maintenance || !item.available || (item.participants ?? []).some(holder => holder.owner === session.owner_id)}>{item.name}{item.maintenance ? ' · maintenance' : !item.available ? ' · reserved' : (item.participants ?? []).length ? ' · shared' : ''}</option>)}</select><small>Automatic selection prefers free clusters, then holder-enabled shared capacity.</small></label>
          <label className="field">Required labels<input id="booking-selector" name="selector" placeholder="region=eu,type=test" value={selector} disabled={booking} onChange={event => setSelector(event.target.value)} maxLength={10000} autoComplete="off" aria-invalid={Boolean(selectorError)} aria-describedby={selectorError ? 'booking-selector-error' : 'booking-selector-help'}/><small id="booking-selector-help">Optional, comma-separated key=value pairs. Every label must match.</small>{selectorError && <span id="booking-selector-error" className="field-error">{selectorError}</span>}</label>
          {requestedCluster && <div className="selection-preview"><span className="eyebrow">YOUR SELECTION</span><ClusterName cluster={requestedCluster}/><Labels cluster={requestedCluster}/><Pill tone={requestedCluster.available ? 'success' : 'warning'}>{requestedCluster.maintenance ? 'Maintenance' : joining ? 'Shared capacity' : 'Exclusive when booked'}</Pill><p>{requestedCluster.reason}</p>{joining && <div className="participants">{(requestedCluster.participants ?? []).map(holder => <Contact key={holder.id} person={holder}/>)}</div>}<small>Availability is confirmed by the backend when you book.</small></div>}
          <dl className="summary-list"><div><dt>Your bookings after this</dt><dd>{profile.active_bookings + 1} of {profile.max_bookings} allowed</dd></div><div><dt>Primary after this</dt><dd>{primary ? `${clusterName(primary.cluster)} · unchanged` : 'Your new booking'}</dd></div></dl>
          {blocked && <div className="notice warning"><Icon name="info"/><p>Your booking limit is reached. Release a booking or ask an administrator to increase your limit.</p></div>}
          <div className="notice"><Icon name="info"/><p>Activity keeps only the cluster being used reserved. Auto-release ends gateway access; Kubernetes workloads remain.</p></div><div className="quiet-note"><Icon name="lock"/>{joining ? 'The current holder controls sharing. Coordinate with the people above before joining.' : 'Sharing is off by default on a free cluster. You can allow it after booking.'}</div>
        </div><div className="drawer-footer"><Button onClick={() => setBookingOpen(false)} disabled={booking}>Cancel</Button><button id="booking-submit" className="button primary" type="submit" disabled={blocked || booking || Boolean(requestedCluster && !requestedCluster.available)} data-limit-blocked={String(blocked)}>{booking ? 'Booking…' : joining ? 'Join shared cluster' : 'Book cluster'}<Icon name="arrow"/></button></div>
      </form>
    </Dialog>
  </>;
}
