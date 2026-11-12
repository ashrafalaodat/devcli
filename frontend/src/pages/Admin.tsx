import {useEffect, useRef, useState} from 'react';
import type {FormEvent} from 'react';
import {PATTable} from '../components/PATTable';
import {Button, Contact, DataTable, Pill, date} from '../components/ui';
import {parseLabels} from '../lib/labels';
import type {Cluster, DeveloperProfile, PageProps, Settings} from '../types';

type Controls = Pick<PageProps, 'api' | 'refresh' | 'notify'>;

function useAction(notify: PageProps['notify']) {
  const [busy, setBusy] = useState(false);
  const running = useRef(false);

  async function run(work: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    try {
      await work();
    } catch (error) {
      notify(error instanceof Error ? error.message : 'The request could not be completed.', true);
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  return {busy, run};
}

function BookingPolicy({settings, api, refresh, notify}: Controls & {settings: Settings}) {
  const [maximum, setMaximum] = useState(String(settings.default_max_bookings));
  const [grace, setGrace] = useState(settings.inactivity_grace_period);
  const [reason, setReason] = useState('');
  const {busy, run} = useAction(notify);

  useEffect(() => setMaximum(String(settings.default_max_bookings)), [settings.default_max_bookings]);
  useEffect(() => setGrace(settings.inactivity_grace_period), [settings.inactivity_grace_period]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      const auditReason = reason.trim();
      if (!auditReason) throw new Error('An audit reason is required.');
      const limit = Number(maximum);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
        throw new Error('Default maximum clusters must be an integer from 1 through 100.');
      }
      await api('/v1/admin/settings', {
        method: 'PATCH',
        body: {default_max_bookings: limit, inactivity_grace_period: grace.trim(), reason: auditReason},
      });
      await refresh();
      setReason('');
      notify('Booking policy updated. The inactivity period applies to current and future bookings.');
    });
  }

  return <section className="panel" aria-labelledby="limits-title">
    <h2 id="limits-title">Booking policy</h2>
    <p>Each developer can hold one cluster by default. Increase the default or set a developer-specific override. Lowering a limit preserves existing bookings and prevents new ones until the developer is below the limit.</p>
    <form id="settings-form" className="form-grid" onSubmit={submit}>
      <label>Default maximum clusters<input id="default-booking-limit" name="default_max_bookings" type="number" min="1" max="100" step="1" value={maximum} onChange={event => setMaximum(event.target.value)} required/></label>
      <label>Release after inactivity<input id="inactivity-grace-period" name="inactivity_grace_period" value={grace} onChange={event => setGrace(event.target.value)} required autoComplete="off"/><span className="field-help">1m through 168h; default 4h. Applies to current and future bookings.</span></label>
      <label className="span-two">Audit reason<input name="reason" placeholder="Update the team booking policy" maxLength={500} value={reason} onChange={event => setReason(event.target.value)} required autoComplete="off"/></label>
      <button className="button primary align-start" type="submit" disabled={busy}>Save booking policy</button>
    </form>
    <p className="field-help">Limits apply across all browsers, terminals, profiles, and shared bookings for the same SSO identity. Kubernetes requests, open authenticated connections, primary selection, and interaction with a visible browser page extend only the selected booking. An idle tab or token refresh does not. Shortening inactivity time can release already-idle bookings.</p>
  </section>;
}

function DeveloperLimit({profile, api, refresh, notify}: Controls & {profile: DeveloperProfile}) {
  const [maximum, setMaximum] = useState(profile.max_bookings_override == null ? '' : String(profile.max_bookings_override));
  const [reason, setReason] = useState('');
  const {busy, run} = useAction(notify);
  const name = profile.user.display_name || profile.user.name;

  useEffect(() => {
    setMaximum(profile.max_bookings_override == null ? '' : String(profile.max_bookings_override));
  }, [profile.max_bookings_override]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      const auditReason = reason.trim();
      if (!auditReason) throw new Error('An audit reason is required.');
      const value = maximum.trim();
      const limit = value === '' ? null : Number(value);
      if (limit !== null && (!Number.isInteger(limit) || limit < 1 || limit > 100)) {
        throw new Error('The booking override must be an integer from 1 through 100, or blank to inherit the default.');
      }
      await api(`/v1/admin/developers/${encodeURIComponent(profile.owner_id)}`, {
        method: 'PATCH', body: {max_bookings: limit, reason: auditReason},
      });
      await refresh();
      setReason('');
      notify('Developer booking limit updated. Existing bookings were preserved.');
    });
  }

  return <form className="developer-limit-form" onSubmit={submit}>
    <input type="number" min="1" max="100" step="1" name="max_bookings" placeholder="Use default" value={maximum} onChange={event => setMaximum(event.target.value)} aria-label={`Booking override for ${name}`}/>
    <input name="reason" value={reason} onChange={event => setReason(event.target.value)} required maxLength={500} placeholder="Audit reason" aria-label={`Audit reason for ${name}`}/>
    <button className="button secondary small" type="submit" disabled={busy}>Save limit</button>
  </form>;
}

function Registration({api, refresh, notify}: Controls) {
  const [id, setID] = useState('');
  const [name, setName] = useState('');
  const [maximum, setMaximum] = useState('2');
  const [labels, setLabels] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const {busy, run} = useAction(notify);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      const file = fileInput.current?.files?.[0];
      if (!file || !file.size || file.size > 1_500_000) {
        throw new Error('Choose a trusted kubeconfig smaller than 1.5 MB.');
      }
      const participants = Number(maximum);
      if (!Number.isInteger(participants) || participants < 2 || participants > 10) {
        throw new Error('Maximum shared holders must be an integer from 2 through 10.');
      }
      const registryLabels = parseLabels(labels);
      // Imported credentials are transient request data, never component state.
      let raw = await file.text();
      try {
        await api('/v1/admin/clusters', {
          method: 'POST',
          body: {id: id.trim(), name: name.trim(), labels: registryLabels, max_participants: participants, kubeconfig: raw},
        });
      } finally {
        raw = '';
      }
      setID('');
      setName('');
      setMaximum('2');
      setLabels('');
      if (fileInput.current) fileInput.current.value = '';
      await refresh();
      notify('Cluster registered. Its credentials are encrypted on the backend. No Kubernetes resources were changed.');
    });
  }

  return <section className="panel" aria-labelledby="register-title">
    <h2 id="register-title">Register a cluster</h2>
    <p>Import an approved, trusted kubeconfig. The server encrypts it before storage. Registration does not connect to or modify the cluster.</p>
    <form id="register-form" className="form-grid" onSubmit={submit}>
      <label>Cluster ID<input name="id" placeholder="dev-eu-01" pattern={'[a-zA-Z0-9][a-zA-Z0-9_.\\-]{0,62}'} value={id} onChange={event => setID(event.target.value)} required maxLength={63} autoComplete="off"/></label>
      <label>Display name<input name="name" placeholder="Development EU 01" value={name} onChange={event => setName(event.target.value)} required maxLength={128} autoComplete="off"/></label>
      <label>Maximum shared holders<input name="max_participants" type="number" min="2" max="10" step="1" value={maximum} onChange={event => setMaximum(event.target.value)} required/></label>
      <label>Labels<input name="labels" placeholder="region=eu,type=test" value={labels} onChange={event => setLabels(event.target.value)} autoComplete="off"/></label>
      <label className="span-two">Trusted kubeconfig file<input ref={fileInput} name="kubeconfig" type="file" required/><span className="field-help">One selected context, embedded certificate data, and static credentials; no executable authentication commands.</span></label>
      <button className="button primary align-start" type="submit" disabled={busy}>Register cluster</button>
    </form>
  </section>;
}

function ClusterControls({cluster, api, refresh, notify}: Controls & {cluster: Cluster}) {
  const [reason, setReason] = useState('');
  const form = useRef<HTMLFormElement>(null);
  const reasonInput = useRef<HTMLInputElement>(null);
  const {busy, run} = useAction(notify);
  const blocked = (cluster.participants || []).some(session => session.state === 'ACTIVE');

  function maintain(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      const auditReason = reason.trim();
      if (!auditReason) throw new Error('An audit reason is required.');
      await api(`/v1/admin/clusters/${encodeURIComponent(cluster.id)}`, {
        method: 'PATCH', body: {maintenance: !cluster.maintenance, reason: auditReason},
      });
      await refresh();
      setReason('');
      notify('Cluster placement controls updated. Existing bookings remain.');
    });
  }

  function deregister() {
    const auditReason = reason.trim();
    reasonInput.current?.setCustomValidity(auditReason ? '' : 'An audit reason is required.');
    if (!form.current?.reportValidity()) return;
    if (!window.confirm(`Deregister ${cluster.name} (${cluster.id})? Its stored Kubernetes credentials will be removed from devctl. Booking history and Kubernetes workloads will remain.`)) return;
    void run(async () => {
      try {
        await api(`/v1/admin/clusters/${encodeURIComponent(cluster.id)}`, {
          method: 'DELETE', body: {reason: auditReason},
        });
      } catch (error) {
        // Refresh stale occupancy before reporting the authoritative conflict.
        try { await refresh(); } catch { /* The original operation is the useful failure. */ }
        throw error;
      }
      await refresh();
      notify('Cluster deregistered. Stored Kubernetes credentials were removed; booking history and workloads were retained.');
    });
  }

  return <article className="cluster-card" data-cluster-id={cluster.id}>
    <div className="card-top">
      <div><h3>{cluster.name}</h3><small className="mono">{cluster.id}</small></div>
      <Pill tone={cluster.maintenance ? 'warning' : cluster.available ? 'success' : 'neutral'}>{cluster.maintenance ? 'Maintenance' : cluster.available ? 'Available' : 'Reserved'}</Pill>
    </div>
    <div className="labels">{Object.entries(cluster.labels || {}).map(([key, value]) => <span className="label" key={key}>{key}={value}</span>)}</div>
    <p>{cluster.reason}</p>
    <div className="participants">{cluster.participants?.length ? cluster.participants.map(person => <div className="participant" key={person.id}><Contact person={person}/></div>) : <span>No active holders.</span>}</div>
    <form ref={form} className="maintenance-form" onSubmit={maintain}>
      <label>Audit reason<input ref={reasonInput} name="reason" required maxLength={1000} placeholder={cluster.maintenance ? 'Ready for bookings' : 'Planned maintenance'} value={reason} onChange={event => { event.target.setCustomValidity(''); setReason(event.target.value); }}/></label>
      <div className="card-actions">
        <button className={`button ${cluster.maintenance ? 'secondary' : 'danger'} small`} type="submit" disabled={busy}>{cluster.maintenance ? 'Enable placement' : 'Set maintenance'}</button>
        <button className="button danger small" type="button" disabled={busy || blocked} title={blocked ? 'Release all active bookings before deregistering this cluster.' : undefined} onClick={deregister}>Deregister</button>
      </div>
    </form>
    {blocked && <p className="field-help">Release all active bookings before deregistering this cluster.</p>}
  </article>;
}

function ReleaseBooking({data, api, refresh, notify}: PageProps) {
  const [id, setID] = useState('');
  const [reason, setReason] = useState('');
  const {busy, run} = useAction(notify);
  const active = data.sessions.filter(session => session.state === 'ACTIVE');

  useEffect(() => {
    if (id && !data.sessions.some(session => session.id === id && session.state === 'ACTIVE')) setID('');
  }, [data.sessions, id]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(async () => {
      const auditReason = reason.trim();
      if (!auditReason) throw new Error('An audit reason is required.');
      if (!id) throw new Error('Select an active booking.');
      if (!window.confirm('Release this booking? If it is primary, the oldest remaining booking becomes primary. Personal tokens and Kubernetes workloads will remain. Enabled automatic booking tokens can reserve again on their next Kubernetes request.')) return;
      await api(`/v1/admin/sessions/${encodeURIComponent(id)}/release`, {method: 'POST', body: {reason: auditReason}});
      await refresh();
      setID('');
      setReason('');
      notify('Booking released through administrator controls. Workloads were retained.');
    });
  }

  return <section className="panel" aria-labelledby="release-title">
    <h2 id="release-title">Release a booking</h2>
    <p>End a booking. If it is primary, the oldest remaining booking becomes primary; otherwise kubectl reports no cluster is booked. Personal gateway tokens remain valid until their own expiry or revocation. Enabled automatic booking tokens can reserve again on their next Kubernetes request. Workloads remain.</p>
    <form id="release-form" className="form-grid" onSubmit={submit}>
      <label>Active booking<select id="release-session" name="session_id" value={id} onChange={event => setID(event.target.value)} required>
        <option value="">Select a booking</option>
        {active.map(session => <option key={session.id} value={session.id}>{data.clusters.find(cluster => cluster.id === session.cluster)?.name || session.cluster} · {session.display_name || session.name} · {session.id.slice(0, 10)}</option>)}
      </select></label>
      <label className="span-two">Audit reason<input name="reason" placeholder="Owner requested release" value={reason} onChange={event => setReason(event.target.value)} required maxLength={500} autoComplete="off"/></label>
      <button className="button danger align-start" type="submit" disabled={busy}>Release booking</button>
    </form>
  </section>;
}

export default function Admin(props: PageProps) {
  const {data, api, refresh, notify} = props;
  if (!data.session.user.admin) return null;
  const controls = {api, refresh, notify};
  const clusterName = (id: string) => data.clusters.find(cluster => cluster.id === id)?.name || id;

  return <>
    <div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1 id="admin-title">Manage the workspace</h1><p>Administrative changes are audited. No action here deletes Kubernetes workloads.</p></div><Button id="refresh-admin" className="button secondary" onClick={refresh} notify={notify}>↻ Refresh</Button></div>
    {data.settings && <BookingPolicy settings={data.settings} {...controls}/>}
    <div className="section-heading"><h2>Developer overrides</h2><span className="subtle">Leave the override empty to inherit the default</span></div>
    <div id="developer-list" className="panel table-wrap"><DataTable headers={['Developer', 'Held / limit', 'Policy', 'Primary cluster', 'Override and audit reason']} rows={data.developers.map(profile => [
      <Contact person={{...profile.user, owner: profile.owner_id}}/>,
      `${profile.active_bookings} / ${profile.max_bookings}`,
      profile.max_bookings_override == null ? 'Default' : 'Override',
      profile.primary_session ? clusterName(profile.primary_session.cluster) : 'No cluster booked',
      <DeveloperLimit key={profile.owner_id} profile={profile} {...controls}/>,
    ])} emptyText="Developers appear after their first application login."/></div>
    <Registration {...controls}/>
    <div className="section-heading"><h2>Cluster placement controls</h2></div>
    <p className="field-help">Deregister an unused cluster to remove its stored credentials from devctl. Release all active bookings first. Booking history and Kubernetes workloads remain.</p>
    <div id="maintenance-list" className="cluster-grid">{data.clusters.map(cluster => <ClusterControls key={cluster.id} cluster={cluster} {...controls}/>)}</div>
    <ReleaseBooking {...props}/>
    <div className="section-heading"><h2>All gateway tokens</h2><span className="subtle">Administrators can revoke access without viewing token values</span></div>
    <div id="admin-pat-list" className="panel table-wrap"><PATTable data={data} api={api} refresh={refresh} notify={notify} pats={data.allPats} admin/></div>
    <div className="section-heading"><h2>Audit activity</h2><span className="subtle">Latest 100 events</span></div>
    <div id="audit-list" className="panel table-wrap"><DataTable headers={['Time', 'Actor', 'Action', 'Object', 'Detail']} rows={data.audit.map(event => [
      date(event.at), <span className="mono">{event.actor.slice(0, 14)}</span>, event.action,
      <span className="mono">{event.object_id}</span>, <span className="audit-detail">{event.detail}</span>,
    ])} emptyText="No audit events."/></div>
  </>;
}
