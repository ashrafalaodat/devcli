import {useEffect, useMemo, useRef, useState} from 'react';
import type {FormEvent, ReactNode} from 'react';
import {Dialog} from '../components/Dialog';
import {Icon} from '../components/Icon';
import {PATTable} from '../components/PATTable';
import {Button, Contact, FormError, Pill, date, errorMessage} from '../components/ui';
import {formatLabels, parseLabels} from '../lib/labels';
import type {Cluster, DeveloperProfile, PageProps, Session, Settings} from '../types';

export type AdminView = 'clusters' | 'people' | 'tokens' | 'audit';
type Controls = Pick<PageProps, 'api' | 'refresh' | 'notify'>;
interface FieldIssue {id: string; message: string}

class FieldError extends Error {
  constructor(message: string, readonly field: string) {super(message);}
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fields, setFields] = useState<FieldIssue[]>([]);
  const running = useRef(false);
  async function run(work: () => Promise<void>): Promise<boolean> {
    if (running.current) return false;
    running.current = true;
    setBusy(true);
    setError(null);
    setFields([]);
    try {await work(); return true;}
    catch (failure) {
      setError(errorMessage(failure));
      if (failure instanceof FieldError) setFields([{id: failure.field, message: failure.message}]);
      return false;
    } finally {running.current = false; setBusy(false);}
  }
  return {busy, error, fields, run, invalid: (id: string) => fields.some(field => field.id === id)};
}

function auditReason(value: string, field: string): string {
  const reason = value.trim();
  if (!reason) throw new FieldError('Enter an audit reason.', field);
  return reason;
}

function Search({label, placeholder, value, onChange}: {label: string; placeholder: string; value: string; onChange: (value: string) => void}) {
  return <label className="search-input"><Icon name="search"/><span className="sr-only">{label}</span><input type="search" value={value} onChange={event => onChange(event.target.value)} placeholder={placeholder}/></label>;
}

interface AdminRow {key: string; cluster?: string; session?: string; owner?: string; cells: ReactNode[]}
function AdminTable({headers, rows, empty}: {headers: string[]; rows: AdminRow[]; empty: string}) {
  if (!rows.length) return <div className="empty"><strong>{empty}</strong></div>;
  return <table className="data-table mobile-records"><thead><tr>{headers.map(heading => <th key={heading} scope="col">{heading}</th>)}</tr></thead><tbody>{rows.map(row => <tr key={row.key} data-cluster-id={row.cluster} data-session-id={row.session} data-owner-id={row.owner}>{row.cells.map((cell, index) => <td key={headers[index]} data-label={headers[index]}>{cell ?? '—'}</td>)}</tr>)}</tbody></table>;
}

function ClusterLabel({cluster, id}: {cluster?: Cluster; id?: string}) {
  return <div className="cluster-name"><Icon name="cluster"/><div><strong>{cluster?.name || id}</strong><small className="mono">{cluster?.id || id}</small>{cluster && Object.keys(cluster.labels || {}).length > 0 && <div className="tags">{Object.entries(cluster.labels).map(([key,value]) => <span className="tag mono" key={key}>{key}={value}</span>)}</div>}</div></div>;
}

function Registration({api, refresh, notify, onClose}: Controls & {onClose: () => void}) {
  const [id, setID] = useState('');
  const [name, setName] = useState('');
  const [maximum, setMaximum] = useState('2');
  const [labels, setLabels] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const action = useAction();
  function close() {if (!action.busy) {if (fileInput.current) fileInput.current.value = ''; onClose();}}
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const saved = await action.run(async () => {
      const clusterID = id.trim();
      if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/.test(clusterID)) throw new FieldError('Use a cluster ID of 1–63 letters, numbers, dots, underscores or hyphens.', 'register-id');
      if (!name.trim()) throw new FieldError('Enter a display name.', 'register-name');
      const file = fileInput.current?.files?.[0];
      if (!file || !file.size || file.size > 1_500_000) throw new FieldError('Choose a trusted kubeconfig smaller than 1.5 MB.', 'register-kubeconfig');
      const participants = Number(maximum);
      if (!Number.isInteger(participants) || participants < 2 || participants > 10) throw new FieldError('Maximum shared holders must be an integer from 2 through 10.', 'register-maximum');
      let registryLabels: Record<string,string>;
      try {registryLabels = parseLabels(labels);} catch (error) {throw new FieldError(errorMessage(error), 'register-labels');}
      // Credential contents exist only for this request, never in React state.
      let raw = await file.text();
      try {
        await api('/v1/admin/clusters', {method: 'POST', body: {id: clusterID, name: name.trim(), labels: registryLabels, max_participants: participants, kubeconfig: raw}});
      } finally {raw = '';}
      if (fileInput.current) fileInput.current.value = '';
      await refresh();
    });
    if (saved) {onClose(); notify('Cluster registered. Its credentials are encrypted on the backend. No Kubernetes resources were changed.');}
  }
  return <Dialog open busy={action.busy} onClose={close} title="Register a cluster" description="Add an approved environment. Registration saves encrypted credentials and does not contact Kubernetes." footer={<><Button onClick={close} disabled={action.busy}>Cancel</Button><button form="register-form" className="button primary" type="submit" disabled={action.busy}>{action.busy ? 'Registering…' : 'Register cluster'}</button></>}>
    <form id="register-form" onSubmit={submit}>
      <FormError message={action.error} fields={action.fields}/>
      <fieldset disabled={action.busy} className="form-fields">
        <div className="two-columns fields"><label className="field" htmlFor="register-id">Cluster ID<input id="register-id" name="id" value={id} onChange={event => setID(event.target.value)} maxLength={63} required autoComplete="off" aria-invalid={action.invalid('register-id')}/><small>Unique and permanent. Register each physical cluster once.</small></label>
        <label className="field" htmlFor="register-name">Display name<input id="register-name" name="name" value={name} onChange={event => setName(event.target.value)} maxLength={128} required autoComplete="off" aria-invalid={action.invalid('register-name')}/></label></div>
        <label className="field" htmlFor="register-labels">Labels<input id="register-labels" name="labels" placeholder="region=eu,type=test" value={labels} onChange={event => setLabels(event.target.value)} autoComplete="off" aria-invalid={action.invalid('register-labels')}/><small>Optional key=value pairs for cluster selection and PAT automatic booking.</small></label>
        <label className="field" htmlFor="register-maximum">Maximum shared holders<input id="register-maximum" name="max_participants" type="number" min="2" max="10" step="1" value={maximum} onChange={event => setMaximum(event.target.value)} required aria-invalid={action.invalid('register-maximum')}/><small>A holder must explicitly allow sharing. This does not enable it automatically.</small></label>
        <label className="field" htmlFor="register-kubeconfig">Trusted kubeconfig file<input id="register-kubeconfig" ref={fileInput} name="kubeconfig" type="file" required aria-invalid={action.invalid('register-kubeconfig')}/><small>Maximum 1.5 MB. One selected context, embedded certificate data and static credentials; no executable authentication plugins.</small></label>
      </fieldset>
      <div className="notice"><Icon name="info"/><p>The imported identity’s existing Kubernetes permissions are available through the gateway. Register only credentials approved for the intended developers.</p></div>
      <p className="quiet-note"><Icon name="lock"/>Original credentials remain on the backend and are not returned to developers.</p>
    </form>
  </Dialog>;
}

function ClusterAction({cluster, operation, api, refresh, notify, onClose}: Controls & {cluster: Cluster; operation: 'placement' | 'deregister'; onClose: () => void}) {
  const [reason, setReason] = useState('');
  const action = useAction();
  const blocked = cluster.participants.some(session => session.state === 'ACTIVE');
  const removing = operation === 'deregister';
  const heading = removing ? `Deregister ${cluster.name}?` : `${cluster.maintenance ? 'Enable' : 'Pause'} placement for ${cluster.name}?`;
  const form = removing ? 'deregister-form' : 'maintenance-form';
  const reasonID = removing ? 'deregister-reason' : 'maintenance-reason';
  const close = () => {if (!action.busy) onClose();};
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const saved = await action.run(async () => {
      const why = auditReason(reason, reasonID);
      if (removing && blocked) throw new Error('Release all active bookings before deregistering this cluster.');
      try {
        await api(`/v1/admin/clusters/${encodeURIComponent(cluster.id)}`, removing ? {method: 'DELETE', body: {reason: why}} : {method: 'PATCH', body: {maintenance: !cluster.maintenance, reason: why}});
      } catch (error) {
        if (removing) {try {await refresh();} catch { /* Preserve the original conflict as the actionable failure. */ }}
        throw error;
      }
      await refresh();
    });
    if (saved) {onClose(); notify(removing ? 'Cluster deregistered. Stored credentials were removed; booking history and Kubernetes workloads remain.' : 'Cluster placement updated. Existing bookings remain.');}
  }
  return <Dialog open busy={action.busy} onClose={close} title={heading} description={removing ? 'Remove this registration and its stored Kubernetes credentials from devctl.' : cluster.maintenance ? 'Allow this cluster to receive new bookings again.' : 'Prevent new bookings without evicting its current holders.'} footer={<><Button onClick={close} disabled={action.busy}>Cancel</Button><button form={form} className={`button ${removing ? 'danger' : 'primary'}`} type="submit" disabled={action.busy || removing && blocked}>{action.busy ? 'Saving…' : removing ? 'Deregister cluster' : cluster.maintenance ? 'Enable placement' : 'Set maintenance'}</button></>}>
    <ClusterLabel cluster={cluster}/>
    {removing && <div className={`notice ${blocked ? 'warning' : ''}`}><Icon name="info"/><p>{blocked ? 'This cluster has active bookings. Release them through the audited admin flow before deregistering it.' : 'Deregistration removes future placement and the stored kubeconfig. Booking history and Kubernetes workloads remain.'}</p></div>}
    {cluster.participants.length > 0 && <section className="dialog-detail"><h3>Current holders</h3>{cluster.participants.map(holder => <Contact key={holder.id} person={holder}/>)}</section>}
    <form id={form} onSubmit={submit}>
      <FormError message={action.error} fields={action.fields}/>
      <label className="field" htmlFor={reasonID}>Audit reason<input id={reasonID} name="reason" required maxLength={1000} value={reason} onChange={event => setReason(event.target.value)} placeholder={removing ? 'Retiring this environment' : cluster.maintenance ? 'Ready for new bookings' : 'Planned maintenance'} disabled={action.busy} autoComplete="off" aria-invalid={action.invalid(reasonID)}/></label>
    </form>
    {!removing && <p className="quiet-note"><Icon name="info"/>Placement changes preserve existing reservations, tokens and Kubernetes workloads.</p>}
  </Dialog>;
}

function Fleet(props: PageProps) {
  const {data, api, refresh, notify} = props;
  const [search, setSearch] = useState('');
  const [placement, setPlacement] = useState('all');
  const [registration, setRegistration] = useState(false);
  const [selected, setSelected] = useState<{id: string; operation: 'placement' | 'deregister'} | null>(null);
  const registered = data.clusters.map(cluster => ({...cluster, participants: (cluster.participants || []).filter(session => session.state === 'ACTIVE')}));
  const current = selected && registered.find(cluster => cluster.id === selected.id);
  const query = search.trim().toLowerCase();
  const clusters = registered.filter(cluster => (!query || `${cluster.name} ${cluster.id} ${formatLabels(cluster.labels)}`.toLowerCase().includes(query)) && (placement === 'all' || (placement === 'maintenance') === cluster.maintenance));
  useEffect(() => {if (selected && !data.clusters.some(cluster => cluster.id === selected.id)) setSelected(null);}, [data.clusters, selected]);
  return <>
    <div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1 id="admin-title">Cluster registry</h1><p>Control which registered environments developers can reserve.</p></div><Button className="button primary" onClick={() => setRegistration(true)}><Icon name="plus"/>Register cluster</Button></div>
    <div className="admin-summary"><div><strong>{data.clusters.length}</strong><span>registered</span></div><div><strong>{registered.filter(cluster => cluster.participants.length > 0).length}</strong><span>with active holders</span></div><div><strong>{data.clusters.filter(cluster => cluster.maintenance).length}</strong><span>in maintenance</span></div><span className="small muted">Reservation state only · No upstream health check</span></div>
    <section id="maintenance-list" className="panel flush table-wrap mobile-records" aria-label="Cluster placement controls"><div className="table-toolbar"><Search label="Search registered clusters" placeholder="Search name, ID or label" value={search} onChange={setSearch}/><div className="toolbar-actions"><label className="filter-label"><span className="sr-only">Placement filter</span><select value={placement} onChange={event => setPlacement(event.target.value)}><option value="all">All placement</option><option value="enabled">Placement enabled</option><option value="maintenance">Maintenance</option></select></label><Button id="refresh-admin" onClick={refresh} notify={notify}><Icon name="refresh"/>Refresh registry</Button></div></div>
      <AdminTable headers={['Cluster', 'Placement', 'Holders', 'Sharing limit', 'Manage']} empty={query || placement !== 'all' ? 'No clusters match these filters.' : 'No clusters registered. Register an approved environment to get started.'} rows={clusters.map(cluster => ({key: cluster.id, cluster: cluster.id, cells: [
        <ClusterLabel cluster={cluster}/>,
        <div><Pill tone={cluster.maintenance ? 'warning' : cluster.participants.length ? cluster.shareable ? 'brand' : 'neutral' : 'success'}>{cluster.maintenance ? 'Maintenance' : cluster.participants.length ? cluster.shareable ? 'Sharing enabled' : 'Reserved' : 'Free'}</Pill><small>{cluster.reason}</small></div>,
        cluster.participants.length ? cluster.participants.map(holder => <Contact key={holder.id} person={holder}/>) : <span className="muted">No active holders</span>,
        <div><strong>{cluster.max_participants} developers</strong><small>{cluster.shareable ? `${cluster.participants.length} currently held` : 'Sharing is currently off'}</small></div>,
        <div><div className="row-actions"><Button className="button subtle" onClick={() => setSelected({id: cluster.id, operation: 'placement'})}>{cluster.maintenance ? 'Enable placement…' : 'Maintenance…'}</Button><Button className="button danger-text" disabled={cluster.participants.length > 0} aria-describedby={cluster.participants.length ? `deregister-blocked-${cluster.id}` : undefined} onClick={() => setSelected({id: cluster.id, operation: 'deregister'})}>Deregister…</Button></div>{cluster.participants.length > 0 && <small id={`deregister-blocked-${cluster.id}`}>Release active bookings first.</small>}</div>,
      ]}))}/>
      <div className="table-footer"><span>{clusters.length} of {data.clusters.length} live registrations</span><span>Retired entries remain in booking and audit history</span></div>
    </section>
    <div className="two-columns compact-panels"><section className="panel"><h3>Maintenance pauses new bookings</h3><p>Current holders keep their reservations. An audit reason is required for placement changes.</p></section><section className="panel"><h3>Deregistration removes stored access</h3><p>Release active bookings first. Removing a registration leaves Kubernetes workloads and booking history intact.</p></section></div>
    {registration && <Registration api={api} refresh={refresh} notify={notify} onClose={() => setRegistration(false)}/>}
    {selected && current && <ClusterAction key={`${selected.id}-${selected.operation}`} cluster={current} operation={selected.operation} api={api} refresh={refresh} notify={notify} onClose={() => setSelected(null)}/>}
  </>;
}

function BookingPolicy({settings, api, refresh, notify}: Controls & {settings: Settings}) {
  const [maximum, setMaximum] = useState(String(settings.default_max_bookings));
  const [grace, setGrace] = useState(settings.inactivity_grace_period);
  const [reason, setReason] = useState('');
  const action = useAction();
  useEffect(() => setMaximum(String(settings.default_max_bookings)), [settings.default_max_bookings]);
  useEffect(() => setGrace(settings.inactivity_grace_period), [settings.inactivity_grace_period]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const saved = await action.run(async () => {
      const why = auditReason(reason, 'policy-reason');
      const limit = Number(maximum);
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new FieldError('Default maximum clusters must be an integer from 1 through 100.', 'default-booking-limit');
      if (!grace.trim()) throw new FieldError('Enter an inactivity period, for example 4h.', 'inactivity-grace-period');
      await api('/v1/admin/settings', {method: 'PATCH', body: {default_max_bookings: limit, inactivity_grace_period: grace.trim(), reason: why}});
      await refresh();
    });
    if (saved) {setReason(''); notify('Booking policy updated. The inactivity period applies to current and future bookings.');}
  }
  return <section className="panel policy-panel" aria-labelledby="limits-title"><div className="section-title"><div><h2 id="limits-title">Team booking policy</h2><p>Developers without an override inherit these defaults.</p></div><Pill>Current policy</Pill></div>
    <form id="settings-form" onSubmit={submit}><FormError message={action.error} fields={action.fields}/><fieldset disabled={action.busy} className="policy-fields">
      <label className="field" htmlFor="default-booking-limit">Default maximum bookings<input id="default-booking-limit" name="default_max_bookings" type="number" min="1" max="100" step="1" value={maximum} onChange={event => setMaximum(event.target.value)} required aria-invalid={action.invalid('default-booking-limit')}/><small>Whole clusters per developer.</small></label>
      <label className="field" htmlFor="inactivity-grace-period">Release after inactivity<input id="inactivity-grace-period" name="inactivity_grace_period" value={grace} onChange={event => setGrace(event.target.value)} required autoComplete="off" aria-invalid={action.invalid('inactivity-grace-period')}/><small>1m through 168h; default 4h.</small></label>
      <label className="field" htmlFor="policy-reason">Audit reason<input id="policy-reason" name="reason" value={reason} onChange={event => setReason(event.target.value)} required maxLength={500} placeholder="Explain why the policy is changing" autoComplete="off" aria-invalid={action.invalid('policy-reason')}/><small>Required for every policy change.</small></label>
      <div className="policy-save"><button className="button primary" type="submit" disabled={action.busy}>{action.busy ? 'Saving…' : 'Save policy'}</button></div>
    </fieldset></form><div className="policy-warning"><Icon name="info"/><p>Lower limits preserve existing bookings. A shorter inactivity period can release already-idle bookings. Only the cluster being used is extended; idle tabs and token refresh do not create activity.</p></div>
  </section>;
}

function DeveloperLimit({profile, api, refresh, notify, onClose}: Controls & {profile: DeveloperProfile; onClose: () => void}) {
  const [maximum, setMaximum] = useState(profile.max_bookings_override == null ? '' : String(profile.max_bookings_override));
  const [reason, setReason] = useState('');
  const action = useAction();
  const name = profile.user.display_name || profile.user.name;
  const close = () => {if (!action.busy) onClose();};
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const saved = await action.run(async () => {
      const why = auditReason(reason, 'developer-limit-reason');
      const value = maximum.trim();
      const limit = value === '' ? null : Number(value);
      if (limit !== null && (!Number.isInteger(limit) || limit < 1 || limit > 100)) throw new FieldError('Use an integer from 1 through 100, or leave blank to inherit the team default.', 'developer-booking-limit');
      await api(`/v1/admin/developers/${encodeURIComponent(profile.owner_id)}`, {method: 'PATCH', body: {max_bookings: limit, reason: why}});
      await refresh();
    });
    if (saved) {onClose(); notify('Developer booking limit updated. Existing bookings were preserved.');}
  }
  return <Dialog open busy={action.busy} onClose={close} title={`Edit booking limit for ${name}`} description="The limit applies across every profile, browser, terminal and device for this identity." footer={<><Button onClick={close} disabled={action.busy}>Cancel</Button><button form="developer-limit-form" type="submit" className="button primary" disabled={action.busy}>{action.busy ? 'Saving…' : 'Save override'}</button></>}>
    <Contact person={{...profile.user, owner: profile.owner_id}}/>
    <form id="developer-limit-form" onSubmit={submit}><FormError message={action.error} fields={action.fields}/><fieldset disabled={action.busy} className="form-fields">
      <label className="field" htmlFor="developer-booking-limit">Maximum bookings override<input id="developer-booking-limit" type="number" name="max_bookings" min="1" max="100" step="1" placeholder="Use team default" value={maximum} onChange={event => setMaximum(event.target.value)} aria-invalid={action.invalid('developer-booking-limit')}/><small>Leave blank to inherit the team default. The developer currently holds {profile.active_bookings} bookings.</small></label>
      <label className="field" htmlFor="developer-limit-reason">Audit reason<input id="developer-limit-reason" name="reason" required maxLength={500} value={reason} onChange={event => setReason(event.target.value)} autoComplete="off" aria-invalid={action.invalid('developer-limit-reason')}/></label>
    </fieldset></form><div className="notice"><Icon name="info"/><p>Lowering a limit keeps existing bookings and blocks new ones until this developer is below the limit.</p></div>
  </Dialog>;
}

function ReleaseBooking({session, cluster, api, refresh, notify, onClose}: Controls & {session: Session; cluster?: Cluster; onClose: () => void}) {
  const [reason, setReason] = useState('');
  const action = useAction();
  const active = session.state === 'ACTIVE';
  const close = () => {if (!action.busy) onClose();};
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const saved = await action.run(async () => {
      const why = auditReason(reason, 'release-reason');
      if (!active) throw new Error('This booking has already ended.');
      await api(`/v1/admin/sessions/${encodeURIComponent(session.id)}/release`, {method: 'POST', body: {reason: why}});
      await refresh();
    });
    if (saved) {onClose(); notify('Booking released through administrator controls. Personal tokens and Kubernetes workloads remain.');}
  }
  return <Dialog open busy={action.busy} onClose={close} title={`Release booking on ${cluster?.name || session.cluster}?`} description="End this developer’s gateway reservation through the audited administrator flow." footer={<><Button onClick={close} disabled={action.busy}>Keep booking</Button><button form="release-form" className="button danger" type="submit" disabled={action.busy || !active}>{action.busy ? 'Releasing…' : 'Release booking'}</button></>}>
    <Contact person={session}/><div className="dialog-detail"><span className="mono">{session.id}</span><p>If this is primary, the oldest remaining active booking becomes primary.</p></div>
    <ul className="consequence-list"><li>Kubernetes workloads and data remain.</li><li>Personal tokens remain valid until their own expiry or explicit revocation.</li><li>An enabled automatic-booking token can reserve again on its next Kubernetes request.</li></ul>
    <form id="release-form" onSubmit={submit}><FormError message={action.error} fields={action.fields}/><label className="field" htmlFor="release-reason">Audit reason<input id="release-reason" name="reason" required maxLength={500} value={reason} onChange={event => setReason(event.target.value)} placeholder="Owner confirmed testing is complete" disabled={action.busy} autoComplete="off" aria-invalid={action.invalid('release-reason')}/></label></form>
    {!active && <div className="notice warning"><Icon name="info"/><p>This booking has already ended. Refresh the list to inspect its current state.</p></div>}
  </Dialog>;
}

function People(props: PageProps) {
  const {data, api, refresh, notify} = props;
  const [search, setSearch] = useState('');
  const [selectedOwner, setSelectedOwner] = useState<string | null>(null);
  const [selectedBooking, setSelectedBooking] = useState<string | null>(null);
  const query = search.trim().toLowerCase();
  const profiles = data.developers.filter(profile => !query || `${profile.user.display_name} ${profile.user.name} ${profile.user.email || ''} ${profile.owner_id}`.toLowerCase().includes(query));
  const profile = data.developers.find(person => person.owner_id === selectedOwner);
  const booking = data.sessions.find(session => session.id === selectedBooking);
  const cluster = (id: string) => data.clusters.find(item => item.id === id);
  const active = data.sessions.filter(session => session.state === 'ACTIVE');
  return <>
    <div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1 id="admin-title">People & booking policy</h1><p>Set team defaults and explicit developer overrides. Changes require an audit reason.</p></div><Button id="refresh-admin" onClick={refresh} notify={notify}><Icon name="refresh"/>Refresh</Button></div>
    {data.settings && <BookingPolicy settings={data.settings} api={api} refresh={refresh} notify={notify}/>}
    <div className="section-title"><div><h2>Developer limits</h2><p>Limits and primary selection apply across profiles, browsers, terminals and devices.</p></div></div>
    <section id="developer-list" className="panel flush table-wrap mobile-records" aria-label="Developer booking limits"><div className="table-toolbar"><Search label="Find a developer" placeholder="Find a developer" value={search} onChange={setSearch}/><span className="small muted">{data.developers.length} known identities</span></div><AdminTable headers={['Developer', 'Active / allowed', 'Limit source', 'Primary', 'Action']} empty={query ? 'No developers match your search.' : 'Developers appear after their first application login.'} rows={profiles.map(person => ({key: person.owner_id, owner: person.owner_id, cells: [
      <Contact person={{...person.user, owner: person.owner_id}}/>, <div className="booking-count">{person.active_bookings}<span> / {person.max_bookings}</span></div>,
      <div><Pill tone={person.max_bookings_override == null ? 'neutral' : 'brand'}>{person.max_bookings_override == null ? 'Team default' : `Override: ${person.max_bookings_override}`}</Pill>{person.max_bookings_override != null && <small>Team default: {data.settings?.default_max_bookings ?? '—'}</small>}</div>,
      person.primary_session ? <span className="mono">{cluster(person.primary_session.cluster)?.name || person.primary_session.cluster}</span> : <span className="muted">No active booking</span>,
      <Button onClick={() => setSelectedOwner(person.owner_id)}>Edit override…</Button>,
    ]}))}/></section>
    <div className="section-title"><div><h2>Active bookings</h2><p>Release access only when needed. Existing workloads are left in place.</p></div><span className="meta-count">{active.length} active</span></div>
    <section className="panel flush table-wrap mobile-records" aria-label="All active bookings"><AdminTable headers={['Booking / cluster', 'Owner', 'Auto-release if inactive', 'Admin action']} empty="No active bookings." rows={active.map(session => ({key: session.id, session: session.id, cells: [
      <div><ClusterLabel cluster={cluster(session.cluster)} id={session.cluster}/><small className="mono">{session.id}</small></div>, <Contact person={session}/>, date(session.expires_at), <Button className="button danger-text" onClick={() => setSelectedBooking(session.id)}>Release with reason…</Button>,
    ]}))}/></section>
    {profile && <DeveloperLimit key={profile.owner_id} profile={profile} api={api} refresh={refresh} notify={notify} onClose={() => setSelectedOwner(null)}/>}
    {booking && <ReleaseBooking key={booking.id} session={booking} cluster={cluster(booking.cluster)} api={api} refresh={refresh} notify={notify} onClose={() => setSelectedBooking(null)}/>}
  </>;
}

function Tokens(props: PageProps) {
  const {data, api, refresh, notify} = props;
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const now = Date.now();
  const state = (pat: typeof data.allPats[number]) => pat.revoked_at ? 'revoked' : !Number.isFinite(Date.parse(pat.expires_at)) || Date.parse(pat.expires_at) <= now ? 'expired' : 'active';
  const query = search.trim().toLowerCase();
  const pats = data.allPats.filter(pat => {
    const owner = data.developers.find(person => person.owner_id === pat.owner)?.user;
    return (status === 'all' || state(pat) === status) && (!query || `${pat.name} ${pat.id} ${owner?.display_name || ''} ${owner?.name || ''} ${owner?.email || ''} ${pat.owner}`.toLowerCase().includes(query));
  });
  return <>
    <div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1 id="admin-title">Organisation tokens</h1><p>Review personal gateway credentials and manage policy or revocation with an audit reason.</p></div></div>
    <div className="admin-summary"><div><strong>{data.allPats.filter(pat => state(pat) === 'active').length}</strong><span>active personal tokens</span></div><div><strong>{data.allPats.filter(pat => state(pat) === 'active' && pat.auto_booking?.enabled).length}</strong><span>automatic booking enabled</span></div><div><strong>{data.allPats.filter(pat => state(pat) !== 'active').length}</strong><span>expired or revoked</span></div></div>
    <section id="admin-pat-list" className="panel flush table-wrap mobile-records" aria-label="All gateway tokens"><div className="table-toolbar"><Search label="Search all gateway tokens" placeholder="Search token or owner" value={search} onChange={setSearch}/><div className="toolbar-actions"><label className="filter-label"><span className="sr-only">Token status</span><select value={status} onChange={event => setStatus(event.target.value)}><option value="all">Status: all</option><option value="active">Active</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select></label><Button id="refresh-admin" onClick={refresh} notify={notify}><Icon name="refresh"/>Refresh</Button></div></div><PATTable data={data} api={api} refresh={refresh} notify={notify} pats={pats} admin/><div className="table-footer"><span>{pats.length} of {data.allPats.length} credentials · Metadata only</span><span>Secrets and digests are never shown</span></div></section>
    <div className="notice"><Icon name="info"/><p>Changing another developer’s token policy or revoking it requires an audit reason. Policy edits retain the token, downloaded kubeconfig and fixed expiry.</p></div>
    <div className="two-columns compact-panels"><section className="panel"><h3>Offboarding needs explicit revocation</h3><p>Provider sign-out or group removal alone does not immediately invalidate existing PATs. Review tokens as well as bookings.</p></section><section className="panel"><h3>Automatic booking is opt-in</h3><p>An enabled token can reserve a matching unused cluster after release or sign-out. Disable its policy or revoke the token to prevent it.</p></section></div>
  </>;
}

function Audit(props: PageProps) {
  const {data, refresh, notify} = props;
  const [search, setSearch] = useState('');
  const [action, setAction] = useState('');
  const query = search.trim().toLowerCase();
  const actorName = (owner: string) => {
    const person = data.developers.find(profile => profile.owner_id === owner)?.user;
    return person ? person.display_name || person.name : owner;
  };
  const events = data.audit.filter(event => (!action || event.action === action) && (!query || `${event.actor} ${actorName(event.actor)} ${event.action} ${event.object_id} ${event.detail}`.toLowerCase().includes(query)));
  const actions = useMemo(() => [...new Set(data.audit.map(event => event.action))].sort(), [data.audit]);
  return <>
    <div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1 id="admin-title">Audit log</h1><p>Review who changed access, reservations and team policy.</p></div><Button id="refresh-admin" onClick={refresh} notify={notify}><Icon name="refresh"/>Refresh events</Button></div>
    <section id="audit-list" className="panel flush table-wrap mobile-records" aria-label="Audit activity"><div className="table-toolbar"><Search label="Filter loaded audit events" placeholder="Filter actor, action, object or reason" value={search} onChange={setSearch}/><div className="toolbar-actions"><label className="filter-label"><span className="sr-only">Audit action</span><select value={action} onChange={event => setAction(event.target.value)}><option value="">All actions</option>{actions.map(name => <option key={name} value={name}>{name.replaceAll('_', ' ')}</option>)}</select></label><span className="meta-count">Latest 100 events</span></div></div><AdminTable headers={['Time', 'Actor', 'Action', 'Object', 'Reason / detail']} empty={query || action ? 'No loaded events match these filters.' : 'No audit events yet.'} rows={events.map(event => ({key: String(event.id), cells: [
      <time dateTime={event.at}>{date(event.at)}</time>, <div><strong>{actorName(event.actor)}</strong>{actorName(event.actor) !== event.actor && <small className="mono">{event.actor}</small>}</div>, <Pill>{event.action.replaceAll('_', ' ')}</Pill>, <span className="mono">{event.object_id}</span>, <span className="audit-detail">{event.detail}</span>,
    ]}))}/><div className="table-footer"><span>Showing {events.length} of {data.audit.length} loaded events</span><span>Filters apply to the latest 100 events only</span></div></section>
    <p className="quiet-note"><Icon name="shield"/>Audit entries contain metadata and reasons. Access tokens, secrets and raw kubeconfigs are not displayed.</p>
  </>;
}

export default function Admin({section = 'clusters', ...props}: PageProps & {section?: AdminView}) {
  if (!props.data.session.user.admin) return null;
  return section === 'clusters' ? <Fleet {...props}/> : section === 'people' ? <People {...props}/> : section === 'tokens' ? <Tokens {...props}/> : <Audit {...props}/>;
}
