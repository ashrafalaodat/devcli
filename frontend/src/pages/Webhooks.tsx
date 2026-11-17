import {useCallback, useEffect, useRef, useState} from 'react';
import type {FormEvent} from 'react';
import {Dialog} from '../components/Dialog';
import {Icon} from '../components/Icon';
import {Button, DataTable, FormError, Pill, date, errorMessage} from '../components/ui';
import {ApiError} from '../lib/api';
import {formatLabels, parseLabels} from '../lib/labels';
import type {PageProps, WebhookCatalogue, WebhookDelivery, WebhookRule} from '../types';

type Controls = Pick<PageProps, 'api' | 'notify'>;
type RuleFields = Omit<WebhookRule, 'id' | 'version' | 'selector'> & {selector: string; reason: string};
const terminal = (state: string) => state === 'SUCCEEDED' || state === 'RESOLVED';
function fields(rule?: WebhookRule): RuleFields {
  return {name: rule?.name || '', url: rule?.url || '', events: rule?.events || [], cluster_id: rule?.cluster_id || '', selector: formatLabels(rule?.selector || {}), blocking: rule?.blocking || false, idempotent: rule?.idempotent || false, enabled: rule?.enabled || false, timeout_seconds: rule?.timeout_seconds || 3600, reason: ''};
}

function RuleEditor({rule, catalogue, api, onClose, onSaved}: Controls & {rule?: WebhookRule; catalogue: WebhookCatalogue; onClose: () => void; onSaved: (secret?: string) => void}) {
  const [form, setForm] = useState(() => fields(rule));
  const [version, setVersion] = useState(rule?.version);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const running = useRef(false);
  const patch = (change: Partial<RuleFields>) => setForm(previous => ({...previous, ...change}));
  const canBlock = form.events.length === 1 && form.events[0] === 'cluster_idle';
  async function reload() {
    if (running.current) return;
    running.current = true; setBusy(true); setError(null);
    try {
      const latest = (await api<WebhookCatalogue>('/v1/admin/webhooks')).rules.find(value => value.id === rule?.id);
      if (!latest) throw new Error('This rule is no longer available. Close the editor and refresh.');
      setForm(fields(latest)); setVersion(latest.version); setConflict(false);
    } catch (failure) {setError(errorMessage(failure));}
    finally {running.current = false; setBusy(false);}
  }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (running.current || conflict) return;
    running.current = true; setBusy(true); setError(null);
    try {
      if (!form.name.trim() || !form.events.length || !form.reason.trim()) throw new Error('Enter a name, choose an event and supply an audit reason.');
      const url = new URL(form.url);
      if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('Use an HTTPS endpoint without credentials, query parameters or a fragment.');
      if (form.blocking && (!canBlock || !form.idempotent)) throw new Error('A blocking rule must use only cluster_idle and a receiver that deduplicates the delivery ID.');
      if (form.blocking && form.enabled && catalogue.health_mode === 'disabled') throw new Error('Enable health monitoring before enabling a blocking webhook.');
      const selector = parseLabels(form.selector, true);
      if ((form.cluster_id.trim() || Object.keys(selector).length) && form.events.some(name => !catalogue.events.find(value => value.name === name)?.cluster)) throw new Error('Cluster filters require cluster-related events only.');
      const body = {...form, name: form.name.trim(), url: url.toString(), cluster_id: form.cluster_id.trim(), selector, reason: form.reason.trim(), ...(rule ? {expected_version: version} : {})};
      const result = await api<{rule: WebhookRule; secret?: string}>(rule ? `/v1/admin/webhooks/${encodeURIComponent(rule.id)}` : '/v1/admin/webhooks', {method: rule ? 'PATCH' : 'POST', body});
      onSaved(result.secret);
    } catch (failure) {if (failure instanceof ApiError && failure.status === 409 && rule && /version|changed|reload/i.test(failure.message)) setConflict(true); setError(errorMessage(failure));}
    finally {running.current = false; setBusy(false);}
  }
  return <Dialog open id="webhook-rule-dialog" title={rule ? 'Edit webhook' : 'Create webhook'} description="Choose committed application events and an approved HTTPS receiver." busy={busy} onClose={() => {if (!busy) onClose();}} footer={<><Button onClick={onClose} disabled={busy}>Cancel</Button><button form="webhook-rule-form" type="submit" className="button primary" disabled={busy || conflict}>{busy ? 'Saving…' : rule ? 'Save webhook' : 'Create webhook'}</button></>}>
    <form id="webhook-rule-form" onSubmit={save}>
      <FormError message={error}/>
      {conflict && <div className="notice warning"><p>Your draft is retained. Reload the current rule and review it before saving.</p><Button onClick={reload} disabled={busy}>Reload rule</Button></div>}
      <fieldset className="form-fields" disabled={busy || conflict}>
        <label className="field" htmlFor="webhook-name">Name<input id="webhook-name" value={form.name} onChange={event => patch({name: event.target.value})} required maxLength={100}/></label>
        <label className="field" htmlFor="webhook-url">HTTPS endpoint<input id="webhook-url" type="url" value={form.url} onChange={event => patch({url: event.target.value})} required maxLength={2048} placeholder="https://ci.example.test/devctl" autoComplete="off"/><small>{catalogue.allowed_origins.length ? `Allowed origins: ${catalogue.allowed_origins.join(', ')}` : 'An operator must configure approved receiver origins on the backend.'}</small></label>
        <fieldset className="webhook-events"><legend>Events</legend>{catalogue.events.map(value => <label className="webhook-checkbox" key={value.name}><input type="checkbox" checked={form.events.includes(value.name)} onChange={event => patch({events: event.target.checked ? [...form.events, value.name] : form.events.filter(name => name !== value.name)})}/><span><strong className="mono">{value.name}</strong><small>{value.description}</small></span></label>)}</fieldset>
        <div className="two-columns fields"><label className="field" htmlFor="webhook-cluster">Cluster ID<input id="webhook-cluster" value={form.cluster_id} onChange={event => patch({cluster_id: event.target.value})} maxLength={63}/><small>Optional exact cluster filter.</small></label><label className="field" htmlFor="webhook-selector">Cluster labels<input id="webhook-selector" value={form.selector} onChange={event => patch({selector: event.target.value})} placeholder="region=eu,type=test"/><small>Optional comma-separated key=value filter.</small></label></div>
        <label className="webhook-checkbox"><input id="webhook-blocking" type="checkbox" disabled={!canBlock && !form.blocking} checked={form.blocking} onChange={event => patch({blocking: event.target.checked})}/><span><strong>Hold the cluster until completion</strong><small>Available for cluster_idle only. Requires health monitoring. Failures keep the hold.</small></span></label>
        <label className="webhook-checkbox"><input id="webhook-idempotent" type="checkbox" checked={form.idempotent} onChange={event => patch({idempotent: event.target.checked})}/><span><strong>The receiver deduplicates the delivery ID</strong><small>Required for blocking rules. Retries reuse the same Idempotency-Key.</small></span></label>
        <label className="field" htmlFor="webhook-timeout">Completion timeout<select id="webhook-timeout" value={form.timeout_seconds} onChange={event => patch({timeout_seconds: Number(event.target.value)})}>{![300,900,3600,14400,86400].includes(form.timeout_seconds) && <option value={form.timeout_seconds}>{form.timeout_seconds} seconds</option>}<option value={300}>5 minutes</option><option value={900}>15 minutes</option><option value={3600}>1 hour</option><option value={14400}>4 hours</option><option value={86400}>24 hours</option></select></label>
        <label className="webhook-checkbox"><input id="webhook-enabled" type="checkbox" checked={form.enabled} onChange={event => patch({enabled: event.target.checked})}/><span><strong>Enabled</strong><small>Future matching events will send requests to this receiver.</small></span></label>
        <label className="field" htmlFor="webhook-reason">Audit reason<input id="webhook-reason" value={form.reason} onChange={event => patch({reason: event.target.value})} required maxLength={1000}/></label>
      </fieldset>
      <div className="notice"><Icon name="info"/><p>Rule edits affect future events. Queued deliveries retain their original endpoint and signing secret. Disabling a rule does not remove existing holds.</p></div>
    </form>
  </Dialog>;
}

function DeliveryAction({delivery, action, api, onClose, onSaved}: Controls & {delivery: WebhookDelivery; action: 'retry' | 'resolve'; onClose: () => void; onSaved: () => void}) {
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const running = useRef(false);
  const resolving = action === 'resolve';
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (running.current) return;
    running.current = true; setBusy(true); setError(null);
    try {
      if (!reason.trim() || resolving && !confirmed) throw new Error('Enter an audit reason and confirm external work has stopped when resolving a hold.');
      await api(`/v1/admin/webhook-deliveries/${encodeURIComponent(delivery.id)}/${action}`, {method: 'POST', body: {expected_state: delivery.state, reason: reason.trim(), ...(resolving ? {confirmed_stopped: true} : {})}});
      onSaved();
    } catch (failure) {setError(errorMessage(failure));}
    finally {running.current = false; setBusy(false);}
  }
  return <Dialog open id="webhook-delivery-dialog" title={resolving ? 'Resolve cluster hold?' : 'Retry webhook delivery?'} description={resolving ? 'This does not cancel a pipeline. Verify external work has stopped first.' : 'Resend the same delivery ID. This does not create a new pipeline execution.'} busy={busy} onClose={() => {if (!busy) onClose();}} footer={<><Button onClick={onClose} disabled={busy}>Cancel</Button><button form="webhook-delivery-form" className={`button ${resolving ? 'danger' : 'primary'}`} type="submit" disabled={busy || resolving && !confirmed}>{busy ? 'Saving…' : resolving ? 'Resolve hold' : 'Retry delivery'}</button></>}>
    <p className="mono">{delivery.id}</p><p>{delivery.cluster_id || 'Application event'} · {delivery.state}</p>
    <form id="webhook-delivery-form" onSubmit={submit}><FormError message={error}/><label className="field" htmlFor="webhook-delivery-reason">Audit reason<input id="webhook-delivery-reason" value={reason} onChange={event => setReason(event.target.value)} maxLength={1000} required disabled={busy}/></label>{resolving && <label className="webhook-checkbox"><input id="webhook-stopped" type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy}/><span>I have verified the external work has stopped and reviewed the cluster.</span></label>}</form>
    {resolving && <div className="notice warning"><Icon name="warning"/><p>This resolves only this delivery's hold. Other holds, manual maintenance and enforced health checks still apply.</p></div>}
  </Dialog>;
}

export default function Webhooks({api, notify}: PageProps) {
  const [catalogue, setCatalogue] = useState<WebhookCatalogue | null>(null);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<WebhookRule | 'new' | null>(null);
  const [action, setAction] = useState<{delivery: WebhookDelivery; action: 'retry' | 'resolve'} | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const secret = useRef('');
  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const [rules, runs] = await Promise.all([api<WebhookCatalogue>('/v1/admin/webhooks', {signal}), api<WebhookDelivery[]>('/v1/admin/webhook-deliveries', {signal})]);
      if (!signal?.aborted) {setCatalogue(rules); setDeliveries(runs); setError(null);}
    } catch (failure) {if (!signal?.aborted) setError(errorMessage(failure));}
  }, [api]);
  useEffect(() => {const abort = new AbortController(); void load(abort.signal); return () => {abort.abort(); secret.current = '';};}, [load]);
  const saved = (value?: string) => {setEditing(null); if (value) {secret.current = value; setShowSecret(true);} void load(); notify('Webhook saved. Existing deliveries keep their original configuration.');};
  const closeSecret = () => {secret.current = ''; setShowSecret(false);};
  return <>
    <div className="page-heading"><div><div className="eyebrow">ADMINISTRATION</div><h1 tabIndex={-1}>Events & automations</h1><p>Send application events to approved receivers and inspect cluster holds.</p></div><Button className="button primary" onClick={() => setEditing('new')} disabled={!catalogue}><Icon name="plus"/>Create webhook</Button></div>
    <div className="notice"><Icon name="info"/><p>Notifications run after committed actions. A blocking cluster_idle rule holds the cluster after its last booking ends until completion and fresh health verification.</p></div>
    {error && <FormError message={error}/>}<div className="webhook-toolbar"><Button id="refresh-webhooks" onClick={() => load()}><Icon name="refresh"/>Refresh events</Button><span className="small muted">Opening this page does not send webhooks.</span></div>
    {!catalogue ? <section className="panel" role="status">{error ? 'Unable to load webhooks. Use Refresh events to retry.' : 'Loading webhooks…'}</section> : <section className="panel flush table-wrap"><div className="webhook-panel-heading"><h2>Webhook rules</h2><span>{catalogue.rules.length} configured</span></div><DataTable headers={['Rule', 'Receiver', 'Events / filters', 'Behavior', 'Manage']} emptyText="No webhooks configured. Create a disabled rule to prepare an integration." rows={catalogue.rules.map(rule => [<><strong>{rule.name}</strong><small className="mono">{rule.id}</small></>, <span className="mono webhook-url">{rule.url}</span>, <><span className="mono">{rule.events.join(', ')}</span><small>{rule.cluster_id || 'All matching clusters'}{Object.keys(rule.selector || {}).length ? ` · ${formatLabels(rule.selector)}` : ''}</small></>, <><Pill tone={rule.enabled ? 'brand' : 'neutral'}>{rule.enabled ? 'Enabled' : 'Disabled'}</Pill><small>{rule.blocking ? 'Holds cluster until completion' : 'Notification only'}</small></>, <Button onClick={() => setEditing(rule)}>Edit webhook</Button>])}/></section>}
    <section className="panel flush table-wrap"><div className="webhook-panel-heading"><h2>Recent deliveries</h2><span>Latest 100</span></div><DataTable headers={['Delivery / event', 'Cluster', 'State', 'Last update', 'Actions']} emptyText="No deliveries yet." rows={deliveries.map(delivery => [<><strong className="mono">{delivery.id}</strong><small>{delivery.event_type} · {delivery.attempts} attempts</small></>, delivery.cluster_id || '—', <><Pill tone={terminal(delivery.state) ? 'success' : delivery.state === 'FAILED' || delivery.state === 'TIMED_OUT' ? 'warning' : 'neutral'}>{delivery.state.replaceAll('_', ' ')}</Pill><small>{delivery.blocking && !terminal(delivery.state) ? 'Cluster hold active' : 'No cluster hold'}</small>{delivery.reason_code && <small>{delivery.reason_code.replaceAll('_', ' ')}</small>}</>, <><span>{date(delivery.updated_at)}</span><small>Deadline {date(delivery.deadline)}</small></>, <div className="row-actions">{delivery.state === 'FAILED' && <Button onClick={() => setAction({delivery, action: 'retry'})}>Retry delivery</Button>}{delivery.blocking && !terminal(delivery.state) && <Button className="button subtle" onClick={() => setAction({delivery, action: 'resolve'})}>Resolve hold…</Button>}</div>])}/></section>
    {editing && catalogue && <RuleEditor rule={editing === 'new' ? undefined : editing} catalogue={catalogue} api={api} notify={notify} onClose={() => setEditing(null)} onSaved={saved}/>}
    {action && <DeliveryAction {...action} api={api} notify={notify} onClose={() => setAction(null)} onSaved={() => {setAction(null); void load(); notify('Delivery updated. Other placement controls remain in effect.');}}/>}
    {showSecret && <Dialog open id="webhook-secret-dialog" title="Save the signing secret" description="This secret is shown once. Configure it on your approved receiver before enabling the rule." onClose={closeSecret} footer={<Button className="button primary" onClick={closeSecret}>I saved the secret</Button>}><label className="field" htmlFor="webhook-secret">Signing secret<textarea id="webhook-secret" readOnly defaultValue={secret.current} spellCheck={false}/></label><p>Verify incoming signatures and deduplicate the Idempotency-Key. The secret is not included in rule lists or delivery history.</p></Dialog>}
  </>;
}
