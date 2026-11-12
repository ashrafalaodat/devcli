import {useRef, useState} from 'react';
import type {FormEvent} from 'react';
import type {PageProps, PAT} from '../types';
import {Button, FormError, Pill, errorMessage} from './ui';
import {Dialog} from './Dialog';
import {Icon} from './Icon';
import {formatLabels, parseLabels} from '../lib/labels';
import {relative, timestamp} from '../pages/developer-utils';

export type PATTableProps = Pick<PageProps, 'data' | 'api' | 'refresh' | 'notify'> & {pats: PAT[]; admin?: boolean};
type PATControlProps = Pick<PATTableProps, 'data' | 'api' | 'refresh' | 'notify'> & {pat: PAT; admin: boolean};

function hasEnded(pat: PAT): boolean {
  const expiry = Date.parse(pat.expires_at);
  return Boolean(pat.revoked_at) || !Number.isFinite(expiry) || expiry <= Date.now();
}

function PATState({pat}: {pat: PAT}) {
  if (pat.revoked_at) return <Pill tone="danger">Revoked</Pill>;
  if (hasEnded(pat)) return <Pill>Expired</Pill>;
  return <Pill tone="success">Active</Pill>;
}

function PATPolicy({pat, admin, data, api, refresh, notify}: PATControlProps) {
  const policy = pat.auto_booking ?? {enabled: false, selector: {}};
  const [enabled, setEnabled] = useState(policy.enabled);
  const [selector, setSelector] = useState(formatLabels(policy.selector ?? {}));
  const [reason, setReason] = useState('');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [fields, setFields] = useState<Array<{id: string; message: string}>>([]);
  const submitting = useRef(false);
  const foreign = admin && pat.owner !== data.session.owner_id;
  const ended = hasEnded(pat);
  const selectorID = `pat-policy-selector-${pat.id}`;
  const reasonID = `pat-policy-reason-${pat.id}`;

  function edit() {
    setEnabled(policy.enabled);
    setSelector(formatLabels(policy.selector ?? {}));
    setReason('');
    setError('');
    setFields([]);
    setOpen(true);
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current || ended) return;
    const invalid: Array<{id: string; message: string}> = [];
    let labels: Record<string, string> = {};
    try {labels = parseLabels(selector, true);} catch (problem) {invalid.push({id: selectorID, message: errorMessage(problem)});}
    if (foreign && !reason.trim()) invalid.push({id: reasonID, message: 'Enter an audit reason for changing another developer’s token.'});
    if (invalid.length) {setFields(invalid); setError('Check the highlighted fields and try again.'); return;}
    submitting.current = true;
    setBusy(true);
    setError('');
    setFields([]);
    try {
      const body: {auto_booking: {enabled: boolean; selector: Record<string, string>}; reason?: string} = {auto_booking: {enabled, selector: labels}};
      if (foreign) body.reason = reason.trim();
      await api<PAT>(`/v1/pats/${encodeURIComponent(pat.id)}`, {method: 'PATCH', body});
      setOpen(false);
      try {await refresh();} catch {notify('Policy saved. Refresh the token list to load its latest preferences.', true); return;}
      notify('Automatic booking preferences saved. Your current primary, token, downloaded file and expiry are unchanged.');
    } catch (problem) {setError(errorMessage(problem));} finally {submitting.current = false; setBusy(false);}
  }

  return <>
    <Button className="button subtle" onClick={edit} disabled={ended || pat.scope !== 'kubernetes:primary'}>Edit policy</Button>
    <Dialog open={open} busy={busy} onClose={() => {if (!submitting.current) setOpen(false);}} title="Edit booking policy" description="Update when this token can book a cluster. The token and downloaded kubeconfig stay the same." id={`pat-policy-${pat.id}`}>
      <form className="drawer-form pat-policy-form" onSubmit={save} noValidate><div className="drawer-content"><FormError message={error} fields={fields}/><div className="token-name"><Icon name="key"/><div><strong>{pat.name}</strong><small>Expires {timestamp(pat.expires_at)}</small></div></div>
        <label className="checkbox-field policy-switch"><span><strong>Automatic booking</strong><small>Only when you have no existing primary.</small></span><input type="checkbox" name="enabled" checked={enabled} onChange={event => setEnabled(event.target.checked)} disabled={busy || ended} aria-label="Enable automatic booking"/></label>
        <label className="field">Required labels<input id={selectorID} name="selector" value={selector} onChange={event => setSelector(event.target.value)} placeholder="region=eu,type=test" maxLength={10000} disabled={busy || ended} autoComplete="off" aria-invalid={fields.some(field => field.id === selectorID)} aria-describedby={fields.some(field => field.id === selectorID) ? `${selectorID}-error` : `${selectorID}-help`}/><small id={`${selectorID}-help`}>Every equality label must match. Blank allows any unused cluster. The saved selector is retained when automatic booking is off.</small>{fields.find(field => field.id === selectorID) && <span className="field-error" id={`${selectorID}-error`}>{fields.find(field => field.id === selectorID)?.message}</span>}</label>
        <div className="selection-preview"><span className="eyebrow">HOW THIS POLICY WORKS</span><ol className="policy-steps"><li>Use your current primary, even when it has different labels.</li><li>With no primary and automatic booking on, book an unused matching cluster.</li><li>If none match, return a clear error. No queue or fallback outside these labels.</li></ol></div>
        {foreign && <label className="field">Audit reason<input id={reasonID} name="reason" value={reason} onChange={event => setReason(event.target.value)} required maxLength={500} disabled={busy || ended} aria-invalid={fields.some(field => field.id === reasonID)} aria-describedby={fields.some(field => field.id === reasonID) ? `${reasonID}-error` : `${reasonID}-help`}/><small id={`${reasonID}-help`}>Required when changing another developer’s token.</small>{fields.find(field => field.id === reasonID) && <span className="field-error" id={`${reasonID}-error`}>{fields.find(field => field.id === reasonID)?.message}</span>}</label>}
        {ended && <div className="notice warning"><Icon name="info"/><p>This token has expired or been revoked. Its policy can no longer be changed.</p></div>}
        <div className="notice"><Icon name="info"/><p>This edit affects future automatic bookings only. It does not change your current primary, token value, downloaded file or fixed expiry.</p></div><div className="quiet-note">A valid token with automatic booking enabled can reserve again after sign-out or release.</div>
      </div><div className="drawer-footer"><Button onClick={() => setOpen(false)} disabled={busy}>Cancel</Button><button type="submit" className="button primary" disabled={busy || ended}>{busy ? 'Saving…' : 'Save policy'}</button></div></form>
    </Dialog>
  </>;
}

function PATRevoke({pat, admin, data, api, refresh, notify}: PATControlProps) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [reasonError, setReasonError] = useState('');
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const foreign = admin && pat.owner !== data.session.owner_id;
  const ended = hasEnded(pat);
  const reasonID = `pat-revoke-reason-${pat.id}`;
  async function revoke(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current || ended) return;
    if (foreign && !reason.trim()) {setReasonError('Enter an audit reason for revoking another developer’s token.'); setError('An audit reason is required.'); return;}
    submitting.current = true;
    setBusy(true);
    setError('');
    setReasonError('');
    try {
      await api(`/v1/pats/${encodeURIComponent(pat.id)}`, {method: 'DELETE', body: {reason: reason.trim()}});
      setOpen(false);
      try {await refresh();} catch {notify('Personal gateway token revoked. Refresh the token list to load its latest state.', true); return;}
      notify('Personal gateway credential revoked. Bookings and workloads remain.');
    } catch (problem) {setError(errorMessage(problem));} finally {submitting.current = false; setBusy(false);}
  }
  if (ended) return null;
  return <>
    <Button className="button danger-text" onClick={() => {setError(''); setReasonError(''); setReason(''); setOpen(true);}}>Revoke</Button>
    <Dialog open={open} busy={busy} onClose={() => {if (!submitting.current) setOpen(false);}} title={`Revoke ${pat.name}?`} description="Its downloaded kubeconfig will stop working. This cannot be undone. Create a new personal kubeconfig if you need a replacement." id={`pat-revoke-${pat.id}`}>
      <form className="drawer-form" onSubmit={revoke} noValidate><div className="drawer-content"><FormError message={error} fields={reasonError ? [{id: reasonID, message: reasonError}] : undefined}/><div className="notice warning"><Icon name="info"/><p>Bookings and Kubernetes workloads remain. Revocation prevents this token from using a primary or making future automatic bookings.</p></div>{foreign && <label className="field">Audit reason<input id={reasonID} name="reason" value={reason} onChange={event => setReason(event.target.value)} required maxLength={500} disabled={busy} aria-invalid={Boolean(reasonError)} aria-describedby={reasonError ? `${reasonID}-error` : `${reasonID}-help`}/><small id={`${reasonID}-help`}>Required for another developer’s credential.</small>{reasonError && <span className="field-error" id={`${reasonID}-error`}>{reasonError}</span>}</label>}</div><div className="drawer-footer"><Button onClick={() => setOpen(false)} disabled={busy}>Keep token</Button><button type="submit" className="button danger" disabled={busy}>{busy ? 'Revoking…' : 'Revoke token'}</button></div></form>
    </Dialog>
  </>;
}

export function PATTable({pats, admin = false, data, api, refresh, notify}: PATTableProps) {
  if (!pats.length) return <div className="empty"><strong>{admin ? 'No matching personal gateway tokens.' : 'No personal gateway tokens yet.'}</strong><p>{admin ? 'Change your filters or check again after a developer creates a credential.' : 'Create a personal kubeconfig above. No booking is required to create it.'}</p></div>;
  const headers = admin ? ['Credential / owner', 'Status & expiry', 'Automatic booking', 'Last used', 'Actions'] : ['Token', 'Expires', 'Automatic booking', 'Actions'];
  return <table className="mobile-records"><thead><tr>{headers.map(header => <th key={header} scope="col">{header}</th>)}</tr></thead><tbody>{pats.map(pat => {
    const person = pat.owner === data.session.owner_id ? data.session.user : data.developers.find(developer => developer.owner_id === pat.owner)?.user;
    const ended = hasEnded(pat);
    const controls = {pat, admin, data, api, refresh, notify};
    const policy = pat.auto_booking ?? {enabled: false, selector: {}};
    return <tr key={pat.id} data-pat-id={pat.id}><td data-label={headers[0]}><strong>{pat.name}</strong>{admin ? <small>{person ? person.display_name || person.name : pat.owner.slice(0, 20)}{person?.email ? ` · ${person.email}` : ''}</small> : <small>Created {timestamp(pat.created_at)} · Last used {pat.last_used_at ? relative(pat.last_used_at) : 'not yet'}</small>}<small className="mono">{pat.id}</small>{pat.scope !== 'kubernetes:primary' && <small>Legacy credential</small>}</td><td data-label={headers[1]}><PATState pat={pat}/><small>{timestamp(pat.expires_at)}</small><small>{ended ? 'No longer usable' : 'Fixed expiry'}</small></td><td data-label="Automatic booking"><span className="pat-policy-summary"><Pill tone={!ended && policy.enabled ? 'brand' : 'neutral'}>{ended ? 'Not active' : policy.enabled ? 'On' : 'Off'}</Pill></span>{!ended && policy.enabled ? <div className="tags">{Object.entries(policy.selector ?? {}).length ? Object.entries(policy.selector).map(([key, value]) => <span className="tag mono" key={key}>{key}={value}</span>) : <small>Any unused cluster</small>}</div> : !ended ? <small>Use an existing primary only</small> : null}</td>{admin && <td data-label="Last used"><strong>{pat.last_used_at ? relative(pat.last_used_at) : 'Not yet'}</strong><small>{pat.last_used_at ? timestamp(pat.last_used_at) : '—'}</small></td>}<td data-label="Actions"><div className="row-actions">{!ended && pat.scope === 'kubernetes:primary' && <PATPolicy {...controls}/>}<PATRevoke {...controls}/>{ended && <span className="muted">No actions available</span>}</div></td></tr>;
  })}</tbody></table>;
}
