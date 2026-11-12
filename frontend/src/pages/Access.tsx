import {useRef, useState} from 'react';
import type {FormEvent} from 'react';
import type {PageProps, PAT} from '../types';
import {Button, FormError, errorMessage} from '../components/ui';
import {Dialog} from '../components/Dialog';
import {Icon} from '../components/Icon';
import {PATTable} from '../components/PATTable';
import {parseLabels} from '../lib/labels';
import {timestamp} from './developer-utils';

interface PATCreation {pat: PAT; kubeconfig: string}

function downloadConfig(raw: string, username: string) {
  const filename = `devctl-${username}`.replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 80);
  const blob = new Blob([raw], {type: 'application/yaml'});
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = `${filename}.yaml`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(href), 1000);
}

export default function Access({data, api, refresh, notify}: PageProps) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('Browser kubeconfig');
  const [ttl, setTTL] = useState('8h');
  const [autoBooking, setAutoBooking] = useState(false);
  const [selector, setSelector] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Array<{id: string; message: string}>>([]);
  const [query, setQuery] = useState('');
  const submitting = useRef(false);
  const active = data.pats.filter(pat => !pat.revoked_at && Date.parse(pat.expires_at) > Date.now()).length;
  const pats = data.pats.filter(pat => [pat.name, pat.id].join(' ').toLowerCase().includes(query.trim().toLowerCase()));

  function showCreation() {setError(''); setFieldErrors([]); setOpen(true);}
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current) return;
    const fields: Array<{id: string; message: string}> = [];
    if (!name.trim()) fields.push({id: 'pat-name', message: 'Enter a credential name.'});
    let labels: Record<string, string> = {};
    if (autoBooking) {
      try {labels = parseLabels(selector, true);} catch (problem) {fields.push({id: 'pat-selector', message: errorMessage(problem)});}
    }
    if (fields.length) {setFieldErrors(fields); setError('Check the highlighted fields and try again.'); return;}
    submitting.current = true;
    setBusy(true);
    setError('');
    setFieldErrors([]);
    try {
      // Keep the one-time credential in this local response and Blob only.
      // Never store it in React state, browser storage or an error message.
      const issued = await api<PATCreation>('/v1/pats', {method: 'POST', body: {name: name.trim(), ttl, auto_booking: {enabled: autoBooking, selector: labels}}});
      try {downloadConfig(issued.kubeconfig, data.session.user.name || 'developer');} finally {issued.kubeconfig = '';}
      setOpen(false);
      const expiry = issued.pat.expires_at;
      setName('Browser kubeconfig');
      setTTL('8h');
      setAutoBooking(false);
      setSelector('');
      try {await refresh();} catch {notify(`Kubeconfig downloaded. Access expires ${timestamp(expiry)}. Refresh to update the token list.`, true); return;}
      notify(`Kubeconfig downloaded. Set its file permissions to 0600. Access expires ${timestamp(expiry)}.`);
    } catch (problem) {setError(errorMessage(problem));} finally {submitting.current = false; setBusy(false);}
  }

  return <>
    <div className="page-title page-heading"><div><div className="eyebrow">ACCESS & TOKENS</div><h1 id="access-title">Connect once. Keep building.</h1><p>Your gateway kubeconfig follows your current primary cluster.</p></div><Button className="button primary" onClick={showCreation}><Icon name="plus"/>Create kubeconfig</Button></div>
    <div className="connection-options access-grid">
      <article className="panel connection-card"><span className="connection-icon"><Icon name="file"/></span><div><div className="eyebrow">BROWSER + STOCK KUBECTL</div><h2>Your personal kubeconfig</h2><p>Create a personal token and download its gateway config once. No additional executable is required.</p></div><div className="code-block"><span className="code-caption">USE THE DOWNLOADED FILE</span><pre><code>{'export KUBECONFIG=/path/to/devctl.yaml\nkubectl get namespaces'}</code></pre></div><Button className="button primary" onClick={showCreation}><Icon name="arrow"/>Create & download</Button><span className="small muted">A new download issues a new token.</span></article>
      <article className="panel connection-card"><span className="connection-icon secondary-icon"><Icon name="terminal"/></span><div><div className="eyebrow">FULL CLI</div><h2>More control from your terminal</h2><p>Use the developer CLI for booking, selection, sharing and approved administrator operations.</p></div><div className="code-block"><span className="code-caption">DEVELOPER CLI</span><pre><code>{'devctl login\ndevctl start\nexport KUBECONFIG="$(devctl setup)"\nkubectl get namespaces'}</code></pre></div><div className="inline-meta"><Icon name="key"/>Uses short-lived SSO access and refresh tokens.</div></article>
    </div>
    <div className="section-title section-heading"><div><h2>Your personal tokens</h2><p>Secret values appear only in the original download. Existing tokens cannot be downloaded again.</p></div><div className="row-actions"><span className="meta-count">{active} active · {data.pats.length - active} ended</span><Button id="refresh-pats" className="button subtle" onClick={refresh} notify={notify}><Icon name="refresh"/>Refresh</Button></div></div>
    <div id="pat-list" className="panel flush table-wrap mobile-records"><div className="table-toolbar"><label className="search-input"><Icon name="search"/><input type="search" aria-label="Search personal tokens" placeholder="Search token name or ID" value={query} onChange={event => setQuery(event.target.value)}/></label><span className="small muted">{pats.length} of {data.pats.length} credentials</span></div><PATTable pats={pats} data={data} api={api} refresh={refresh} notify={notify}/></div>
    <div className="notice"><Icon name="info"/><p>Signing out and releasing bookings leave these tokens valid until expiry or explicit revocation. An enabled automatic-booking token can book again on its next Kubernetes request.</p></div>
    <Dialog open={open} busy={busy} onClose={() => {if (!submitting.current) setOpen(false);}} title="Create a kubeconfig" description="Issue one personal gateway token. Its secret is included in a one-time kubeconfig download." id="create-pat-dialog">
      <form id="pat-form" className="drawer-form" onSubmit={create} noValidate><div className="drawer-content"><FormError message={error} fields={fieldErrors}/>
        <label className="field">Credential name<input id="pat-name" name="name" value={name} onChange={event => setName(event.target.value)} maxLength={100} required disabled={busy} autoComplete="off" aria-invalid={fieldErrors.some(field => field.id === 'pat-name')} aria-describedby={fieldErrors.some(field => field.id === 'pat-name') ? 'pat-name-error' : 'pat-name-help'}/><small id="pat-name-help">Choose a name you will recognise later.</small>{fieldErrors.find(field => field.id === 'pat-name') && <span className="field-error" id="pat-name-error">{fieldErrors.find(field => field.id === 'pat-name')?.message}</span>}</label>
        <label className="field">Token lifetime<select name="ttl" value={ttl} onChange={event => setTTL(event.target.value)} disabled={busy}><option value="8h">8 hours</option><option value="1h">1 hour</option><option value="24h">1 day</option><option value="168h">7 days</option></select><small>Fixed expiry. Cluster activity does not extend this token.</small></label>
        <label className="checkbox-field policy-switch"><span><strong>Automatic booking</strong><small>Book a matching unused cluster when you have no primary.</small></span><input id="pat-auto-booking" name="auto_booking_enabled" type="checkbox" checked={autoBooking} onChange={event => setAutoBooking(event.target.checked)} disabled={busy} aria-label="Enable automatic booking"/></label>
        <p className="small muted">{autoBooking ? 'An existing primary always takes precedence over these labels.' : 'Off by default. This token will use your existing primary.'}</p>
        <label className={`field${autoBooking ? '' : ' disabled-field'}`}>Required labels<input id="pat-selector" name="auto_booking_selector" placeholder="region=eu,type=test" value={selector} onChange={event => setSelector(event.target.value)} disabled={!autoBooking || busy} maxLength={10000} autoComplete="off" aria-invalid={fieldErrors.some(field => field.id === 'pat-selector')} aria-describedby={fieldErrors.some(field => field.id === 'pat-selector') ? 'pat-selector-error' : 'pat-selector-help'}/><small id="pat-selector-help">{autoBooking ? 'Every equality label must match. Blank allows any unused cluster.' : 'Enable automatic booking to set a selector.'}</small>{fieldErrors.find(field => field.id === 'pat-selector') && <span className="field-error" id="pat-selector-error">{fieldErrors.find(field => field.id === 'pat-selector')?.message}</span>}</label>
        <div className="notice"><Icon name="info"/><p>If enabled, automatic booking can reserve again after release or sign-out. Preferences can be edited later without replacing the file.</p></div><div className="quiet-note"><Icon name="lock"/>Treat the downloaded file as a secret. Set its permissions to 0600. PATs do not refresh themselves.</div>
      </div><div className="drawer-footer"><Button onClick={() => setOpen(false)} disabled={busy}>Cancel</Button><button type="submit" className="button primary" disabled={busy}>{busy ? 'Creating…' : 'Create & download'}<Icon name="file"/></button></div></form>
    </Dialog>
  </>;
}
