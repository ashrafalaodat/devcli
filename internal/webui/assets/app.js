'use strict';

// No OAuth tokens or PATs are kept in browser storage. A PAT appears only in an
// explicitly requested one-time download and is discarded immediately afterward.
(() => {
  const state = {session: null, clusters: [], sessions: [], pats: [], allPats: [], audit: [], section: 'overview', refreshing: false};
  const $ = id => document.getElementById(id);
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };
  const clear = node => node.replaceChildren();
  const pill = (text, tone = 'neutral') => element('span', text, `pill ${tone}`);
  const date = raw => raw ? new Date(raw).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'}) : 'Until stop or logout';
  const owner = () => state.session && state.session.owner_id;
  const mine = () => state.sessions.filter(s => s.owner === owner());
  const active = () => mine().filter(s => s.state === 'ACTIVE');
  const cluster = id => state.clusters.find(c => c.id === id);
  const clusterName = id => { const c = cluster(id); return c ? c.name : id; };
  const safeName = name => String(name || 'devctl').replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 80);
  const button = (text, tone, action) => { const b = element('button', text, `button ${tone || 'secondary'}`); b.type = 'button'; if (action) b.addEventListener('click', () => run(b, action)); return b; };

  function notify(message, error = false) {
    const node = $('notification'); clear(node); node.append(element('span', message));
    node.className = `notification${error ? ' error' : ''}`;
    const close = button('×', 'notification-close', () => node.classList.add('hidden'));
    close.className = 'notification-close'; close.setAttribute('aria-label', 'Dismiss notification'); node.append(close);
  }
  async function api(path, options = {}) {
    const headers = {'Accept': 'application/json', ...options.headers};
    if (state.session) headers['X-CSRF-Token'] = state.session.csrf_token;
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, {credentials: 'same-origin', ...options, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body)});
    const content = response.headers.get('Content-Type') || '';
    let result = null;
    if (content.includes('application/json')) result = await response.json();
    if (!response.ok) {
      if (response.status === 401) signedOut();
      throw new Error(result && result.error ? result.error : `Request failed (${response.status}).`);
    }
    return result;
  }
  async function run(control, work) {
    if (control && control.disabled) return;
    if (control) control.disabled = true;
    try { await work(); } catch (error) { notify(error.message || 'The request could not be completed.', true); }
    finally { if (control) control.disabled = false; }
  }
  function parseLabels(raw) {
    const out = {};
    for (const field of raw.split(',')) {
      const entry = field.trim(); if (!entry) continue;
      const at = entry.indexOf('=');
      if (at < 1 || at === entry.length - 1) throw new Error('Labels must use comma-separated key=value pairs.');
      const key = entry.slice(0, at).trim(), value = entry.slice(at + 1).trim();
      if (!key || !value || Object.hasOwn(out, key)) throw new Error('Label keys and values must be nonempty, with no duplicate keys.');
      Object.defineProperty(out, key, {value, enumerable: true, configurable: true, writable: true});
    }
    return out;
  }
  function signedOut() {
    state.session = null; state.clusters = []; state.sessions = []; state.pats = []; state.allPats = []; state.audit = [];
    $('welcome').classList.remove('hidden'); $('workspace').classList.add('hidden');
    clear($('identity'));
    const link = element('a', 'Sign in', 'button secondary'); link.href = '/auth/login'; $('identity').append(link);
  }
  function renderIdentity() {
    const u = state.session.user, node = $('identity'); clear(node);
    node.append(element('span', (u.display_name || u.name || '?').slice(0, 1).toUpperCase(), 'avatar'));
    const name = element('span', null, 'identity-name'); name.append(element('span', u.display_name || u.name || 'Developer'), element('small', u.email || u.name)); node.append(name);
    node.append(pill(u.admin ? 'Administrator' : 'Developer', 'neutral'));
    node.append(button('Sign out', 'text', async () => {
      if (!window.confirm('Sign out and release ALL of your bookings? Your personal gateway tokens will be revoked. Kubernetes workloads will remain.')) return;
      await api('/auth/logout', {method: 'POST'}); signedOut(); notify('Signed out. Your bookings were released and personal gateway tokens revoked.');
    }));
    $('admin-nav').classList.toggle('hidden', !u.admin);
  }
  function showSection(name) {
    if (name === 'admin' && !(state.session && state.session.user.admin)) name = 'overview';
    state.section = name;
    for (const section of document.querySelectorAll('.page-section')) section.classList.toggle('hidden', section.id !== `section-${name}`);
    for (const nav of document.querySelectorAll('[data-section]')) {
      const selected = nav.dataset.section === name; nav.classList.toggle('active', selected);
      if (selected) nav.setAttribute('aria-current', 'page'); else nav.removeAttribute('aria-current');
    }
  }
  function option(value, text) { const node = element('option', text); node.value = value; return node; }
  function populateSelect(node, rows, first) {
    const previous = node.value; node.replaceChildren(option('', first));
    for (const row of rows) node.append(option(row.value, row.text));
    if (Array.from(node.options).some(o => o.value === previous)) node.value = previous;
  }
  function renderMetrics() {
    const values = [ ['Your bookings', active().length, '◫'], ['Available clusters', state.clusters.filter(c => c.available).length, '◇'], ['Team members active', new Set(state.sessions.filter(s => s.state === 'ACTIVE').map(s => s.owner)).size, '↗'] ];
    clear($('metrics'));
    for (const [label, count, icon] of values) {
      const card = element('div', null, 'metric'), info = element('div'); info.append(element('div', label, 'metric-label'), element('div', count, 'metric-value')); card.append(info, element('div', icon, 'metric-icon')); $('metrics').append(card);
    }
  }
  function table(target, headers, rows, emptyText) {
    clear(target);
    if (!rows.length) { target.append(element('div', emptyText || 'Nothing here yet.', 'empty')); return; }
    const node = element('table'), head = element('thead'), hr = element('tr');
    for (const label of headers) { const th = element('th', label); th.scope = 'col'; hr.append(th); } head.append(hr); node.append(head);
    const body = element('tbody');
    for (const cells of rows) { const tr = element('tr'); for (const value of cells) { const td = element('td'); if (value instanceof Node) td.append(value); else td.textContent = String(value == null ? '—' : value); tr.append(td); } body.append(tr); }
    node.append(body); target.append(node);
  }
  function contact(session) { const node = element('div'); node.append(element('strong', session.display_name || session.name || 'Developer')); if (session.email) { const a = element('a', session.email); a.href = `mailto:${encodeURIComponent(session.email)}`; node.append(element('br'), a); } else node.append(element('small', session.name || session.owner.slice(0, 12))); return node; }
  function detail(label, value) { const node = element('div'); node.append(element('span', label, 'detail-label'), element('span', value, 'text-break')); return node; }
  function sessionAction(id, suffix, body) { return api(`/v1/sessions/${encodeURIComponent(id)}/${suffix}`, {method: 'POST', body}); }
  function renderBookings() {
    const node = $('my-bookings'); clear(node); const rows = active(); $('booking-count').textContent = `${rows.length} active`;
    if (!rows.length) { const empty = element('div', null, 'empty'); empty.append(element('strong', 'Your next environment is ready when you are.'), element('span', 'Book an available cluster above to get started.')); node.append(empty); }
    for (const s of rows) {
      const c = cluster(s.cluster), card = element('article', null, 'booking-card'), top = element('div', null, 'card-top'), title = element('div', null, 'card-title');
      title.append(element('span', '◇', 'cluster-mark')); const info = element('div'); info.append(element('h3', clusterName(s.cluster)), element('small', s.cluster)); title.append(info); top.append(title, pill(c && c.shareable ? 'Shared' : 'Exclusive', c && c.shareable ? 'warning' : 'success')); card.append(top);
      const details = element('div', null, 'details'); details.append(detail('Expires', date(s.expires_at)), detail('Last activity', s.last_activity_at ? date(s.last_activity_at) : 'No requests yet')); card.append(details);
      const actions = element('div', null, 'card-actions');
      actions.append(button('↓ Get kubeconfig', 'primary small', () => { showSection('access'); $('pat-session').value = s.id; $('pat-form').scrollIntoView({behavior: 'smooth', block: 'center'}); }));
      if (c && c.controller_session === s.id) actions.append(button(c.shareable ? 'Disable sharing' : 'Allow sharing', 'secondary small', async () => { await sessionAction(s.id, 'share', {shareable: !c.shareable}); await refresh(); notify(c.shareable ? 'New shared bookings are now disabled.' : 'Sharing enabled. Other developers can join this cluster.'); }));
      actions.append(button('Stop', 'danger small', async () => { if (!window.confirm(`Release your booking on ${clusterName(s.cluster)}? Gateway access will end. Kubernetes workloads will remain.`)) return; await sessionAction(s.id, 'stop'); await refresh(); notify('Booking released. Kubernetes workloads were retained.'); })); card.append(actions);
      const renew = element('form', null, 'renew-form'), input = element('input'); input.name = 'ttl'; input.value = '4h'; input.required = true; input.setAttribute('aria-label', `Renew ${s.cluster} duration`); const submit = element('button', 'Renew lease', 'button secondary small'); submit.type = 'submit'; renew.append(input, submit);
      renew.addEventListener('submit', event => { event.preventDefault(); run(submit, async () => { await sessionAction(s.id, 'renew', {ttl: input.value.trim()}); await refresh(); notify('Booking lease renewed. Existing PAT expiry is unchanged.'); }); }); card.append(renew, element('span', s.id, 'mono booking-id')); node.append(card);
    }
    table($('team-bookings'), ['Cluster', 'Developer / contact', 'Access', 'Expires'], state.sessions.filter(s => s.state === 'ACTIVE').map(s => [clusterName(s.cluster), contact(s), pill((cluster(s.cluster) || {}).shareable ? 'Shared' : 'Exclusive', (cluster(s.cluster) || {}).shareable ? 'warning' : 'neutral'), date(s.expires_at)]), 'No active team bookings.');
    table($('booking-history'), ['Cluster', 'Session', 'State', 'Ended'], mine().filter(s => s.state !== 'ACTIVE').slice().reverse().map(s => [clusterName(s.cluster), s.id, pill(s.state), date(s.ended_at)]), 'No previous bookings.');
  }
  function labelsNode(labels) { const node = element('div', null, 'labels'); for (const [key, value] of Object.entries(labels || {})) node.append(element('span', `${key}=${value}`, 'label')); return node; }
  function clusterCard(c, admin = false) {
    const card = element('article', null, 'cluster-card'), top = element('div', null, 'card-top'), title = element('div'); title.append(element('h3', c.name), element('small', c.id, 'mono')); top.append(title, pill(c.maintenance ? 'Maintenance' : c.available ? 'Available' : 'Reserved', c.maintenance ? 'warning' : c.available ? 'success' : 'neutral')); card.append(top, labelsNode(c.labels), element('p', c.reason));
    const people = element('div', null, 'participants');
    if (!(c.participants || []).length) people.append(element('span', 'No active holders.'));
    for (const person of c.participants || []) { const row = element('div', null, 'participant'); row.append(contact(person)); people.append(row); } card.append(people);
    if (!admin) {
      if (c.available && !(c.participants || []).some(s => s.owner === owner())) card.append(button((c.participants || []).length ? 'Join shared cluster' : 'Book cluster', 'secondary', () => { showSection('overview'); $('booking-cluster').value = c.id; $('booking-form').scrollIntoView({behavior: 'smooth', block: 'center'}); }));
    } else {
      const form = element('form', null, 'maintenance-form'), label = element('label', 'Audit reason'), input = element('input'); input.name = 'reason'; input.required = true; input.maxLength = 500; input.placeholder = c.maintenance ? 'Ready for bookings' : 'Planned maintenance'; label.append(input);
      const submit = element('button', c.maintenance ? 'Enable placement' : 'Set maintenance', `button ${c.maintenance ? 'secondary' : 'danger'} small`); submit.type = 'submit'; form.append(label, submit);
      form.addEventListener('submit', event => { event.preventDefault(); run(submit, async () => { await api(`/v1/admin/clusters/${encodeURIComponent(c.id)}`, {method: 'PATCH', body: {maintenance: !c.maintenance, reason: input.value.trim()}}); await refresh(); notify('Cluster placement controls updated. Existing bookings remain.'); }); }); card.append(form);
    }
    return card;
  }
  function renderClusters() { clear($('cluster-list')); clear($('maintenance-list')); if (!state.clusters.length) { $('cluster-list').append(element('div', 'No clusters registered. Ask an administrator to register an approved environment.', 'empty')); return; } for (const c of state.clusters) { $('cluster-list').append(clusterCard(c)); if (state.session.user.admin) $('maintenance-list').append(clusterCard(c, true)); } }
  function patState(p) { if (p.revoked_at) return pill('Revoked', 'danger'); if (Date.parse(p.expires_at) <= Date.now()) return pill('Expired', 'neutral'); if (!state.sessions.some(s => s.id === p.session_id && s.state === 'ACTIVE')) return pill('Booking ended', 'neutral'); return pill('Active', 'success'); }
  function renderPATs() {
    const rows = (pats, admin) => pats.map(p => {
      const title = element('div'); title.append(element('strong', p.name), element('small', p.id, 'mono'));
      const session = state.sessions.find(s => s.id === p.session_id), booking = element('div'); booking.append(element('span', session ? clusterName(session.cluster) : p.session_id), element('small', session ? `${session.display_name || session.name} · ${p.session_id}` : p.owner.slice(0, 16), 'mono'));
      let action = element('span', '—', 'subtle');
      if (!p.revoked_at && Date.parse(p.expires_at) > Date.now()) action = button('Revoke', 'danger small', async () => {
        let reason = '';
        if (admin && p.owner !== owner()) { reason = window.prompt('Audit reason for revoking this developer’s gateway token:') || ''; if (!reason.trim()) return; }
        else if (!window.confirm(`Revoke “${p.name}”? Its downloaded kubeconfig will stop working. The booking and workloads remain.`)) return;
        await api(`/v1/pats/${encodeURIComponent(p.id)}`, {method: 'DELETE', body: {reason: reason.trim()}}); await refresh(); notify('Personal gateway credential revoked.');
      });
      return [title, booking, patState(p), date(p.expires_at), p.last_used_at ? date(p.last_used_at) : 'Not yet', action];
    });
    const headers = ['Credential', 'Booking / owner', 'State', 'Expires', 'Last used', ''];
    table($('pat-list'), headers, rows(state.pats, false), 'No personal gateway tokens. Create a kubeconfig for an active booking above.');
    if (state.session.user.admin) table($('admin-pat-list'), headers, rows(state.allPats, true), 'No personal gateway tokens have been issued.');
  }
  function renderAudit() { table($('audit-list'), ['Time', 'Actor', 'Action', 'Object', 'Detail'], state.audit.map(a => [date(a.at), element('span', a.actor.slice(0, 14), 'mono'), a.action, element('span', a.object_id, 'mono'), element('span', a.detail, 'audit-detail')]), 'No audit events.'); }
  async function refresh() {
    if (state.refreshing || !state.session) return;
    state.refreshing = true;
    try {
      const work = [api('/v1/clusters'), api('/v1/sessions'), api('/v1/pats')];
      if (state.session.user.admin) work.push(api('/v1/pats?all=true'), api('/v1/admin/audit?limit=100'));
      const result = await Promise.all(work);
      if (!state.session) return;
      state.clusters = result[0] || []; state.sessions = result[1] || []; state.pats = result[2] || []; state.allPats = result[3] || []; state.audit = result[4] || [];
      renderMetrics(); renderBookings(); renderClusters(); renderPATs(); renderAudit();
      populateSelect($('booking-cluster'), state.clusters.map(c => ({value: c.id, text: `${c.name}${c.maintenance ? ' · maintenance' : !c.available ? ' · reserved' : ''}`})), 'Choose automatically');
      populateSelect($('pat-session'), active().map(s => ({value: s.id, text: `${clusterName(s.cluster)} · ${s.id.slice(0, 10)}`})), 'Select a booking');
      populateSelect($('release-session'), state.sessions.filter(s => s.state === 'ACTIVE').map(s => ({value: s.id, text: `${clusterName(s.cluster)} · ${s.display_name || s.name} · ${s.id.slice(0, 10)}`})), 'Select a booking');
    } finally { state.refreshing = false; }
  }
  function downloadConfig(raw, name) {
    const blob = new Blob([raw], {type: 'application/yaml'}), href = URL.createObjectURL(blob), link = element('a');
    link.href = href; link.download = `${safeName(name)}.yaml`; document.body.append(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  function submit(formId, action) { const form = $(formId); form.addEventListener('submit', event => { event.preventDefault(); run(form.querySelector('[type=submit]'), () => action(form, new FormData(form))); }); }
  for (const nav of document.querySelectorAll('[data-section]')) nav.addEventListener('click', () => showSection(nav.dataset.section));
  for (const id of ['refresh-overview', 'refresh-clusters', 'refresh-pats', 'refresh-admin']) $(id).addEventListener('click', () => run($(id), refresh));
  submit('booking-form', async (form, data) => {
    const body = {cluster: String(data.get('cluster') || ''), selector: parseLabels(String(data.get('selector') || '')), ttl: String(data.get('ttl') || '').trim()};
    const key = form.dataset.requestKey || crypto.randomUUID(); form.dataset.requestKey = key;
    const result = await api('/v1/sessions', {method: 'POST', body, headers: {'Idempotency-Key': key}});
    delete form.dataset.requestKey; await refresh(); notify(`Booked ${clusterName(result.cluster)}. Session ${result.id}.`);
    $('pat-session').value = result.id;
  });
  // Changing the desired request must not reuse an earlier retry key.
  $('booking-form').addEventListener('input', () => delete $('booking-form').dataset.requestKey);
  $('booking-form').addEventListener('change', () => delete $('booking-form').dataset.requestKey);
  submit('pat-form', async (form, data) => {
    let result = await api('/v1/pats', {method: 'POST', body: {session_id: String(data.get('session_id')), name: String(data.get('name')).trim(), ttl: String(data.get('ttl'))}});
    downloadConfig(result.kubeconfig, `devctl-${result.pat.id}`); result.kubeconfig = ''; const expiry = result.pat.expires_at; result = null;
    await refresh(); notify(`Kubeconfig downloaded. Set its file permissions to 0600. Access expires ${date(expiry)}.`);
  });
  submit('register-form', async (form, data) => {
    if (!state.session.user.admin) throw new Error('Administrator required.');
    const file = data.get('kubeconfig'); if (!(file instanceof File) || !file.size || file.size > 1500000) throw new Error('Choose a trusted kubeconfig smaller than 1.5 MB.');
    let raw = await file.text();
    try { await api('/v1/admin/clusters', {method: 'POST', body: {id: String(data.get('id')).trim(), name: String(data.get('name')).trim(), labels: parseLabels(String(data.get('labels') || '')), max_participants: Number(data.get('max_participants')), kubeconfig: raw}}); }
    finally { raw = ''; }
    form.reset(); await refresh(); notify('Cluster registered. Its credentials are encrypted on the backend. No Kubernetes resources were changed.');
  });
  submit('release-form', async (form, data) => {
    const id = String(data.get('session_id')), reason = String(data.get('reason')).trim();
    if (!reason) throw new Error('An audit reason is required.');
    if (!window.confirm('Release this booking and end its gateway access? Kubernetes workloads will remain.')) return;
    await api(`/v1/admin/sessions/${encodeURIComponent(id)}/release`, {method: 'POST', body: {reason}}); form.reset(); await refresh(); notify('Booking released through administrator controls. Workloads were retained.');
  });
  async function boot() {
    try {
      const response = await fetch('/web/session', {credentials: 'same-origin', headers: {'Accept': 'application/json'}});
      if (response.status === 401) { signedOut(); return; }
      if (!response.ok) throw new Error('The backend is unavailable. Reload this page to retry.');
      state.session = await response.json(); renderIdentity(); $('welcome').classList.add('hidden'); $('workspace').classList.remove('hidden'); showSection('overview'); await refresh();
    } catch (error) { signedOut(); notify(error.message || 'Unable to connect to devctl.', true); }
  }
  boot();
})();
