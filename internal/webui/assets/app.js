'use strict';

// No OAuth tokens or PATs are kept in browser storage. A PAT appears only in an
// explicitly requested one-time download and is discarded immediately afterward.
(() => {
  const state = {session: null, profile: null, settings: null, developers: [], clusters: [], sessions: [], pats: [], allPats: [], audit: [], section: 'overview', refreshing: false};
  const $ = id => document.getElementById(id);
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  };
  const clear = node => node.replaceChildren();
  const pill = (text, tone = 'neutral') => element('span', text, `pill ${tone}`);
  const date = raw => raw ? new Date(raw).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'}) : '—';
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
    finally { if (control) control.disabled = control.dataset.limitBlocked === 'true'; }
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
    clearPresence();
    state.session = null; state.profile = null; state.settings = null; state.developers = []; state.clusters = []; state.sessions = []; state.pats = []; state.allPats = []; state.audit = [];
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
      if (!window.confirm('Sign out and release ALL of your bookings? Your PATs will remain valid. Kubernetes workloads will remain.')) return;
      await api('/auth/logout', {method: 'POST'}); signedOut(); notify('Signed out. Your bookings were released. Your PATs remain valid.');
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
    const values = [ ['Your bookings / limit', `${state.profile.active_bookings} / ${state.profile.max_bookings}`, '◫'], ['Available clusters', state.clusters.filter(c => c.available).length, '◇'], ['Team members active', new Set(state.sessions.filter(s => s.state === 'ACTIVE').map(s => s.owner)).size, '↗'] ];
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
  function detail(label, value, className = '') { const node = element('div'); node.append(element('span', label, 'detail-label'), element('span', value, `text-break ${className}`)); return node; }
  function sessionAction(id, suffix, body) { return api(`/v1/sessions/${encodeURIComponent(id)}/${suffix}`, {method: 'POST', body}); }
  function renderPrimary() {
    const profile = state.profile, primary = profile.primary_session, target = $('primary-summary'); clear(target);
    const title = element('div', null, 'section-heading'); title.append(element('h2', 'Your primary cluster'), pill(primary ? 'Selected' : 'No cluster booked', primary ? 'success' : 'neutral')); target.append(title);
    if (primary) {
      target.append(element('h3', clusterName(primary.cluster)), element('p', 'Your kubeconfig routes to this cluster. Switching primary affects new commands in every terminal and device; open connections to the previous primary are closed.'));
    } else {
      target.append(element('p', 'No cluster is booked. Book an available cluster to start using kubectl. Your first booking becomes primary automatically.'));
    }
    target.append(button('Get reusable kubeconfig', 'secondary', () => showSection('access')));
    const blocked = profile.active_bookings >= profile.max_bookings, submit = $('booking-submit');
    submit.dataset.limitBlocked = String(blocked); submit.disabled = blocked;
    $('booking-limit-help').textContent = blocked ? `You hold ${profile.active_bookings} of ${profile.max_bookings} allowed clusters. Release a booking or ask an administrator to increase your limit.` : `You can hold up to ${profile.max_bookings} cluster${profile.max_bookings === 1 ? '' : 's'}. Your first booking becomes primary; additional bookings do not change it.`;
  }
  function renderBookings() {
    const node = $('my-bookings'); clear(node); const rows = active(); $('booking-count').textContent = `${rows.length} / ${state.profile.max_bookings} held`;
    if (!rows.length) { const empty = element('div', null, 'empty'); empty.append(element('strong', 'No cluster is booked.'), element('span', 'Book an available cluster above. Your first booking becomes primary.')); node.append(empty); }
    for (const s of rows) {
      const isPrimary = state.profile.primary_session && state.profile.primary_session.id === s.id;
      const c = cluster(s.cluster), card = element('article', null, `booking-card${isPrimary ? ' primary-booking' : ''}`), top = element('div', null, 'card-top'), title = element('div', null, 'card-title');
      title.append(element('span', '◇', 'cluster-mark')); const info = element('div'); info.append(element('h3', clusterName(s.cluster)), element('small', s.cluster)); title.append(info); top.append(title);
      const badges = element('div', null, 'labels'); if (isPrimary) badges.append(pill('Primary', 'success')); badges.append(pill(c && c.shareable ? 'Shared' : 'Exclusive', c && c.shareable ? 'warning' : 'neutral')); top.append(badges); card.append(top);
      card.dataset.sessionId = s.id;
      const details = element('div', null, 'details'); details.append(detail('Auto-release', date(s.expires_at), 'booking-auto-release'), detail('Last activity', s.last_activity_at ? date(s.last_activity_at) : 'No requests yet', 'booking-last-activity')); card.append(details);
      const actions = element('div', null, 'card-actions');
      if (!isPrimary) actions.append(button('Make primary', 'primary small', async () => {
        if (!window.confirm(`Use ${clusterName(s.cluster)} as your primary cluster on all devices? Open connections to the previous primary will close.`)) return;
        await api('/v1/primary', {method: 'POST', body: {cluster: s.cluster}}); await refresh(); notify(`Primary cluster changed to ${clusterName(s.cluster)}. Keep using the same kubeconfig.`);
      }));
      if (c && c.controller_session === s.id) actions.append(button(c.shareable ? 'Disable sharing' : 'Allow sharing', 'secondary small', async () => { await sessionAction(s.id, 'share', {shareable: !c.shareable}); await refresh(); notify(c.shareable ? 'New shared bookings are now disabled.' : 'Sharing enabled. Other developers can join this cluster.'); }));
      actions.append(button('Stop', 'danger small', async () => { if (!window.confirm(`Release your booking on ${clusterName(s.cluster)}? If it is primary, your oldest remaining booking becomes primary. Kubernetes workloads will remain.`)) return; await sessionAction(s.id, 'stop'); await refresh(); notify('Booking released. Your primary selection was updated; personal tokens and Kubernetes workloads were retained.'); })); card.append(actions);
      card.append(element('span', s.id, 'mono booking-id')); node.append(card);
    }
    table($('team-bookings'), ['Cluster', 'Developer / contact', 'Access', 'Auto-release'], state.sessions.filter(s => s.state === 'ACTIVE').map(s => [clusterName(s.cluster), contact(s), pill((cluster(s.cluster) || {}).shareable ? 'Shared' : 'Exclusive', (cluster(s.cluster) || {}).shareable ? 'warning' : 'neutral'), date(s.expires_at)]), 'No active team bookings.');
    table($('booking-history'), ['Cluster', 'Booking', 'State', 'Ended'], mine().filter(s => s.state !== 'ACTIVE').slice().reverse().map(s => [clusterName(s.cluster), s.id, pill(s.state), date(s.ended_at)]), 'No previous bookings.');
  }
  function labelsNode(labels) { const node = element('div', null, 'labels'); for (const [key, value] of Object.entries(labels || {})) node.append(element('span', `${key}=${value}`, 'label')); return node; }
  function clusterCard(c, admin = false) {
    const card = element('article', null, 'cluster-card'), top = element('div', null, 'card-top'), title = element('div'); title.append(element('h3', c.name), element('small', c.id, 'mono')); top.append(title, pill(c.maintenance ? 'Maintenance' : c.available ? 'Available' : 'Reserved', c.maintenance ? 'warning' : c.available ? 'success' : 'neutral')); card.append(top, labelsNode(c.labels), element('p', c.reason));
    card.dataset.clusterId = c.id;
    const people = element('div', null, 'participants');
    if (!(c.participants || []).length) people.append(element('span', 'No active holders.'));
    for (const person of c.participants || []) { const row = element('div', null, 'participant'); row.append(contact(person)); people.append(row); } card.append(people);
    if (!admin) {
      if (c.available && state.profile.active_bookings < state.profile.max_bookings && !(c.participants || []).some(s => s.owner === owner())) card.append(button((c.participants || []).length ? 'Join shared cluster' : 'Book cluster', 'secondary', () => { showSection('overview'); $('booking-cluster').value = c.id; $('booking-form').scrollIntoView({behavior: 'smooth', block: 'center'}); }));
    } else {
      const form = element('form', null, 'maintenance-form'), label = element('label', 'Audit reason'), input = element('input'); input.name = 'reason'; input.required = true; input.maxLength = 1000; input.placeholder = c.maintenance ? 'Ready for bookings' : 'Planned maintenance'; label.append(input);
      const submit = element('button', c.maintenance ? 'Enable placement' : 'Set maintenance', `button ${c.maintenance ? 'secondary' : 'danger'} small`); submit.type = 'submit';
      const deregister = button('Deregister', 'danger small', async () => {
        const reason = input.value.trim();
        input.setCustomValidity(reason ? '' : 'An audit reason is required.');
        if (!form.reportValidity()) return;
        if (!window.confirm(`Deregister ${c.name} (${c.id})? Its stored Kubernetes credentials will be removed from devctl. Booking history and Kubernetes workloads will remain.`)) return;
        try { await api(`/v1/admin/clusters/${encodeURIComponent(c.id)}`, {method: 'DELETE', body: {reason}}); }
        catch (error) { await refresh(); throw error; }
        await refresh(); notify('Cluster deregistered. Stored Kubernetes credentials were removed; booking history and workloads were retained.');
      });
      input.addEventListener('input', () => input.setCustomValidity(''));
      const blocked = (c.participants || []).some(s => s.state === 'ACTIVE'); deregister.disabled = blocked;
      if (blocked) deregister.title = 'Release all active bookings before deregistering this cluster.';
      const actions = element('div', null, 'card-actions'); actions.append(submit, deregister); form.append(label, actions);
      form.addEventListener('submit', event => { event.preventDefault(); run(submit, async () => { await api(`/v1/admin/clusters/${encodeURIComponent(c.id)}`, {method: 'PATCH', body: {maintenance: !c.maintenance, reason: input.value.trim()}}); await refresh(); notify('Cluster placement controls updated. Existing bookings remain.'); }); }); card.append(form);
      if (blocked) card.append(element('p', 'Release all active bookings before deregistering this cluster.', 'field-help'));
    }
    return card;
  }
  function renderClusters() { clear($('cluster-list')); clear($('maintenance-list')); if (!state.clusters.length) { $('cluster-list').append(element('div', 'No clusters registered. Ask an administrator to register an approved environment.', 'empty')); return; } for (const c of state.clusters) { $('cluster-list').append(clusterCard(c)); if (state.session.user.admin) $('maintenance-list').append(clusterCard(c, true)); } }
  function patState(p) { if (p.revoked_at) return pill('Revoked', 'danger'); if (Date.parse(p.expires_at) <= Date.now()) return pill('Expired', 'neutral'); return pill('Active', 'success'); }
  function renderPATs() {
    const rows = (pats, admin) => pats.map(p => {
      const title = element('div'); title.append(element('strong', p.name), element('small', p.id, 'mono'));
      const person = p.owner === owner() ? state.session.user : (state.developers.find(d => d.owner_id === p.owner) || {}).user;
      const access = element('div'); access.append(element('span', person ? person.display_name || person.name : p.owner.slice(0, 16)), element('small', p.scope === 'kubernetes:primary' ? 'Follows primary cluster' : 'Legacy credential', 'subtle'));
      let action = element('span', '—', 'subtle');
      if (!p.revoked_at && Date.parse(p.expires_at) > Date.now()) action = button('Revoke', 'danger small', async () => {
        let reason = '';
        if (admin && p.owner !== owner()) { reason = window.prompt('Audit reason for revoking this developer’s gateway token:') || ''; if (!reason.trim()) return; }
        else if (!window.confirm(`Revoke “${p.name}”? Its downloaded kubeconfig will stop working. Bookings and workloads remain.`)) return;
        await api(`/v1/pats/${encodeURIComponent(p.id)}`, {method: 'DELETE', body: {reason: reason.trim()}}); await refresh(); notify('Personal gateway credential revoked.');
      });
      return [title, access, patState(p), date(p.expires_at), p.last_used_at ? date(p.last_used_at) : 'Not yet', action];
    });
    const headers = ['Credential', 'Developer / access', 'State', 'Expires', 'Last used', ''];
    table($('pat-list'), headers, rows(state.pats, false), 'No personal gateway tokens. Download your reusable kubeconfig above; no booking is required to create it.');
    if (state.session.user.admin) table($('admin-pat-list'), headers, rows(state.allPats, true), 'No personal gateway tokens have been issued.');
  }
  function renderDeveloperLimits() {
    if (!state.session.user.admin) return;
    $('default-booking-limit').value = state.settings.default_max_bookings;
    $('inactivity-grace-period').value = state.settings.inactivity_grace_period;
    const rows = state.developers.map(profile => {
      const primary = profile.primary_session;
      const form = element('form', null, 'developer-limit-form'), input = element('input'), reason = element('input'), submit = element('button', 'Save limit', 'button secondary small');
      input.type = 'number'; input.min = '1'; input.max = '100'; input.name = 'max_bookings'; input.placeholder = 'Use default'; input.value = profile.max_bookings_override == null ? '' : profile.max_bookings_override;
      input.setAttribute('aria-label', `Booking override for ${profile.user.display_name || profile.user.name}`);
      reason.name = 'reason'; reason.required = true; reason.maxLength = 500; reason.placeholder = 'Audit reason'; reason.setAttribute('aria-label', `Audit reason for ${profile.user.display_name || profile.user.name}`); submit.type = 'submit'; form.append(input, reason, submit);
      form.addEventListener('submit', event => { event.preventDefault(); run(submit, async () => {
        const value = input.value.trim(); await api(`/v1/admin/developers/${encodeURIComponent(profile.owner_id)}`, {method: 'PATCH', body: {max_bookings: value === '' ? null : Number(value), reason: reason.value.trim()}}); await refresh(); notify('Developer booking limit updated. Existing bookings were preserved.');
      }); });
      return [contact({...profile.user, owner: profile.owner_id}), `${profile.active_bookings} / ${profile.max_bookings}`, profile.max_bookings_override == null ? 'Default' : 'Override', primary ? clusterName(primary.cluster) : 'No cluster booked', form];
    });
    table($('developer-list'), ['Developer', 'Held / limit', 'Policy', 'Primary cluster', 'Override and audit reason'], rows, 'Developers appear after their first application login.');
  }
  function renderAudit() { table($('audit-list'), ['Time', 'Actor', 'Action', 'Object', 'Detail'], state.audit.map(a => [date(a.at), element('span', a.actor.slice(0, 14), 'mono'), a.action, element('span', a.object_id, 'mono'), element('span', a.detail, 'audit-detail')]), 'No audit events.'); }
  async function refresh() {
    if (state.refreshing || !state.session) return;
    state.refreshing = true;
    try {
      const work = [api('/v1/clusters'), api('/v1/sessions'), api('/v1/pats'), api('/v1/profile')];
      if (state.session.user.admin) work.push(api('/v1/pats?all=true'), api('/v1/admin/audit?limit=100'), api('/v1/admin/settings'), api('/v1/admin/developers'));
      const result = await Promise.all(work);
      if (!state.session) return;
      state.clusters = result[0] || []; state.sessions = result[1] || []; state.pats = result[2] || []; state.profile = result[3]; state.allPats = result[4] || []; state.audit = result[5] || []; state.settings = result[6]; state.developers = result[7] || [];
      renderMetrics(); renderPrimary(); renderBookings(); renderClusters(); renderPATs(); renderDeveloperLimits(); renderAudit();
      populateSelect($('booking-cluster'), state.clusters.map(c => ({value: c.id, text: `${c.name}${c.maintenance ? ' · maintenance' : !c.available ? ' · reserved' : ''}`})), 'Choose automatically');
      populateSelect($('release-session'), state.sessions.filter(s => s.state === 'ACTIVE').map(s => ({value: s.id, text: `${clusterName(s.cluster)} · ${s.display_name || s.name} · ${s.id.slice(0, 10)}`})), 'Select a booking');
    } finally { state.refreshing = false; }
  }
  // Presence is sent only for actual input on a visible page. A pending send
  // represents one observed interaction, never a self-renewing heartbeat.
  const presence = {pending: null, timer: null, sending: false, lastSent: 0};
  const currentSelection = () => {
    const profile = state.profile, selected = profile && profile.primary_session;
    return state.session && selected && selected.state === 'ACTIVE' ? {session_id: selected.id, selection_version: profile.selection_version} : null;
  };
  const sameSelection = (a, b) => a && b && a.session_id === b.session_id && a.selection_version === b.selection_version;
  function clearPresence() {
    window.clearTimeout(presence.timer); presence.timer = null; presence.pending = null;
  }
  function schedulePresence() {
    if (!presence.pending || presence.sending || presence.timer) return;
    presence.timer = window.setTimeout(sendPresence, Math.max(0, 30000 - (Date.now() - presence.lastSent)));
  }
  async function sendPresence() {
    presence.timer = null;
    const selected = presence.pending; presence.pending = null;
    if (document.visibilityState !== 'visible' || !sameSelection(selected, currentSelection())) return;
    presence.sending = true; presence.lastSent = Date.now();
    try {
      const updated = await api('/v1/activity', {method: 'POST', body: selected});
      if (updated && sameSelection(selected, currentSelection())) {
        Object.assign(state.profile.primary_session, updated);
        const session = state.sessions.find(s => s.id === selected.session_id); if (session) Object.assign(session, updated);
        // Preserve in-progress inputs and click targets while refreshing metadata.
        for (const card of document.querySelectorAll('.booking-card')) if (card.dataset.sessionId === selected.session_id) {
          card.querySelector('.booking-auto-release').textContent = date(updated.expires_at);
          card.querySelector('.booking-last-activity').textContent = updated.last_activity_at ? date(updated.last_activity_at) : 'No requests yet';
        }
      }
    } catch (_) { if (state.session) refresh().catch(() => {}); }
    finally { presence.sending = false; schedulePresence(); }
  }
  function interacted(event) {
    if (!event.isTrusted || document.visibilityState !== 'visible') return;
    const selected = currentSelection(); if (!selected) return;
    presence.pending = selected; schedulePresence();
  }
  for (const name of ['pointerdown', 'keydown', 'wheel', 'touchstart']) document.addEventListener(name, interacted, {passive: true});
  document.addEventListener('visibilitychange', () => { if (document.visibilityState !== 'visible') clearPresence(); });

  function downloadConfig(raw, name) {
    const blob = new Blob([raw], {type: 'application/yaml'}), href = URL.createObjectURL(blob), link = element('a');
    link.href = href; link.download = `${safeName(name)}.yaml`; document.body.append(link); link.click(); link.remove();
    window.setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  function submit(formId, action) { const form = $(formId); form.addEventListener('submit', event => { event.preventDefault(); run(form.querySelector('[type=submit]'), () => action(form, new FormData(form))); }); }
  for (const nav of document.querySelectorAll('[data-section]')) nav.addEventListener('click', () => showSection(nav.dataset.section));
  for (const id of ['refresh-overview', 'refresh-clusters', 'refresh-pats', 'refresh-admin']) $(id).addEventListener('click', () => run($(id), refresh));
  submit('booking-form', async (form, data) => {
    const body = {cluster: String(data.get('cluster') || ''), selector: parseLabels(String(data.get('selector') || ''))};
    const key = form.dataset.requestKey || crypto.randomUUID(); form.dataset.requestKey = key;
    const result = await api('/v1/sessions', {method: 'POST', body, headers: {'Idempotency-Key': key}});
    delete form.dataset.requestKey; await refresh(); notify(`Booked ${clusterName(result.cluster)}. Session ${result.id}.`);
  });
  // Changing the desired request must not reuse an earlier retry key.
  $('booking-form').addEventListener('input', () => delete $('booking-form').dataset.requestKey);
  $('booking-form').addEventListener('change', () => delete $('booking-form').dataset.requestKey);
  submit('pat-form', async (form, data) => {
    let result = await api('/v1/pats', {method: 'POST', body: {name: String(data.get('name')).trim(), ttl: String(data.get('ttl'))}});
    downloadConfig(result.kubeconfig, `devctl-${state.session.user.name || 'developer'}`); result.kubeconfig = ''; const expiry = result.pat.expires_at; result = null;
    await refresh(); notify(`Kubeconfig downloaded. Set its file permissions to 0600. Access expires ${date(expiry)}.`);
  });
  submit('settings-form', async (form, data) => {
    const reason = String(data.get('reason')).trim(); if (!reason) throw new Error('An audit reason is required.');
    await api('/v1/admin/settings', {method: 'PATCH', body: {default_max_bookings: Number(data.get('default_max_bookings')), inactivity_grace_period: String(data.get('inactivity_grace_period')).trim(), reason}}); form.reset(); await refresh(); notify('Booking policy updated. The inactivity period applies to current and future bookings.');
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
    if (!window.confirm('Release this booking? If it is primary, the oldest remaining booking becomes primary. Personal tokens and Kubernetes workloads will remain.')) return;
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
