'use strict';
// Standalone UI contract regression. Uses only local fixture responses; real
// Keycloak, PostgreSQL and Kubernetes gateway behavior have separate Go tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || path.resolve(__dirname, '../../../frontend/node_modules/playwright'));
const assets = path.resolve(__dirname, '../assets');
const productionCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const alice = {issuer: 'https://issuer.test', subject: 'alice', name: 'alice', display_name: 'Alice <img src=x onerror=alert(1)>', email: 'alice@example.test', admin: false};
const administrator = {issuer: 'https://issuer.test', subject: 'admin', name: 'admin', display_name: 'Administrator', email: 'admin@example.test', admin: true};
const state = {
  primary: 's-a', version: 1, defaultLimit: 1, inactivityGrace: '4h', override: 2, serial: 0, patSerial: 0, pats: [], mutations: [], signedOut: false, retired: new Set(), deregistrationConflict: null, registryReads: 0,
  registry: new Map(['a', 'b', 'c'].map(id => [id, {id, name: `Cluster ${id.toUpperCase()}`, labels: {test: 'ui'}, max_participants: 2}])),
  maintenance: new Map(), registrationFailure: false, maintenanceFailure: false, releaseFailure: false, heldRequest: null, kubernetesRequests: 0, profileReads: 0,
  sessions: ['a', 'b'].map(id => ({id: `s-${id}`, owner: 'alice', name: 'alice', display_name: 'Alice Developer', email: alice.email, cluster: id, state: 'ACTIVE', primary: id === 'a', created_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-01T04:00:00Z', reason: 'fixture'})),
};
let origin;
const sessionRows = () => state.sessions.map(s => ({...s, primary: s.id === state.primary}));
const primary = () => sessionRows().find(s => s.id === state.primary && s.state === 'ACTIVE');
const profile = admin => ({owner_id: admin ? 'admin' : 'alice', user: admin ? administrator : alice, max_bookings: admin ? state.defaultLimit : state.override ?? state.defaultLimit, max_bookings_override: admin ? null : state.override, active_bookings: admin ? 0 : state.sessions.filter(s => s.state === 'ACTIVE').length, primary_session: admin ? null : primary(), selection_version: state.version});
const clusters = () => Array.from(state.registry.values()).filter(c => !state.retired.has(c.id)).map(c => ({...c, maintenance: state.maintenance.get(c.id) || false, controller_session: state.sessions.find(s => s.cluster === c.id && s.state === 'ACTIVE')?.id, shareable: false, participants: sessionRows().filter(s => s.cluster === c.id && s.state === 'ACTIVE'), available: !state.maintenance.get(c.id) && !state.sessions.some(s => s.cluster === c.id && s.state === 'ACTIVE'), reason: state.maintenance.get(c.id) ? 'Fixture maintenance: new bookings disabled' : 'Fixture cluster'}));
function holdRequest(method, pathname) {
  assert.equal(state.heldRequest, null, 'only one fixture response may be held at a time');
  let arrive, release, timeout;
  const arrived = new Promise((resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(`Expected fixture request did not arrive: ${method} ${pathname}`)), 10000);
    arrive = () => { clearTimeout(timeout); resolve(); };
  });
  const wait = new Promise(resolve => { release = resolve; });
  state.heldRequest = {method, pathname, arrive, wait};
  return {arrived, release: () => { clearTimeout(timeout); release(); }};
}
function releaseFixtureSession(id, reason) {
  const selected = state.sessions.find(session => session.id === id && session.state === 'ACTIVE');
  if (!selected) return false;
  selected.state = 'RELEASED'; selected.ended_at = new Date().toISOString(); selected.reason = reason;
  if (state.primary === id) { state.primary = state.sessions.find(session => session.state === 'ACTIVE')?.id || null; state.version++; }
  return true;
}
function reply(res, status, body) { res.writeHead(status, {'Content-Type': 'application/json'}); res.end(JSON.stringify(body)); }
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, origin || 'http://127.0.0.1');
  const admin = req.headers['x-ui-test-role'] === 'admin';
  if (url.pathname === '/k8s' || url.pathname.startsWith('/k8s/')) state.kubernetesRequests++;
  try {
    if (req.method === 'GET' && ['/', '/assets/app.js', '/assets/app.css'].includes(url.pathname)) {
      const name = url.pathname === '/' ? 'index.html' : path.basename(url.pathname);
      res.writeHead(200, {'Content-Type': name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html', 'Content-Security-Policy': productionCSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'}); res.end(fs.readFileSync(path.join(assets, name))); return;
    }
    if (req.method === 'GET') {
      if (url.pathname === '/v1/clusters') state.registryReads++;
      if (url.pathname === '/v1/profile' && !admin) state.profileReads++;
      if (url.pathname === '/web/session' && state.signedOut && !admin) { reply(res, 401, {error: 'signed out'}); return; }
      const routes = {
        '/web/session': {user: admin ? administrator : alice, owner_id: admin ? 'admin' : 'alice', csrf_token: admin ? 'csrf-admin' : 'csrf-alice', expires_at: '2099-01-01T00:00:00Z'},
        '/v1/profile': profile(admin), '/v1/clusters': clusters(), '/v1/sessions': sessionRows(), '/v1/pats': state.pats.filter(p => url.searchParams.get('all') === 'true' && admin || p.owner === (admin ? 'admin' : 'alice')),
        '/v1/admin/settings': {default_max_bookings: state.defaultLimit, inactivity_grace_period: state.inactivityGrace}, '/v1/admin/developers': [profile(false), profile(true)], '/v1/admin/audit': [],
      };
      if (url.pathname.startsWith('/v1/admin/') && !admin) { reply(res, 403, {error: 'administrator required'}); return; }
      // Capture the response before waiting so this can model an old in-flight
      // profile read completing after a later primary-selection mutation.
      if (state.heldRequest?.method === req.method && state.heldRequest.pathname === url.pathname) {
        const held = state.heldRequest; state.heldRequest = null; held.arrive(); await held.wait;
      }
      if (Object.hasOwn(routes, url.pathname)) { reply(res, 200, routes[url.pathname]); return; }
      reply(res, 404, {error: 'fixture route not found'}); return;
    }
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    assert.equal(req.headers.origin, origin, 'mutation must retain same Origin');
    assert.equal(req.headers['x-csrf-token'], admin ? 'csrf-admin' : 'csrf-alice', 'mutation must send CSRF token');
    state.mutations.push({path: url.pathname, method: req.method, body});
    if (state.heldRequest?.method === req.method && state.heldRequest.pathname === url.pathname) {
      const held = state.heldRequest; state.heldRequest = null; held.arrive(); await held.wait;
    }
    if (url.pathname.startsWith('/v1/admin/') && !admin) { reply(res, 403, {error: 'administrator required'}); return; }
    if (url.pathname === '/auth/logout' && req.method === 'POST') {
      for (const session of state.sessions) if (session.owner === 'alice' && session.state === 'ACTIVE') session.state = 'RELEASED';
      state.primary = null; state.version++; state.signedOut = true;
      reply(res, 200, {status: 'signed out; bookings released; PATs preserved'}); return;
    }
    if (url.pathname === '/v1/activity' && req.method === 'POST') {
      assert.deepEqual(Object.keys(body).sort(), ['selection_version', 'session_id']);
      if (admin || body.session_id !== state.primary || body.selection_version !== state.version) { reply(res, 409, {error: 'primary selection changed'}); return; }
      const selected = primary(); selected.last_activity_at = new Date().toISOString(); selected.expires_at = new Date(Date.now() + 4 * 3600000).toISOString();
      reply(res, 200, selected); return;
    }
    if (url.pathname === '/v1/primary') {
      const selection = state.sessions.find(s => s.cluster === body.cluster && s.state === 'ACTIVE'); assert.ok(selection);
      state.primary = selection.id; state.version++; reply(res, 200, profile(admin)); return;
    }
    if (/^\/v1\/sessions\/[^/]+\/stop$/.test(url.pathname)) {
      const id = url.pathname.split('/')[3]; assert.ok(releaseFixtureSession(id, 'Owner ended fixture booking'));
      reply(res, 200, {status: 'released'}); return;
    }
    if (url.pathname === '/v1/sessions' && req.method === 'POST') {
      assert.ok(profile(admin).active_bookings < profile(admin).max_bookings); assert.ok(req.headers['idempotency-key']); assert.equal(Object.hasOwn(body, 'ttl'), false, 'booking duration is retired');
      const booked = {id: `s-booked-${++state.serial}`, owner: 'alice', name: 'alice', display_name: 'Alice Developer', cluster: body.cluster || 'c', state: 'ACTIVE', created_at: '2026-01-01T00:00:00Z'};
      state.sessions.push(booked); if (!primary()) {state.primary = booked.id; state.version++;} reply(res, 201, {...booked, primary: booked.id === state.primary}); return;
    }
    if (url.pathname === '/v1/pats' && req.method === 'POST') {
      assert.equal(Object.hasOwn(body, 'session_id'), false, 'personal credential must not select a session');
      assert.equal(body.ttl, '8h', 'PAT access duration remains independently configurable');
      const pat = {id: `p-fixture-${++state.patSerial}`, owner: admin ? 'admin' : 'alice', name: body.name, scope: 'kubernetes:primary', created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z', auto_booking: structuredClone(body.auto_booking || {enabled: false, selector: {}})}; state.pats.push(pat);
      reply(res, 201, {pat, kubeconfig: 'apiVersion: v1\nkind: Config\nclusters:\n- name: gateway\n  cluster:\n    server: https://gateway.example.test/k8s\nusers:\n- name: personal\n  user:\n    token: dcpat_UI_FIXTURE_' + state.patSerial + '_ONLY\n'}); return;
    }
    if (/^\/v1\/pats\/[^/]+$/.test(url.pathname) && req.method === 'PATCH') {
      const pat = state.pats.find(p => p.id === url.pathname.split('/').at(-1));
      if (!pat) { reply(res, 404, {error: 'credential not found'}); return; }
      if (!admin && pat.owner !== 'alice') { reply(res, 403, {error: 'owner required'}); return; }
      if (admin && pat.owner !== 'admin' && !body.reason?.trim()) { reply(res, 400, {error: 'administrator audit reason required'}); return; }
      if (pat.revoked_at || Date.parse(pat.expires_at) <= Date.now()) { reply(res, 409, {error: 'credential ended'}); return; }
      assert.equal(typeof body.auto_booking.enabled, 'boolean'); assert.equal(typeof body.auto_booking.selector, 'object');
      pat.auto_booking = structuredClone(body.auto_booking); reply(res, 200, pat); return;
    }
    if (url.pathname === '/v1/admin/settings' && req.method === 'PATCH' && admin) { assert.ok(body.reason); state.defaultLimit = body.default_max_bookings; state.inactivityGrace = body.inactivity_grace_period; reply(res, 200, {status: 'updated'}); return; }
    if (url.pathname === '/v1/admin/developers/alice' && req.method === 'PATCH' && admin) { assert.ok(body.reason); state.override = body.max_bookings; reply(res, 200, {status: 'updated'}); return; }
    if (url.pathname === '/v1/admin/clusters' && req.method === 'POST') {
      assert.deepEqual(Object.keys(body).sort(), ['id', 'kubeconfig', 'labels', 'max_participants', 'name']);
      assert.ok(body.id); assert.ok(body.name); assert.ok(typeof body.kubeconfig === 'string' && body.kubeconfig.includes('UI_FIXTURE_TOKEN_NOT_REAL'));
      assert.ok(Number.isInteger(body.max_participants) && body.max_participants >= 2 && body.max_participants <= 10);
      if (state.registrationFailure) { state.registrationFailure = false; reply(res, 503, {error: 'Fixture registration rejected'}); return; }
      if (state.registry.has(body.id)) { reply(res, 409, {error: 'Fixture ID already registered'}); return; }
      state.registry.set(body.id, {id: body.id, name: body.name, labels: structuredClone(body.labels), max_participants: body.max_participants});
      reply(res, 200, {id: body.id, status: 'registered'}); return;
    }
    if (/^\/v1\/admin\/clusters\/[^/]+$/.test(url.pathname) && req.method === 'PATCH') {
      assert.deepEqual(Object.keys(body).sort(), ['maintenance', 'reason']); assert.equal(typeof body.maintenance, 'boolean'); assert.ok(body.reason.trim()); assert.equal(body.reason, body.reason.trim());
      const id = url.pathname.split('/').at(-1);
      if (!state.registry.has(id) || state.retired.has(id)) { reply(res, 404, {error: 'Fixture cluster not found'}); return; }
      if (state.maintenanceFailure) { state.maintenanceFailure = false; reply(res, 503, {error: 'Fixture maintenance rejected'}); return; }
      state.maintenance.set(id, body.maintenance); reply(res, 200, {status: 'updated'}); return;
    }
    if (/^\/v1\/admin\/sessions\/[^/]+\/release$/.test(url.pathname) && req.method === 'POST') {
      assert.deepEqual(Object.keys(body), ['reason']); assert.ok(body.reason.trim()); assert.equal(body.reason, body.reason.trim());
      if (state.releaseFailure) { state.releaseFailure = false; reply(res, 503, {error: 'Fixture release rejected'}); return; }
      if (!releaseFixtureSession(url.pathname.split('/')[4], body.reason)) { reply(res, 409, {error: 'Fixture booking already ended'}); return; }
      reply(res, 200, {status: 'released'}); return;
    }
    if (/^\/v1\/admin\/clusters\/[^/]+$/.test(url.pathname) && req.method === 'DELETE') {
      if (!admin) { reply(res, 403, {error: 'administrator required'}); return; }
      assert.deepEqual(Object.keys(body), ['reason']); assert.ok(body.reason.trim()); assert.equal(body.reason, body.reason.trim());
      const id = url.pathname.split('/').at(-1);
      if (state.deregistrationConflict === id) { state.deregistrationConflict = null; reply(res, 409, {error: 'Release active bookings before deregistering this cluster.'}); return; }
      if (clusters().find(c => c.id === id)?.participants.length) { reply(res, 409, {error: 'Release active bookings first.'}); return; }
      state.retired.add(id); reply(res, 200, {status: 'deregistered'}); return;
    }
    reply(res, 404, {error: 'fixture route not implemented'});
  } catch (error) { console.error('UI fixture assertion:', error.message); reply(res, 500, {error: 'UI fixture assertion failed'}); }
});
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({headless: true, executablePath: process.env.CHROME_PATH || (fs.existsSync('/opt/google/chrome/chrome') ? '/opt/google/chrome/chrome' : undefined)});
  try {
    const context = await browser.newContext({acceptDownloads: true}); const page = await context.newPage(); const errors = [], dialogs = [], cspErrors = [], externalRequests = [];
    const guardNetwork = async route => {
      const requested = new URL(route.request().url());
      if (['http:', 'https:'].includes(requested.protocol) && requested.origin !== origin) {
        externalRequests.push(requested.origin); await route.abort(); return;
      }
      await route.continue();
    };
    await context.route('**/*', guardNetwork);
    page.on('pageerror', error => errors.push(error.message)); page.on('dialog', dialog => { dialogs.push(dialog.message()); return dialog.accept(); });
    const checkConsole = message => { if (message.type() === 'error' && /content security policy|violates the following|refused to (execute|load|apply|connect)|unsafe-eval/i.test(message.text())) cspErrors.push(message.text()); };
    page.on('console', checkConsole);
    await page.clock.install({time: new Date('2026-01-01T12:00:00Z')});
    await page.goto(origin, {waitUntil: 'domcontentloaded'}); await page.locator('#workspace').waitFor({state: 'visible'});
    await page.locator('#primary-summary h3').filter({hasText: 'Cluster A'}).waitFor();
    assert.equal(await page.locator('#admin-nav').isVisible(), false); assert.equal(await page.locator('#identity img').count(), 0);
    assert.equal(await page.getByRole('button', {name: 'Deregister', exact: true}).count(), 0, 'developers must not see registry removal controls');
    assert.equal(await page.locator('#booking-submit').isDisabled(), true);
    assert.equal(await page.locator('#booking-form [name=ttl]').count(), 0);
    assert.equal(await page.getByRole('button', {name: 'Renew lease', exact: true}).count(), 0);
    assert.equal(await page.locator('#pat-form [name=ttl]').count(), 1, 'PAT lifetime stays independent');
    assert.equal(await page.locator('#pat-auto-booking').isChecked(), false, 'automatic booking requires explicit opt-in');
    assert.equal(await page.locator('.access-card').count(), 2); assert.equal(await page.getByRole('heading', {name: 'kubectl plugin', exact: true}).count(), 0);
    assert.equal((await page.locator('body').textContent()).includes('kubectl devctl'), false, 'standalone kubectl plugin instructions are removed');
    const activity = () => state.mutations.filter(r => r.path === '/v1/activity');
    await page.clock.runFor(90000);
    assert.equal(activity().length, 0, 'idle open tab must not renew a reservation');
    await page.evaluate(async () => { await fetch('/v1/profile'); await fetch('/v1/sessions'); document.dispatchEvent(new KeyboardEvent('keydown', {key: 'x'})); });
    await page.clock.runFor(1000);
    assert.equal(activity().length, 0, 'polling and synthetic input must not count as presence');
    const bDeadline = state.sessions.find(s => s.id === 's-b').expires_at;
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(5);
    await page.waitForFunction(() => document.querySelector('.booking-last-activity').textContent !== 'No requests yet');
    assert.deepEqual(activity().at(-1).body, {session_id: 's-a', selection_version: 1});
    assert.equal(state.sessions.find(s => s.id === 's-b').expires_at, bDeadline, 'activity must not extend the other held cluster');
    const firstCount = activity().length;
    await page.keyboard.press('ArrowRight'); await page.keyboard.press('ArrowRight'); await page.clock.runFor(15000);
    assert.equal(activity().length, firstCount, 'interaction heartbeat must be throttled');
    const delayedActivityResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/activity' && response.request().method() === 'POST');
    await page.clock.runFor(15000); await delayedActivityResponse;
    assert.equal(activity().length, firstCount + 1, 'one pending real interaction gets one delayed send');
    await page.clock.runFor(120000);
    assert.equal(activity().length, firstCount + 1, 'a prior interaction must not renew itself indefinitely');
    await page.evaluate(() => Object.defineProperty(document, 'visibilityState', {configurable: true, get: () => 'hidden'}));
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(40000);
    assert.equal(activity().length, firstCount + 1, 'hidden page input must not extend a booking');
    // A mutation must refresh after an older read, rather than sharing its
    // stale result. Presence remains hidden here to isolate the read ordering.
    const heldProfile = holdRequest('GET', '/v1/profile');
    const oldProfileResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/profile' && response.request().method() === 'GET');
    let readsAtHeldProfile;
    try {
      await page.locator('#refresh-overview').click(); await heldProfile.arrived;
      readsAtHeldProfile = state.profileReads;
      const primaryMutation = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/primary' && response.request().method() === 'POST');
      await page.getByRole('button', {name: 'Make primary', exact: true}).click();
      await (await primaryMutation).finished();
      await page.evaluate(async () => { for (let turn = 0; turn < 8; turn++) await Promise.resolve(); });
      assert.equal(state.primary, 's-b');
      assert.equal(state.profileReads, readsAtHeldProfile, 'fresh post-mutation read waits for the old read to finish');
    } finally { heldProfile.release(); }
    const staleProfile = await oldProfileResponse;
    assert.equal((await staleProfile.json()).primary_session.id, 's-a', 'the delayed response really is the old primary snapshot');
    await page.locator('#primary-summary h3').filter({hasText: 'Cluster B'}).waitFor();
    assert.equal(state.profileReads, readsAtHeldProfile + 1, 'selection queues exactly one fresh profile read behind the old response');
    await page.evaluate(() => delete document.visibilityState);
    assert.deepEqual(state.mutations.find(r => r.path === '/v1/primary').body, {cluster: 'b'});
    const switchedActivityResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/v1/activity' && response.request().method() === 'POST');
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(30000); await switchedActivityResponse;
    assert.deepEqual(activity().at(-1).body, {session_id: 's-b', selection_version: 2}, 'new activity follows only the current primary and selection version');
    await page.locator('#my-bookings article').filter({has: page.getByRole('heading', {name: 'Cluster B', exact: true})}).getByRole('button', {name: 'Stop', exact: true}).click();
    await page.locator('#primary-summary h3').filter({hasText: 'Cluster A'}).waitFor();
    await page.waitForFunction(() => !document.querySelector('#booking-submit').disabled);
    await page.locator('#my-bookings article').filter({has: page.getByRole('heading', {name: 'Cluster A', exact: true})}).getByRole('button', {name: 'Stop', exact: true}).click();
    await page.locator('#primary-summary').getByText('No cluster is booked.', {exact: false}).waitFor();
    await page.getByRole('button', {name: 'Access & tokens', exact: false}).click();
    assert.equal(await page.locator('#pat-session').count(), 0);
    const downloadPending = page.waitForEvent('download'); await page.locator('#pat-form button[type=submit]').click();
    const download = await downloadPending; const content = fs.readFileSync(await download.path(), 'utf8');
    assert.ok(content.includes('https://gateway.example.test/k8s')); assert.equal(content.includes('/sessions/'), false); assert.equal(content.includes('refresh_token'), false);
    await page.getByRole('button', {name: 'Overview', exact: false}).click();
    await page.locator('#booking-cluster').selectOption('c'); await page.locator('#booking-submit').click();
    await page.locator('#primary-summary h3').filter({hasText: 'Cluster C'}).waitFor();
    await page.getByRole('button', {name: 'Access & tokens', exact: false}).click(); await page.getByRole('cell', {name: 'Follows primary cluster'}).first().waitFor();
    const originalPrimary = state.primary, originalToken = structuredClone(state.pats[0]);
    assert.deepEqual(originalToken.auto_booking, {enabled: false, selector: {}}, 'default download must not silently allow allocation');
    const policyPatches = () => state.mutations.filter(r => r.method === 'PATCH' && r.path.startsWith('/v1/pats/'));
    const tokenEditor = id => page.locator(`#pat-list .pat-policy-editor[data-pat-id="${id}"]`);
    await tokenEditor(originalToken.id).locator('summary').click();
    await tokenEditor(originalToken.id).locator('input[name=enabled]').check();
    await tokenEditor(originalToken.id).locator('input[name=selector]').fill('region=eu,test=');
    await tokenEditor(originalToken.id).getByRole('button', {name: 'Save preferences', exact: true}).click();
    await page.locator('#pat-list .pat-policy-summary').filter({hasText: 'Automatic: region=eu,test='}).waitFor();
    assert.deepEqual(policyPatches().at(-1).body, {auto_booking: {enabled: true, selector: {region: 'eu', test: ''}}});
    assert.equal(state.primary, originalPrimary, 'editing preferences must not replace an active primary');
    assert.deepEqual({...state.pats[0], auto_booking: originalToken.auto_booking}, originalToken, 'editing must preserve identity, lifetime and credential metadata');
    assert.equal(fs.readFileSync(await download.path(), 'utf8'), content, 'editing preferences must not replace the downloaded kubeconfig or secret');
    await tokenEditor(originalToken.id).locator('summary').click();
    await tokenEditor(originalToken.id).locator('input[name=selector]').fill('region');
    const patchesBeforeInvalid = policyPatches().length;
    await tokenEditor(originalToken.id).getByRole('button', {name: 'Save preferences', exact: true}).click();
    await page.locator('#notification.error').filter({hasText: 'key=value'}).waitFor(); assert.equal(policyPatches().length, patchesBeforeInvalid);
    await tokenEditor(originalToken.id).locator('input[name=selector]').fill('');
    await tokenEditor(originalToken.id).getByRole('button', {name: 'Save preferences', exact: true}).click();
    await page.locator('#pat-list .pat-policy-summary').filter({hasText: 'Automatic: Any free cluster'}).waitFor();
    assert.deepEqual(policyPatches().at(-1).body, {auto_booking: {enabled: true, selector: {}}}, 'empty selector deliberately matches any free cluster');
    await tokenEditor(originalToken.id).locator('summary').click(); await tokenEditor(originalToken.id).locator('input[name=enabled]').uncheck();
    await tokenEditor(originalToken.id).getByRole('button', {name: 'Save preferences', exact: true}).click();
    await page.locator('#pat-list .pat-policy-summary').filter({hasText: 'Automatic booking disabled'}).waitFor();
    assert.deepEqual(policyPatches().at(-1).body, {auto_booking: {enabled: false, selector: {}}});
    await page.locator('#pat-auto-booking').check(); await page.locator('#pat-selector').fill('environment=testing,region=eu');
    await page.locator('#pat-form input[name=name]').fill('Automatic test token');
    const automaticDownloadPending = page.waitForEvent('download'); await page.locator('#pat-form button[type=submit]').click(); const automaticDownload = await automaticDownloadPending;
    const automaticContent = fs.readFileSync(await automaticDownload.path(), 'utf8');
    assert.deepEqual(state.pats[1].auto_booking, {enabled: true, selector: {environment: 'testing', region: 'eu'}});
    assert.equal(automaticContent.includes('environment'), false, 'selection rules stay on backend rather than in native config');
    assert.equal(state.primary, originalPrimary); assert.equal(state.sessions.filter(s => s.state === 'ACTIVE').length, 1, 'PAT creation must not allocate');
    state.pats.push({...originalToken, id: 'p-expired', name: 'Expired fixture', expires_at: '2025-01-01T00:00:00Z'}, {...originalToken, id: 'p-revoked', name: 'Revoked fixture', revoked_at: '2026-01-01T00:00:00Z'}, {...originalToken, id: 'p-bob', owner: 'bob', name: 'Other developer token'});
    await page.getByRole('button', {name: '↻ Refresh', exact: true}).filter({visible: true}).last().click();
    await page.locator('#pat-list').getByText('Expired fixture', {exact: true}).waitFor();
    assert.equal(await tokenEditor('p-expired').count(), 0); assert.equal(await tokenEditor('p-revoked').count(), 0);
    assert.equal(await page.locator('#pat-list').getByText('Other developer token', {exact: true}).count(), 0, 'owner token listing excludes other developers');
    assert.deepEqual(await page.evaluate(() => ({local: localStorage.length, session: sessionStorage.length})), {local: 0, session: 0});
    await page.setViewportSize({width: 390, height: 844}); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(errors, []);
    const adminContext = await browser.newContext({extraHTTPHeaders: {'X-UI-Test-Role': 'admin'}}); const adminPage = await adminContext.newPage(); const adminErrors = [];
    await adminContext.route('**/*', guardNetwork);
    adminPage.on('pageerror', error => adminErrors.push(error.message)); adminPage.on('console', checkConsole);
    let acceptAdminDialog = true; const adminDialogs = []; adminPage.on('dialog', dialog => { adminDialogs.push(dialog.message()); return acceptAdminDialog ? dialog.accept() : dialog.dismiss(); });
    await adminPage.goto(origin, {waitUntil: 'domcontentloaded'}); await adminPage.locator('#workspace').waitFor({state: 'visible'});
    await adminPage.getByRole('button', {name: 'Administration', exact: false}).click(); await adminPage.locator('#developer-list table').waitFor();
    const adminTokenEditor = adminPage.locator('#admin-pat-list .pat-policy-editor[data-pat-id="p-fixture-2"]');
    await adminTokenEditor.locator('summary').click(); await adminTokenEditor.locator('input[name=selector]').fill('region=us');
    const patchesBeforeAdmin = policyPatches().length;
    await adminTokenEditor.getByRole('button', {name: 'Save preferences', exact: true}).click();
    await adminPage.waitForTimeout(10); assert.equal(policyPatches().length, patchesBeforeAdmin, 'administrator changes require an audit reason');
    await adminTokenEditor.locator('input[name=reason]').fill('  Administrator selector correction  ');
    await adminTokenEditor.getByRole('button', {name: 'Save preferences', exact: true}).click();
    await adminPage.locator('#admin-pat-list .pat-policy-summary').filter({hasText: 'Automatic: region=us'}).waitFor();
    assert.deepEqual(policyPatches().at(-1).body, {auto_booking: {enabled: true, selector: {region: 'us'}}, reason: 'Administrator selector correction'});
    assert.equal(state.primary, originalPrimary, 'administrator policy edits must not switch the developer primary');

    await adminPage.locator('#inactivity-grace-period').fill('2h'); await adminPage.locator('#default-booking-limit').fill('3'); await adminPage.locator('#settings-form input[name=reason]').fill('UI policy test'); await adminPage.locator('#settings-form button').click();
    await adminPage.waitForFunction(() => document.querySelector('#default-booking-limit').value === '3');
    assert.equal(state.inactivityGrace, '2h');
    assert.deepEqual(state.mutations.find(r => r.path === '/v1/admin/settings').body, {default_max_bookings: 3, inactivity_grace_period: '2h', reason: 'UI policy test'});
    let row = adminPage.locator('#developer-list tbody tr').first(); await row.locator('input[name=max_bookings]').fill('4'); await row.locator('input[name=reason]').fill('UI override test'); await row.getByRole('button', {name: 'Save limit'}).click();
    await adminPage.getByRole('cell', {name: '1 / 4', exact: true}).waitFor();
    row = adminPage.locator('#developer-list tbody tr').first(); await row.locator('input[name=max_bookings]').fill(''); await row.locator('input[name=reason]').fill('UI inherit test'); await row.getByRole('button', {name: 'Save limit'}).click();
    await adminPage.getByRole('cell', {name: '1 / 3', exact: true}).waitFor(); assert.equal(state.mutations.at(-1).body.max_bookings, null);
    assert.equal(state.sessions.filter(s => s.state === 'ACTIVE').length, 1);
    const adminCard = id => adminPage.locator(`#maintenance-list .cluster-card[data-cluster-id="${id}"]`);
    const deregistrations = () => state.mutations.filter(r => r.method === 'DELETE' && r.path.startsWith('/v1/admin/clusters/'));
    assert.equal(await adminCard('c').getByRole('button', {name: 'Deregister', exact: true}).isDisabled(), true, 'an active booking must block deregistration');
    assert.ok((await adminCard('c').innerText()).includes('Release all active bookings'));
    await adminCard('a').getByRole('button', {name: 'Deregister', exact: true}).click();
    await adminPage.waitForTimeout(10);
    assert.equal(deregistrations().length, 0); assert.equal(adminDialogs.length, 0, 'missing reason must fail before confirmation');
    await adminCard('a').locator('input[name=reason]').fill('  '); await adminCard('a').getByRole('button', {name: 'Deregister', exact: true}).click();
    await adminPage.waitForTimeout(10); assert.equal(deregistrations().length, 0); assert.equal(adminDialogs.length, 0, 'whitespace reason must not request deletion');
    acceptAdminDialog = false;
    await adminCard('a').locator('input[name=reason]').fill('  Retired fixture  '); await adminCard('a').getByRole('button', {name: 'Deregister', exact: true}).click();
    await adminPage.waitForTimeout(10); assert.equal(deregistrations().length, 0, 'cancelled confirmation must not delete');
    assert.ok(adminDialogs.at(-1).includes('Cluster A (a)')); assert.ok(adminDialogs.at(-1).includes('stored Kubernetes credentials')); assert.ok(adminDialogs.at(-1).includes('workloads will remain'));
    acceptAdminDialog = true;
    const beforeDeregisterPATs = structuredClone(state.pats);
    await adminCard('a').getByRole('button', {name: 'Deregister', exact: true}).click();
    await adminCard('a').waitFor({state: 'detached'});
    assert.equal(await adminPage.locator('#cluster-list .cluster-card[data-cluster-id="a"]').count(), 0, 'deregistered cluster must leave developer cluster list too');
    assert.equal(await adminPage.locator('#booking-cluster option[value=a]').count(), 0);
    assert.deepEqual(deregistrations().at(-1).body, {reason: 'Retired fixture'});
    assert.equal(state.sessions.find(s => s.id === 's-a').state, 'RELEASED', 'booking history must remain'); assert.deepEqual(state.pats, beforeDeregisterPATs);
    state.deregistrationConflict = 'b'; const readsBeforeConflict = state.registryReads;
    await adminCard('b').locator('input[name=reason]').fill('Concurrent reservation fixture'); await adminCard('b').getByRole('button', {name: 'Deregister', exact: true}).click();
    await adminPage.locator('#notification.error').filter({hasText: 'Release active bookings'}).waitFor();
    assert.equal(await adminCard('b').count(), 1); assert.equal(state.retired.has('b'), false); assert.ok(state.registryReads > readsBeforeConflict, 'conflict should refresh authoritative registry state');
    assert.equal(state.mutations.some(r => r.method === 'PATCH' && r.path.startsWith('/v1/admin/clusters/')), false, 'deregister button must not submit maintenance form');

    // Registration uses an in-memory development-only file; no original
    // credential or cluster endpoint is read or contacted by this harness.
    const registerForm = adminPage.locator('#register-form');
    const registrations = () => state.mutations.filter(r => r.method === 'POST' && r.path === '/v1/admin/clusters');
    await registerForm.locator('input[name=id]').fill('ui-registered');
    await registerForm.locator('input[name=name]').fill('UI registration fixture');
    await registerForm.locator('input[name=max_participants]').fill('3');
    await registerForm.locator('input[name=labels]').fill('region=eu,purpose=gui');
    await registerForm.locator('input[name=kubeconfig]').setInputFiles({name: 'empty.yaml', mimeType: 'application/yaml', buffer: Buffer.alloc(0)});
    const registrationsBeforeValidation = registrations().length;
    await registerForm.getByRole('button', {name: 'Register cluster', exact: true}).click();
    await adminPage.locator('#notification.error').filter({hasText: 'Choose a trusted kubeconfig smaller than 1.5 MB'}).waitFor();
    assert.equal(registrations().length, registrationsBeforeValidation, 'an empty kubeconfig must fail before a request');
    const fakeKubeconfig = 'apiVersion: v1\nkind: Config\ncurrent-context: ui-fixture\nclusters:\n- name: ui-fixture\n  cluster:\n    server: https://127.0.0.1:7443\ncontexts:\n- name: ui-fixture\n  context:\n    cluster: ui-fixture\n    user: ui-fixture\nusers:\n- name: ui-fixture\n  user:\n    token: UI_FIXTURE_TOKEN_NOT_REAL\n';
    await registerForm.locator('input[name=kubeconfig]').setInputFiles({name: 'fixture.yaml', mimeType: 'application/yaml', buffer: Buffer.from(fakeKubeconfig)});
    state.registrationFailure = true;
    const heldRegistration = holdRequest('POST', '/v1/admin/clusters');
    const rejectedRegistration = adminPage.waitForResponse(response => new URL(response.url()).pathname === '/v1/admin/clusters' && response.request().method() === 'POST');
    try {
      await registerForm.getByRole('button', {name: 'Register cluster', exact: true}).click(); await heldRegistration.arrived;
      await adminPage.waitForFunction(() => document.querySelector('#register-form button[type=submit]').disabled);
      assert.equal(registrations().length, registrationsBeforeValidation + 1, 'one submit sends one registration');
    } finally { heldRegistration.release(); }
    assert.equal((await rejectedRegistration).status(), 503);
    await adminPage.locator('#notification.error').filter({hasText: 'Fixture registration rejected'}).waitFor();
    await adminPage.waitForFunction(() => !document.querySelector('#register-form button[type=submit]').disabled);
    assert.equal(state.registry.has('ui-registered'), false, 'failed registration must not create a registry entry');
    assert.equal(await registerForm.locator('input[name=id]').inputValue(), 'ui-registered', 'failed registration preserves editable inputs');
    await registerForm.getByRole('button', {name: 'Register cluster', exact: true}).click();
    await adminCard('ui-registered').waitFor();
    assert.deepEqual(registrations().at(-1).body, {id: 'ui-registered', name: 'UI registration fixture', labels: {region: 'eu', purpose: 'gui'}, max_participants: 3, kubeconfig: fakeKubeconfig});
    assert.equal(Object.hasOwn(state.registry.get('ui-registered'), 'kubeconfig'), false, 'public registry metadata excludes imported credentials');
    assert.equal(await adminPage.locator('#cluster-list .cluster-card[data-cluster-id="ui-registered"]').count(), 1);
    assert.equal(await adminPage.locator('#booking-cluster option[value=ui-registered]').count(), 1, 'registration refreshes booking choices');
    assert.equal(await registerForm.locator('input[name=id]').inputValue(), '');
    assert.equal(await registerForm.locator('input[name=kubeconfig]').evaluate(input => input.files.length), 0, 'successful import clears the selected file');
    assert.deepEqual(await adminPage.evaluate(() => ({local: localStorage.length, session: sessionStorage.length})), {local: 0, session: 0}, 'imported credentials must not enter browser storage');

    const maintenancePath = '/v1/admin/clusters/ui-registered';
    const maintenanceUpdates = () => state.mutations.filter(r => r.method === 'PATCH' && r.path === maintenancePath);
    const registeredCard = () => adminCard('ui-registered');
    const beforeMissingMaintenanceReason = maintenanceUpdates().length;
    await registeredCard().getByRole('button', {name: 'Set maintenance', exact: true}).click();
    assert.equal(maintenanceUpdates().length, beforeMissingMaintenanceReason, 'maintenance requires an audit reason');
    state.maintenanceFailure = true;
    await registeredCard().locator('input[name=reason]').fill('  UI rejected maintenance  ');
    const heldMaintenance = holdRequest('PATCH', maintenancePath);
    const rejectedMaintenance = adminPage.waitForResponse(response => new URL(response.url()).pathname === maintenancePath && response.request().method() === 'PATCH');
    try {
      await registeredCard().getByRole('button', {name: 'Set maintenance', exact: true}).click(); await heldMaintenance.arrived;
      await adminPage.waitForFunction(() => document.querySelector('#maintenance-list [data-cluster-id="ui-registered"] button[type=submit]').disabled);
    } finally { heldMaintenance.release(); }
    assert.equal((await rejectedMaintenance).status(), 503);
    await adminPage.locator('#notification.error').filter({hasText: 'Fixture maintenance rejected'}).waitFor();
    await adminPage.waitForFunction(() => !document.querySelector('#maintenance-list [data-cluster-id="ui-registered"] button[type=submit]').disabled);
    assert.equal(state.maintenance.get('ui-registered') || false, false, 'failed maintenance keeps placement enabled');
    await registeredCard().locator('input[name=reason]').fill('  UI maintenance on  ');
    await registeredCard().getByRole('button', {name: 'Set maintenance', exact: true}).click();
    await registeredCard().getByRole('button', {name: 'Enable placement', exact: true}).waitFor();
    assert.deepEqual(maintenanceUpdates().at(-1).body, {maintenance: true, reason: 'UI maintenance on'});
    assert.equal(clusters().find(c => c.id === 'ui-registered').available, false);
    assert.equal(await adminPage.locator('#cluster-list [data-cluster-id="ui-registered"]').getByText('Maintenance', {exact: true}).count(), 1, 'maintenance is reflected in the public cluster card');
    await registeredCard().locator('input[name=reason]').fill('  UI maintenance off  ');
    await registeredCard().getByRole('button', {name: 'Enable placement', exact: true}).click();
    await registeredCard().getByRole('button', {name: 'Set maintenance', exact: true}).waitFor();
    assert.deepEqual(maintenanceUpdates().at(-1).body, {maintenance: false, reason: 'UI maintenance off'});
    assert.equal(clusters().find(c => c.id === 'ui-registered').available, true);

    const releases = () => state.mutations.filter(r => r.method === 'POST' && /^\/v1\/admin\/sessions\/[^/]+\/release$/.test(r.path));
    const releaseForm = adminPage.locator('#release-form'), activeBooking = primary(); assert.ok(activeBooking);
    const beforeReleasePATs = structuredClone(state.pats);
    await releaseForm.locator('select[name=session_id]').selectOption(activeBooking.id);
    await releaseForm.locator('input[name=reason]').fill('  ');
    const dialogsBeforeRelease = adminDialogs.length, releaseCount = releases().length;
    await releaseForm.getByRole('button', {name: 'Release booking', exact: true}).click();
    await adminPage.locator('#notification.error').filter({hasText: 'An audit reason is required'}).waitFor();
    assert.equal(releases().length, releaseCount); assert.equal(adminDialogs.length, dialogsBeforeRelease, 'blank release reason fails before confirmation');
    await releaseForm.locator('input[name=reason]').fill('  UI audited release  '); acceptAdminDialog = false;
    await releaseForm.getByRole('button', {name: 'Release booking', exact: true}).click();
    assert.equal(releases().length, releaseCount, 'cancelling release confirmation must not send a request');
    assert.ok(adminDialogs.at(-1).includes('Release this booking?')); assert.ok(adminDialogs.at(-1).includes('workloads will remain'));
    acceptAdminDialog = true; state.releaseFailure = true;
    const releasePath = `/v1/admin/sessions/${activeBooking.id}/release`;
    const heldRelease = holdRequest('POST', releasePath);
    const rejectedRelease = adminPage.waitForResponse(response => new URL(response.url()).pathname === releasePath && response.request().method() === 'POST');
    try {
      await releaseForm.getByRole('button', {name: 'Release booking', exact: true}).click(); await heldRelease.arrived;
      await adminPage.waitForFunction(() => document.querySelector('#release-form button[type=submit]').disabled);
    } finally { heldRelease.release(); }
    assert.equal((await rejectedRelease).status(), 503);
    await adminPage.locator('#notification.error').filter({hasText: 'Fixture release rejected'}).waitFor();
    await adminPage.waitForFunction(() => !document.querySelector('#release-form button[type=submit]').disabled);
    assert.equal(state.sessions.find(s => s.id === activeBooking.id).state, 'ACTIVE', 'failed release preserves the reservation');
    await releaseForm.getByRole('button', {name: 'Release booking', exact: true}).click();
    await adminPage.waitForFunction(id => !document.querySelector(`#release-session option[value="${id}"]`), activeBooking.id);
    assert.deepEqual(releases().at(-1), {path: releasePath, method: 'POST', body: {reason: 'UI audited release'}});
    assert.equal(state.sessions.find(s => s.id === activeBooking.id).state, 'RELEASED'); assert.equal(state.primary, null);
    assert.deepEqual(state.pats, beforeReleasePATs, 'administrator release must preserve PATs and their preferences');
    assert.equal(await releaseForm.locator('input[name=reason]').inputValue(), '');
    assert.equal(state.kubernetesRequests, 0, 'administrative UI controls never call the Kubernetes gateway');
    assert.deepEqual(adminErrors, []); assert.deepEqual(cspErrors, [], 'React production bundle must work under strict CSP');
    await adminPage.setViewportSize({width: 390, height: 844}); assert.ok(await adminPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await adminContext.close();
    await page.locator('#refresh-pats').click();
    await page.waitForFunction(() => document.querySelector('#primary-summary').textContent.includes('No cluster is booked.'));
    const beforeLogoutPATs = structuredClone(state.pats), beforeLogoutDeletes = state.mutations.filter(r => r.method === 'DELETE').length;
    await page.getByRole('button', {name: 'Sign out', exact: true}).click();
    await page.locator('#welcome').waitFor({state: 'visible'});
    assert.ok(dialogs.at(-1).includes('Your PATs will remain valid.'));
    assert.equal(dialogs.at(-1).includes('will be revoked'), false);
    assert.ok((await page.locator('#notification').innerText()).includes('Your PATs remain valid.'));
    assert.deepEqual(state.pats, beforeLogoutPATs, 'sign-out must not revoke or extend PATs');
    assert.equal(state.mutations.filter(r => r.method === 'DELETE').length, beforeLogoutDeletes, 'sign-out must not call PAT revocation');
    assert.equal(state.mutations.at(-1).path, '/auth/logout');
    const afterLogoutActivity = activity().length; await page.clock.runFor(90000); assert.equal(activity().length, afterLogoutActivity, 'logout clears pending presence');
    assert.equal(state.sessions.filter(s => s.state === 'ACTIVE').length, 0);
    assert.deepEqual(errors, []); assert.deepEqual(cspErrors, []); assert.equal(state.kubernetesRequests, 0); assert.deepEqual(externalRequests, [], 'UI tests must use only the local fixture origin'); await context.close();
    console.log('Primary UI contracts passed: React production strict CSP, stale-read primary ordering, audited registration/maintenance/release with validation, busy/error/retry/confirmation guards, transient imports, mutable PAT automatic booking, explicit opt-in, owner/admin policy editing, unchanged native config, two clients, audited admin deregistration, active-booking/confirmation/conflict guards, registry refresh, per-cluster interaction heartbeat, idle/hidden/polling guards, throttling, inactivity policy, retired booking duration/renewal, limits, selection, promotion, no-booking PAT download, stable config, admin override/reset, logout preserving PATs, CSRF, text escaping, storage and mobile layout.');
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => {console.error(error.stack); server.close(); process.exitCode = 1;});
