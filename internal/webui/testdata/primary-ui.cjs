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
const fixtureStartedAt = Date.now();
const administrator = {issuer: 'https://issuer.test', subject: 'admin', name: 'admin', display_name: 'Administrator', email: 'admin@example.test', admin: true};
const state = {
  primary: 's-a', version: 1, defaultLimit: 1, inactivityGrace: '4h', override: 2, serial: 0, patSerial: 0, pats: [], mutations: [], requests: [], unauthorized: [], signedOut: false, retired: new Set(), deregistrationConflict: null, registryReads: 0,
  registry: new Map(['a', 'b', 'c'].map(id => [id, {id, name: `Cluster ${id.toUpperCase()}`, labels: {test: 'ui'}, max_participants: 2}])),
  sharing: new Map(), bookingKeys: [], bookingFailure: false, sessionFailure: false, audit: [{id: 1, at: new Date(fixtureStartedAt - 1000).toISOString(), actor: 'admin', action: 'settings.updated', object_id: 'team-policy', detail: 'Fixture policy reason'}, {id: 2, at: new Date(fixtureStartedAt - 3600000).toISOString(), actor: 'alice', action: 'session.created', object_id: 's-a', detail: '<img src=x onerror=alert(1)>'}], maintenance: new Map(), registrationFailure: false, maintenanceFailure: false, releaseFailure: false, heldRequest: null, kubernetesRequests: 0, profileReads: 0,
  sessions: ['a', 'b'].map(id => ({id: `s-${id}`, owner: 'alice', name: 'alice', display_name: 'Alice Developer', email: alice.email, cluster: id, state: 'ACTIVE', primary: id === 'a', created_at: new Date(fixtureStartedAt - 1800000).toISOString(), expires_at: new Date(fixtureStartedAt + 4 * 3600000).toISOString(), reason: 'fixture'})),
};
let origin;
const sessionRows = () => state.sessions.map(s => ({...s, primary: s.id === state.primary}));
const primary = () => sessionRows().find(s => s.id === state.primary && s.state === 'ACTIVE');
const profile = admin => ({owner_id: admin ? 'admin' : 'alice', user: admin ? administrator : alice, max_bookings: admin ? state.defaultLimit : state.override ?? state.defaultLimit, max_bookings_override: admin ? null : state.override, active_bookings: admin ? 0 : state.sessions.filter(s => s.state === 'ACTIVE' && s.owner === 'alice').length, primary_session: admin ? null : primary(), selection_version: state.version});
const clusters = () => Array.from(state.registry.values()).filter(c => !state.retired.has(c.id)).map(c => ({...c, maintenance: state.maintenance.get(c.id) || false, controller_session: state.sessions.find(s => s.cluster === c.id && s.state === 'ACTIVE')?.id, shareable: state.sharing.get(c.id) || false, participants: sessionRows().filter(s => s.cluster === c.id && s.state === 'ACTIVE'), available: !state.maintenance.get(c.id) && (!state.sessions.some(s => s.cluster === c.id && s.state === 'ACTIVE') || state.sharing.get(c.id) && state.sessions.filter(s => s.cluster === c.id && s.state === 'ACTIVE').length < c.max_participants), reason: state.maintenance.get(c.id) ? 'Fixture maintenance: new bookings disabled' : 'Fixture cluster'}));
function holdRequest(method, pathname) {
  assert.equal(state.heldRequest, null, 'only one fixture response may be held at a time');
  let arrive, release, timeout;
  const arrived = new Promise((resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(`Expected fixture request did not arrive: ${method} ${pathname}`)), 10000);
    arrive = () => { clearTimeout(timeout); resolve(); };
  });
  arrived.catch(() => {});
  const wait = new Promise(resolve => { release = resolve; });
  state.heldRequest = {method, pathname, arrive, wait};
  return {arrived, release: () => { clearTimeout(timeout); release(); }};
}
function releaseFixtureSession(id, reason) {
  const selected = state.sessions.find(session => session.id === id && session.state === 'ACTIVE');
  if (!selected) return false;
  selected.state = 'RELEASED'; selected.ended_at = new Date().toISOString(); selected.reason = reason;
  if (state.primary === id) { state.primary = state.sessions.find(session => session.state === 'ACTIVE' && session.owner === selected.owner)?.id || null; state.version++; }
  return true;
}
function reply(res, status, body) { res.writeHead(status, {'Content-Type': 'application/json'}); res.end(JSON.stringify(body)); }
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, origin || 'http://127.0.0.1');
  const admin = req.headers['x-ui-test-role'] === 'admin';
  state.requests.push({method:req.method,path:url.pathname});
  if (url.pathname === '/k8s' || url.pathname.startsWith('/k8s/')) state.kubernetesRequests++;
  try {
    if (req.method === 'GET' && ['/', '/assets/app.js', '/assets/app.css'].includes(url.pathname)) {
      const name = url.pathname === '/' ? 'index.html' : path.basename(url.pathname);
      res.writeHead(200, {'Content-Type': name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html', 'Content-Security-Policy': productionCSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'}); res.end(fs.readFileSync(path.join(assets, name))); return;
    }
    // Losing browser authentication must reach the typed API client's 401
    // handler before CSRF or any mutation is accepted. Record attempts as well
    // as mutations so stale destructive requests cannot hide behind this guard.
    if (state.signedOut && !admin && url.pathname.startsWith('/v1/')) {
      state.unauthorized.push({method:req.method,path:url.pathname});
      req.resume(); reply(res,401,{error:'fixture browser identity expired'}); return;
    }
    if (req.method === 'GET') {
      if (url.pathname === '/web/session' && state.sessionFailure) { state.sessionFailure = false; reply(res, 503, {error: 'Fixture login service unavailable'}); return; }
      if (url.pathname === '/v1/clusters') state.registryReads++;
      if (url.pathname === '/v1/profile' && !admin) state.profileReads++;
      if (url.pathname === '/web/session' && state.signedOut && !admin) { reply(res, 401, {error: 'signed out'}); return; }
      const routes = {
        '/web/session': {user: admin ? administrator : alice, owner_id: admin ? 'admin' : 'alice', csrf_token: admin ? 'csrf-admin' : 'csrf-alice', expires_at: '2099-01-01T00:00:00Z'},
        '/v1/profile': profile(admin), '/v1/clusters': clusters(), '/v1/sessions': sessionRows(), '/v1/pats': state.pats.filter(p => url.searchParams.get('all') === 'true' && admin || p.owner === (admin ? 'admin' : 'alice')),
        '/v1/admin/settings': {default_max_bookings: state.defaultLimit, inactivity_grace_period: state.inactivityGrace}, '/v1/admin/developers': [profile(false), profile(true)], '/v1/admin/audit': state.audit,
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
    if (/^\/v1\/sessions\/[^/]+\/share$/.test(url.pathname)) {
      const selected = state.sessions.find(session => session.id === url.pathname.split('/')[3] && session.state === 'ACTIVE');
      assert.ok(selected); assert.equal(typeof body.shareable, 'boolean');
      state.sharing.set(selected.cluster, body.shareable); reply(res, 200, {status: 'updated'}); return;
    }
    if (/^\/v1\/sessions\/[^/]+\/stop$/.test(url.pathname)) {
      const id = url.pathname.split('/')[3]; assert.ok(releaseFixtureSession(id, 'Owner ended fixture booking'));
      reply(res, 200, {status: 'released'}); return;
    }
    if (url.pathname === '/v1/sessions' && req.method === 'POST') {
      assert.ok(profile(admin).active_bookings < profile(admin).max_bookings); assert.ok(req.headers['idempotency-key']); state.bookingKeys.push(req.headers['idempotency-key']); if (state.bookingFailure) { state.bookingFailure = false; reply(res, 503, {error: 'Fixture booking rejected; retry this request'}); return; } assert.equal(Object.hasOwn(body, 'ttl'), false, 'booking duration is retired');
      const booked = {id: `s-booked-${++state.serial}`, owner: 'alice', name: 'alice', display_name: 'Alice Developer', cluster: body.cluster || 'c', state: 'ACTIVE', created_at: '2026-01-01T00:00:00Z'};
      state.sessions.push(booked); if (!primary()) {state.primary = booked.id; state.version++;} reply(res, 201, {...booked, primary: booked.id === state.primary}); return;
    }
    if (url.pathname === '/v1/pats' && req.method === 'POST') {
      assert.equal(Object.hasOwn(body, 'session_id'), false, 'personal credential must not select a session');
      assert.equal(body.ttl, '8h', 'PAT access duration remains independently configurable');
      const pat = {id: `p-fixture-${++state.patSerial}`, owner: admin ? 'admin' : 'alice', name: body.name, scope: 'kubernetes:primary', created_at: new Date(fixtureStartedAt).toISOString(), expires_at: new Date(fixtureStartedAt + 8 * 3600000).toISOString(), auto_booking: structuredClone(body.auto_booking || {enabled: false, selector: {}})}; state.pats.push(pat);
      reply(res, 201, {pat, kubeconfig: 'apiVersion: v1\nkind: Config\nclusters:\n- name: gateway\n  cluster:\n    server: https://gateway.example.test/k8s\nusers:\n- name: personal\n  user:\n    token: dcpat_UI_FIXTURE_' + state.patSerial + '_ONLY\n'}); return;
    }
    if (/^\/v1\/pats\/[^/]+$/.test(url.pathname) && req.method === 'DELETE') {
      const pat = state.pats.find(value => value.id === url.pathname.split('/').at(-1));
      if (!pat) { reply(res, 404, {error: 'credential not found'}); return; }
      if (!admin && pat.owner !== 'alice') { reply(res, 403, {error: 'owner required'}); return; }
      if (admin && pat.owner !== 'admin' && !body.reason?.trim()) { reply(res, 400, {error: 'administrator audit reason required'}); return; }
      pat.revoked_at = new Date().toISOString(); reply(res, 200, {status: 'revoked'}); return;
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
  const errors = [], cspErrors = [], externalRequests = [], nativeDialogs = [];
  const guardNetwork = async route => {
    const requested = new URL(route.request().url());
    if (['http:', 'https:'].includes(requested.protocol) && requested.origin !== origin) {
      externalRequests.push(requested.origin); await route.abort(); return;
    }
    await route.continue();
  };
  const observe = page => {
    page.on('pageerror', error => errors.push(error.message));
    page.on('dialog', dialog => { nativeDialogs.push(dialog.message()); return dialog.dismiss(); });
    page.on('console', message => { if (message.type() === 'error' && /content security policy|violates the following|refused to (execute|load|apply|connect)|unsafe-eval/i.test(message.text())) cspErrors.push(message.text()); });
  };
  const responseFor = (page, predicate) => {const pending = page.waitForResponse(predicate); pending.catch(() => {}); return pending;};
  const mutation = (pathname, method) => state.mutations.filter(row => row.path === pathname && (!method || row.method === method));
  const nav = (page, section) => page.locator(`[data-section="${section}"]`).filter({visible: true}).first().click();
  const dialog = (page, title) => page.getByRole('dialog', {name: title, exact: typeof title === 'string'});
  const closeDialog = async (page, target) => {
    await target.getByRole('button', {name: /^Cancel$|^Keep current$|^Keep booking$|^Keep token$/}).click();
    await target.waitFor({state: 'hidden'});
  };
  const expectNoOverflow = async (page, label) => {
    const result = await page.evaluate(() => ({width:innerWidth,scroll:document.documentElement.scrollWidth,offenders:[...document.querySelectorAll('body *')].filter(node=>node.getClientRects().length&&node.getBoundingClientRect().right>innerWidth+1).slice(0,20).map(node=>({tag:node.tagName,id:node.id,className:typeof node.className==='string'?node.className:'',right:Math.round(node.getBoundingClientRect().right),width:Math.round(node.getBoundingClientRect().width),text:node.textContent?.slice(0,70)}))}));
    if(result.scroll>result.width+1){console.error('Overflow diagnosis:',JSON.stringify({label,...result}));await page.screenshot({path:path.resolve('.demo/slate-ui-overflow.png'),fullPage:true});}
    assert.ok(result.scroll<=result.width+1,`${label} must fit without horizontal page overflow`);
  };
  const expectInWidth = async (locator, width) => {
    await locator.scrollIntoViewIfNeeded(); const box = await locator.boundingBox();
    assert.ok(box && box.x >= -1 && box.x + box.width <= width + 1, 'important mobile control must fit within the viewport');
  };
  const expectStorageEmpty = async page => assert.deepEqual(await page.evaluate(() => ({local: localStorage.length, session: sessionStorage.length})), {local: 0, session: 0});
  try {
    // Isolate initial loading and recovery from presence tests. No real SSO or
    // registered Kubernetes endpoint is involved in this browser fixture.
    const recoveryContext = await browser.newContext(); await recoveryContext.route('**/*', guardNetwork);
    const recovery = await recoveryContext.newPage(); observe(recovery);
    const heldBootstrap = holdRequest('GET', '/web/session');
    try {
      await recovery.goto(origin, {waitUntil: 'domcontentloaded'}); await heldBootstrap.arrived;
      await recovery.getByText('Loading your workspace…', {exact: true}).waitFor();
      assert.equal(await recovery.locator('#workspace').count(), 0, 'loading must not expose application forms before identity is known');
    } finally { heldBootstrap.release(); }
    await recovery.locator('#workspace').waitFor(); await recoveryContext.close();
    const retryContext = await browser.newContext(); await retryContext.route('**/*', guardNetwork);
    const retryPage = await retryContext.newPage(); observe(retryPage); state.sessionFailure = true;
    await retryPage.goto(origin, {waitUntil: 'domcontentloaded'});
    await retryPage.getByRole('button', {name: 'Retry connection', exact: true}).click();
    await retryPage.locator('#workspace').waitFor(); await retryContext.close();

    const context = await browser.newContext({acceptDownloads: true, viewport: {width: 1440, height: 1040}});
    await context.route('**/*', guardNetwork); const page = await context.newPage(); observe(page);
    await page.clock.install({time: new Date(fixtureStartedAt)});
    await page.goto(origin, {waitUntil: 'domcontentloaded'}); await page.locator('#workspace').waitFor({state: 'visible'});
    await page.locator('#primary-summary').getByRole('heading', {name: 'Cluster A', exact: true}).waitFor();
    assert.equal(await page.locator('[data-section^="admin-"]').count(), 0, 'developers must not receive administration navigation');
    assert.equal(await page.locator('#identity img').count(), 0, 'identity text must be escaped');
    assert.equal(await page.getByRole('button', {name: /^Deregister/}).count(), 0);
    assert.equal(await page.getByRole('button',{name:'Book a cluster',exact:true}).filter({visible:true}).first().isDisabled(),true,'reached booking limits must block new placement in the UI');
    assert.match(await page.locator('#booking-limit-help').innerText(),/limit is reached.*administrator/i);
    assert.equal(await page.getByRole('button', {name: 'Renew lease', exact: true}).count(), 0);
    assert.equal((await page.locator('body').textContent()).includes('kubectl devctl'), false, 'standalone plugin instructions remain removed');
    assert.equal(await page.getByRole('heading', {name: 'kubectl plugin', exact: true}).count(), 0);
    const activity = () => mutation('/v1/activity');
    await page.clock.runFor(90000); assert.equal(activity().length, 0, 'idle open tabs must not renew reservations');
    await page.evaluate(async () => { await fetch('/v1/profile'); await fetch('/v1/sessions'); document.dispatchEvent(new KeyboardEvent('keydown', {key: 'x'})); });
    await page.clock.runFor(1000); assert.equal(activity().length, 0, 'polling and synthetic input must not count as presence');
    const bDeadline = state.sessions.find(value => value.id === 's-b').expires_at;
    const firstActivity = responseFor(page, response => new URL(response.url()).pathname === '/v1/activity' && response.request().method() === 'POST');
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(5); await firstActivity;
    assert.deepEqual(activity().at(-1).body, {session_id: 's-a', selection_version: 1});
    assert.equal(state.sessions.find(value => value.id === 's-b').expires_at, bDeadline, 'activity must extend only the primary booking');
    const firstCount = activity().length;
    await page.keyboard.press('ArrowRight'); await page.keyboard.press('ArrowRight'); await page.clock.runFor(15000);
    assert.equal(activity().length, firstCount, 'interaction heartbeat must be throttled');
    const delayedActivity = responseFor(page, response => new URL(response.url()).pathname === '/v1/activity' && response.request().method() === 'POST');
    await page.clock.runFor(15000); await delayedActivity;
    assert.equal(activity().length, firstCount + 1, 'one pending interaction gets one delayed send');
    await page.clock.runFor(120000); assert.equal(activity().length, firstCount + 1, 'a prior interaction must not renew itself');
    await page.evaluate(() => Object.defineProperty(document, 'visibilityState', {configurable: true, get: () => 'hidden'}));
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(40000);
    assert.equal(activity().length, firstCount + 1, 'hidden input must not renew a booking');

    // Hold the old primary snapshot while accepting an explicit primary change.
    // The post-mutation refresh must queue a fresh read rather than reuse it.
    const heldProfile = holdRequest('GET', '/v1/profile');
    const oldProfileResponse = responseFor(page, response => new URL(response.url()).pathname === '/v1/profile' && response.request().method() === 'GET');
    let readsAtHeldProfile;
    try {
      await page.locator('#refresh-overview').click(); await heldProfile.arrived; readsAtHeldProfile = state.profileReads;
      await page.locator('#my-bookings [data-session-id="s-b"]').getByRole('button', {name: 'Make primary', exact: true}).click();
      const confirmation = dialog(page, 'Use Cluster B as primary?');
      await confirmation.getByText(/every terminal|every device|all devices/).first().waitFor();
      const primaryMutation = responseFor(page, response => new URL(response.url()).pathname === '/v1/primary' && response.request().method() === 'POST');
      await confirmation.getByRole('button', {name: 'Switch primary', exact: true}).click();
      await (await primaryMutation).finished();
      assert.equal(state.primary, 's-b'); assert.equal(state.profileReads, readsAtHeldProfile, 'new snapshot waits for the older response');
    } finally { heldProfile.release(); }
    assert.equal((await (await oldProfileResponse).json()).primary_session.id, 's-a');
    await page.locator('#primary-summary').getByRole('heading', {name: 'Cluster B', exact: true}).waitFor();
    assert.equal(state.profileReads, readsAtHeldProfile + 1, 'selection must queue exactly one fresh profile read');
    await page.evaluate(() => delete document.visibilityState);
    assert.deepEqual(mutation('/v1/primary').at(-1).body, {cluster: 'b'});
    const switchedActivity = responseFor(page, response => new URL(response.url()).pathname === '/v1/activity' && response.request().method() === 'POST');
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(30000); await switchedActivity;
    assert.deepEqual(activity().at(-1).body, {session_id: 's-b', selection_version: 2});

    // The same functional actions remain reachable without sideways scrolling.
    await page.setViewportSize({width: 390, height: 844}); await expectNoOverflow(page, 'Mobile workspace');
    await expectInWidth(page.locator('#my-bookings [data-session-id="s-a"]').getByRole('button', {name: 'Make primary', exact: true}), 390);
    await expectInWidth(page.locator('#my-bookings [data-session-id="s-b"]').getByRole('button', {name: 'Release booking', exact: true}), 390);
    assert.ok(await page.locator('[data-section="clusters"]').filter({visible: true}).count());
    await page.setViewportSize({width: 1440, height: 1040});
    // Controller sharing is explicit and never silently releases holders.
    await page.locator('#my-bookings [data-session-id="s-b"]').getByRole('button', {name: 'Allow sharing', exact: true}).click();
    await dialog(page,'Allow sharing on Cluster B?').getByRole('button',{name:'Allow sharing',exact:true}).click();
    await page.waitForFunction(() => document.querySelector('#my-bookings [data-session-id="s-b"]').textContent.includes('Disable sharing'));
    assert.equal(state.sharing.get('b'), true); assert.equal(state.sessions.filter(value => value.state === 'ACTIVE').length, 2);
    await page.locator('#my-bookings [data-session-id="s-b"]').getByRole('button', {name: 'Disable sharing', exact: true}).click();
    await dialog(page,'Disable new joins on Cluster B?').getByRole('button',{name:'Disable sharing',exact:true}).click();
    await page.waitForFunction(() => document.querySelector('#my-bookings [data-session-id="s-b"]').textContent.includes('Allow sharing'));
    assert.equal(state.sharing.get('b'), false);
    for (const [id,name] of [['s-b','Cluster B'],['s-a','Cluster A']]) {
      await page.locator(`#my-bookings [data-session-id="${id}"]`).getByRole('button', {name: 'Release booking', exact: true}).click();
      const confirmation = dialog(page, `Release ${name}?`);
      assert.match(await confirmation.innerText(), /workloads/i); assert.match(await confirmation.innerText(), /token|PAT/i);
      await confirmation.getByRole('button', {name: 'Release booking', exact: true}).click();
      await page.locator(`#my-bookings [data-session-id="${id}"]`).waitFor({state: 'detached'});
    }
    await page.locator('#my-bookings').getByText(/No cluster is booked|No primary selected|No cluster booked/).first().waitFor();
    assert.equal(state.primary, null);
    await nav(page, 'access'); assert.equal(await page.locator('.connection-card').count(), 2);
    assert.equal(await page.locator('#pat-session').count(), 0, 'PAT creation never binds a booking');
    const createTrigger = page.getByRole('button', {name: 'Create kubeconfig', exact: true});
    await createTrigger.click(); let create = dialog(page, 'Create a kubeconfig');
    await create.waitFor(); assert.equal(await create.locator('#pat-form [name=ttl]').count(), 1);
    assert.equal(await create.locator('#pat-auto-booking').isChecked(), false);
    for (let step = 0; step < 18; step++) {
      await page.keyboard.press(step % 3 === 0 ? 'Shift+Tab' : 'Tab');
      assert.equal(await create.evaluate(node => node.contains(document.activeElement)), true, 'keyboard focus must stay in the open drawer');
    }
    let backgroundBlocked = false;
    try { await page.locator('[data-section="clusters"]').filter({visible: true}).first().click({timeout: 250}); } catch { backgroundBlocked = true; }
    assert.equal(backgroundBlocked, true, 'native drawer must make background navigation inert');
    await page.keyboard.press('Escape'); await create.waitFor({state: 'hidden'});
    assert.equal(await createTrigger.evaluate(node => node === document.activeElement), true, 'Escape returns focus to the trigger');
    assert.equal(mutation('/v1/pats','POST').length, 0, 'cancelling creation issues no token');
    await createTrigger.click(); create = dialog(page, 'Create a kubeconfig');
    const downloadPending = page.waitForEvent('download');
    await create.getByRole('button', {name: 'Create & download', exact: true}).click();
    const download = await downloadPending; const content = fs.readFileSync(await download.path(), 'utf8');
    await create.waitFor({state: 'hidden'});
    assert.ok(content.includes('https://gateway.example.test/k8s')); assert.equal(content.includes('/sessions/'), false); assert.equal(content.includes('refresh_token'), false);
    assert.equal(state.primary, null); assert.equal(state.sessions.filter(value => value.state === 'ACTIVE').length, 0, 'creation does not allocate');
    assert.equal((await page.locator('body').textContent()).includes('dcpat_UI_FIXTURE_'), false, 'raw PAT never enters rendered content');
    const originalToken = structuredClone(state.pats[0]); assert.deepEqual(originalToken.auto_booking, {enabled: false, selector: {}});

    // Booking failure retains its inputs and idempotency key for a retry.
    await nav(page, 'overview'); await page.getByRole('button', {name: 'Book a cluster', exact: true}).filter({visible:true}).first().click();
    let booking = dialog(page, 'Book a cluster');
    assert.equal(await booking.locator('[name=ttl]').count(), 0);
    await booking.locator('#booking-cluster').selectOption('c');
    state.bookingFailure = true;
    await booking.getByRole('button', {name: 'Book cluster', exact: true}).click();
    await booking.getByRole('alert').filter({hasText: 'Fixture booking rejected'}).waitFor();
    assert.equal(await booking.locator('#booking-cluster').inputValue(), 'c');
    await booking.getByRole('button', {name: 'Book cluster', exact: true}).click();
    await booking.waitFor({state: 'hidden'});
    assert.equal(state.bookingKeys.length, 2); assert.equal(state.bookingKeys[0], state.bookingKeys[1]);
    await page.locator('#primary-summary').getByRole('heading', {name: 'Cluster C', exact: true}).waitFor();
    await nav(page, 'clusters'); await page.getByRole('searchbox', {name: 'Search clusters', exact: true}).fill('does-not-exist');
    await page.getByText(/No clusters match|No matching clusters/).first().waitFor();
    await page.getByRole('searchbox', {name: 'Search clusters', exact: true}).fill('test=ui');
    assert.ok(await page.locator('#cluster-list [data-cluster-id="c"]').count());
    await nav(page, 'access');
    const originalPrimary = state.primary;
    const policyPatches = () => state.mutations.filter(value => value.method === 'PATCH' && value.path.startsWith('/v1/pats/'));
    const tokenRow = (target, id, admin = false) => target.locator(`${admin ? '#admin-pat-list' : '#pat-list'} [data-pat-id="${id}"]`);
    async function openPolicy(target, id, admin = false) {
      await tokenRow(target,id,admin).getByRole('button', {name: 'Edit policy', exact: true}).click();
      const editor = dialog(target, 'Edit booking policy'); await editor.waitFor(); return editor;
    }
    let editor = await openPolicy(page, originalToken.id);
    await editor.locator('input[name=enabled]').check(); await editor.locator('input[name=selector]').fill('region=eu,test=');
    await editor.getByRole('button', {name: 'Save policy', exact: true}).click(); await editor.waitFor({state: 'hidden'});
    assert.deepEqual(policyPatches().at(-1).body, {auto_booking: {enabled: true, selector: {region: 'eu',test: ''}}});
    assert.equal(state.primary, originalPrimary);
    assert.deepEqual({...state.pats[0],auto_booking:originalToken.auto_booking}, originalToken, 'policy changes preserve token identity/lifetime');
    assert.equal(fs.readFileSync(await download.path(),'utf8'),content);
    editor = await openPolicy(page, originalToken.id); await editor.locator('input[name=selector]').fill('region');
    const beforeInvalid = policyPatches().length; await editor.getByRole('button', {name: 'Save policy', exact: true}).click();
    await editor.getByRole('alert').filter({hasText: 'key=value'}).waitFor(); assert.equal(policyPatches().length,beforeInvalid);
    assert.equal(await editor.getByRole('alert').evaluate(node => node === document.activeElement), true, 'validation summary receives focus');
    const fieldErrorLinks = editor.getByRole('alert').locator('a[href^="#"]');
    assert.ok(await fieldErrorLinks.count(),'validation summary must link to its invalid field');
    await fieldErrorLinks.first().click(); assert.equal(await editor.locator('input[name=selector]').evaluate(node => node === document.activeElement),true);
    await editor.locator('input[name=selector]').fill(''); await editor.getByRole('button', {name: 'Save policy', exact: true}).click(); await editor.waitFor({state: 'hidden'});
    assert.deepEqual(policyPatches().at(-1).body,{auto_booking:{enabled:true,selector:{}}});
    editor = await openPolicy(page, originalToken.id); await editor.locator('input[name=enabled]').uncheck();
    await editor.getByRole('button',{name:'Save policy',exact:true}).click(); await editor.waitFor({state:'hidden'});
    assert.deepEqual(policyPatches().at(-1).body,{auto_booking:{enabled:false,selector:{}}});
    await createTrigger.click(); create = dialog(page,'Create a kubeconfig');
    assert.equal(await create.locator('#pat-auto-booking').isChecked(),false);
    await create.locator('#pat-form input[name=name]').fill('Automatic test token');
    await create.locator('#pat-auto-booking').check(); await create.locator('#pat-selector').fill('environment=testing,region=eu');
    const automaticDownloadPending = page.waitForEvent('download'); await create.getByRole('button',{name:'Create & download',exact:true}).click();
    const automaticDownload = await automaticDownloadPending; const automaticContent = fs.readFileSync(await automaticDownload.path(),'utf8'); await create.waitFor({state:'hidden'});
    assert.deepEqual(state.pats[1].auto_booking,{enabled:true,selector:{environment:'testing',region:'eu'}});
    assert.equal(automaticContent.includes('environment'),false); assert.equal(state.primary,originalPrimary); assert.equal(state.sessions.filter(value=>value.state==='ACTIVE').length,1);
    state.pats.push({...originalToken,id:'p-expired',name:'Expired fixture',expires_at:'2025-01-01T00:00:00Z'}, {...originalToken,id:'p-revoked',name:'Revoked fixture',revoked_at:'2026-01-01T00:00:00Z'}, {...originalToken,id:'p-bob',owner:'bob',name:'Other developer token'});
    await page.locator('#refresh-pats').click(); await tokenRow(page,'p-expired').waitFor();
    assert.equal(await tokenRow(page,'p-expired').getByRole('button',{name:'Edit policy',exact:true}).count(),0);
    assert.equal(await tokenRow(page,'p-revoked').getByRole('button',{name:'Edit policy',exact:true}).count(),0);
    assert.equal(await page.locator('#pat-list').getByText('Other developer token',{exact:true}).count(),0);
    await expectStorageEmpty(page);
    await page.setViewportSize({width:390,height:844}); await expectNoOverflow(page,'Mobile access');
    await expectInWidth(tokenRow(page,originalToken.id).getByRole('button',{name:'Edit policy',exact:true}),390);
    await expectInWidth(tokenRow(page,originalToken.id).getByRole('button',{name:'Revoke',exact:true}),390);
    await page.setViewportSize({width:1440,height:1040});
    const beforeRevokeBookings = state.sessions.filter(value=>value.state==='ACTIVE').length;
    await tokenRow(page,originalToken.id).getByRole('button',{name:'Revoke',exact:true}).click();
    let revoke = dialog(page,`Revoke ${originalToken.name}?`); await closeDialog(page,revoke);
    assert.equal(mutation(`/v1/pats/${originalToken.id}`,'DELETE').length,0);
    await tokenRow(page,originalToken.id).getByRole('button',{name:'Revoke',exact:true}).click(); revoke=dialog(page,`Revoke ${originalToken.name}?`);
    await revoke.getByRole('button',{name:'Revoke token',exact:true}).click(); await revoke.waitFor({state:'hidden'});
    await page.waitForFunction(id=>document.querySelector(`#pat-list [data-pat-id="${id}"]`).textContent.includes('Revoked'),originalToken.id);
    assert.ok(state.pats[0].revoked_at); assert.equal(state.sessions.filter(value=>value.state==='ACTIVE').length,beforeRevokeBookings);

    const adminContext = await browser.newContext({extraHTTPHeaders:{'X-UI-Test-Role':'admin'},viewport:{width:1440,height:1040}});
    await adminContext.route('**/*',guardNetwork); const adminPage=await adminContext.newPage(); observe(adminPage);
    await adminPage.goto(origin,{waitUntil:'domcontentloaded'}); await adminPage.locator('#workspace').waitFor();
    await nav(adminPage,'admin-tokens');
    editor=await openPolicy(adminPage,'p-fixture-2',true); await editor.locator('input[name=selector]').fill('region=us');
    await editor.locator('input[name=reason]').fill('  '); const beforeAdminPatch=policyPatches().length;
    await editor.getByRole('button',{name:'Save policy',exact:true}).click(); await editor.getByRole('alert').filter({hasText:'audit reason'}).waitFor();
    assert.equal(policyPatches().length,beforeAdminPatch);
    await editor.locator('input[name=reason]').fill('  Administrator selector correction  ');
    await editor.getByRole('button',{name:'Save policy',exact:true}).click(); await editor.waitFor({state:'hidden'});
    assert.deepEqual(policyPatches().at(-1).body,{auto_booking:{enabled:true,selector:{region:'us'}},reason:'Administrator selector correction'});
    assert.equal(state.primary,originalPrimary);
    await nav(adminPage,'admin-people');
    await adminPage.locator('#inactivity-grace-period').fill('2h'); await adminPage.locator('#default-booking-limit').fill('3');
    await adminPage.locator('#settings-form input[name=reason]').fill('UI policy test');
    await adminPage.locator('#settings-form').getByRole('button',{name:/Save/}).click();
    await adminPage.waitForFunction(()=>document.querySelector('#default-booking-limit').value==='3');
    assert.equal(state.inactivityGrace,'2h'); assert.deepEqual(mutation('/v1/admin/settings').at(-1).body,{default_max_bookings:3,inactivity_grace_period:'2h',reason:'UI policy test'});
    const developerRow=()=>adminPage.locator('#developer-list [data-owner-id="alice"]');
    for (const [limit,reason] of [['4','UI override test'],['','UI inherit test']]) {
      await developerRow().getByRole('button',{name:/Edit override|Edit limit/}).click(); const limits=dialog(adminPage,/Edit booking limit for/);
      await limits.locator('input[name=max_bookings]').fill(limit); await limits.locator('input[name=reason]').fill(reason);
      await limits.getByRole('button',{name:'Save override',exact:true}).click(); await limits.waitFor({state:'hidden'});
      assert.equal(state.override,limit===''?null:4);
    }
    assert.equal(state.sessions.filter(value=>value.state==='ACTIVE').length,1);
    await nav(adminPage,'admin-clusters');
    const adminRow=id=>adminPage.locator(`#maintenance-list [data-cluster-id="${id}"]`);
    const deregistrations=()=>state.mutations.filter(value=>value.method==='DELETE'&&value.path.startsWith('/v1/admin/clusters/'));
    assert.equal(await adminRow('c').getByRole('button',{name:/^Deregister/}).isDisabled(),true);
    assert.match(await adminRow('c').innerText(),/Release.*active booking/i);
    await adminRow('a').getByRole('button',{name:/^Deregister/}).click(); let deregister=dialog(adminPage,'Deregister Cluster A?');
    assert.match(await deregister.innerText(),/stored.*credential/i); assert.match(await deregister.innerText(),/workloads.*remain/i);
    await deregister.locator('input[name=reason]').fill('  '); await deregister.getByRole('button',{name:'Deregister cluster',exact:true}).click();
    await deregister.getByRole('alert').filter({hasText:/audit reason/i}).waitFor(); assert.equal(deregistrations().length,0);
    await deregister.locator('input[name=reason]').fill('  Retired fixture  '); await closeDialog(adminPage,deregister); assert.equal(deregistrations().length,0);
    const beforeDeregisterPATs=structuredClone(state.pats);
    await adminRow('a').getByRole('button',{name:/^Deregister/}).click(); deregister=dialog(adminPage,'Deregister Cluster A?');
    await deregister.locator('input[name=reason]').fill('  Retired fixture  '); await deregister.getByRole('button',{name:'Deregister cluster',exact:true}).click();
    await deregister.waitFor({state:'hidden'}); await adminRow('a').waitFor({state:'detached'});
    assert.deepEqual(deregistrations().at(-1).body,{reason:'Retired fixture'}); assert.equal(state.sessions.find(value=>value.id==='s-a').state,'RELEASED'); assert.deepEqual(state.pats,beforeDeregisterPATs);
    state.deregistrationConflict='b'; const beforeConflictReads=state.registryReads;
    await adminRow('b').getByRole('button',{name:/^Deregister/}).click(); deregister=dialog(adminPage,'Deregister Cluster B?');
    await deregister.locator('input[name=reason]').fill('Concurrent reservation fixture'); await deregister.getByRole('button',{name:'Deregister cluster',exact:true}).click();
    await deregister.getByRole('alert').filter({hasText:'Release active bookings'}).waitFor();
    assert.equal(state.retired.has('b'),false); assert.ok(state.registryReads>beforeConflictReads); await closeDialog(adminPage,deregister);
    assert.equal(state.mutations.some(value=>value.method==='PATCH'&&value.path.startsWith('/v1/admin/clusters/')),false);

    await adminPage.getByRole('button',{name:'Register cluster',exact:true}).click(); let registration=dialog(adminPage,'Register a cluster');
    const registerForm=registration.locator('#register-form'); const registrations=()=>mutation('/v1/admin/clusters','POST');
    await registerForm.locator('input[name=id]').fill('ui-registered'); await registerForm.locator('input[name=name]').fill('UI registration fixture');
    await registerForm.locator('input[name=max_participants]').fill('3'); await registerForm.locator('input[name=labels]').fill('region=eu,purpose=gui');
    await registerForm.locator('input[name=kubeconfig]').setInputFiles({name:'empty.yaml',mimeType:'application/yaml',buffer:Buffer.alloc(0)});
    await registration.getByRole('button',{name:'Register cluster',exact:true}).click();
    await registration.getByRole('alert').filter({hasText:'Choose a trusted kubeconfig smaller than 1.5 MB'}).waitFor(); assert.equal(registrations().length,0);
    const fakeKubeconfig='apiVersion: v1\nkind: Config\ncurrent-context: ui-fixture\nclusters:\n- name: ui-fixture\n  cluster:\n    server: https://127.0.0.1:7443\ncontexts:\n- name: ui-fixture\n  context:\n    cluster: ui-fixture\n    user: ui-fixture\nusers:\n- name: ui-fixture\n  user:\n    token: UI_FIXTURE_TOKEN_NOT_REAL\n';
    await registerForm.locator('input[name=kubeconfig]').setInputFiles({name:'fixture.yaml',mimeType:'application/yaml',buffer:Buffer.from(fakeKubeconfig)});
    state.registrationFailure=true; const heldRegistration=holdRequest('POST','/v1/admin/clusters');
    const rejectedRegistration=responseFor(adminPage, response=>new URL(response.url()).pathname==='/v1/admin/clusters'&&response.request().method()==='POST');
    try {
      await registration.getByRole('button',{name:'Register cluster',exact:true}).click(); await heldRegistration.arrived;
      assert.equal(await registration.locator('button[type=submit]').isDisabled(),true);
    } finally {heldRegistration.release();}
    assert.equal((await rejectedRegistration).status(),503); await registration.getByRole('alert').filter({hasText:'Fixture registration rejected'}).waitFor();
    assert.equal(await registerForm.locator('input[name=id]').inputValue(),'ui-registered'); assert.equal(state.registry.has('ui-registered'),false);
    await registration.getByRole('button',{name:'Register cluster',exact:true}).click(); await registration.waitFor({state:'hidden'}); await adminRow('ui-registered').waitFor();
    assert.deepEqual(registrations().at(-1).body,{id:'ui-registered',name:'UI registration fixture',labels:{region:'eu',purpose:'gui'},max_participants:3,kubeconfig:fakeKubeconfig});
    assert.equal(Object.hasOwn(state.registry.get('ui-registered'),'kubeconfig'),false);
    assert.equal((await adminPage.locator('body').textContent()).includes('UI_FIXTURE_TOKEN_NOT_REAL'),false);
    await adminPage.getByRole('button',{name:'Register cluster',exact:true}).click(); registration=dialog(adminPage,'Register a cluster');
    assert.equal(await registration.locator('input[name=id]').inputValue(),''); assert.equal(await registration.locator('input[name=kubeconfig]').evaluate(input=>input.files.length),0);
    await closeDialog(adminPage,registration); await expectStorageEmpty(adminPage);

    const maintenancePath='/v1/admin/clusters/ui-registered', maintenanceUpdates=()=>mutation(maintenancePath,'PATCH');
    await adminRow('ui-registered').getByRole('button',{name:'Maintenance…',exact:true}).click(); let maintenance=dialog(adminPage,'Pause placement for UI registration fixture?');
    await maintenance.locator('input[name=reason]').fill('  '); await maintenance.getByRole('button',{name:'Set maintenance',exact:true}).click();
    await maintenance.getByRole('alert').filter({hasText:/audit reason/i}).waitFor(); assert.equal(maintenanceUpdates().length,0);
    await maintenance.locator('input[name=reason]').fill('  UI rejected maintenance  '); state.maintenanceFailure=true;
    const heldMaintenance=holdRequest('PATCH',maintenancePath), rejectedMaintenance=responseFor(adminPage, response=>new URL(response.url()).pathname===maintenancePath&&response.request().method()==='PATCH');
    try {
      await maintenance.getByRole('button',{name:'Set maintenance',exact:true}).click(); await heldMaintenance.arrived;
      assert.equal(await maintenance.locator('button[type=submit]').isDisabled(),true);
    } finally {heldMaintenance.release();}
    assert.equal((await rejectedMaintenance).status(),503); await maintenance.getByRole('alert').filter({hasText:'Fixture maintenance rejected'}).waitFor();
    assert.equal(state.maintenance.get('ui-registered')||false,false);
    await maintenance.locator('input[name=reason]').fill('  UI maintenance on  '); await maintenance.getByRole('button',{name:'Set maintenance',exact:true}).click(); await maintenance.waitFor({state:'hidden'});
    assert.deepEqual(maintenanceUpdates().at(-1).body,{maintenance:true,reason:'UI maintenance on'}); assert.equal(clusters().find(value=>value.id==='ui-registered').available,false);
    await adminRow('ui-registered').getByRole('button',{name:'Enable placement…',exact:true}).click(); maintenance=dialog(adminPage,'Enable placement for UI registration fixture?');
    await maintenance.locator('input[name=reason]').fill('  UI maintenance off  '); await maintenance.getByRole('button',{name:'Enable placement',exact:true}).click(); await maintenance.waitFor({state:'hidden'});
    assert.deepEqual(maintenanceUpdates().at(-1).body,{maintenance:false,reason:'UI maintenance off'});

    await nav(adminPage,'admin-people'); const activeBooking=primary(); assert.ok(activeBooking); const beforeReleasePATs=structuredClone(state.pats);
    const releases=()=>state.mutations.filter(value=>value.method==='POST'&&/^\/v1\/admin\/sessions\/[^/]+\/release$/.test(value.path));
    const openRelease=async()=>{await adminPage.locator(`[data-session-id="${activeBooking.id}"]`).filter({visible:true}).getByRole('button',{name:/Release/}).click();return dialog(adminPage,'Release booking on Cluster C?');};
    let release=await openRelease(); await release.locator('input[name=reason]').fill('  '); await release.getByRole('button',{name:'Release booking',exact:true}).click();
    await release.getByRole('alert').filter({hasText:/audit reason/i}).waitFor(); assert.equal(releases().length,0); await closeDialog(adminPage,release);
    release=await openRelease(); await release.locator('input[name=reason]').fill('  UI audited release  '); state.releaseFailure=true;
    const releasePath=`/v1/admin/sessions/${activeBooking.id}/release`, heldRelease=holdRequest('POST',releasePath), rejectedRelease=responseFor(adminPage, response=>new URL(response.url()).pathname===releasePath&&response.request().method()==='POST');
    try {
      await release.getByRole('button',{name:'Release booking',exact:true}).click(); await heldRelease.arrived;
      assert.equal(await release.locator('button[type=submit]').isDisabled(),true);
    } finally {heldRelease.release();}
    assert.equal((await rejectedRelease).status(),503); await release.getByRole('alert').filter({hasText:'Fixture release rejected'}).waitFor();
    assert.equal(state.sessions.find(value=>value.id===activeBooking.id).state,'ACTIVE');
    await release.getByRole('button',{name:'Release booking',exact:true}).click(); await release.waitFor({state:'hidden'});
    assert.deepEqual(releases().at(-1),{path:releasePath,method:'POST',body:{reason:'UI audited release'}}); assert.equal(state.primary,null); assert.deepEqual(state.pats,beforeReleasePATs);
    await nav(adminPage,'admin-audit'); await adminPage.getByText('Fixture policy reason',{exact:true}).waitFor();
    assert.equal(await adminPage.locator('#audit-list img').count(),0,'audit text must be escaped');
    await adminPage.getByRole('searchbox',{name:'Filter loaded audit events',exact:true}).fill('no-such-event');
    await adminPage.getByText('No loaded events match these filters.',{exact:true}).waitFor();
    await adminPage.getByRole('searchbox',{name:'Filter loaded audit events',exact:true}).fill('Fixture policy reason');
    assert.equal(await adminPage.locator('#audit-list tbody tr').count(),1,'audit filters operate on loaded events');
    await adminPage.getByRole('searchbox',{name:'Filter loaded audit events',exact:true}).fill('');
    await adminPage.setViewportSize({width:390,height:844}); await expectNoOverflow(adminPage,'Mobile administration');
    await adminContext.close();
    // Joining through the catalogue must preselect the holder-approved cluster,
    // not silently open an unrelated automatic booking. The controlling holder
    // keeps the sharing permission when another developer joins or leaves.
    state.registry.set('shared',{id:'shared',name:'Shared fixture',labels:{test:'ui'},max_participants:2});
    state.sharing.set('shared',true);
    state.sessions.push({id:'s-bob-shared',owner:'bob',name:'bob',display_name:'Bob Developer',email:'bob@example.test',cluster:'shared',state:'ACTIVE',created_at:'2026-01-01T00:00:00Z',expires_at:'2099-01-01T00:00:00Z',reason:'fixture'});
    await page.locator('#refresh-pats').click(); await nav(page,'clusters');
    await page.locator('#cluster-list [data-cluster-id="shared"]').getByRole('button',{name:'Join shared cluster',exact:true}).click();
    booking=dialog(page,'Book a cluster'); await booking.waitFor();
    assert.equal(await booking.locator('#booking-cluster').inputValue(),'shared');
    await booking.getByText('Bob Developer',{exact:true}).waitFor();
    await booking.getByRole('button',{name:'Join shared cluster',exact:true}).click(); await booking.waitFor({state:'hidden'});
    const sharedBooking=primary(); assert.equal(sharedBooking.cluster,'shared');
    const sharedRow=page.locator(`#my-bookings [data-session-id="${sharedBooking.id}"]`);
    assert.equal(await sharedRow.getByRole('button',{name:'Allow sharing',exact:true}).count(),0,'a participant cannot control another holder’s sharing');
    state.sharing.set('shared',false); await page.locator('#refresh-overview').click();
    await sharedRow.getByText('Shared · new joins off',{exact:true}).waitFor();
    assert.doesNotMatch(await sharedRow.innerText(),/Exclusive/,'disabling new joins does not make existing shared holders exclusive');
    assert.equal(state.sessions.filter(value=>value.cluster==='shared'&&value.state==='ACTIVE').length,2);
    // A 401 from real typed-API presence can arrive while a confirmation waits.
    // It must cancel that promise, close the native modal and unlock Welcome,
    // without accepting the stale release action or implicitly logging out.
    await sharedRow.getByRole('button',{name:'Release booking',exact:true}).click();
    const staleConfirmation=dialog(page,'Release Shared fixture?'); await staleConfirmation.waitFor();
    const beforeAuthLossSessions=structuredClone(state.sessions), beforeAuthLossPATs=structuredClone(state.pats);
    const destructiveAttempts=()=>state.requests.filter(value=>value.path==='/auth/logout'||/^\/v1\/sessions\/[^/]+\/stop$/.test(value.path));
    const beforeAuthLossDestructive=destructiveAttempts().length;
    state.signedOut=true;
    const rejectedPresence=responseFor(page,response=>new URL(response.url()).pathname==='/v1/activity'&&response.request().method()==='POST'&&response.status()===401);
    await page.keyboard.press('ArrowRight'); await page.clock.runFor(30010);
    assert.equal((await rejectedPresence).status(),401);
    await page.locator('#welcome').waitFor({state:'visible'});
    assert.equal(await page.locator('dialog[open]').count(),0,'authentication loss closes pending confirmations');
    assert.equal(await page.locator('body').evaluate(body=>body.classList.contains('dialog-open')),false,'authentication loss must unlock the sign-in view');
    const loginLink=page.locator('#welcome a[href="/auth/login"]').first(); await loginLink.focus();
    assert.equal(await loginLink.evaluate(node=>node===document.activeElement),true,'Welcome remains interactive after authentication loss');
    assert.equal(destructiveAttempts().length,beforeAuthLossDestructive,'a cancelled stale action must issue no release or logout request');
    assert.deepEqual(state.sessions,beforeAuthLossSessions,'authentication loss alone must not release or alter bookings');
    assert.deepEqual(state.pats,beforeAuthLossPATs,'authentication loss alone must preserve PAT metadata and expiry');
    assert.ok(state.unauthorized.some(value=>value.method==='POST'&&value.path==='/v1/activity'));
    state.signedOut=false; await page.reload({waitUntil:'domcontentloaded'}); await page.locator('#workspace').waitFor();
    await sharedRow.waitFor(); assert.equal(state.primary,sharedBooking.id);
    await sharedRow.getByRole('button',{name:'Release booking',exact:true}).click();
    await dialog(page,'Release Shared fixture?').getByRole('button',{name:'Release booking',exact:true}).click();
    await sharedRow.waitFor({state:'detached'}); assert.equal(state.sessions.find(value=>value.id==='s-bob-shared').state,'ACTIVE');
    assert.equal(state.primary,null,'a departing developer must not inherit another owner’s primary');
    await page.locator('#my-bookings').getByText(/No cluster is booked|No primary selected|No cluster booked/).first().waitFor();
    const beforeLogoutPATs=structuredClone(state.pats), beforeLogoutDeletes=state.mutations.filter(value=>value.method==='DELETE').length;
    await page.getByRole('button',{name:'Sign out',exact:true}).filter({visible:true}).click(); const logout=dialog(page,'Release all bookings and sign out?');
    assert.match(await logout.innerText(),/personal tokens.*remain/i); assert.match(await logout.innerText(),/automatic.booking.*book again/i);
    await logout.getByRole('button',{name:'Release all & sign out',exact:true}).click(); await page.locator('#welcome').waitFor({state:'visible'});
    assert.deepEqual(state.pats,beforeLogoutPATs); assert.equal(state.mutations.filter(value=>value.method==='DELETE').length,beforeLogoutDeletes); assert.equal(state.mutations.at(-1).path,'/auth/logout');
    const afterLogoutActivity=activity().length; await page.clock.runFor(90000); assert.equal(activity().length,afterLogoutActivity);
    assert.equal(state.sessions.filter(value=>value.state==='ACTIVE'&&value.owner==='alice').length,0); assert.equal(state.sessions.find(value=>value.id==='s-bob-shared').state,'ACTIVE','logout must preserve another developer’s booking'); await expectStorageEmpty(page);
    assert.deepEqual(nativeDialogs,[],'product flows must use accessible in-page dialogs'); assert.deepEqual(errors,[]); assert.deepEqual(cspErrors,[]); assert.equal(state.kubernetesRequests,0); assert.deepEqual(externalRequests,[]);
    await context.close();
    console.log('Slate UI contracts passed: strict production CSP, role-aware navigation, bootstrap loading/retry, modal keyboard/focus/Escape/background guards and 401 cancellation, mobile action records, per-primary activity/idle/hidden/throttling, stale-read selection ordering, retry idempotency, token creation/policies/revocation and immutable downloads, admin limits/inheritance, audited registration/maintenance/release/deregistration with validation/busy/error/retry/cancellation/conflict recovery, transient secrets, PAT-preserving logout, escaped text, browser storage and network isolation.');
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error=>{console.error(error.stack);server.close();process.exitCode=1;});
