'use strict';
// Standalone UI contract regression. Uses only local fixture responses; real
// Keycloak, PostgreSQL and Kubernetes gateway behavior have separate Go tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assets = path.resolve(__dirname, '../assets');
const alice = {issuer: 'https://issuer.test', subject: 'alice', name: 'alice', display_name: 'Alice <img src=x onerror=alert(1)>', email: 'alice@example.test', admin: false};
const administrator = {issuer: 'https://issuer.test', subject: 'admin', name: 'admin', display_name: 'Administrator', email: 'admin@example.test', admin: true};
const state = {
  primary: 's-a', version: 1, defaultLimit: 1, override: 2, serial: 0, pats: [], mutations: [], signedOut: false,
  sessions: ['a', 'b'].map(id => ({id: `s-${id}`, owner: 'alice', name: 'alice', display_name: 'Alice Developer', email: alice.email, cluster: id, state: 'ACTIVE', primary: id === 'a', created_at: '2026-01-01T00:00:00Z', reason: 'fixture'})),
};
let origin;
const sessionRows = () => state.sessions.map(s => ({...s, primary: s.id === state.primary}));
const primary = () => sessionRows().find(s => s.id === state.primary && s.state === 'ACTIVE');
const profile = admin => ({owner_id: admin ? 'admin' : 'alice', user: admin ? administrator : alice, max_bookings: admin ? state.defaultLimit : state.override ?? state.defaultLimit, max_bookings_override: admin ? null : state.override, active_bookings: admin ? 0 : state.sessions.filter(s => s.state === 'ACTIVE').length, primary_session: admin ? null : primary(), selection_version: state.version});
const clusters = () => ['a', 'b', 'c'].map(id => ({id, name: `Cluster ${id.toUpperCase()}`, labels: {test: 'ui'}, maintenance: false, controller_session: state.sessions.find(s => s.cluster === id && s.state === 'ACTIVE')?.id, shareable: false, max_participants: 2, participants: sessionRows().filter(s => s.cluster === id && s.state === 'ACTIVE'), available: !state.sessions.some(s => s.cluster === id && s.state === 'ACTIVE'), reason: 'Fixture cluster'}));
function reply(res, status, body) { res.writeHead(status, {'Content-Type': 'application/json'}); res.end(JSON.stringify(body)); }
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, origin || 'http://127.0.0.1');
  const admin = req.headers['x-ui-test-role'] === 'admin';
  try {
    if (req.method === 'GET' && ['/', '/assets/app.js', '/assets/app.css'].includes(url.pathname)) {
      const name = url.pathname === '/' ? 'index.html' : path.basename(url.pathname);
      res.writeHead(200, {'Content-Type': name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html'}); res.end(fs.readFileSync(path.join(assets, name))); return;
    }
    if (req.method === 'GET') {
      if (url.pathname === '/web/session' && state.signedOut && !admin) { reply(res, 401, {error: 'signed out'}); return; }
      const routes = {
        '/web/session': {user: admin ? administrator : alice, owner_id: admin ? 'admin' : 'alice', csrf_token: admin ? 'csrf-admin' : 'csrf-alice', expires_at: '2099-01-01T00:00:00Z'},
        '/v1/profile': profile(admin), '/v1/clusters': clusters(), '/v1/sessions': sessionRows(), '/v1/pats': state.pats,
        '/v1/admin/settings': {default_max_bookings: state.defaultLimit}, '/v1/admin/developers': [profile(false), profile(true)], '/v1/admin/audit': [],
      };
      if (url.pathname.startsWith('/v1/admin/') && !admin) { reply(res, 403, {error: 'administrator required'}); return; }
      if (Object.hasOwn(routes, url.pathname)) { reply(res, 200, routes[url.pathname]); return; }
      reply(res, 404, {error: 'fixture route not found'}); return;
    }
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    assert.equal(req.headers.origin, origin, 'mutation must retain same Origin');
    assert.equal(req.headers['x-csrf-token'], admin ? 'csrf-admin' : 'csrf-alice', 'mutation must send CSRF token');
    state.mutations.push({path: url.pathname, method: req.method, body});
    if (url.pathname === '/auth/logout' && req.method === 'POST') {
      for (const session of state.sessions) if (session.owner === 'alice' && session.state === 'ACTIVE') session.state = 'RELEASED';
      state.primary = null; state.version++; state.signedOut = true;
      reply(res, 200, {status: 'signed out; bookings released; PATs preserved'}); return;
    }
    if (url.pathname === '/v1/primary') {
      const selection = state.sessions.find(s => s.cluster === body.cluster && s.state === 'ACTIVE'); assert.ok(selection);
      state.primary = selection.id; state.version++; reply(res, 200, profile(admin)); return;
    }
    if (/^\/v1\/sessions\/[^/]+\/stop$/.test(url.pathname)) {
      const id = url.pathname.split('/')[3], selected = state.sessions.find(s => s.id === id); assert.ok(selected); selected.state = 'RELEASED';
      if (state.primary === id) { state.primary = state.sessions.find(s => s.state === 'ACTIVE')?.id || null; state.version++; }
      reply(res, 200, {status: 'released'}); return;
    }
    if (url.pathname === '/v1/sessions' && req.method === 'POST') {
      assert.ok(profile(admin).active_bookings < profile(admin).max_bookings); assert.ok(req.headers['idempotency-key']);
      const booked = {id: `s-booked-${++state.serial}`, owner: 'alice', name: 'alice', display_name: 'Alice Developer', cluster: body.cluster || 'c', state: 'ACTIVE', created_at: '2026-01-01T00:00:00Z'};
      state.sessions.push(booked); if (!primary()) {state.primary = booked.id; state.version++;} reply(res, 201, {...booked, primary: booked.id === state.primary}); return;
    }
    if (url.pathname === '/v1/pats' && req.method === 'POST') {
      assert.equal(Object.hasOwn(body, 'session_id'), false, 'personal credential must not select a session');
      const pat = {id: 'p-fixture', owner: 'alice', name: body.name, scope: 'kubernetes:primary', created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z'}; state.pats.push(pat);
      reply(res, 201, {pat, kubeconfig: 'apiVersion: v1\nkind: Config\nclusters:\n- name: gateway\n  cluster:\n    server: https://gateway.example.test/k8s\nusers:\n- name: personal\n  user:\n    token: dcpat_UI_FIXTURE_ONLY\n'}); return;
    }
    if (url.pathname === '/v1/admin/settings' && req.method === 'PATCH' && admin) { assert.ok(body.reason); state.defaultLimit = body.default_max_bookings; reply(res, 200, {status: 'updated'}); return; }
    if (url.pathname === '/v1/admin/developers/alice' && req.method === 'PATCH' && admin) { assert.ok(body.reason); state.override = body.max_bookings; reply(res, 200, {status: 'updated'}); return; }
    reply(res, 404, {error: 'fixture route not implemented'});
  } catch (error) { console.error('UI fixture assertion:', error.message); reply(res, 500, {error: 'UI fixture assertion failed'}); }
});
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); origin = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({headless: true, executablePath: process.env.CHROME_PATH || '/opt/google/chrome/chrome'});
  try {
    const context = await browser.newContext({acceptDownloads: true}); const page = await context.newPage(); const errors = [], dialogs = [];
    page.on('pageerror', error => errors.push(error.message)); page.on('dialog', dialog => { dialogs.push(dialog.message()); return dialog.accept(); });
    await page.goto(origin, {waitUntil: 'domcontentloaded'}); await page.locator('#workspace').waitFor({state: 'visible'});
    await page.locator('#primary-summary h3').filter({hasText: 'Cluster A'}).waitFor();
    assert.equal(await page.locator('#admin-nav').isVisible(), false); assert.equal(await page.locator('#identity img').count(), 0);
    assert.equal(await page.locator('#booking-submit').isDisabled(), true);
    await page.getByRole('button', {name: 'Make primary', exact: true}).click();
    await page.locator('#primary-summary h3').filter({hasText: 'Cluster B'}).waitFor();
    assert.deepEqual(state.mutations.find(r => r.path === '/v1/primary').body, {cluster: 'b'});
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
    await page.getByRole('button', {name: 'Access & tokens', exact: false}).click(); await page.getByRole('cell', {name: 'Follows primary cluster'}).waitFor();
    assert.deepEqual(await page.evaluate(() => ({local: localStorage.length, session: sessionStorage.length})), {local: 0, session: 0});
    await page.setViewportSize({width: 390, height: 844}); assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(errors, []);
    const adminContext = await browser.newContext({extraHTTPHeaders: {'X-UI-Test-Role': 'admin'}}); const adminPage = await adminContext.newPage(); adminPage.on('dialog', dialog => dialog.accept());
    await adminPage.goto(origin, {waitUntil: 'domcontentloaded'}); await adminPage.locator('#workspace').waitFor({state: 'visible'});
    await adminPage.getByRole('button', {name: 'Administration', exact: false}).click(); await adminPage.locator('#developer-list table').waitFor();
    await adminPage.locator('#default-booking-limit').fill('3'); await adminPage.locator('#settings-form input[name=reason]').fill('UI policy test'); await adminPage.locator('#settings-form button').click();
    await adminPage.waitForFunction(() => document.querySelector('#default-booking-limit').value === '3');
    let row = adminPage.locator('#developer-list tbody tr').first(); await row.locator('input[name=max_bookings]').fill('4'); await row.locator('input[name=reason]').fill('UI override test'); await row.getByRole('button', {name: 'Save limit'}).click();
    await adminPage.getByRole('cell', {name: '1 / 4', exact: true}).waitFor();
    row = adminPage.locator('#developer-list tbody tr').first(); await row.locator('input[name=max_bookings]').fill(''); await row.locator('input[name=reason]').fill('UI inherit test'); await row.getByRole('button', {name: 'Save limit'}).click();
    await adminPage.getByRole('cell', {name: '1 / 3', exact: true}).waitFor(); assert.equal(state.mutations.at(-1).body.max_bookings, null);
    assert.equal(state.sessions.filter(s => s.state === 'ACTIVE').length, 1); await adminContext.close();
    const beforeLogoutPATs = structuredClone(state.pats), beforeLogoutDeletes = state.mutations.filter(r => r.method === 'DELETE').length;
    await page.getByRole('button', {name: 'Sign out', exact: true}).click();
    await page.locator('#welcome').waitFor({state: 'visible'});
    assert.ok(dialogs.at(-1).includes('Your PATs will remain valid.'));
    assert.equal(dialogs.at(-1).includes('will be revoked'), false);
    assert.ok((await page.locator('#notification').innerText()).includes('Your PATs remain valid.'));
    assert.deepEqual(state.pats, beforeLogoutPATs, 'sign-out must not revoke or extend PATs');
    assert.equal(state.mutations.filter(r => r.method === 'DELETE').length, beforeLogoutDeletes, 'sign-out must not call PAT revocation');
    assert.equal(state.mutations.at(-1).path, '/auth/logout');
    assert.equal(state.sessions.filter(s => s.state === 'ACTIVE').length, 0);
    assert.deepEqual(errors, []); await context.close();
    console.log('Primary UI contracts passed: limits, selection, promotion, no-booking PAT download, stable config, admin override/reset, logout preserving PATs, CSRF, text escaping, storage and mobile layout.');
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => {console.error(error.stack); server.close(); process.exitCode = 1;});
