import assert from 'node:assert/strict';
import {afterEach, test} from 'node:test';
import {ApiError, createApi} from './api.ts';

const originalFetch = globalThis.fetch;
afterEach(() => {globalThis.fetch = originalFetch;});

test('API failures preserve HTTP status without exposing response details', async () => {
  let rejected = 0;
  globalThis.fetch = async () => Response.json({error: 'Cluster labels changed. Reload before saving.'}, {status: 409});
  const api = createApi(() => 'csrf', () => {rejected++;});
  await assert.rejects(api('/v1/admin/clusters/example', {method: 'PATCH', body: {labels: {}}}), error => error instanceof ApiError && error.status === 409 && error.message === 'Cluster labels changed. Reload before saving.');
  assert.equal(rejected, 0);
  globalThis.fetch = async () => Response.json({error: 'Sign in again.'}, {status: 401});
  await assert.rejects(api('/v1/profile'), error => error instanceof ApiError && error.status === 401 && error.message === 'Sign in again.');
  assert.equal(rejected, 1, 'status-aware errors must still clear rejected authentication');
});

test('API requests use same-origin cookies and only the current session CSRF token', async () => {
  const requests: {input: RequestInfo | URL; init: RequestInit | undefined}[] = [];
  let csrf: string | undefined = 'first-session-csrf';
  globalThis.fetch = async (input, init) => {
    requests.push({input, init});
    return Response.json({status: 'saved'});
  };
  const api = createApi(() => csrf, () => {assert.fail('successful request was unauthorized');});
  const controller = new AbortController();
  const body = {auto_booking: {enabled: true, selector: {region: 'eu'}}};
  const result = await api<{status: string}>('/v1/pats/p-example', {
    method: 'PATCH', body, signal: controller.signal,
    headers: {
      'Idempotency-Key': 'retry-this-action',
      'aUtHoRiZaTiOn': 'Bearer caller-credential',
      'Proxy-Authorization': 'Basic caller-proxy-credential',
      Cookie: 'caller-cookie=credential',
      'x-csrf-token': 'caller-csrf',
      'content-type': 'text/plain',
    },
  });
  assert.deepEqual(result, {status: 'saved'});
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.ok(request?.init);
  assert.equal(request.input, '/v1/pats/p-example');
  assert.equal(request.init.method, 'PATCH');
  assert.equal(request.init.credentials, 'same-origin');
  assert.equal(request.init.signal, controller.signal);
  assert.equal(request.init.body, JSON.stringify(body));
  const headers = new Headers(request.init.headers);
  assert.equal(headers.get('Accept'), 'application/json');
  assert.equal(headers.get('Content-Type'), 'application/json');
  assert.equal(headers.get('Idempotency-Key'), 'retry-this-action');
  assert.equal(headers.get('X-CSRF-Token'), 'first-session-csrf');
  assert.equal(headers.get('Authorization'), null);
  assert.equal(headers.get('Proxy-Authorization'), null);
  assert.equal(headers.get('Cookie'), null);
  assert.equal(headers.get('X-Access-Token'), null);
  assert.equal(headers.get('X-Refresh-Token'), null);

  csrf = 'replacement-session-csrf';
  await api('/v1/profile');
  assert.equal(new Headers(requests[1]?.init?.headers).get('X-CSRF-Token'), 'replacement-session-csrf');
  csrf = undefined;
  await api('/v1/profile', {headers: {'X-CSRF-Token': 'caller-cannot-restore-old-session'}});
  assert.equal(new Headers(requests[2]?.init?.headers).get('X-CSRF-Token'), null);
});

test('GET requests do not manufacture a JSON body or Content-Type', async () => {
  let seen: RequestInit | undefined;
  globalThis.fetch = async (_input, init) => {
    seen = init;
    return Response.json([{id: 'cluster-a'}]);
  };
  const result = await createApi(() => undefined, () => {})<{id: string}[]>('/v1/clusters');
  assert.deepEqual(result, [{id: 'cluster-a'}]);
  assert.ok(seen);
  assert.equal(seen.body, undefined);
  assert.equal(new Headers(seen.headers).get('Content-Type'), null);
  assert.equal(new Headers(seen.headers).get('Authorization'), null);
  assert.equal(seen.credentials, 'same-origin');
});

test('401 invalidates authentication once and keeps the useful API error', async () => {
  let unauthorized = 0;
  globalThis.fetch = async () => Response.json({error: 'browser login expired; sign in again'}, {status: 401});
  const api = createApi(() => 'csrf', () => {unauthorized++;});
  await assert.rejects(api('/v1/profile'), {message: 'browser login expired; sign in again'});
  assert.equal(unauthorized, 1);
});

test('ordinary API errors do not invalidate login or expose unrelated response fields', async () => {
  let unauthorized = 0;
  globalThis.fetch = async () => Response.json({error: 'release active bookings first', refresh_token: 'unexpected-provider-value'}, {status: 409});
  const api = createApi(() => 'csrf', () => {unauthorized++;});
  await assert.rejects(api('/v1/admin/clusters/cluster-a', {method: 'DELETE', body: {reason: 'retired'}}), error => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'release active bookings first');
    assert.equal(error.message.includes('unexpected-provider-value'), false);
    return true;
  });
  assert.equal(unauthorized, 0);
});

test('non-JSON and non-string JSON errors use a bounded HTTP fallback', async () => {
  const api = createApi(() => undefined, () => {});
  globalThis.fetch = async () => new Response('<html>gateway unavailable</html>', {status: 502, headers: {'Content-Type': 'text/html'}});
  await assert.rejects(api('/v1/profile'), {message: 'Request failed (502).'});
  globalThis.fetch = async () => Response.json({error: {untrusted: 'not a message'}}, {status: 503});
  await assert.rejects(api('/v1/profile'), {message: 'Request failed (503).'});
});

test('malformed JSON on 401 still signs out once and uses the HTTP fallback', async () => {
  let unauthorized = 0;
  globalThis.fetch = async () => new Response('{invalid-json', {status: 401, headers: {'Content-Type': 'application/json'}});
  const api = createApi(() => 'csrf', () => {unauthorized++;});
  await assert.rejects(api('/v1/profile'), {message: 'Request failed (401).'});
  assert.equal(unauthorized, 1);
});

test('malformed successful JSON is an actionable error without signing out', async () => {
  let unauthorized = 0;
  globalThis.fetch = async () => new Response('{invalid-json', {headers: {'Content-Type': 'application/json'}});
  const api = createApi(() => 'csrf', () => {unauthorized++;});
  await assert.rejects(api('/v1/profile'), {message: 'Backend returned invalid JSON.'});
  assert.equal(unauthorized, 0);
});

test('an empty successful response returns null and network errors do not sign out', async () => {
  let unauthorized = 0;
  const api = createApi(() => undefined, () => {unauthorized++;});
  globalThis.fetch = async () => new Response(null, {status: 204});
  assert.equal(await api<null>('/v1/example', {method: 'DELETE'}), null);
  globalThis.fetch = async () => {throw new TypeError('Failed to fetch');};
  await assert.rejects(api('/v1/profile'), {message: 'Failed to fetch'});
  assert.equal(unauthorized, 0);
});
