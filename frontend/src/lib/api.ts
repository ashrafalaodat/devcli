import type {ApiClient, ApiOptions} from '../types';

export function createApi(csrfToken: () => string | undefined, onUnauthorized: () => void): ApiClient {
  return async <T>(path: string, options: ApiOptions = {}) => {
    const {body, headers: extraHeaders, ...request} = options;
    const headers = new Headers({Accept: 'application/json', ...extraHeaders});
    for (const name of ['Authorization', 'Proxy-Authorization', 'Cookie', 'X-CSRF-Token']) headers.delete(name);
    const csrf = csrfToken();
    if (csrf) headers.set('X-CSRF-Token', csrf);
    if (body !== undefined) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {...request, credentials: 'same-origin', headers, body: body === undefined ? undefined : JSON.stringify(body)});
    if (response.status === 401) onUnauthorized();
    let result: unknown = null;
    if (response.headers.get('Content-Type')?.includes('application/json')) {
      try {result = await response.json();} catch {
        if (response.ok) throw new Error('Backend returned invalid JSON.');
      }
    }
    if (!response.ok) {
      const message = result && typeof result === 'object' && 'error' in result && typeof result.error === 'string' ? result.error : `Request failed (${response.status}).`;
      throw new Error(message);
    }
    return result as T;
  };
}
