import { useState, type FormEvent } from 'react';
import type { PageProps, PAT } from '../types';
import { Button, date } from '../components/ui';
import { PATTable } from '../components/PATTable';
import { parseLabels } from '../lib/labels';

interface PATCreation {
  pat: PAT;
  kubeconfig: string;
}

function downloadConfig(raw: string, username: string) {
  const filename = `devctl-${username}`.replace(/[^a-zA-Z0-9_.-]/g, '-').slice(0, 80);
  const blob = new Blob([raw], { type: 'application/yaml' });
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = `${filename}.yaml`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(href), 1000);
}

export default function Access({ data, api, refresh, notify }: PageProps) {
  const [name, setName] = useState('Browser kubeconfig');
  const [ttl, setTTL] = useState('8h');
  const [autoBooking, setAutoBooking] = useState(false);
  const [selector, setSelector] = useState('');
  const [busy, setBusy] = useState(false);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      // The one-time credential exists only in this local response and Blob.
      // Never place the response, token or kubeconfig in React/browser storage.
      const issued = await api<PATCreation>('/v1/pats', {
        method: 'POST',
        body: {
          name: name.trim(),
          ttl,
          auto_booking: { enabled: autoBooking, selector: parseLabels(selector, true) },
        },
      });
      try {
        downloadConfig(issued.kubeconfig, data.session.user.name || 'developer');
      } finally {
        issued.kubeconfig = '';
      }
      const expiry = issued.pat.expires_at;
      await refresh();
      notify(`Kubeconfig downloaded. Set its file permissions to 0600. Access expires ${date(expiry)}.`);
    } catch (error) {
      notify(error instanceof Error ? error.message : 'The request could not be completed.', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">CONNECT YOUR TOOLS</div>
          <h1 id="access-title">One backend. Two ways in.</h1>
          <p>
            One stable configuration follows your primary cluster on every device. Book explicitly or enable automatic
            booking on a personal token.
          </p>
        </div>
      </div>
      <div className="access-grid">
        <article className="panel access-card">
          <span className="option-number">01 / FULL CONTROL</span>
          <h2>Developer CLI</h2>
          <p>Book, select, share, and stop environments. Administrator commands are available to approved admins.</p>
          <pre>{'devctl login\ndevctl start\nexport KUBECONFIG="$(devctl setup)"\nkubectl get pods\ndevctl sessions'}</pre>
          <span className="pill neutral">Client installation required</span>
        </article>
        <article className="panel access-card highlighted">
          <span className="option-number">02 / NO EXTRA INSTALLATION</span>
          <h2>Browser kubeconfig</h2>
          <p>Download one personal config. Stock kubectl follows your current primary cluster without installing a helper.</p>
          <pre>{'export KUBECONFIG=/path/to/download.yaml\nkubectl get namespaces'}</pre>
          <span className="pill success">Only kubectl required</span>
        </article>
      </div>
      <section className="panel" aria-labelledby="download-title">
        <h2 id="download-title">Your reusable browser kubeconfig</h2>
        <p>
          This file contains a personal gateway token and works across your primary-cluster changes. You can create it
          before booking. Original cluster credentials stay on the backend.
        </p>
        <form id="pat-form" className="form-grid" onSubmit={create}>
          <label>
            Credential name
            <input
              name="name"
              value={name}
              onChange={event => setName(event.target.value)}
              maxLength={100}
              required
              autoComplete="off"
            />
          </label>
          <label>
            Access duration
            <select name="ttl" value={ttl} onChange={event => setTTL(event.target.value)}>
              <option value="8h">8 hours</option>
              <option value="1h">1 hour</option>
              <option value="24h">1 day</option>
              <option value="168h">7 days</option>
            </select>
          </label>
          <label className="checkbox-field span-two">
            <input
              id="pat-auto-booking"
              name="auto_booking_enabled"
              type="checkbox"
              checked={autoBooking}
              onChange={event => setAutoBooking(event.target.checked)}
            />
            Automatically book when no cluster is selected
          </label>
          <label>
            Automatic booking labels
            <input
              id="pat-selector"
              name="auto_booking_selector"
              placeholder="region=eu,type=test"
              maxLength={10000}
              autoComplete="off"
              value={selector}
              onChange={event => setSelector(event.target.value)}
            />
            <span className="field-help">Optional key=value pairs; blank matches any free cluster.</span>
          </label>
          <p className="field-help span-two">
            Preferences are stored on the backend and can be edited below without replacing this file. Your existing
            primary always wins; labels apply only to the next automatic booking.
          </p>
          <button className="button primary align-start" type="submit" disabled={busy}>
            Download kubeconfig <span aria-hidden="true">↓</span>
          </button>
        </form>
        <p className="callout">
          PATs expire and do not refresh themselves; create a replacement after expiry or revocation. Stopping a booking
          does not revoke this token. Signing out releases your bookings but does not revoke your PATs. A valid token
          with automatic booking enabled can reserve again on its next Kubernetes request. Disable automatic booking or
          revoke the token to prevent this.
        </p>
      </section>
      <div className="section-heading">
        <h2>Your gateway tokens</h2>
        <Button id="refresh-pats" className="button secondary" onClick={refresh} notify={notify}>
          ↻ Refresh
        </Button>
      </div>
      <div id="pat-list" className="panel table-wrap">
        <PATTable pats={data.pats} data={data} api={api} refresh={refresh} notify={notify} />
      </div>
    </>
  );
}
