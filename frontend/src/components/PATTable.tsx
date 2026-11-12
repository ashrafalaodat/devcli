import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import type { PageProps, PAT } from '../types';
import { Button, DataTable, Pill, date } from './ui';
import { formatLabels, parseLabels } from '../lib/labels';

export type PATTableProps = Pick<PageProps, 'data' | 'api' | 'refresh' | 'notify'> & {
  pats: PAT[];
  admin?: boolean;
};

type PATControlProps = Pick<PATTableProps, 'data' | 'api' | 'refresh' | 'notify'> & {
  pat: PAT;
  admin: boolean;
};

function hasEnded(pat: PAT): boolean {
  const expiry = Date.parse(pat.expires_at);
  return Boolean(pat.revoked_at) || !Number.isFinite(expiry) || expiry <= Date.now();
}

function PATState({ pat }: { pat: PAT }) {
  if (pat.revoked_at) return <Pill tone="danger">Revoked</Pill>;
  if (hasEnded(pat)) return <Pill>Expired</Pill>;
  return <Pill tone="success">Active</Pill>;
}

function PATPolicy({ pat, admin, data, api, refresh, notify }: PATControlProps) {
  const policy = pat.auto_booking ?? { enabled: false, selector: {} };
  const savedSelector = formatLabels(policy.selector ?? {});
  const [enabled, setEnabled] = useState(policy.enabled);
  const [selector, setSelector] = useState(savedSelector);
  const [reason, setReason] = useState('');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const foreign = admin && pat.owner !== data.session.owner_id;

  useEffect(() => {
    setEnabled(policy.enabled);
    setSelector(savedSelector);
  }, [policy.enabled, savedSelector]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      const body: {
        auto_booking: { enabled: boolean; selector: Record<string, string> };
        reason?: string;
      } = { auto_booking: { enabled, selector: parseLabels(selector, true) } };
      if (foreign) {
        if (!reason.trim()) throw new Error('An audit reason is required.');
        body.reason = reason.trim();
      }
      await api<PAT>(`/v1/pats/${encodeURIComponent(pat.id)}`, { method: 'PATCH', body });
      await refresh();
      setOpen(false);
      setReason('');
      notify('Automatic booking preferences saved. Existing bookings and your downloaded kubeconfig are unchanged.');
    } catch (error) {
      notify(error instanceof Error ? error.message : 'The request could not be completed.', true);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <span className="pat-policy-summary">
        {policy.enabled ? `Automatic: ${savedSelector || 'Any free cluster'}` : 'Automatic booking disabled'}
      </span>
      {hasEnded(pat) || pat.scope !== 'kubernetes:primary' ? (
        <span className="subtle">Editing unavailable for ended tokens.</span>
      ) : (
        <details
          className="pat-policy-editor"
          data-pat-id={pat.id}
          open={open}
          onToggle={event => setOpen(event.currentTarget.open)}
        >
          <summary>Edit automatic booking</summary>
          <form className="pat-policy-form" onSubmit={save}>
            <label className="checkbox-field">
              <input
                type="checkbox"
                name="enabled"
                checked={enabled}
                onChange={event => setEnabled(event.target.checked)}
              />
              Enable automatic booking
            </label>
            <label>
              Required labels
              <input
                name="selector"
                value={selector}
                onChange={event => setSelector(event.target.value)}
                placeholder="region=eu,type=test"
                maxLength={10000}
                autoComplete="off"
              />
            </label>
            <p className="field-help">
              Blank matches any free cluster. Changes apply to the next automatic booking; your existing primary stays
              selected. The same token and kubeconfig remain valid.
            </p>
            {foreign && (
              <label>
                Audit reason
                <input
                  name="reason"
                  required
                  maxLength={1000}
                  value={reason}
                  onChange={event => setReason(event.target.value)}
                />
              </label>
            )}
            <button className="button secondary small" type="submit" disabled={busy}>
              Save preferences
            </button>
          </form>
        </details>
      )}
    </div>
  );
}

function PATRevoke({ pat, admin, data, api, refresh, notify }: PATControlProps) {
  if (hasEnded(pat)) return <span className="subtle">—</span>;

  async function revoke() {
    let reason = '';
    if (admin && pat.owner !== data.session.owner_id) {
      reason = window.prompt('Audit reason for revoking this developer’s gateway token:') ?? '';
      if (!reason.trim()) return;
    } else if (
      !window.confirm(`Revoke “${pat.name}”? Its downloaded kubeconfig will stop working. Bookings and workloads remain.`)
    ) {
      return;
    }
    await api(`/v1/pats/${encodeURIComponent(pat.id)}`, { method: 'DELETE', body: { reason: reason.trim() } });
    await refresh();
    notify('Personal gateway credential revoked.');
  }

  return (
    <Button className="button danger small" onClick={revoke} notify={notify}>
      Revoke
    </Button>
  );
}

export function PATTable({ pats, admin = false, data, api, refresh, notify }: PATTableProps) {
  const rows: ReactNode[][] = pats.map(pat => {
    const person =
      pat.owner === data.session.owner_id
        ? data.session.user
        : data.developers.find(developer => developer.owner_id === pat.owner)?.user;
    const controls = { pat, admin, data, api, refresh, notify };
    return [
      <div key="credential">
        <strong>{pat.name}</strong>
        <small className="mono">{pat.id}</small>
      </div>,
      <div key="access">
        <span>{person ? person.display_name || person.name : pat.owner.slice(0, 16)}</span>
        <small className="subtle">{pat.scope === 'kubernetes:primary' ? 'Follows primary cluster' : 'Legacy credential'}</small>
      </div>,
      <PATState key="state" pat={pat} />,
      <PATPolicy key={`policy-${pat.id}`} {...controls} />,
      date(pat.expires_at),
      pat.last_used_at ? date(pat.last_used_at) : 'Not yet',
      <PATRevoke key={`revoke-${pat.id}`} {...controls} />,
    ];
  });

  return (
    <DataTable
      headers={['Credential', 'Developer / access', 'State', 'Automatic booking', 'Expires', 'Last used', '']}
      rows={rows}
      emptyText={
        admin
          ? 'No personal gateway tokens have been issued.'
          : 'No personal gateway tokens. Download your reusable kubeconfig above; no booking is required to create it.'
      }
    />
  );
}
