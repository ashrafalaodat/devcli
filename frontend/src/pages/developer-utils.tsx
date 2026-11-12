import type {Cluster} from '../types';
import {Icon} from '../components/Icon';

export function timestamp(raw?: string | null): string {
  if (!raw || !Number.isFinite(Date.parse(raw))) return '—';
  return `${new Date(raw).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', hour12: false})} UTC`;
}

export function relative(raw?: string | null, future = false): string {
  if (!raw || !Number.isFinite(Date.parse(raw))) return 'No activity yet';
  const seconds = Math.round((Date.parse(raw) - Date.now()) / 1000);
  if (future && seconds <= 0) return 'Deadline reached';
  const minutes = Math.floor(Math.abs(seconds) / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  const value = days ? `${days}d ${hours % 24}h` : hours ? `${hours}h ${minutes % 60}m` : minutes ? `${minutes} min` : 'a moment';
  return seconds > 0 ? `In ${value}` : `${value} ago`;
}

export function Labels({cluster}: {cluster?: Cluster}) {
  return <div className="tags">{Object.entries(cluster?.labels ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => <span className="tag mono" key={key}>{key}={value}</span>)}</div>;
}

export function ClusterName({cluster, fallback}: {cluster?: Cluster; fallback?: string}) {
  return <div className="cluster-name"><Icon name="cluster"/><span><strong>{cluster?.name || fallback || 'Cluster'}</strong><small className="mono">{cluster?.id || fallback}</small></span></div>;
}

export function allocation(cluster?: Cluster): string {
  const holders = cluster?.participants?.length ?? 0;
  if (holders > 1) return cluster?.shareable ? 'Shared' : 'Shared · new joins off';
  return cluster?.shareable ? 'Shareable' : 'Exclusive';
}
