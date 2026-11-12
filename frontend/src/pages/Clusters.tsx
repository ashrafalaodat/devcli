import {useState} from 'react';
import type {Cluster, PageProps} from '../types';
import {Button, Contact, Pill} from '../components/ui';
import {Icon} from '../components/Icon';
import {useConfirm} from '../components/Dialog';
import {ClusterName, Labels} from './developer-utils';

type Filter = 'all' | 'free' | 'shared' | 'yours' | 'reserved' | 'maintenance';

export default function Clusters({data, api, refresh, notify, navigate, requestBooking}: PageProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [region, setRegion] = useState('');
  const confirm = useConfirm();
  const {clusters, profile, session} = data;
  const blocked = profile.active_bookings >= profile.max_bookings;
  const owns = (cluster: Cluster) => (cluster.participants ?? []).some(item => item.owner === session.owner_id);
  function category(cluster: Cluster): Filter {
    if (cluster.maintenance) return 'maintenance';
    if (owns(cluster)) return 'yours';
    if (cluster.available && !(cluster.participants ?? []).length) return 'free';
    if (cluster.available && cluster.shareable) return 'shared';
    return 'reserved';
  }
  const regions = [...new Set(clusters.map(cluster => cluster.labels?.region).filter(Boolean))].sort();
  const shown = clusters.filter(cluster => {
    const searchable = [cluster.name, cluster.id, ...Object.entries(cluster.labels ?? {}).map(([key, value]) => `${key}=${value}`)].join(' ').toLowerCase();
    return (!query.trim() || searchable.includes(query.trim().toLowerCase())) && (!region || cluster.labels?.region === region) && (filter === 'all' || category(cluster) === filter);
  });
  function chooseCluster(id: string) {requestBooking(id); navigate('overview');}
  async function selectPrimary(cluster: Cluster) {
    if (!await confirm({title: `Use ${cluster.name} as primary?`, description: 'New Kubernetes commands will use this cluster in every terminal and device using your identity.', confirmLabel: 'Switch primary', children: <div className="notice"><Icon name="info"/><p>Open watch, exec and port-forward connections to the previous primary will close. Workloads are not migrated.</p></div>})) return;
    await api('/v1/primary', {method: 'POST', body: {cluster: cluster.id}});
    await refresh();
    notify(`Primary cluster changed to ${cluster.name}. Your kubeconfig stays the same.`);
  }

  return <>
    <div className="page-title page-heading"><div><div className="eyebrow">CLUSTER CATALOGUE</div><h1 id="clusters-title">Find the right place to work.</h1><p>Book an unused cluster exclusively, or join one its holder has made shareable.</p></div><Button id="refresh-clusters" onClick={refresh} notify={notify}><Icon name="refresh"/>Refresh</Button></div>
    <div className="catalogue-stats"><div><strong>{clusters.length}</strong><span>registered clusters</span></div><div><strong>{clusters.filter(cluster => cluster.available && !(cluster.participants ?? []).length && !cluster.maintenance).length}</strong><span>unused clusters</span></div><div><strong>{clusters.reduce((total, cluster) => total + (cluster.shareable && cluster.available && !cluster.maintenance ? Math.max(0, cluster.max_participants - (cluster.participants ?? []).length) : 0), 0)}</strong><span>shared seats available</span></div><div><strong>{profile.active_bookings} / {profile.max_bookings}</strong><span>your bookings</span></div></div>
    {blocked && <div className="notice warning"><Icon name="info"/><p>Your booking limit is reached. Release a booking or ask an administrator to increase your limit before booking another cluster.</p></div>}
    <section id="cluster-list" className="panel flush table-wrap mobile-records">
      <div className="table-toolbar"><label className="search-input"><Icon name="search"/><input aria-label="Search clusters" placeholder="Search name, ID or label" value={query} onChange={event => setQuery(event.target.value)} type="search"/></label><div className="toolbar-actions">{regions.length > 0 && <label className="filter-label">Region<select aria-label="Filter cluster region" value={region} onChange={event => setRegion(event.target.value)}><option value="">All regions</option>{regions.map(value => <option key={value} value={value}>{value}</option>)}</select></label>}<label className="filter-label">Availability<select aria-label="Filter cluster availability" value={filter} onChange={event => setFilter(event.target.value as Filter)}><option value="all">All states</option><option value="free">Free</option><option value="shared">Shareable</option><option value="yours">Yours</option><option value="reserved">Reserved</option><option value="maintenance">Maintenance</option></select></label></div></div>
      {!shown.length ? <div className="empty"><strong>{clusters.length ? 'No clusters match your filters.' : 'No clusters registered.'}</strong><p>{clusters.length ? 'Try a different name, label or availability state.' : 'Ask an administrator to register an approved environment.'}</p>{clusters.length > 0 && <Button onClick={() => {setQuery(''); setFilter('all'); setRegion('');}}>Clear filters</Button>}</div> : <table className="mobile-records"><thead><tr>{['Cluster / labels', 'Availability', 'Current holders', 'Action'].map(header => <th key={header} scope="col">{header}</th>)}</tr></thead><tbody>{shown.map(cluster => {
        const participants = cluster.participants ?? [];
        const owned = owns(cluster);
        const current = profile.primary_session?.cluster === cluster.id;
        const state = category(cluster);
        const canBook = cluster.available && !cluster.maintenance && !owned && !blocked;
        const availableSeats = Math.max(0, cluster.max_participants - participants.length);
        return <tr key={cluster.id} data-cluster-id={cluster.id}><td data-label="Cluster / labels"><ClusterName cluster={cluster}/><Labels cluster={cluster}/></td><td data-label="Availability"><Pill tone={state === 'free' ? 'success' : state === 'shared' || owned ? 'brand' : state === 'maintenance' ? 'warning' : 'neutral'}>{state === 'maintenance' ? 'Maintenance' : owned ? current ? 'Yours · primary' : 'Yours' : state === 'free' ? 'Free' : state === 'shared' ? `Shareable · ${availableSeats} ${availableSeats === 1 ? 'seat' : 'seats'} free` : 'Reserved'}</Pill><small>{state === 'free' ? 'Exclusive when booked' : cluster.reason}</small></td><td data-label="Current holders">{participants.length ? participants.map(holder => <div key={holder.id} className="holder"><Contact person={holder}/>{holder.id === cluster.controller_session && <small className="muted">Controls sharing</small>}</div>) : <span className="muted">No active holders</span>}</td><td data-label="Action"><div className="row-actions">{canBook && <Button className={`button ${participants.length ? 'secondary' : 'primary'}`} onClick={() => chooseCluster(cluster.id)}>{participants.length ? 'Join shared cluster' : 'Book cluster'}</Button>}{owned && !current && <Button onClick={() => selectPrimary(cluster)} notify={notify}>Make primary</Button>}{owned && <Button className="button subtle" onClick={() => navigate('overview')}>View booking</Button>}{!owned && !canBook && <span className="small muted">{blocked && cluster.available && !cluster.maintenance ? 'Your booking limit is reached' : 'Unavailable for booking'}</span>}</div></td></tr>;
      })}</tbody></table>}
      <div className="table-footer"><span>{shown.length} of {clusters.length} clusters</span><span>Filters apply to this view only</span></div>
    </section>
    <div className="notice"><Icon name="info"/><p>Availability shows reservations, not cluster health or available CPU. Existing Kubernetes permissions and workloads are unchanged.</p></div>
    <div className="two-columns compact-panels"><section className="panel"><h3>Exclusive comes first</h3><p>A free cluster is reserved for you. Other developers cannot join unless you enable sharing.</p></section><section className="panel"><h3>Share with context</h3><p>See holder names and contact details, then coordinate directly before sharing an environment.</p></section></div>
  </>;
}
