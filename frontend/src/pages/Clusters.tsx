import type { PageProps } from '../types';
import { Button, Contact, Pill } from '../components/ui';

export default function Clusters({ data, refresh, notify, navigate, requestBooking }: PageProps) {
  const { clusters, profile, session } = data;

  function chooseCluster(id: string) {
    requestBooking(id);
    navigate('overview');
    window.requestAnimationFrame(() => document.getElementById('booking-form')?.scrollIntoView({ behavior: 'smooth', block: 'center' }));
  }

  return <>
    <div className="page-heading">
      <div><div className="eyebrow">CLUSTER REGISTRY</div><h1 id="clusters-title">Find your next environment</h1><p>Availability reflects reservations. Sharing is always controlled by the current holder.</p></div>
      <Button id="refresh-clusters" className="button secondary" onClick={refresh} notify={notify}>↻ Refresh</Button>
    </div>
    <div id="cluster-list" className="cluster-grid">
      {!clusters.length && <div className="empty">No clusters registered. Ask an administrator to register an approved environment.</div>}
      {clusters.map(cluster => {
        const participants = cluster.participants || [];
        const canBook = cluster.available && profile.active_bookings < profile.max_bookings && !participants.some(item => item.owner === session.owner_id);
        return <article className="cluster-card" key={cluster.id} data-cluster-id={cluster.id}>
          <div className="card-top"><div><h3>{cluster.name}</h3><small className="mono">{cluster.id}</small></div><Pill tone={cluster.maintenance ? 'warning' : cluster.available ? 'success' : 'neutral'}>{cluster.maintenance ? 'Maintenance' : cluster.available ? 'Available' : 'Reserved'}</Pill></div>
          <div className="labels">{Object.entries(cluster.labels || {}).map(([key, value]) => <span className="label" key={key}>{key}={value}</span>)}</div>
          <p>{cluster.reason}</p>
          <div className="participants">
            {!participants.length && <span>No active holders.</span>}
            {participants.map(person => <div className="participant" key={person.id}><Contact person={person} /></div>)}
          </div>
          {canBook && <Button className="button secondary" onClick={() => chooseCluster(cluster.id)}>{participants.length ? 'Join shared cluster' : 'Book cluster'}</Button>}
        </article>;
      })}
    </div>
  </>;
}
