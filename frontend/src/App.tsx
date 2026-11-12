import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {Button, Pill, errorMessage} from './components/ui';
import {createApi} from './lib/api';
import {usePresence} from './hooks/usePresence';
import Overview from './pages/Overview';
import Clusters from './pages/Clusters';
import Access from './pages/Access';
import Admin from './pages/Admin';
import type {AuditEvent, BrowserSession, Cluster, DeveloperProfile, Notify, PageProps, PAT, Section, Session, Settings, Workspace} from './types';

function Welcome({hidden}: {hidden: boolean}) {
  return <section id="welcome" className={`welcome${hidden ? ' hidden' : ''}`} aria-labelledby="welcome-title">
    <div className="eyebrow">YOUR TEAM'S DEVELOPMENT CLUSTERS</div><h1 id="welcome-title">A cluster to call your own.</h1>
    <p className="welcome-copy">Book an environment, see who is using it, and get straight to work. Keep your existing kubectl workflow.</p>
    <a className="button primary large" href="/auth/login">Sign in with SSO <span aria-hidden="true">↗</span></a>
    <p className="subtle">Organisation access is experimental. Your administrator controls who can sign in.</p>
    <div className="welcome-options"><article><span className="option-number">01</span><h2>Full CLI</h2><p>Manage bookings, sharing, and administration from your terminal.</p></article>
      <article><span className="option-number">02</span><h2>Browser only</h2><p>Sign in here and download a personal gateway kubeconfig. No extra client to install.</p></article></div>
  </section>;
}

export default function App() {
  const [session, setSession] = useState<BrowserSession | null>(null);
  const [data, setData] = useState<Workspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [section, setSection] = useState<Section>('overview');
  const [notification, setNotification] = useState<{message: string; error: boolean} | null>(null);
  const [booking, setBooking] = useState({cluster: '', version: 0});
  const sessionRef = useRef<BrowserSession | null>(null);
  const generation = useRef(0);
  const refreshing = useRef<Promise<void> | null>(null);
  const notify: Notify = useCallback((message, error = false) => setNotification({message, error}), []);
  const signedOut = useCallback(() => {
    generation.current++;
    sessionRef.current = null;
    setSession(null);
    setData(null);
    setLoading(false);
    setSection('overview');
    setBooking({cluster: '', version: 0});
  }, []);
  const api = useMemo(() => createApi(() => sessionRef.current?.csrf_token, signedOut), [signedOut]);
  const refresh = useCallback(async () => {
    const active = sessionRef.current;
    if (!active) return;
    const epoch = generation.current;
    const previous = refreshing.current;
    const work = (async () => {
      // A mutation must observe a new read, even when an earlier snapshot is
      // still in flight. Queue behind it rather than reusing the old result.
      if (previous) await previous.catch(() => {});
      if (generation.current !== epoch || sessionRef.current !== active) return;
      const base = await Promise.all([
        api<Cluster[]>('/v1/clusters'), api<Session[]>('/v1/sessions'), api<PAT[]>('/v1/pats'), api<DeveloperProfile>('/v1/profile'),
      ]);
      const admin = active.user.admin ? await Promise.all([
        api<PAT[]>('/v1/pats?all=true'), api<AuditEvent[]>('/v1/admin/audit?limit=100'), api<Settings>('/v1/admin/settings'), api<DeveloperProfile[]>('/v1/admin/developers'),
      ]) : null;
      if (generation.current !== epoch || sessionRef.current !== active) return;
      setData({session: active, clusters: base[0] ?? [], sessions: base[1] ?? [], pats: base[2] ?? [], profile: base[3], allPats: admin?.[0] ?? [], audit: admin?.[1] ?? [], settings: admin?.[2] ?? null, developers: admin?.[3] ?? []});
    })();
    refreshing.current = work;
    try {await work;} finally {if (refreshing.current === work) refreshing.current = null;}
  }, [api]);
  useEffect(() => {
    const abort = new AbortController();
    let disposed = false;
    void (async () => {
      try {
        const response = await fetch('/web/session', {credentials: 'same-origin', headers: {Accept: 'application/json'}, signal: abort.signal});
        if (disposed) return;
        if (response.status === 401) {signedOut(); return;}
        if (!response.ok) throw new Error('The backend is unavailable. Reload this page to retry.');
        const active = await response.json() as BrowserSession;
        if (disposed) return;
        sessionRef.current = active;
        setSession(active);
        await refresh();
      } catch (error) {
        if (disposed) return;
        signedOut();
        notify(errorMessage(error), true);
      } finally {if (!disposed) setLoading(false);}
    })();
    return () => {disposed = true; abort.abort();};
  }, [notify, refresh, signedOut]);
  const navigate = useCallback((next: Section) => setSection(next === 'admin' && !sessionRef.current?.user.admin ? 'overview' : next), []);
  const requestBooking = useCallback((cluster: string) => setBooking(previous => ({cluster, version: previous.version + 1})), []);
  const onActivity = useCallback((updated: Session, version: number) => {
    setData(previous => {
      if (!previous || previous.profile.selection_version !== version || previous.profile.primary_session?.id !== updated.id) return previous;
      return {...previous, profile: {...previous.profile, primary_session: {...previous.profile.primary_session, ...updated}}, sessions: previous.sessions.map(value => value.id === updated.id ? {...value, ...updated} : value)};
    });
    // Do not let an older pending snapshot permanently replace this deadline.
    if (refreshing.current) void refresh().catch(() => {});
  }, [refresh]);
  const onPresenceRejected = useCallback(() => {void refresh().catch(() => {});}, [refresh]);
  usePresence({session: data?.profile.primary_session, version: data?.profile.selection_version ?? 0, api, onActivity, onRejected: onPresenceRejected});
  const logout = async () => {
    if (!window.confirm('Sign out and release ALL of your bookings? Your PATs will remain valid. Tokens with automatic booking enabled can reserve again on their next Kubernetes request. Kubernetes workloads will remain.')) return;
    await api('/auth/logout', {method: 'POST'});
    signedOut();
    notify('Signed out. Your bookings were released. Your PATs remain valid. Enabled automatic booking tokens can reserve again on their next Kubernetes request.');
  };
  const pages: PageProps | null = data ? {data, api, refresh, notify, navigate, requestBooking, selectedBookingCluster: booking.cluster, bookingRequestVersion: booking.version} : null;
  const user = session?.user;
  return <>
    <a className="skip-link" href="#main">Skip to content</a>
    <header className="topbar"><a className="brand" href="/" aria-label="devctl home"><span className="brand-icon" aria-hidden="true">›_</span><span>devctl<span className="brand-sub">development environments</span></span></a>
      <div id="identity" className="identity">{user ? <>
        <span className="avatar">{(user.display_name || user.name || '?').slice(0, 1).toUpperCase()}</span>
        <span className="identity-name"><span>{user.display_name || user.name || 'Developer'}</span><small>{user.email || user.name}</small></span>
        <Pill>{user.admin ? 'Administrator' : 'Developer'}</Pill><Button className="button text" onClick={logout} notify={notify}>Sign out</Button>
      </> : loading ? <Pill>Connecting…</Pill> : <a className="button secondary" href="/auth/login">Sign in</a>}</div>
    </header>
    <div id="notification" className={`notification${notification ? notification.error ? ' error' : '' : ' hidden'}`} role="status" aria-live="polite">{notification && <><span>{notification.message}</span><button className="notification-close" aria-label="Dismiss notification" onClick={() => setNotification(null)}>×</button></>}</div>
    <main id="main"><Welcome hidden={loading || session !== null}/>{loading && <p className="panel" role="status">Loading your environments…</p>}
      {pages && <div id="workspace" className="workspace">
        <nav className="sidebar" aria-label="Main navigation"><div className="nav-label">WORKSPACE</div>
          {(['overview', 'clusters', 'access'] as const).map((name, index) => <button key={name} type="button" className={`nav-item${section === name ? ' active' : ''}`} data-section={name} aria-current={section === name ? 'page' : undefined} onClick={() => navigate(name)}><span aria-hidden="true">{['◫', '◇', '⌘'][index]}</span>{['Overview', 'Clusters', 'Access & tokens'][index]}</button>)}
          <div id="admin-nav" className={user?.admin ? '' : 'hidden'}><div className="nav-label">ADMINISTRATION</div><button type="button" className={`nav-item${section === 'admin' ? ' active' : ''}`} data-section="admin" aria-current={section === 'admin' ? 'page' : undefined} onClick={() => navigate('admin')}><span aria-hidden="true">⚙</span>Administration</button></div>
          <div className="sidebar-note"><span className="status-dot" aria-hidden="true"/> Original cluster credentials stay on the server.</div>
        </nav>
        <div className="content"><section id="section-overview" className={`page-section${section === 'overview' ? '' : ' hidden'}`} aria-labelledby="overview-title"><Overview {...pages}/></section>
          <section id="section-clusters" className={`page-section${section === 'clusters' ? '' : ' hidden'}`} aria-labelledby="clusters-title"><Clusters {...pages}/></section>
          <section id="section-access" className={`page-section${section === 'access' ? '' : ' hidden'}`} aria-labelledby="access-title"><Access {...pages}/></section>
          {user?.admin && <section id="section-admin" className={`page-section${section === 'admin' ? '' : ' hidden'}`} aria-labelledby="admin-title"><Admin {...pages}/></section>}
          <footer>devctl <span aria-hidden="true">·</span> Whole-cluster reservations <span aria-hidden="true">·</span> Experimental organisation SSO</footer>
        </div>
      </div>}
    </main>
  </>;
}
