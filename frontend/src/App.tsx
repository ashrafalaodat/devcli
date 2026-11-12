import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {Button, errorMessage} from './components/ui';
import {ConfirmProvider, useCancelConfirmation, useConfirm} from './components/Dialog';
import {Icon} from './components/Icon';
import {createApi} from './lib/api';
import {usePresence} from './hooks/usePresence';
import Overview from './pages/Overview';
import Clusters from './pages/Clusters';
import Access from './pages/Access';
import Admin from './pages/Admin';
import type {AuditEvent, BrowserSession, Cluster, DeveloperProfile, Notify, PageProps, PAT, Section, Session, Settings, Workspace} from './types';

const navigation: Array<{id: Section; label: string; short: string; icon: string}> = [
  {id: 'overview', label: 'My workspace', short: 'Workspace', icon: 'grid'},
  {id: 'clusters', label: 'Clusters', short: 'Clusters', icon: 'cluster'},
  {id: 'access', label: 'Access & tokens', short: 'Access', icon: 'key'},
  {id: 'admin-clusters', label: 'Cluster registry', short: 'Registry', icon: 'cluster'},
  {id: 'admin-people', label: 'People & policy', short: 'People & policy', icon: 'people'},
  {id: 'admin-tokens', label: 'Organisation tokens', short: 'Tokens', icon: 'key'},
  {id: 'admin-audit', label: 'Audit log', short: 'Audit', icon: 'audit'},
];

function Brand() {
  return <a className="brand" href="/" aria-label="devctl home"><span className="brand-symbol"><Icon name="terminal" size={23}/></span><span>devctl</span><span className="brand-dot" aria-hidden="true"/></a>;
}

function Welcome() {
  return <div id="welcome" className="signin-page">
    <header className="signin-header"><Brand/><span className="meta-count">Experimental organisation SSO</span></header>
    <main id="main" className="signin-main">
      <section className="signin-story" aria-labelledby="welcome-title"><p className="eyebrow">DEVELOPMENT, WITHOUT THE COORDINATION</p><h1 id="welcome-title">A clear path<br/>to your next build.</h1><p>Book a cluster, see who is using it, and get straight to work with your existing kubectl workflow.</p>
        <div className="signin-illustration" aria-hidden="true"><div className="illustration-cluster"><Icon name="cluster" size={35}/><span>Cluster</span></div><span className="illustration-line"/><div className="illustration-primary"><Icon name="check"/><span>Your primary</span></div></div>
        <div className="signin-points"><span><Icon name="lock"/>Exclusive by default</span><span><Icon name="people"/>Share when you choose</span></div>
      </section>
      <section className="signin-form" aria-labelledby="signin-title"><span className="signin-emblem"><Icon name="terminal" size={25}/></span><p className="eyebrow">WELCOME TO DEVCTL</p><h2 id="signin-title">Your workspace is waiting.</h2><p>Sign in with your organisation to reserve an environment and connect your tools.</p><a className="button primary full-width" href="/auth/login">Continue with organisation SSO <Icon name="arrow"/></a><p className="field-help">Your administrator controls who can sign in.</p>
        <ol className="signin-steps"><li><span>01</span><div><strong>Book an environment</strong><p>Choose a cluster or let devctl find a match.</p></div></li><li><span>02</span><div><strong>Connect your tools</strong><p>Use a personal kubeconfig or the full CLI.</p></div></li><li><span>03</span><div><strong>Keep building</strong><p>Activity keeps your selected booking reserved.</p></div></li></ol>
      </section>
    </main><footer className="signin-footer"><span>Whole-cluster reservations</span><span>Original cluster credentials stay on the backend.</span></footer>
  </div>;
}

function WorkspaceApplication() {
  const [session, setSession] = useState<BrowserSession | null>(null);
  const [data, setData] = useState<Workspace | null>(null);
  const [loading, setLoading] = useState(true);
  const [bootstrapError, setBootstrapError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [section, setSection] = useState<Section>('overview');
  const [notification, setNotification] = useState<{message: string; error: boolean} | null>(null);
  const [booking, setBooking] = useState({cluster: '', version: 0});
  const sessionRef = useRef<BrowserSession | null>(null);
  const generation = useRef(0);
  const refreshing = useRef<Promise<void> | null>(null);
  const confirm = useConfirm();
  const cancelConfirmation = useCancelConfirmation();
  const notify: Notify = useCallback((message, error = false) => setNotification({message, error}), []);
  const signedOut = useCallback(() => {
    cancelConfirmation();
    generation.current++;
    sessionRef.current = null;
    setSession(null);
    setData(null);
    setLoading(false);
    setBootstrapError(null);
    setSection('overview');
    setBooking({cluster: '', version: 0});
  }, [cancelConfirmation]);
  const api = useMemo(() => createApi(() => sessionRef.current?.csrf_token, signedOut), [signedOut]);
  const refresh = useCallback(async () => {
    const active = sessionRef.current;
    if (!active) return;
    const epoch = generation.current;
    const previous = refreshing.current;
    const work = (async () => {
      // Every mutation gets a fresh read after earlier snapshots finish.
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
    setLoading(true);
    setBootstrapError(null);
    void (async () => {
      try {
        const response = await fetch('/web/session', {credentials: 'same-origin', headers: {Accept: 'application/json'}, signal: abort.signal});
        if (disposed) return;
        if (response.status === 401) {signedOut(); return;}
        if (!response.ok) throw new Error('We could not reach your workspace. Check your connection and try again.');
        const active = await response.json() as BrowserSession;
        if (disposed) return;
        sessionRef.current = active;
        setSession(active);
        await refresh();
      } catch (error) {
        if (disposed) return;
        signedOut();
        setBootstrapError(errorMessage(error));
      } finally {if (!disposed) setLoading(false);}
    })();
    return () => {disposed = true; abort.abort();};
  }, [attempt, refresh, signedOut]);
  const navigate = useCallback((next: Section) => {
    const allowed = next.startsWith('admin-') && !sessionRef.current?.user.admin ? 'overview' : next;
    setSection(allowed);
    requestAnimationFrame(() => {
      const heading = document.querySelector<HTMLElement>(`#section-${allowed} h1`);
      if (heading) {heading.tabIndex = -1; heading.focus({preventScroll: true});}
      window.scrollTo({top: 0, behavior: 'instant'});
    });
  }, []);
  const requestBooking = useCallback((cluster: string) => {
    setBooking(previous => ({cluster, version: previous.version + 1}));
    setSection('overview');
  }, []);
  const onActivity = useCallback((updated: Session, version: number) => {
    setData(previous => {
      if (!previous || previous.profile.selection_version !== version || previous.profile.primary_session?.id !== updated.id) return previous;
      return {...previous, profile: {...previous.profile, primary_session: {...previous.profile.primary_session, ...updated}}, sessions: previous.sessions.map(value => value.id === updated.id ? {...value, ...updated} : value)};
    });
    if (refreshing.current) void refresh().catch(() => {});
  }, [refresh]);
  const onPresenceRejected = useCallback(() => {void refresh().catch(() => {});}, [refresh]);
  usePresence({session: data?.profile.primary_session, version: data?.profile.selection_version ?? 0, api, onActivity, onRejected: onPresenceRejected});
  const logout = async () => {
    if (!await confirm({title: 'Release all bookings and sign out?', confirmLabel: 'Release all & sign out', danger: true, description: 'This applies to your identity across all browsers, terminals and devices.', children: <><ul className="consequences"><li>All of your bookings will be released.</li><li>Your personal tokens and Kubernetes workloads will remain.</li><li>A PAT with automatic booking enabled can book again on its next Kubernetes request.</li></ul><p className="muted">Revoke tokens separately when you want to remove that access.</p></>})) return;
    await api('/auth/logout', {method: 'POST'});
    signedOut();
    notify('Signed out. Your bookings were released. PATs remain valid; enabled automatic booking can reserve again.');
  };
  const pages: PageProps | null = data ? {data, api, refresh, notify, navigate, requestBooking, selectedBookingCluster: booking.cluster, bookingRequestVersion: booking.version} : null;
  const user = session?.user;
  const name = user?.display_name || user?.name || 'Developer';
  const initials = name.trim().split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase();
  const primary = data?.profile.primary_session;
  const primaryName = data?.clusters.find(cluster => cluster.id === primary?.cluster)?.name || primary?.cluster;
  const adminSection = section.startsWith('admin-');
  const current = navigation.find(item => item.id === section)!;
  const navItem = (item: typeof navigation[number], mobile = false) => <button key={item.id} type="button" className={`${mobile ? 'mobile-nav-item' : 'nav-item'}${section === item.id ? ' active' : ''}`} data-section={item.id} aria-current={section === item.id ? 'page' : undefined} onClick={() => navigate(item.id)}>{!mobile && <Icon name={item.icon}/>}<span>{mobile ? item.short : item.label}</span></button>;
  const identity = (mobile = false) => <div className={mobile ? 'mobile-user' : 'user-menu'} id={mobile ? undefined : 'identity'}><span className="avatar" aria-hidden="true">{initials}</span><span className="identity-name"><strong>{name}</strong><small>{user?.admin ? 'Administrator' : 'Developer'}</small></span><Button className="button icon-button" aria-label="Sign out" title="Sign out" onClick={logout} notify={notify}><Icon name="logout"/></Button></div>;
  return <>
    <a className="skip-link" href="#main">Skip to content</a>
    <div id="notification" className={`notification${notification ? notification.error ? ' error' : '' : ' hidden'}`} role={notification?.error ? 'alert' : 'status'} aria-live="polite">{notification && <><Icon name={notification.error ? 'warning' : 'check'}/><span>{notification.message}</span><button className="button icon-button" aria-label="Dismiss notification" onClick={() => setNotification(null)}><Icon name="close"/></button></>}</div>
    {loading ? <div className="bootstrap"><Brand/><main id="main" role="status" aria-live="polite"><span className="loading-mark" aria-hidden="true"/><h1>Loading your workspace…</h1><p>Connecting to devctl.</p></main></div>
      : bootstrapError ? <div className="bootstrap"><Brand/><main id="main"><section className="panel bootstrap-error" role="alert"><Icon name="warning" size={28}/><h1>Unable to load your workspace</h1><p>{bootstrapError}</p><button className="button primary" onClick={() => setAttempt(value => value + 1)}><Icon name="refresh"/>Retry connection</button></section></main></div>
      : !pages || !user ? <Welcome/>
      : <div id="workspace" className="workspace slate">
        <aside className="sidebar"><Brand/><div className="organisation"><span className="organisation-icon">D</span><span><strong>Developer workspace</strong><small>Team environments</small></span></div><nav aria-label="Main navigation"><p className="nav-label">WORKSPACE</p>{navigation.slice(0, 3).map(item => navItem(item))}
          {user.admin && <div id="admin-nav"><p className="nav-label admin-label">ADMINISTRATION</p>{navigation.slice(3).map(item => navItem(item))}</div>}
        </nav><div className="sidebar-bottom"><p className="sidebar-note"><Icon name="shield"/>Original cluster credentials stay on the backend.</p>{identity()}</div></aside>
        <div className="app-shell"><div className="mobile-app-navigation"><header className="mobile-app-header"><Brand/>{identity(true)}</header><nav className="mobile-product-tabs" aria-label="Mobile workspace navigation">{navigation.slice(0, 3).map(item => navItem(item, true))}</nav>{user.admin && <nav className="mobile-admin-tabs" aria-label="Mobile administration">{navigation.slice(3).map(item => navItem(item, true))}</nav>}</div>
          <header className="utility-bar"><div className="breadcrumb"><Icon name={adminSection ? 'shield' : 'grid'}/><span>{adminSection ? 'Administration' : 'Workspace'}</span><span className="breadcrumb-slash">/</span><strong>{current.label}</strong></div><button className="primary-context" type="button" onClick={() => navigate('overview')} aria-label="View primary cluster and bookings"><span className={`status-dot${primary ? '' : ' inactive'}`}/><span>{primary ? 'Primary' : 'No primary selected'}</span>{primary && <strong>{primaryName}</strong>}<Icon name="down" size={15}/></button></header>
          <main id="main" className="content"><section id="section-overview" className={section === 'overview' ? 'page-section' : 'page-section hidden'} aria-label="My workspace"><Overview {...pages}/></section>
            <section id="section-clusters" className={section === 'clusters' ? 'page-section' : 'page-section hidden'} aria-label="Clusters"><Clusters {...pages}/></section>
            <section id="section-access" className={section === 'access' ? 'page-section' : 'page-section hidden'} aria-label="Access and tokens"><Access {...pages}/></section>
            {user.admin && adminSection && <section id={`section-${section}`} className="page-section" aria-label={current.label}><Admin {...pages} section={section.slice(6) as 'clusters' | 'people' | 'tokens' | 'audit'}/></section>}
          </main><footer className="page-footer"><span>Whole-cluster reservations</span><span>All times UTC · Experimental organisation SSO</span></footer>
        </div>
      </div>}
  </>;
}

export default function App() {
  return <ConfirmProvider><WorkspaceApplication/></ConfirmProvider>;
}
