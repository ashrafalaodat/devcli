import {useEffect, useRef} from 'react';
import type {ApiClient, Session} from '../types';

interface Selection {session_id: string; selection_version: number}
interface Options {
  session?: Session | null;
  version: number;
  api: ApiClient;
  onActivity: (session: Session, version: number) => void;
  onRejected: () => void;
}

const same = (a: Selection | null, b: Selection | null) => a !== null && b !== null && a.session_id === b.session_id && a.selection_version === b.selection_version;

// One pending send represents actual input. Neither an idle tab nor a completed
// request schedules a new heartbeat without another trusted input event.
export function usePresence({session, version, api, onActivity, onRejected}: Options): void {
  const current = useRef<Selection | null>(null);
  const callbacks = useRef({api, onActivity, onRejected});
  const state = useRef<{pending: Selection | null; timer: ReturnType<typeof setTimeout> | null; sending: boolean; lastSent: number}>({pending: null, timer: null, sending: false, lastSent: 0});
  useEffect(() => {callbacks.current = {api, onActivity, onRejected};}, [api, onActivity, onRejected]);
  useEffect(() => {
    const selected = session?.state === 'ACTIVE' ? {session_id: session.id, selection_version: version} : null;
    if (!same(selected, current.current)) {
      if (state.current.timer !== null) clearTimeout(state.current.timer);
      state.current.timer = null;
      state.current.pending = null;
    }
    current.current = selected;
  }, [session?.id, session?.state, version]);
  useEffect(() => {
    let disposed = false;
    const clear = () => {
      if (state.current.timer !== null) clearTimeout(state.current.timer);
      state.current.timer = null;
      state.current.pending = null;
    };
    const schedule = () => {
      const value = state.current;
      if (disposed || !value.pending || value.sending || value.timer !== null) return;
      value.timer = setTimeout(() => {void send();}, Math.max(0, 30_000 - (Date.now() - value.lastSent)));
    };
    const send = async () => {
      const value = state.current;
      value.timer = null;
      const selected = value.pending;
      value.pending = null;
      if (disposed || document.visibilityState !== 'visible' || !same(selected, current.current) || selected === null) return;
      value.sending = true;
      value.lastSent = Date.now();
      try {
        const updated = await callbacks.current.api<Session>('/v1/activity', {method: 'POST', body: selected});
        if (!disposed && same(selected, current.current)) callbacks.current.onActivity(updated, selected.selection_version);
      } catch {
        if (!disposed && current.current) callbacks.current.onRejected();
      } finally {
        value.sending = false;
        schedule();
      }
    };
    const interacted = (event: Event) => {
      if (!event.isTrusted || document.visibilityState !== 'visible' || current.current === null) return;
      state.current.pending = {...current.current};
      schedule();
    };
    const visibility = () => {if (document.visibilityState !== 'visible') clear();};
    for (const name of ['pointerdown', 'keydown', 'wheel', 'touchstart']) document.addEventListener(name, interacted, {passive: true});
    document.addEventListener('visibilitychange', visibility);
    return () => {
      disposed = true;
      clear();
      for (const name of ['pointerdown', 'keydown', 'wheel', 'touchstart']) document.removeEventListener(name, interacted);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, []);
}
