import {createContext, useCallback, useContext, useEffect, useId, useRef, useState} from 'react';
import type {ReactNode} from 'react';
import {createPortal} from 'react-dom';
import {Icon} from './Icon';

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  id?: string;
  className?: string;
  busy?: boolean;
  returnFocus?: HTMLElement | null;
}

// Native modal dialogs make the rest of the document inert. Explicit focus
// handling also keeps the trigger usable when a drawer is closed or rerendered.
export function Dialog({open, onClose, title, description, children, footer, id, className = '', busy = false, returnFocus}: DialogProps) {
  const generated = useId();
  const titleID = `${id ?? generated}-title`;
  const descriptionID = `${id ?? generated}-description`;
  const element = useRef<HTMLDialogElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const closeRef = useRef(onClose);
  const busyRef = useRef(busy);
  closeRef.current = onClose;
  busyRef.current = busy;
  useEffect(() => {
    const dialog = element.current;
    if (!dialog || !open) return;
    const trigger = returnFocus ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null);
    document.body.classList.add('dialog-open');
    if (!dialog.open) dialog.showModal();
    heading.current?.focus({preventScroll: true});
    const keyboard = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return;
      const controls = [...dialog.querySelectorAll<HTMLElement>('a[href],button:not(:disabled),input:not(:disabled):not([type=hidden]),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]')].filter(control => control.getClientRects().length > 0 && !control.closest('[hidden],.hidden'));
      const first = controls[0], last = controls.at(-1);
      if (!first) {event.preventDefault(); heading.current?.focus(); return;}
      if (event.shiftKey && (document.activeElement === first || !controls.includes(document.activeElement as HTMLElement))) {event.preventDefault(); last?.focus();}
      else if (!event.shiftKey && (document.activeElement === last || !controls.includes(document.activeElement as HTMLElement))) {event.preventDefault(); first.focus();}
    };
    dialog.addEventListener('keydown', keyboard);
    return () => {
      dialog.removeEventListener('keydown', keyboard);
      if (dialog.open) dialog.close();
      if (!document.querySelector('dialog[open]')) document.body.classList.remove('dialog-open');
      requestAnimationFrame(() => {
        if (document.querySelector('dialog[open]')) return;
        if (trigger?.isConnected && trigger.getClientRects().length && !trigger.matches(':disabled') && !trigger.closest('[inert], [hidden], .hidden')) trigger.focus({preventScroll: true});
        else if ([document.body, document.documentElement].includes(document.activeElement as HTMLElement)) {
          const heading = [...document.querySelectorAll<HTMLElement>('main h1')].find(value => value.getClientRects().length);
          if (heading) {heading.tabIndex = -1; heading.focus({preventScroll: true});}
        }
      });
    };
  }, [open]);
  if (!open) return null;
  return createPortal(<dialog ref={element} id={id} className={`dialog drawer ${className}`} aria-modal="true" aria-labelledby={titleID} aria-describedby={description ? descriptionID : undefined} aria-busy={busy || undefined} onCancel={event => {
    event.preventDefault();
    if (!busyRef.current) closeRef.current();
  }}>
    <header className="drawer-heading"><div><p className="eyebrow">DEVCTL</p><h2 ref={heading} id={titleID} tabIndex={-1}>{title}</h2>{description && <div className="dialog-description" id={descriptionID}>{description}</div>}</div>
      <button type="button" className="button icon-button" aria-label={`Close ${title}`} disabled={busy} onClick={onClose}><Icon name="close"/></button>
    </header>
    <div className="drawer-content">{children}</div>
    {footer && <footer className="drawer-footer">{footer}</footer>}
  </dialog>, document.body);
}

export interface ConfirmOptions {
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  children?: ReactNode;
}
type Ask = (options: ConfirmOptions) => Promise<boolean>;
const Confirmation = createContext<{ask: Ask; cancel: () => void} | null>(null);

export function useConfirm(): Ask {
  const value = useContext(Confirmation);
  if (!value) throw new Error('Confirmation provider is missing.');
  return value.ask;
}

export function useCancelConfirmation(): () => void {
  const value = useContext(Confirmation);
  if (!value) throw new Error('Confirmation provider is missing.');
  return value.cancel;
}

export function ConfirmProvider({children}: {children: ReactNode}) {
  const [options, setOptions] = useState<ConfirmOptions | null>(null);
  const resolve = useRef<((accepted: boolean) => void) | null>(null);
  const focusTrigger = useRef<HTMLElement | null>(null);
  const ask = useCallback<Ask>(options => new Promise<boolean>(done => {
    // A second caller cannot strand the first action waiting for an answer.
    resolve.current?.(false);
    focusTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    resolve.current = done;
    setOptions(options);
  }), []);
  const finish = useCallback((accepted: boolean) => {
    const pending = resolve.current;
    resolve.current = null;
    setOptions(null);
    pending?.(accepted);
  }, []);
  const cancel = useCallback(() => finish(false), [finish]);
  useEffect(() => () => {resolve.current?.(false); resolve.current = null;}, []);
  return <Confirmation value={{ask, cancel}}>{children}<Dialog open={options !== null} onClose={cancel} title={options?.title ?? 'Confirm action'} description={options?.description} returnFocus={focusTrigger.current} className="confirmation-dialog" footer={<>
    <button type="button" className="button secondary" onClick={() => finish(false)}>{options?.cancelLabel ?? 'Cancel'}</button>
    <button type="button" className={`button ${options?.danger ? 'danger' : 'primary'}`} onClick={() => finish(true)}>{options?.confirmLabel ?? 'Confirm'}</button>
  </>}>{options?.children}</Dialog></Confirmation>;
}
