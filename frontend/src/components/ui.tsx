import {useEffect, useRef, useState} from 'react';
import type {ButtonHTMLAttributes, ReactNode} from 'react';
import type {Notify} from '../types';

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The request could not be completed.';
}

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onClick'> {
  onClick?: () => void | Promise<unknown>;
  notify?: Notify;
}

export function Button({onClick, notify, disabled, className = 'button secondary', type = 'button', children, ...props}: ButtonProps) {
  const [pending, setPending] = useState(false);
  const running = useRef(false);
  return <button {...props} type={type} className={className} disabled={disabled || pending} aria-busy={pending || undefined} onClick={onClick ? event => {
    if (running.current || disabled) return;
    const trigger = event.currentTarget;
    const heldFocus = document.activeElement === trigger;
    running.current = true;
    let result: void | Promise<unknown>;
    try {result = onClick();} catch (error) {
      running.current = false;
      notify?.(errorMessage(error), true);
      return;
    }
    if (!result || typeof result.then !== 'function') {running.current = false; return;}
    setPending(true);
    Promise.resolve(result).catch(error => notify?.(errorMessage(error), true)).finally(() => {
      running.current = false;
      setPending(false);
      requestAnimationFrame(() => {
        // Disabling a pending trigger can move focus to the body before the
        // confirmation opens. Restore only that lost focus, never another form.
        if (!heldFocus || document.querySelector('dialog[open]') || ![document.body, document.documentElement].includes(document.activeElement as HTMLElement)) return;
        if (trigger.isConnected && !trigger.disabled && trigger.getClientRects().length) trigger.focus({preventScroll: true});
        else [...document.querySelectorAll<HTMLElement>('main h1')].find(heading => heading.getClientRects().length)?.focus({preventScroll: true});
      });
    });
  } : undefined}>{children}</button>;
}

export function Pill({children, tone = 'neutral'}: {children: ReactNode; tone?: string}) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

export function DataTable({headers, rows, emptyText = 'Nothing here yet.', className = '', caption}: {headers: string[]; rows: ReactNode[][]; emptyText?: string; className?: string; caption?: string}) {
  if (!rows.length) return <div className="empty">{emptyText}</div>;
  return <table className={`data-table mobile-records ${className}`}>{caption && <caption className="sr-only">{caption}</caption>}<thead><tr>{headers.map((header, index) => <th scope="col" key={`${header}-${index}`}>{header || 'Actions'}</th>)}</tr></thead>
    <tbody>{rows.map((cells, row) => <tr key={row}>{cells.map((cell, column) => <td key={column} data-label={headers[column] || 'Actions'}>{cell ?? '—'}</td>)}</tr>)}</tbody></table>;
}

export function Contact({person}: {person: {display_name?: string; name?: string; email?: string; owner?: string}}) {
  const name = person.display_name || person.name || 'Developer';
  return <div className="person"><span className="avatar" aria-hidden="true">{name.trim().split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase()}</span><span><strong>{name}</strong>{person.email
    ? <a className="contact-email" href={`mailto:${encodeURIComponent(person.email)}`}>{person.email}</a>
    : <small>{person.name || person.owner?.slice(0, 12)}</small>}</span></div>;
}

export function date(raw?: string | null): string {
  const parsed = raw ? new Date(raw) : null;
  return parsed && Number.isFinite(parsed.getTime()) ? `${parsed.toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC', hour12: false})} UTC` : '—';
}

export function FormError({message, fields = []}: {message?: string | null; fields?: Array<{id: string; message: string}>}) {
  const summary = useRef<HTMLDivElement>(null);
  useEffect(() => {if (message || fields.length) summary.current?.focus();}, [message, fields.length]);
  if (!message && !fields.length) return null;
  return <div className="form-error" role="alert" tabIndex={-1} ref={summary}><strong>{fields.length ? 'Check the form' : 'The request could not be completed'}</strong>{message && <p>{message}</p>}{fields.length > 0 && <ul>{fields.map(field => <li key={field.id}><a href={`#${field.id}`} onClick={event => {event.preventDefault(); document.getElementById(field.id)?.focus();}}>{field.message}</a></li>)}</ul>}</div>;
}
