import {useState} from 'react';
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
  return <button {...props} type={type} className={className} disabled={disabled || pending} onClick={onClick ? () => {
    if (pending || disabled) return;
    setPending(true);
    Promise.resolve().then(onClick).catch(error => notify?.(errorMessage(error), true)).finally(() => setPending(false));
  } : undefined}>{children}</button>;
}

export function Pill({children, tone = 'neutral'}: {children: ReactNode; tone?: string}) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

export function DataTable({headers, rows, emptyText = 'Nothing here yet.'}: {headers: string[]; rows: ReactNode[][]; emptyText?: string}) {
  if (!rows.length) return <div className="empty">{emptyText}</div>;
  return <table><thead><tr>{headers.map((header, index) => <th scope="col" key={`${header}-${index}`}>{header}</th>)}</tr></thead>
    <tbody>{rows.map((cells, row) => <tr key={row}>{cells.map((cell, column) => <td key={column}>{cell ?? '—'}</td>)}</tr>)}</tbody></table>;
}

export function Contact({person}: {person: {display_name?: string; name?: string; email?: string; owner?: string}}) {
  return <div><strong>{person.display_name || person.name || 'Developer'}</strong>{person.email
    ? <><br/><a href={`mailto:${encodeURIComponent(person.email)}`}>{person.email}</a></>
    : <small>{person.name || person.owner?.slice(0, 12)}</small>}</div>;
}

export function date(raw?: string | null): string {
  return raw ? new Date(raw).toLocaleString(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'}) : '—';
}
