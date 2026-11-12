const shapes: Record<string, string> = {
  grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  cluster: 'm12 3 9 5-9 5-9-5 9-5 M3 12l9 5 9-5 M3 16l9 5 9-5',
  key: 'M12 8a5 5 0 1 1-10 0 5 5 0 0 1 10 0 M11 12l10 9 M16 16l3-3 M13 13l3-3',
  people: 'M12 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0 M3 21v-3a6 6 0 0 1 12 0v3 M16 5a3 3 0 0 1 0 6 M18 14a6 6 0 0 1 3 7',
  audit: 'M8 3H4v18h16V3h-4 M8 2h8v4H8z M8 11h8 M8 16h8',
  arrow: 'M5 12h14 M13 6l6 6-6 6',
  down: 'm6 9 6 6 6-6',
  plus: 'M12 5v14 M5 12h14',
  check: 'm5 12 4 4L19 6',
  search: 'M16 10a6 6 0 1 1-12 0 6 6 0 0 1 12 0 M15 15l6 6',
  clock: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M12 7v5l3 2',
  lock: 'M5 10h14v11H5z M8 10V7a4 4 0 0 1 8 0v3',
  info: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M12 11v6 M12 7h.01',
  shield: 'm12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3 M8 12l3 3 5-5',
  close: 'm6 6 12 12 M6 18 18 6',
  file: 'M14 2H5v20h14V7l-5-5 M14 2v6h5 M8 13h8 M8 17h6',
  more: 'M5 12h.01 M12 12h.01 M19 12h.01',
  refresh: 'M20 7v5h-5 M4 17v-5h5 M5 8a8 8 0 0 1 13-3l2 4 M4 15l2 4a8 8 0 0 0 13-3',
  terminal: 'm4 6 5 6-5 6 M12 18h8',
  upload: 'M12 16V3 M7 8l5-5 5 5 M3 16v5h18v-5',
  logout: 'M9 4H4v16h5 M13 8l4 4-4 4 M8 12h13',
  menu: 'M4 6h16 M4 12h16 M4 18h16',
  settings: 'M4 7h16 M4 17h16 M8 4v6 M16 14v6',
  download: 'M12 3v13 M7 11l5 5 5-5 M3 17v4h18v-4',
  external: 'M14 3h7v7 M10 14 21 3 M10 3H3v18h18v-7',
  warning: 'm12 3 10 18H2L12 3 M12 9v5 M12 17h.01',
};

export function Icon({name, size = 18, className = ''}: {name: string; size?: number; className?: string}) {
  // Dimensions are SVG attributes, so the production CSP needs no inline CSS.
  return <svg className={`icon ${className}`} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false"><path d={shapes[name] ?? shapes.grid}/></svg>;
}
