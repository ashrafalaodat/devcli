export function parseLabels(raw: string, allowEmptyValues = false): Record<string, string> {
  const labels: Record<string, string> = {};
  for (const field of raw.split(',')) {
    const entry = field.trim();
    if (!entry) continue;
    const at = entry.indexOf('=');
    if (at < 1 || (!allowEmptyValues && at === entry.length - 1)) {
      throw new Error('Labels must use comma-separated key=value pairs.');
    }
    const key = entry.slice(0, at).trim();
    const value = entry.slice(at + 1).trim();
    if (!key || (!allowEmptyValues && !value) || Object.hasOwn(labels, key)) {
      throw new Error('Label keys must be nonempty, with no duplicate keys.');
    }
    Object.defineProperty(labels, key, {value, enumerable: true, configurable: true, writable: true});
  }
  return labels;
}

export function formatLabels(labels: Record<string, string>): string {
  return Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}=${value}`).join(',');
}
