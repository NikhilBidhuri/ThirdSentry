import { randomUUID } from 'node:crypto';

/** Sortable, unique scan ID: <UTC timestamp>-<8 hex chars>. */
export function newScanId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `${stamp}-${randomUUID().slice(0, 8)}`;
}
