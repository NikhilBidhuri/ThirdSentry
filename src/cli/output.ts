/**
 * Terminal output helpers. Colour is used only when stdout is a TTY and
 * NO_COLOR is not set. Machine-readable output (--json) bypasses these.
 */

const useColor = (): boolean => process.stdout.isTTY === true && !process.env.NO_COLOR && process.env.TERM !== 'dumb';

function wrap(code: number, close: number): (s: string) => string {
  return (s) => (useColor() ? `\u001b[${code}m${s}\u001b[${close}m` : s);
}

export const color = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
};

export function print(line = ''): void {
  process.stdout.write(`${line}\n`);
}

export function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

export function statusLabel(status: string): string {
  switch (status) {
    case 'complete':
      return color.green('complete');
    case 'partial':
      return color.yellow('PARTIAL');
    case 'failed':
      return color.red('FAILED');
    default:
      return status;
  }
}

export function severityLabel(severity: string): string {
  switch (severity) {
    case 'critical':
      return color.bold(color.red('CRITICAL'));
    case 'high':
      return color.red('HIGH');
    case 'medium':
      return color.yellow('MEDIUM');
    case 'low':
      return color.blue('LOW');
    default:
      return color.gray('INFO');
  }
}

export function truncateMiddle(value: string, max: number): string {
  if (value.length <= max) return value;
  const keep = Math.floor((max - 1) / 2);
  return `${value.slice(0, keep)}…${value.slice(value.length - keep)}`;
}

export function pad(value: string, width: number): string {
  // Strip ANSI codes when measuring.
  // eslint-disable-next-line no-control-regex
  const visible = value.replace(/\u001b\[[0-9;]*m/g, '');
  return visible.length >= width ? value : value + ' '.repeat(width - visible.length);
}
