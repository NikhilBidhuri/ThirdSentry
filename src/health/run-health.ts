import type { AlertRunResult } from '../alerts/alert-manager.js';
import type { ResolvedConfig } from '../config/loader.js';
import { getLogger } from '../utils/logger.js';
import { loadHealthState, recordAlertDelivery, saveHealthState } from './health-state.js';

/**
 * Remember how alert delivery went (per channel) in the health state, so that
 * `status` and `metrics` can show a channel that keeps failing. Channels that
 * had nothing to send are not counted as a success. Never throws: health
 * bookkeeping must not break alerting.
 */
export async function recordAlertHealth(resolved: ResolvedConfig, result: AlertRunResult, now: Date = new Date()): Promise<void> {
  if (result.test || result.dryRun) return;
  const attempts = result.results.filter((r) => !r.ok || r.selected > 0);
  if (attempts.length === 0) return;
  try {
    const state = await loadHealthState(resolved.paths, { quarantine: true });
    for (const r of attempts) recordAlertDelivery(state, r.channel, r.ok, now, r.error);
    await saveHealthState(resolved.paths, state);
  } catch (error) {
    getLogger('health').warn({ err: error instanceof Error ? error.message : String(error) }, 'could not record alert delivery health');
  }
}
