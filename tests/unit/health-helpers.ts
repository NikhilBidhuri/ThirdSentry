import type { FindingState } from '../../src/monitoring/dedup-state.js';

export function emptyFindingStateForTests(): FindingState {
  return { version: 2, findings: {} };
}
