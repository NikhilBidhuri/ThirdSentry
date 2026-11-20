/** Alert channel names (shared by the alert publisher and the finding state). */
export type ChannelName = 'slack' | 'webhook' | 'github' | 'email';
export const CHANNELS: readonly ChannelName[] = ['slack', 'webhook', 'github', 'email'];
