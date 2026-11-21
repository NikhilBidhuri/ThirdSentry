// Types for demo/site/server.mjs (used by tests/integration/demo.test.ts).

export declare const DEMO_HOSTS: string[];

export type DemoState = 'clean' | 'compromised' | 'snippet-hijack';

export declare const DEMO_STATES: DemoState[];

export declare function demoConfig(port: number): Record<string, unknown> & {
  sites: Array<Record<string, unknown>>;
  security: { network: Record<string, unknown> };
};

export interface DemoServer {
  readonly port: number;
  readonly state: DemoState;
  setState(next: DemoState): void;
  start(listenPort?: number): Promise<number>;
  stop(): Promise<void>;
}

export declare function createDemoServer(): DemoServer;
