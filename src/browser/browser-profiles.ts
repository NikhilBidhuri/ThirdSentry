import { devices, type BrowserContextOptions } from 'playwright';
import type { BrowserProfileName } from '../config/schema.js';

export type EngineName = 'chromium' | 'firefox' | 'webkit';

export interface BrowserProfile {
  readonly name: BrowserProfileName;
  readonly engine: EngineName;
  readonly contextOptions: BrowserContextOptions;
  /** Honest, human-readable description of what is (and is not) emulated. */
  readonly emulation: string;
}

const DESKTOP_VIEWPORT = { width: 1366, height: 900 };

function deviceOptions(name: string): BrowserContextOptions {
  const descriptor = devices[name];
  if (!descriptor) throw new Error(`Playwright device descriptor "${name}" not found`);
  // `defaultBrowserType` is not a context option.
  const { defaultBrowserType: _ignored, ...rest } = descriptor;
  return rest;
}

const PROFILES: Record<BrowserProfileName, BrowserProfile> = {
  'desktop-chromium': {
    name: 'desktop-chromium',
    engine: 'chromium',
    contextOptions: { viewport: DESKTOP_VIEWPORT },
    emulation: 'Playwright Chromium build (headless) with a desktop viewport. Not branded Google Chrome.',
  },
  'desktop-firefox': {
    name: 'desktop-firefox',
    engine: 'firefox',
    contextOptions: { viewport: DESKTOP_VIEWPORT },
    emulation: 'Playwright Firefox build (headless, patched by Playwright) with a desktop viewport.',
  },
  'desktop-webkit': {
    name: 'desktop-webkit',
    engine: 'webkit',
    contextOptions: { viewport: DESKTOP_VIEWPORT },
    emulation:
      'Playwright WebKit build (headless) with a desktop viewport. This is the WebKit engine, not Apple Safari; behaviour can differ from Safari on macOS.',
  },
  'mobile-chromium': {
    name: 'mobile-chromium',
    engine: 'chromium',
    contextOptions: deviceOptions('Pixel 7'),
    emulation:
      'Chromium with Pixel 7 emulation (viewport, device scale factor, touch, mobile user agent). This is emulation on a desktop engine, not a real Android device or Chrome for Android.',
  },
  'mobile-webkit': {
    name: 'mobile-webkit',
    engine: 'webkit',
    contextOptions: deviceOptions('iPhone 15'),
    emulation:
      'Playwright WebKit with iPhone 15 emulation (viewport, touch, iOS Safari user agent). This is NOT a real iOS device or Mobile Safari: sites may serve different scripts to real iOS devices, and iOS-specific APIs and behaviours are not reproduced.',
  },
};

export function getBrowserProfile(name: BrowserProfileName): BrowserProfile {
  return PROFILES[name];
}

export function listBrowserProfiles(): readonly BrowserProfile[] {
  return Object.values(PROFILES);
}
