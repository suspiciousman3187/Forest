// Demo mode (browser only): open the dev preview with ?demo to populate the main
// screen with a static, curated set of accounts covering every status color — for
// the GitHub example screenshot. Renders at the real 580×900 window size, no chrome.
import type { Account, AccountStatus, Config, LaunchState } from './types';

export const DEMO = typeof location !== 'undefined' && /[?&]demo\b/.test(location.search);

type Row = { profile: string; windower: string; launcher: 'Windower' | 'Ashita'; slot: number; status: LaunchState };

const ROWS: Row[] = [
  { profile: 'Mike',    windower: 'Box 1',           launcher: 'Windower', slot: 1,  status: 'RUNNING' },
  { profile: 'Sarah',   windower: 'sarah.ini',       launcher: 'Ashita',   slot: 2,  status: 'RUNNING' },
  { profile: 'David',   windower: 'Box 3',           launcher: 'Windower', slot: 3,  status: 'LAUNCHING GAME' },
  { profile: 'Emma',    windower: 'emma.ini',        launcher: 'Ashita',   slot: 4,  status: 'LOGGING IN' },
  { profile: 'James',   windower: 'Box 5',           launcher: 'Windower', slot: 5,  status: 'INPUT PASSWORD' },
  { profile: 'Olivia',  windower: 'olivia.ini',      launcher: 'Ashita',   slot: 6,  status: 'SELECT ACCOUNT' },
  { profile: 'Chris',   windower: 'Box 7',           launcher: 'Windower', slot: 7,  status: 'LAUNCH POL' },
  { profile: 'Anna',    windower: 'anna.ini',        launcher: 'Ashita',   slot: 8,  status: 'LAUNCH ASHITA' },
  { profile: 'Daniel',  windower: 'Box 9',           launcher: 'Windower', slot: 9,  status: 'LAUNCH WINDOWER' },
  { profile: 'Kate',    windower: 'Default Profile', launcher: 'Windower', slot: 10, status: 'QUEUED' },
  { profile: 'Rachel',  windower: 'rachel.ini',      launcher: 'Ashita',   slot: 11, status: 'WRONG SE PASSWORD' },
  { profile: 'Tom',     windower: 'Box 12',          launcher: 'Windower', slot: 12, status: 'FAILED' },
  { profile: 'Lucy',    windower: 'lucy.ini',        launcher: 'Ashita',   slot: 14, status: 'INACTIVE' },
];

export const demoAccounts: Account[] = ROWS.map((r) => ({
  profile: r.profile, windower: r.windower, polSlot: r.slot, ingameSlot: 1,
  launcher: r.launcher, launchArgs: '', hasTotp: false,
}));

export const demoStatuses: AccountStatus[] = ROWS.map((r, i) => ({
  profile: r.profile,
  pid: ['INACTIVE', 'TERMINATED', 'QUEUED'].includes(r.status) ? 0 : 30000 + i,
  status: r.status,
}));

// One launchable + one running pre-selected so LAUNCH (green) and TERMINATE (red) both show enabled.
export const demoSelection = new Set<string>(['Lucy', 'Tom', 'Sarah']);

export const demoConfig: Config = {
  windowerExe: 'C:\\Windower\\Windower.exe',
  ashitaExe: 'C:\\Ashita\\ashita-cli.exe',
  treesDir: 'C:\\Forest\\trees',
  defaultLauncher: 'Windower',
  windowerArgs: '-p="{profile}"',
  ashitaArgs: '{profile}',
  staggerSeconds: 8,
  fastSequential: true,
  loginTimeoutSeconds: 120,
  hidePolWindow: true,
  disableAutoLogin: false,
  usePolProxy: true,
  polProxyUpstream: '202.67.54.55',
  launchSelectedOnStartup: false,
  autoLoginCharacter: true,
  autoLoginSettleSeconds: 5,
  autoLoginSendInputFallback: false,
  debugLogging: false,
  selectedAccounts: [],
  accountOrder: ROWS.map((r) => r.profile),
};
