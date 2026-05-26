// C# <-> JS bridge over WebView2 postMessage.
//
//   JS -> C#:  postMessage({ kind:'req', id, method, params })
//   C# -> JS:  message  { kind:'res', id, ok, result|error }   (reply to a req)
//              message  { kind:'evt', event, data }            (push, e.g. status)
//
// In a plain browser (dev preview, no WebView2) every call is served by an
// in-memory MOCK so the whole UI is usable without the C# host.

import type { Account, AccountSave, AccountStatus, Config, StaleProc } from './types';
import { DEMO, demoAccounts, demoConfig, demoStatuses } from './demo';

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void };

const wv = (window as unknown as { chrome?: { webview?: any } }).chrome?.webview;
export const inWebView2 = !!wv;

const pending = new Map<number, Pending>();
const subs = new Map<string, Set<(d: any) => void>>();
let nextId = 1;

if (wv) {
  wv.addEventListener('message', (ev: { data: unknown }) => {
    const m = typeof ev.data === 'string' ? JSON.parse(ev.data) : (ev.data as any);
    if (m.kind === 'res') {
      const p = pending.get(m.id);
      if (!p) return;
      pending.delete(m.id);
      m.ok ? p.resolve(m.result) : p.reject(new Error(m.error || 'bridge error'));
    } else if (m.kind === 'evt') {
      subs.get(m.event)?.forEach((h) => h(m.data));
    }
  });
}

export function call<T = unknown>(method: string, params?: unknown): Promise<T> {
  if (!wv) return mockCall<T>(method, params);
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    wv.postMessage(JSON.stringify({ kind: 'req', id, method, params: params ?? null }));
  });
}

export function subscribe(event: string, handler: (data: any) => void): () => void {
  let set = subs.get(event);
  if (!set) { set = new Set(); subs.set(event, set); }
  set.add(handler);
  // mock: drive a fake status stream so the preview shows live updates (static in demo)
  if (!wv && !DEMO && event === 'status') mockStatusStream();
  return () => { set!.delete(handler); };
}

function emit(event: string, data: unknown) { subs.get(event)?.forEach((h) => h(data)); }

// ── Typed convenience wrappers used by the views ──────────────────────────────
export const api = {
  getConfig:        () => call<Config>('config.get'),
  setConfig:        (patch: Partial<Config>) => call<void>('config.set', patch),
  listAccounts:     () => call<Account[]>('accounts.list'),
  saveAccount:      (a: AccountSave) => call<void>('accounts.save', a),
  removeAccount:    (profile: string) => call<void>('accounts.remove', { profile }),
  reorder:          (order: string[]) => call<void>('accounts.reorder', { order }),
  statusAll:        () => call<AccountStatus[]>('status.all'),
  launch:           (profiles: string[]) => call<void>('launch', { profiles }),
  terminate:        (profiles: string[]) => call<void>('terminate', { profiles }),
  browse:           (kind: 'file' | 'dir', filter?: string) => call<string>('browse', { kind, filter }),
  exportDiag:       () => call<string>('diagnostics.export'),
  openLogs:         () => call<void>('logs.open'),
  proxyRunning:     () => call<boolean>('polproxy.status'),
  scanStale:        () => call<StaleProc[]>('cleanup.scan'),
  killStale:        (pids: number[]) => call<void>('cleanup.kill', { pids }),
  openExternal:     (url: string) => call<void>('open.external', { url }),
  window:           (action: 'minimize' | 'maximize' | 'close' | 'drag') => call<void>('window.' + action),
  setAlwaysOnTop:   (on: boolean) => call<void>('window.alwaysOnTop', { on }),
};

// ══ MOCK (browser dev only) ═══════════════════════════════════════════════════
const mockConfig: Config = {
  windowerExe: 'C:\\Program Files (x86)\\Windower\\Windower.exe',
  ashitaExe: '',
  treesDir: 'C:\\Forest\\trees',
  defaultLauncher: 'Windower',
  windowerArgs: '-p="{profile}"',
  ashitaArgs: '{profile}',
  staggerSeconds: 8,
  fastSequential: false,
  loginTimeoutSeconds: 120,
  hidePolWindow: true,
  disableAutoLogin: false,
  usePolProxy: false,
  polProxyUpstream: '202.67.54.55',
  launchSelectedOnStartup: false,
  autoLoginCharacter: true,
  autoLoginSettleSeconds: 5,
  autoLoginSendInputFallback: false,
  debugLogging: false,
  selectedAccounts: [],
  accountOrder: ['Tank', 'Healer', 'Shinchan'],
};

let mockAccounts: Account[] = [
  { profile: 'Tank',     windower: 'Box',  polSlot: 1, ingameSlot: 1, launcher: 'Windower', launchArgs: '', hasTotp: false },
  { profile: 'Healer',   windower: 'Box',  polSlot: 2, ingameSlot: 1, launcher: 'Windower', launchArgs: '', hasTotp: false },
  { profile: 'Shinchan', windower: 'Main', polSlot: 3, ingameSlot: 1, launcher: 'Ashita',   launchArgs: '', hasTotp: true },
];
const mockStatus = new Map<string, AccountStatus>(
  mockAccounts.map((a) => [a.profile, { profile: a.profile, pid: 0, status: 'INACTIVE' as const }]),
);

let streaming = false;
function mockStatusStream() {
  if (streaming) return;
  streaming = true;
  setInterval(() => emit('status', [...mockStatus.values()]), 1000);
}

function mockCall<T>(method: string, params?: unknown): Promise<T> {
  const p = params as any;
  const delay = (v: unknown) => new Promise<T>((r) => setTimeout(() => r(v as T), 120));
  if (DEMO) {
    switch (method) {
      case 'config.get': return delay({ ...demoConfig });
      case 'accounts.list': return delay(demoAccounts.map((a) => ({ ...a })));
      case 'status.all': return delay(demoStatuses.map((s) => ({ ...s })));
      case 'polproxy.status': return delay(demoConfig.usePolProxy);
      default: return delay(undefined);
    }
  }
  switch (method) {
    case 'config.get': return delay({ ...mockConfig });
    case 'config.set': Object.assign(mockConfig, p); return delay(undefined);
    case 'accounts.list': return delay(mockAccounts.map((a) => ({ ...a })));
    case 'accounts.save': {
      const a = p as AccountSave;
      const key = a.originalProfile ?? a.profile;
      const idx = mockAccounts.findIndex((x) => x.profile === key);
      const next: Account = { profile: a.profile, windower: a.windower, polSlot: a.polSlot, ingameSlot: a.ingameSlot, launcher: a.launcher, launchArgs: a.launchArgs, hasTotp: !!a.totpSecret };
      if (idx >= 0) mockAccounts[idx] = next; else mockAccounts.push(next);
      if (!mockStatus.has(a.profile)) mockStatus.set(a.profile, { profile: a.profile, pid: 0, status: 'INACTIVE' });
      return delay(undefined);
    }
    case 'accounts.remove': mockAccounts = mockAccounts.filter((x) => x.profile !== p.profile); mockStatus.delete(p.profile); return delay(undefined);
    case 'accounts.reorder': { const order: string[] = p.order; mockAccounts.sort((a, b) => order.indexOf(a.profile) - order.indexOf(b.profile)); return delay(undefined); }
    case 'status.all': return delay([...mockStatus.values()]);
    case 'launch': { (p.profiles as string[]).forEach((pf) => mockRunSim(pf)); return delay(undefined); }
    case 'terminate': { (p.profiles as string[]).forEach((pf) => mockStatus.set(pf, { profile: pf, pid: 0, status: 'TERMINATED' })); emit('status', [...mockStatus.values()]); return delay(undefined); }
    case 'browse': return delay('C:\\Mock\\Selected\\Path');
    case 'diagnostics.export': return delay('C:\\Users\\you\\Desktop\\Forest-Diagnostics-mock.zip');
    case 'logs.open': return delay(undefined);
    case 'polproxy.status': return delay(mockConfig.usePolProxy);
    case 'cleanup.scan': return delay([]);
    case 'cleanup.kill': return delay(undefined);
    case 'open.external': try { window.open(p.url, '_blank', 'noopener'); } catch { /* ignore */ } return delay(undefined);
    default:
      if (method.startsWith('window.')) { console.log('[mock] window action', method); return delay(undefined); }
      console.warn('[mock] unhandled method', method, params);
      return delay(undefined);
  }
}

// Fake the launch state machine for the preview.
function mockRunSim(profile: string) {
  const steps: AccountStatus['status'][] = ['QUEUED', 'LAUNCH WINDOWER', 'LAUNCH POL', 'SELECT ACCOUNT', 'INPUT PASSWORD', 'LOGGING IN', 'LAUNCHING GAME', 'RUNNING'];
  let i = 0;
  mockStatusStream();
  const pid = 10000 + Math.floor(Math.random() * 50000);
  const tick = () => {
    if (i >= steps.length) return;
    mockStatus.set(profile, { profile, pid: steps[i] === 'QUEUED' ? 0 : pid, status: steps[i] });
    emit('status', [...mockStatus.values()]);
    i++;
    if (i < steps.length) setTimeout(tick, 900);
  };
  tick();
}
