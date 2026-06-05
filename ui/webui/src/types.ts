// Mirrors Forest's Core data model (Config / CredentialStore.Account / launch status).
// Kept in lockstep with the C# bridge handlers.

export type Launcher = 'Default' | 'Windower' | 'Ashita';

export interface Account {
  profile: string;     // account name (unique key)
  windower: string;    // Windower profile name OR Ashita boot .ini
  polSlot: number;     // POL member-list slot 1-20, 0 = unset (manual)
  ingameSlot: number;  // FFXI character slot 1-16, 0 = first
  launcher: Launcher;  // per-account launcher, 'Default' falls back to config
  launchArgs: string;  // custom args, '' = use launcher default template
  hasTotp: boolean;    // whether a TOTP secret is stored (the secret itself never crosses the bridge)
}

// Friendly launch states shown on the account row.
// 'LOGIN COMPLETE' is splash-only: the AutoLaunchSplash component substitutes
// it for the underlying RUNNING state when all watched accounts are fully in
// game, during the auto-quit settle countdown. Backend never sets it.
export type LaunchState =
  | 'INACTIVE' | 'QUEUED'
  | 'LAUNCH WINDOWER' | 'LAUNCH ASHITA' | 'LAUNCH POL' | 'SELECT ACCOUNT'
  | 'INPUT PASSWORD' | 'LOGGING IN' | 'LAUNCHING GAME'
  | 'RUNNING' | 'DONE' | 'LOGIN COMPLETE'
  | 'FAILED' | 'WRONG SE PASSWORD' | 'LOGIN STUCK' | 'TIMEOUT' | 'TERMINATED'
  | 'DISCONNECTED';

export interface AccountStatus {
  profile: string;
  pid: number;          // pol.exe pid, 0 = none
  status: LaunchState;
}

export interface Config {
  windowerExe: string;
  ashitaExe: string;
  treesDir: string;
  defaultLauncher: 'Windower' | 'Ashita';
  windowerArgs: string;
  ashitaArgs: string;
  staggerSeconds: number;
  fastSequential: boolean;
  loginTimeoutSeconds: number;
  hidePolWindow: boolean;
  disableAutoLogin: boolean;
  usePolProxy: boolean;
  polProxyUpstream: string;
  launchSelectedOnStartup: boolean;
  autoLoginCharacter: boolean;
  autoLoginSettleSeconds: number;
  autoLoginSendInputFallback: boolean;
  waitForFFXiRegistryReadBetweenLaunches: boolean;
  waitForFFXiRegistryReadTimeoutSeconds: number;
  overrideFFXiResolution: boolean;
  launchMode: 'Full' | 'Splash';
  debugLogging: boolean;
  selectedAccounts: string[];
  accountOrder: string[];
}

// Payload for creating/updating an account. `password`/`totpSecret` are write-only
// (sent to C# to DPAPI-encrypt); omit/blank on edit to keep the existing value.
export interface AccountSave {
  profile: string;
  originalProfile?: string; // set when renaming
  windower: string;
  polSlot: number;
  ingameSlot: number;
  launcher: Launcher;
  launchArgs: string;
  password?: string;
  totpSecret?: string;
}

export interface StaleProc {
  pid: number;
  profile: string;
  slot: number;
}
