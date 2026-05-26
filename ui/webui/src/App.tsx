import { useCallback, useEffect, useState, type ReactNode } from 'react';
import TitleBar from './TitleBar';
import Home from './views/Home';
import Settings from './views/Settings';
import { Tip } from './ui';
import { api, subscribe } from './bridge';
import { syncScrollbarFromVar } from './scrollbar';
import { useTheme } from './theme';
import { DEMO, demoSelection } from './demo';
import type { Account, AccountStatus, Config } from './types';

const VERSION = '1.2.0';
type Tab = 'home' | 'settings';

export default function App() {
  const [tab, setTab] = useState<Tab>('home');
  const [theme] = useTheme();
  const [config, setConfigState] = useState<Config | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [statuses, setStatuses] = useState<Record<string, AccountStatus>>({});
  const [selected, setSelected] = useState<Set<string>>(() => DEMO ? new Set(demoSelection) : new Set());

  useEffect(() => { syncScrollbarFromVar(); }, [theme]);

  const refreshAccounts = useCallback(async () => { setAccounts(await api.listAccounts()); }, []);

  useEffect(() => {
    api.getConfig().then(setConfigState);
    refreshAccounts();
    api.statusAll().then((l) => setStatuses(Object.fromEntries(l.map((s) => [s.profile, s]))));
    return subscribe('status', (l: AccountStatus[]) =>
      setStatuses(Object.fromEntries(l.map((s) => [s.profile, s]))));
  }, [refreshAccounts]);

  const patchConfig = useCallback(async (patch: Partial<Config>) => {
    setConfigState((c) => (c ? { ...c, ...patch } : c));
    await api.setConfig(patch);
  }, []);

  return (
    <div className="@container relative isolate h-full w-full flex flex-col overflow-hidden">
      <div className="le-bg" />
      <TitleBar version={VERSION} />

      <div className="shrink-0 flex items-center gap-1 px-3 py-2 bg-panel border-b border-line">
        <TabButton id="home" tab={tab} setTab={setTab}>HOME</TabButton>
        <TabButton id="settings" tab={tab} setTab={setTab}>SETTINGS</TabButton>
        <div className="ml-auto flex items-center gap-0.5">
          <NavGlyph tip="GitHub" onClick={() => api.openExternal('https://github.com/suspiciousman3187/Forest')}>
            <svg viewBox="0 0 24 24" className="w-4 h-4" fill="currentColor"><path d="M12 .5C5.7.5.5 5.7.5 12c0 5.1 3.3 9.4 7.9 10.9.6.1.8-.3.8-.6v-2c-3.2.7-3.9-1.5-3.9-1.5-.5-1.3-1.3-1.7-1.3-1.7-1-.7.1-.7.1-.7 1.2.1 1.8 1.2 1.8 1.2 1 1.8 2.8 1.3 3.5 1 .1-.8.4-1.3.7-1.6-2.6-.3-5.3-1.3-5.3-5.8 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0C17 5 18 5.3 18 5.3c.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.5-2.7 5.5-5.3 5.8.4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6 4.6-1.5 7.9-5.8 7.9-10.9C23.5 5.7 18.3.5 12 .5z" /></svg>
          </NavGlyph>
          <NavGlyph tip="Discord" onClick={() => api.openExternal('https://discord.gg/vSgYvdh8gT')}>
            <svg viewBox="0 0 24 24" className="w-4 h-4" fill="currentColor"><path d="M20.317 4.369a19.79 19.79 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.6 12.6 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.74 19.74 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.1 13.1 0 0 1-1.872-.892.077.077 0 0 1-.008-.128c.126-.094.252-.192.372-.291a.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.009c.12.099.246.198.373.292a.077.077 0 0 1-.006.127 12.3 12.3 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.331c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" /></svg>
          </NavGlyph>
          <NavGlyph tip="Donate" onClick={() => api.openExternal('https://ko-fi.com/lesserevil')}>
            <svg viewBox="0 0 24 24" className="w-4 h-4" fill="currentColor"><path d="M12 21s-6.7-4.3-9.3-8.1C.9 10.3 1.5 6.9 4.2 5.6c2-1 4.2-.3 5.4 1.3L12 9l2.4-2.1c1.2-1.6 3.4-2.3 5.4-1.3 2.7 1.3 3.3 4.7 1.5 7.3C18.7 16.7 12 21 12 21z" /></svg>
          </NavGlyph>
        </div>
      </div>

      <main className="flex-1 min-h-0">
        <div key={tab} className="le-view h-full">
          {tab === 'home'
            ? <Home accounts={accounts} statuses={statuses} config={config} refreshAccounts={refreshAccounts} sel={selected} setSel={setSelected} />
            : <Settings config={config} patchConfig={patchConfig} />}
        </div>
      </main>

      <footer className="shrink-0 flex items-center gap-2 px-3.5 py-1.5 bg-nav border-t border-line text-[10px] text-fg-4 tracking-wide">
        <span className={`w-1.5 h-1.5 rounded-full ${config?.usePolProxy ? 'bg-emerald-400' : 'bg-red-500'}`} />
        POL PROXY STATUS:&nbsp;
        <span className={`font-bold ${config?.usePolProxy ? 'text-emerald-400' : 'text-red-400'}`}>{config?.usePolProxy ? 'ON' : 'OFF'}</span>
      </footer>
    </div>
  );
}

function TabButton({ id, tab, setTab, children }: { id: Tab; tab: Tab; setTab: (t: Tab) => void; children: ReactNode }) {
  const active = id === tab;
  return (
    <button
      onClick={() => setTab(id)}
      className={`px-3.5 py-1.5 text-[11px] font-bold tracking-wide rounded-md transition-colors ${active ? 'nav-active' : 'text-fg-3 hover:text-fg-2'}`}
    >
      {children}
    </button>
  );
}

function NavGlyph({ tip, onClick, children }: { tip: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      onClick={onClick}
      aria-label={tip}
      className="group relative grid place-items-center w-8 h-8 rounded-md text-fg-4 hover:text-accent hover:bg-line transition-colors"
    >
      {children}
      <Tip label={tip} side="bottom" />
    </button>
  );
}
