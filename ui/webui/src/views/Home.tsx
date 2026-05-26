import { useMemo, useState } from 'react';
import { Button } from '../ui';
import { StatusBadge } from '../widgets';
import { AccountModal } from '../components/AccountModal';
import { AccountWizard } from '../components/AccountWizard';
import { ConfirmModal, type ConfirmOpts } from '../components/ConfirmModal';
import { api } from '../bridge';
import type { Account, AccountStatus, Config, LaunchState } from '../types';

const LAUNCHABLE = new Set<LaunchState>(['INACTIVE', 'FAILED', 'TERMINATED', 'TIMEOUT', 'WRONG SE PASSWORD', 'LOGIN STUCK']);
const isLaunchable = (s: LaunchState) => LAUNCHABLE.has(s);
const isRunning = (s: LaunchState) => !isLaunchable(s);
const BOOTING = new Set<LaunchState>(['LAUNCH WINDOWER', 'LAUNCH ASHITA']);
const canTerminate = (s: LaunchState) => isRunning(s) && !BOOTING.has(s);

export default function Home({ accounts, statuses, config, refreshAccounts, sel, setSel }:
  { accounts: Account[]; statuses: Record<string, AccountStatus>; config: Config | null; refreshAccounts: () => void;
    sel: Set<string>; setSel: React.Dispatch<React.SetStateAction<Set<string>>> }) {
  const [modal, setModal] = useState<{ account: Account | null } | null>(null);
  const [wizard, setWizard] = useState(false);
  const [confirm, setConfirm] = useState<ConfirmOpts | null>(null);
  const [dragFrom, setDragFrom] = useState<number | null>(null);

  const statusOf = (p: string): LaunchState => statuses[p]?.status ?? 'INACTIVE';

  const selList = useMemo(() => [...sel], [sel]);
  const canLaunch = selList.some((p) => isLaunchable(statusOf(p)));
  const canTerm = selList.some((p) => canTerminate(statusOf(p)));
  const allSelected = accounts.length > 0 && accounts.every((a) => sel.has(a.profile));

  const toggle = (p: string) => setSel((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; });
  const toggleAll = () => setSel(allSelected ? new Set() : new Set(accounts.map((a) => a.profile)));

  const launchTargets = selList.filter((p) => isLaunchable(statusOf(p)));
  const termTargets = selList.filter((p) => canTerminate(statusOf(p)));

  const launchSel = () => {
    const noAutoLogin = !!config && config.disableAutoLogin && !config.hidePolWindow;
    if (!noAutoLogin) { api.launch(launchTargets); return; }
    const many = launchTargets.length > 1;
    setConfirm({
      title: 'Launch Without Auto-Login',
      confirmText: many ? `Launch ${launchTargets.length}` : 'Launch',
      message: (
        <>
          <div>Auto-Login is off and the PlayOnline window is shown, so Forest will <b className="text-fg">not</b> log in through PlayOnline for {many ? 'any of the selected accounts' : 'this account'}.</div>
          <div className="mt-2">PlayOnline will open{many ? ' for each account' : ''} and you'll need to log in manually.</div>
        </>
      ),
      onConfirm: () => { api.launch(launchTargets); },
    });
  };

  const confirmTerminate = (profiles: string[]) => {
    if (profiles.length === 0) return;
    const lines = profiles.map((p) => { const pid = statuses[p]?.pid ?? 0; return pid > 0 ? `${p}  (pid ${pid})` : `${p}  (launching)`; });
    setConfirm({
      title: profiles.length === 1 ? 'Terminate Account' : 'Terminate Accounts',
      danger: true,
      confirmText: profiles.length === 1 ? 'Terminate' : `Terminate ${profiles.length}`,
      message: (
        <>
          <div className="mb-2">The following {profiles.length === 1 ? 'process' : 'processes'} will be closed. Your hand-run characters are not affected.</div>
          <ul className="space-y-1 text-fg">{lines.map((l) => <li key={l}>•&nbsp;&nbsp;{l}</li>)}</ul>
        </>
      ),
      onConfirm: () => { api.terminate(profiles); },
    });
  };
  const termSel = () => confirmTerminate(termTargets);

  const removeAccount = (a: Account) => setConfirm({
    title: 'Remove Account', danger: true, confirmText: 'Remove',
    message: <>Remove <b className="text-fg">{a.profile}</b> and its stored credentials? This cannot be undone.</>,
    onConfirm: async () => { await api.removeAccount(a.profile); setSel((s) => { const n = new Set(s); n.delete(a.profile); return n; }); refreshAccounts(); },
  });

  async function onDrop(to: number) {
    if (dragFrom === null || dragFrom === to) { setDragFrom(null); return; }
    const order = accounts.map((a) => a.profile);
    const [moved] = order.splice(dragFrom, 1);
    order.splice(to, 0, moved);
    setDragFrom(null);
    await api.reorder(order);
    refreshAccounts();
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 min-h-0 overflow-y-auto">
        <div className="mx-auto max-w-3xl px-4 py-4">
      <div className="flex items-center gap-2 mb-3">
        <h1 className="text-[12px] font-bold tracking-[0.14em] text-fg-2 [text-shadow:0_1px_4px_rgba(0,0,0,0.8)]">ACCOUNTS <span className="text-fg-3">({accounts.length})</span></h1>
        <div className="ml-auto">
          <Button variant="accent" onClick={() => setWizard(true)}>+ Add Account</Button>
        </div>
      </div>

      <div className="rounded-xl bg-surface border border-line overflow-hidden">
        {/* header */}
        <div className="flex items-center gap-2 px-3 py-2 border-b border-line text-[9px] font-bold tracking-[0.12em] text-fg-4">
          <input type="checkbox" checked={allSelected} onChange={toggleAll} className="le-check" />
          <span className="flex-1">NAME</span>
          <span className="w-10 text-center">TYPE</span>
          <span className="w-20 @max-[520px]:hidden">PROFILE</span>
          <span className="w-10 text-center">SLOT</span>
          <span className="w-40 text-center">STATUS</span>
          <span className="w-20 text-center">MANAGE</span>
        </div>

        {accounts.length === 0 && (
          <div className="px-4 py-10 text-center text-[12px] text-fg-4">
            No accounts yet. Click <b className="text-fg-2">+ Add Account</b> to create one.
          </div>
        )}

        {accounts.map((a, i) => {
          const st = statusOf(a.profile);
          const eff = a.launcher === 'Default' ? (config?.defaultLauncher ?? 'Windower') : a.launcher;
          return (
            <div
              key={a.profile}
              draggable
              onDragStart={() => setDragFrom(i)}
              onDragOver={(e) => e.preventDefault()}
              onDrop={() => onDrop(i)}
              className={`flex items-center gap-2 px-3 py-2.5 border-b border-line last:border-0 hover:bg-surface-hover transition-colors ${dragFrom === i ? 'opacity-40' : ''}`}
            >
              <input type="checkbox" checked={sel.has(a.profile)} onChange={() => toggle(a.profile)} className="le-check" />
              <div className="flex-1 min-w-0">
                <div className="text-[13px] text-fg-2 truncate">{a.profile}</div>
              </div>
              <span className="w-10 grid place-items-center">
                <img src={eff === 'Ashita' ? '/ashita.png' : '/windower.png'} alt={eff} title={eff} className="w-5 h-5 object-contain" />
              </span>
              <span className="w-20 @max-[520px]:hidden text-[11px] text-fg-3 truncate">{a.windower || '—'}</span>
              <span className="w-10 text-center text-[11px] text-fg-3 tabular-nums">{a.polSlot || '—'}</span>
              <span className="w-40 flex justify-center"><StatusBadge status={st} /></span>
              <span className="w-20 flex items-center justify-center gap-1">
                <IconBtn title="Edit" onClick={() => setModal({ account: a })}>✎</IconBtn>
                <IconBtn title="Remove" onClick={() => removeAccount(a)}>🗑</IconBtn>
                <IconBtn title="Terminate" danger disabled={!canTerminate(st)} onClick={() => confirmTerminate([a.profile])}>✕</IconBtn>
              </span>
            </div>
          );
        })}
      </div>

        </div>
      </div>

      {/* large bottom action bar (like the original Forest app) */}
      <div className="shrink-0 flex gap-2.5 px-4 py-3 bg-panel border-t border-line">
        <button
          onClick={canLaunch ? launchSel : undefined}
          className={`flex-1 py-2.5 rounded-lg text-[13px] font-bold tracking-[0.08em] transition-colors ${
            canLaunch ? 'bg-green-500 text-green-950 hover:bg-green-400' : 'bg-surface-raised text-fg-4 border border-line cursor-default'
          }`}
        >LAUNCH{launchTargets.length ? ` (${launchTargets.length})` : ''}</button>
        <button
          onClick={canTerm ? termSel : undefined}
          className={`flex-1 py-2.5 rounded-lg text-[13px] font-bold tracking-[0.08em] transition-colors ${
            canTerm ? 'bg-red-600 text-white hover:bg-red-500' : 'bg-surface-raised text-fg-4 border border-line cursor-default'
          }`}
        >TERMINATE{termTargets.length ? ` (${termTargets.length})` : ''}</button>
      </div>

      {wizard && (
        <AccountWizard
          accounts={accounts}
          config={config}
          onClose={() => setWizard(false)}
          onSaved={refreshAccounts}
          onQuickAdd={() => { setWizard(false); setModal({ account: null }); }}
        />
      )}
      {modal && (
        <AccountModal account={modal.account} accounts={accounts} config={config} onClose={() => setModal(null)} onSaved={refreshAccounts} />
      )}
      <ConfirmModal opts={confirm} onClose={() => setConfirm(null)} />
    </div>
  );
}

function IconBtn({ children, title, onClick, danger, disabled }:
  { children: React.ReactNode; title: string; onClick?: () => void; danger?: boolean; disabled?: boolean }) {
  return (
    <button
      title={title}
      onClick={disabled ? undefined : onClick}
      className={`grid place-items-center w-6 h-6 rounded text-[12px] transition-colors ${
        disabled ? 'text-fg-4/30 cursor-default' : danger ? 'text-fg-3 hover:text-white hover:bg-red-600' : 'text-fg-3 hover:text-fg hover:bg-line'
      }`}
    >{children}</button>
  );
}
