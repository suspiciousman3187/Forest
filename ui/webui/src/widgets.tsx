import { useEffect, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { LaunchState } from './types';

// ── Modal: glass panel centered over a backdrop, portal-rendered ─────────────
export function Modal({ open, title, onClose, children, footer, width = 420, dismissable = true }:
  { open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; width?: number; dismissable?: boolean }) {
  useEffect(() => {
    if (!open || !dismissable) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, dismissable]);
  if (!open) return null;
  return createPortal(
    <div className="fixed inset-0 z-[80] grid place-items-center p-4" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/55" onMouseDown={dismissable ? onClose : undefined} />
      <div className="relative w-full le-view bg-surface-raised border border-line rounded-xl shadow-2xl overflow-hidden" style={{ maxWidth: width }}>
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-line">
          <span className="w-[3px] h-3.5 rounded bg-accent" />
          <h2 className="text-[12px] font-bold tracking-wide text-fg">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="ml-auto grid place-items-center w-6 h-6 rounded text-fg-4 hover:text-fg hover:bg-line">×</button>
        </div>
        <div className="px-4 py-3.5 max-h-[70vh] overflow-y-auto">{children}</div>
        {footer && <div className="flex justify-end gap-2 px-4 py-3 border-t border-line bg-panel-alt">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

// ── Status badge: each login-flow state gets its own color (cool → warm → green),
//    with a matching dot that pulses while the launch is in progress. ───────────
const STATE: Record<LaunchState, { cls: string; dot?: string; pulse?: boolean }> = {
  INACTIVE:          { cls: 'text-fg-4 bg-field border border-line' },
  TERMINATED:        { cls: 'text-fg-4 bg-field border border-line' },
  QUEUED:            { cls: 'text-slate-300 bg-slate-400/12 border border-slate-400/40',     dot: 'bg-slate-300',   pulse: true },
  'LAUNCH WINDOWER': { cls: 'text-sky-300 bg-sky-400/12 border border-sky-400/40',           dot: 'bg-sky-300',     pulse: true },
  'LAUNCH ASHITA':   { cls: 'text-sky-300 bg-sky-400/12 border border-sky-400/40',           dot: 'bg-sky-300',     pulse: true },
  'LAUNCH POL':      { cls: 'text-violet-300 bg-violet-400/12 border border-violet-400/40',   dot: 'bg-violet-300',  pulse: true },
  'SELECT ACCOUNT':  { cls: 'text-fuchsia-300 bg-fuchsia-400/12 border border-fuchsia-400/40', dot: 'bg-fuchsia-300', pulse: true },
  'INPUT PASSWORD':  { cls: 'text-amber-300 bg-amber-400/12 border border-amber-400/40',      dot: 'bg-amber-300',   pulse: true },
  'LOGGING IN':      { cls: 'text-orange-300 bg-orange-400/12 border border-orange-400/40',   dot: 'bg-orange-300',  pulse: true },
  'LAUNCHING GAME':  { cls: 'text-lime-300 bg-lime-400/12 border border-lime-400/40',         dot: 'bg-lime-300',    pulse: true },
  RUNNING:           { cls: 'pill-on', dot: 'bg-emerald-400' },
  DONE:              { cls: 'pill-on', dot: 'bg-emerald-400' },
  FAILED:            { cls: 'text-red-300 bg-red-500/12 border border-red-500/40',   dot: 'bg-red-400' },
  'WRONG SE PASSWORD': { cls: 'text-rose-300 bg-rose-500/12 border border-rose-500/40', dot: 'bg-rose-400' },
  'LOGIN STUCK':     { cls: 'text-red-300 bg-red-500/12 border border-red-500/40',   dot: 'bg-red-400' },
  TIMEOUT:           { cls: 'text-red-300 bg-red-500/12 border border-red-500/40',   dot: 'bg-red-400' },
};

export function StatusBadge({ status }: { status: LaunchState }) {
  const s = STATE[status] ?? STATE.INACTIVE;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-bold tracking-wide whitespace-nowrap ${s.cls}`}>
      {s.dot && <span className={`w-1.5 h-1.5 rounded-full ${s.dot} ${s.pulse ? 'animate-pulse' : ''}`} />}
      {status}
    </span>
  );
}
