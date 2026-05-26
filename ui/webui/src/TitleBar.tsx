import { useState, type ReactNode } from 'react';
import { Tip } from './ui';
import { api } from './bridge';

function WinButton({ children, tip, onClick, danger, active }:
  { children: ReactNode; tip: string; onClick?: () => void; danger?: boolean; active?: boolean }) {
  return (
    <button
      onMouseDown={(e) => e.stopPropagation()}
      onClick={onClick}
      aria-label={tip}
      className={`group relative grid place-items-center w-11 h-9 transition-colors ${
        danger ? 'text-fg-3 hover:bg-red-600 hover:text-white'
          : active ? 'text-accent hover:bg-line'
          : 'text-fg-3 hover:bg-line hover:text-fg'
      }`}
    >
      {children}
      <Tip label={tip} side="bottom" />
    </button>
  );
}

export default function TitleBar({ version }: { version: string }) {
  const [pinned, setPinned] = useState(false);
  const togglePin = () => { const n = !pinned; setPinned(n); api.setAlwaysOnTop(n); };

  return (
    <header
      onMouseDown={(e) => { if (e.button === 0) api.window('drag'); }}
      className="h-9 shrink-0 flex items-center bg-nav border-b border-line select-none pl-3"
    >
      <div className="flex items-center gap-2 pointer-events-none">
        <span className="w-[3px] h-3.5 rounded bg-accent" />
        <span className="text-[11px] font-extrabold tracking-[0.18em] text-accent">FOREST</span>
        <span className="text-[10px] text-fg-4 font-medium">v{version}</span>
      </div>
      <div onMouseDown={(e) => e.stopPropagation()} className="ml-auto flex items-center">
        <WinButton tip={pinned ? 'Unpin (always on top)' : 'Keep on top'} active={pinned} onClick={togglePin}>
          <svg viewBox="0 0 24 24" className="w-4 h-4" fill="currentColor">
            <path d="M16 9V4h1a1 1 0 0 0 0-2H7a1 1 0 0 0 0 2h1v5c0 1.66-1.34 3-3 3v2h5.97v7l1 1 1-1v-7H19v-2c-1.66 0-3-1.34-3-3z" />
          </svg>
        </WinButton>
        <WinButton tip="Minimize" onClick={() => api.window('minimize')}>
          <span className="text-[13px] leading-none">—</span>
        </WinButton>
        <WinButton tip="Close" danger onClick={() => api.window('close')}>
          <span className="text-[13px] leading-none">✕</span>
        </WinButton>
      </div>
    </header>
  );
}
