import { useState, useRef, useEffect, type ReactNode, type CSSProperties } from 'react';
import { createPortal } from 'react-dom';

export function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mb-5">
      <h2 className="text-[10px] font-bold tracking-[0.14em] text-fg-4 px-1 mb-2">{title}</h2>
      <div className="rounded-xl bg-surface border border-line divide-y divide-line overflow-hidden">
        {children}
      </div>
    </section>
  );
}

export function Row({ label, desc, children }: { label: string; desc?: string; children?: ReactNode }) {
  return (
    <div className="flex items-center gap-3 px-3.5 py-2.5">
      <div className="min-w-0">
        <div className="text-[13px] text-fg-2 leading-tight">{label}</div>
        {desc && <div className="text-[11px] text-fg-4 mt-0.5 leading-snug">{desc}</div>}
      </div>
      {children && <div className="ml-auto shrink-0">{children}</div>}
    </div>
  );
}

export function RowStacked({ label, desc, children }: { label: string; desc?: string; children: ReactNode }) {
  return (
    <div className="px-3.5 py-2.5">
      <div className="text-[13px] text-fg-2 leading-tight">{label}</div>
      {desc && <div className="text-[11px] text-fg-4 mt-0.5 leading-snug">{desc}</div>}
      <div className="mt-2">{children}</div>
    </div>
  );
}

export function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      onClick={() => onChange(!on)}
      style={{ filter: on ? undefined : 'saturate(0.3)' }}
      className={`relative w-9 h-5 rounded-full transition-colors ${on ? 'bg-[var(--color-nav-active)]' : 'bg-[var(--color-track)]'}`}
    >
      <span
        style={{ background: on ? '#fff' : 'var(--color-knob)' }}
        className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full shadow transition-transform ${on ? 'translate-x-4' : ''}`}
      />
    </button>
  );
}

export function Segmented<T extends string>({
  value, options, onChange, full = false,
}: { value: T; options: { v: T; label: string }[]; onChange: (v: T) => void; full?: boolean }) {
  return (
    <div className={`${full ? 'flex w-full' : 'inline-flex'} rounded-lg bg-field border border-line p-0.5`}>
      {options.map((o) => (
        <button
          key={o.v}
          onClick={() => onChange(o.v)}
          className={`${full ? 'flex-1 ' : ''}px-2.5 py-1.5 text-[11px] font-semibold rounded-md transition-colors ${
            value === o.v ? 'nav-active' : 'text-fg-3 hover:text-fg-2'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Slider({
  value, min = 0, max = 100, suffix = '', onChange,
}: { value: number; min?: number; max?: number; suffix?: string; onChange: (v: number) => void }) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="flex-1 h-1.5 accent-[var(--color-slider)] cursor-pointer"
      />
      <span className="text-[11px] tabular-nums text-fg-2 w-14 text-right">{value}{suffix}</span>
    </div>
  );
}

export function TextField({
  value, onChange, placeholder,
}: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full bg-field border border-line rounded-md px-2.5 py-1.5 text-xs text-fg-2 placeholder-fg-4 outline-none focus:border-accent/50"
    />
  );
}

// Custom dropdown (replaces the native <select>, which the OS renders with its
// own un-themeable popup colors). Renders the menu in a portal so it's never
// clipped by a scroll container, and flips up when near the screen bottom.
export function Select({
  value, onChange, options, full = false,
}: { value: string; onChange: (v: string) => void; options: string[]; full?: boolean }) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; width: number; up: boolean } | null>(null);

  useEffect(() => {
    if (!open) return;
    const r = btn.current?.getBoundingClientRect();
    if (r) {
      const menuH = Math.min(options.length * 32 + 8, 280);
      const up = r.bottom + menuH > window.innerHeight && r.top > menuH;
      setPos({ left: r.left, top: up ? r.top : r.bottom, width: r.width, up });
    }
    const onScroll = (e: Event) => { if (!menu.current?.contains(e.target as Node)) setOpen(false); };
    const onResize = () => setOpen(false);
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onResize);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('keydown', onKey);
    };
  }, [open, options.length]);

  const menuStyle: CSSProperties = pos
    ? (pos.up
      ? { left: pos.left, width: pos.width, bottom: window.innerHeight - pos.top + 4 }
      : { left: pos.left, width: pos.width, top: pos.top + 4 })
    : {};

  return (
    <>
      <button
        ref={btn}
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={`${full ? 'w-full ' : ''}flex items-center justify-between gap-2 bg-surface border border-line rounded-md px-2.5 py-1.5 text-xs text-fg-2 outline-none hover:border-accent/50`}
      >
        <span className="truncate">{value}</span>
        <svg viewBox="0 0 24 24" className="w-3.5 h-3.5 shrink-0 text-fg-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m6 9 6 6 6-6" /></svg>
      </button>
      {open && pos && createPortal(
        <>
          <div className="fixed inset-0 z-[90]" onMouseDown={() => setOpen(false)} />
          <div ref={menu} className="fixed z-[91] max-h-[280px] overflow-y-auto rounded-md bg-[#2c372f] border border-line-2 shadow-xl py-1" style={menuStyle}>
            {options.map((o) => (
              <button
                key={o}
                type="button"
                onMouseDown={(e) => { e.preventDefault(); onChange(o); setOpen(false); }}
                className={`w-full text-left px-2.5 py-2 text-xs transition-colors ${o === value ? 'bg-accent/20 text-accent font-semibold' : 'text-fg-2 hover:bg-accent/15 hover:text-accent'}`}
              >
                {o}
              </button>
            ))}
          </div>
        </>,
        document.body,
      )}
    </>
  );
}

export function Button({ children, onClick, variant = 'default', full = false }: { children: ReactNode; onClick?: () => void; variant?: 'default' | 'accent'; full?: boolean }) {
  const cls = variant === 'accent'
    ? 'bg-accent text-on-accent hover:bg-accent-hover'
    : 'bg-surface-raised text-fg-2 border border-line hover:bg-surface-hover';
  return (
    <button onClick={onClick} className={`text-[12px] font-semibold rounded-md px-3 py-1.5 transition-colors ${full ? 'w-full' : ''} ${cls}`}>
      {children}
    </button>
  );
}

// Clickable on/off pill (PC / NPC / MOB style multi-select).
export function Chip({ on, onChange, children, full = false }: { on: boolean; onChange: (v: boolean) => void; children: ReactNode; full?: boolean }) {
  return (
    <button
      aria-pressed={on}
      onClick={() => onChange(!on)}
      className={`${full ? 'flex-1 ' : ''}px-3 py-1.5 text-[11px] font-bold rounded-md border transition-colors ${
        on ? 'nav-active border-transparent' : 'bg-field text-fg-3 border-line hover:text-fg-2'
      }`}
    >
      {children}
    </button>
  );
}

// Add-as-you-type list of names, shown as removable chips.
export function TagInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const t = draft.trim();
    if (t && !value.some((v) => v.toLowerCase() === t.toLowerCase())) onChange([...value, t]);
    setDraft('');
  };
  return (
    <div>
      <div className="flex gap-1.5">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
          placeholder={placeholder}
          className="flex-1 min-w-0 bg-field border border-line rounded-md px-2.5 py-1.5 text-xs text-fg-2 placeholder-fg-4 outline-none focus:border-accent/50"
        />
        <Button onClick={add}>Add</Button>
      </div>
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-2">
          {value.map((n) => (
            <span key={n} className="inline-flex items-center gap-1 bg-surface-raised border border-line rounded-md pl-2 pr-1 py-0.5 text-[11px] text-fg-2">
              {n}
              <button onClick={() => onChange(value.filter((x) => x !== n))} aria-label={`Remove ${n}`} className="grid place-items-center w-4 h-4 rounded text-fg-4 hover:text-fg leading-none">×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// Themed tooltip chip. Render inside a `group relative` trigger; it fades in on
// hover. `compactOnly` shows it only when the app is in the narrow layout
// (where icon labels are hidden).
export function Tip({ label, side = 'right', compactOnly = false }: { label: string; side?: 'right' | 'bottom' | 'top'; compactOnly?: boolean }) {
  const pos =
    side === 'right' ? 'left-full ml-2 top-1/2 -translate-y-1/2'
    : side === 'top' ? 'bottom-full mb-1.5 right-0'
    : 'top-full mt-1.5 right-0';
  const gate = compactOnly ? 'hidden @max-[460px]:block' : '';
  return (
    <span
      role="tooltip"
      className={`pointer-events-none absolute z-50 ${pos} ${gate} whitespace-nowrap rounded-md bg-surface-raised border border-line px-2 py-1 text-[11px] font-semibold text-fg-2 shadow-lg opacity-0 transition-opacity duration-150 group-hover:opacity-100`}
    >
      {label}
    </span>
  );
}

export function Note({ children }: { children: ReactNode }) {
  return (
    <div className="note mb-4 text-[11px] rounded-r-md px-3 py-2">
      {children}
    </div>
  );
}
