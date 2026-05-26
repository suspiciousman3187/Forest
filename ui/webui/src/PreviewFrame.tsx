import { useState } from 'react';
import { inWebView2 } from './bridge';
import { DEMO } from './demo';

// In WebView2 the OS window supplies the size, so we fill it. In a plain browser
// (dev preview) we render the app inside a fixed window-sized box matching
// Forest's real window dimensions, so layout is judged at the resolution it runs
// at — not stretched to the whole browser.
const PRESETS: { label: string; w: number; h: number }[] = [
  { label: 'Default 580×740', w: 580, h: 740 },
  { label: 'Min 480×600', w: 480, h: 600 },
  { label: 'Tall 580×900', w: 580, h: 900 },
  { label: 'Wide 820×760', w: 820, h: 760 },
];

export default function PreviewFrame({ children }: { children: React.ReactNode }) {
  if (inWebView2) return <div className="h-screen w-screen">{children}</div>;

  // ?demo — clean 580×900 frame (no chrome) for the GitHub example screenshot.
  if (DEMO) {
    return (
      <div className="min-h-screen w-screen bg-[#0b0e0c] grid place-items-center">
        <div className="overflow-hidden shadow-2xl shadow-black/70" style={{ width: 580, height: 900 }}>
          {children}
        </div>
      </div>
    );
  }

  const [i, setI] = useState(0);
  const p = PRESETS[i];
  return (
    <div className="min-h-screen w-screen bg-[#08080a] flex flex-col items-center justify-center gap-3 py-6">
      <div
        className="relative overflow-hidden rounded-lg border border-white/15 shadow-2xl shadow-black/60"
        style={{ width: p.w, height: p.h }}
      >
        {children}
      </div>
      <div className="flex items-center gap-1.5 text-[11px]">
        <span className="text-gray-500 mr-1">Preview size:</span>
        {PRESETS.map((pp, idx) => (
          <button
            key={pp.label}
            onClick={() => setI(idx)}
            className={`px-2.5 py-1 rounded-md border transition-colors ${
              idx === i
                ? 'bg-white/10 border-white/25 text-gray-100'
                : 'border-white/10 text-gray-400 hover:text-gray-200 hover:bg-white/5'
            }`}
          >
            {pp.label}
          </button>
        ))}
      </div>
      <div className="text-[10px] text-gray-600">
        Forest window preview · the app fills the OS window when running in WebView2.
      </div>
    </div>
  );
}
