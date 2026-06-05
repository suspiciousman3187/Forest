// Minimal splash UI rendered when Forest is in auto-launch/auto-quit mode.
//
// Visual: spinning Forest icon traverses a left-to-right "journey" track
// whose position reflects the slowest watched account's lifecycle progress.
// Below the journey: large account name + the same colored status badge
// the main UI uses (StatusBadgeLarge). When every watched account reaches
// IN_GAME (Friendly'd to RUNNING), the journey stage swaps to a big green
// "LOGIN COMPLETE!" badge while a 5s settle counts down before Forest
// auto-exits. STOP at any time hands control back to the full UI.
import { useEffect, useMemo, useState } from 'react';
import { api, subscribe } from './bridge';
import { StatusBadgeLarge } from './widgets';
import type { AccountStatus, LaunchState } from './types';

const SETTLE_SECONDS = 5;

// Lifecycle state → journey progress (0..1). Failures stay at their last
// observed position (caller filters them out anyway). RUNNING is 100% — that's
// our "fully in-game" state per the Trees.dll IN_GAME → Friendly mapping.
const PROGRESS: Partial<Record<LaunchState, number>> = {
  INACTIVE:          0.00,
  QUEUED:            0.04,
  'LAUNCH WINDOWER': 0.10,
  'LAUNCH ASHITA':   0.10,
  'LAUNCH POL':      0.20,
  'SELECT ACCOUNT':  0.34,
  'INPUT PASSWORD':  0.48,
  'LOGGING IN':      0.62,
  'LAUNCHING GAME':  0.78,
  RUNNING:           1.00,
  DONE:              1.00,
};

const IN_FLIGHT_STATES: ReadonlySet<LaunchState> = new Set([
  'QUEUED', 'LAUNCH WINDOWER', 'LAUNCH ASHITA', 'LAUNCH POL',
  'SELECT ACCOUNT', 'INPUT PASSWORD', 'LOGGING IN', 'LAUNCHING GAME',
]);

interface SplashProps {
  watching?: string[];
}

export default function AutoLaunchSplash({ watching }: SplashProps) {
  const [statuses, setStatuses] = useState<AccountStatus[]>([]);
  const [allInGame, setAllInGame] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);

  // Subscribe to status updates + the synthetic in-game signal the bridge
  // emits when Trees.dll's IN_GAME milestone fires for all watched profiles.
  useEffect(() => {
    const u1 = subscribe('status', (l: AccountStatus[]) => {
      setStatuses(filterWatched(l, watching));
    });
    const u2 = subscribe('inGame', (data: { allInGame: boolean }) => {
      setAllInGame(!!data?.allInGame);
    });
    api.statusAll().then((l) => setStatuses(filterWatched(l, watching))).catch(() => {});
    return () => { u1(); u2(); };
  }, [watching]);

  // Settle countdown — runs locally once allInGame fires. Bridge does the
  // actual shutdown when it elapses; we just count down for display.
  useEffect(() => {
    if (!allInGame) { setSecondsLeft(null); return; }
    setSecondsLeft(SETTLE_SECONDS);
    const start = Date.now();
    const t = setInterval(() => {
      const elapsed = (Date.now() - start) / 1000;
      const rem = Math.max(0, SETTLE_SECONDS - Math.floor(elapsed));
      setSecondsLeft(rem);
      if (rem <= 0) clearInterval(t);
    }, 200);
    return () => clearInterval(t);
  }, [allInGame]);

  const hasFailed = useMemo(
    () => statuses.some((s) =>
      s.status !== 'RUNNING' && !IN_FLIGHT_STATES.has(s.status)
    ),
    [statuses]
  );

  // Journey position = min progress across watched accounts (so the icon
  // shows the laggard, never claiming "done" before everyone is in). When
  // allInGame fires, hard-pin to 1.0 so the icon parks at the right edge.
  // Pixel travel range is (track-width − icon-width) for the icon, and the
  // fill bar grows from 0 to (track-width = 320px) so it ends at the same
  // visual point as the icon's leading edge.
  const progress = useMemo(() => {
    if (allInGame) return 1;
    if (statuses.length === 0) return 0;
    const ps = statuses.map((s) => PROGRESS[s.status] ?? 0);
    return Math.min(...ps);
  }, [statuses, allInGame]);

  // Track is 320px wide, icon is 64px → max translateX is 256. Icon motion
  // is continuous for smoothness; the 12-chunk bar below lights up
  // progressively. A chunk is "on" once progress has reached its share of
  // the total (chunk N lights at progress >= N/CHUNKS).
  const journeyTx = `${Math.round(progress * 256)}px`;
  const CHUNKS = 12;

  const onStop  = () => { void api.splashExit({ reason: 'user-stop' }); };
  const onRetry = () => { void api.splashRetry(); };

  return (
    <div
      className="splash-overlay splash-window"
      style={{ ['--journey-x' as never]: journeyTx } as React.CSSProperties}
    >
      <p className="splash-caption">
        {allInGame ? "It's Showtime!" : 'Now Logging In'}
        {!allInGame && (
          <span className="splash-dots" aria-hidden="true">
            <span>.</span><span>.</span><span>.</span>
          </span>
        )}
      </p>

      <div className="splash-journey">
        <div className="splash-journey-track">
          {Array.from({ length: CHUNKS }).map((_, i) => {
            const threshold = (i + 1) / CHUNKS;
            const on = allInGame || progress >= threshold - 0.001;
            return (
              <div
                key={i}
                className={'splash-journey-chunk' + (on ? ' splash-journey-chunk--on' : '')}
              />
            );
          })}
        </div>
        <div className="splash-traveler">
          <img
            src="/forest-icon.png"
            alt=""
            aria-hidden="true"
            draggable={false}
            className={allInGame ? 'splash-celebrate' : undefined}
          />
        </div>
      </div>

      <div className={'splash-rows' + (statuses.length > 1 ? ' is-multi' : '')}>
        {statuses.length === 0 && (
          <div className="splash-row">
            <span className="splash-row-name">Preparing</span>
            <StatusBadgeLarge status="QUEUED" />
          </div>
        )}
        {statuses.length === 1 && (
          <div key={statuses[0].profile} className="splash-row">
            <span className="splash-row-name">{statuses[0].profile}</span>
            <StatusBadgeLarge status={allInGame ? 'LOGIN COMPLETE' : statuses[0].status} />
          </div>
        )}
        {statuses.length > 1 && statuses.map((s) => {
          const sProgress = allInGame ? 1 : (PROGRESS[s.status] ?? 0);
          return (
            <div key={s.profile} className="splash-row">
              <span className="splash-row-name">{s.profile}</span>
              <RowProgressBar progress={sProgress} allInGame={allInGame} />
              <div className="splash-row-badge">
                <StatusBadgeLarge status={allInGame ? 'LOGIN COMPLETE' : s.status} />
              </div>
            </div>
          );
        })}
      </div>

      {secondsLeft !== null && (
        <p className="splash-countdown">
          Closing in {secondsLeft}s — click STOP to keep Forest open
        </p>
      )}

      <div className="splash-actions">
        {hasFailed && (
          <button className="splash-retry-btn" onClick={onRetry} type="button">
            Retry
          </button>
        )}
        <button className="splash-stop-btn" onClick={onStop} type="button">
          Stop
        </button>
      </div>
    </div>
  );
}

function RowProgressBar({ progress, allInGame }: { progress: number; allInGame: boolean }) {
  const CHUNKS = 12;
  return (
    <div className="splash-row-bar">
      {Array.from({ length: CHUNKS }).map((_, i) => {
        const threshold = (i + 1) / CHUNKS;
        const on = allInGame || progress >= threshold - 0.001;
        return (
          <div
            key={i}
            className={'splash-row-chunk' + (on ? ' splash-row-chunk--on' : '')}
          />
        );
      })}
    </div>
  );
}

function filterWatched(all: AccountStatus[], watching?: string[]): AccountStatus[] {
  if (!watching || watching.length === 0) return all;
  const set = new Set(watching.map((s) => s.toLowerCase()));
  return all.filter((s) => set.has(s.profile.toLowerCase()));
}
