import { useState } from 'react';
import { Button, Group, Row, RowStacked, Segmented, Slider, TextField, Toggle } from '../ui';
import { api } from '../bridge';
import type { Config } from '../types';

export default function Settings({ config, patchConfig }:
  { config: Config | null; patchConfig: (p: Partial<Config>) => void }) {
  const [exportMsg, setExportMsg] = useState('');
  if (!config) return <div className="px-5 py-10 text-center text-[12px] text-fg-4">Loading settings…</div>;
  const c = config;

  const PathRow = ({ label, desc, value, browse, save }:
    { label: string; desc: string; value: string; browse: () => Promise<string>; save: (v: string) => void }) => (
    <RowStacked label={label} desc={desc}>
      <div className="flex gap-1.5">
        <TextField value={value} onChange={save} placeholder="not set" />
        <Button onClick={async () => { const p = await browse(); if (p) save(p); }}>Browse</Button>
      </div>
    </RowStacked>
  );

  return (
    <div className="h-full overflow-y-auto">
    <div className="mx-auto max-w-2xl px-5 py-4">
      <Group title="LAUNCHER SETUP">
        <PathRow label="Windower Executable" desc="Path to Windower.exe."
          value={c.windowerExe} browse={() => api.browse('file', 'exe')} save={(v) => patchConfig({ windowerExe: v })} />
        <PathRow label="Ashita-cli Executable" desc="Path to Ashita-cli.exe (optional)."
          value={c.ashitaExe} browse={() => api.browse('file', 'exe')} save={(v) => patchConfig({ ashitaExe: v })} />
        <Row label="Default Launcher" desc="Used when an account's launcher is 'Default'.">
          <Segmented value={c.defaultLauncher} onChange={(v) => patchConfig({ defaultLauncher: v })}
            options={[{ v: 'Windower', label: 'Windower' }, { v: 'Ashita', label: 'Ashita v4' }]} />
        </Row>
      </Group>

      <Group title="LAUNCH BEHAVIOR">
        <Row label="Multiple Account Launch Speed" desc="Faster lowers the stagger delay but may cause hangs.">
          <Segmented value={c.fastSequential ? 'fast' : 'regular'} onChange={(v) => patchConfig({ fastSequential: v === 'fast' })}
            options={[{ v: 'regular', label: 'Regular' }, { v: 'fast', label: 'Faster' }]} />
        </Row>
        <RowStacked label="Login Timeout" desc="Max seconds to wait for a login before marking it failed.">
          <Slider value={c.loginTimeoutSeconds} min={30} max={300} suffix="s" onChange={(v) => patchConfig({ loginTimeoutSeconds: v })} />
        </RowStacked>
        <Row label="Launch Selected Accounts Automatically On Startup" desc="Automatically launches selected accounts on bootup.">
          <Toggle on={c.launchSelectedOnStartup} onChange={(v) => patchConfig(
            v ? { launchSelectedOnStartup: true }
              : { launchSelectedOnStartup: false, launchMode: 'Full' }
          )} />
        </Row>
        {c.launchSelectedOnStartup && (
          <Row label="Simple Mode" desc="Launch selected accounts automatically on bootup, then close when all logins complete.">
            <Toggle on={c.launchMode === 'Splash'} onChange={(v) => patchConfig({ launchMode: v ? 'Splash' : 'Full' })} />
          </Row>
        )}
      </Group>

      <Group title="PLAYONLINE LOGIN">
        <Row label="Hide PlayOnline Window During Login" desc="Hides the PlayOnline Viewer window by moving it offscreen during the login process.">
          <Toggle on={c.hidePolWindow} onChange={(v) => patchConfig({ hidePolWindow: v })} />
        </Row>
        {!c.hidePolWindow && (
          <Row label="Disable Auto-Login" desc="Skip the account-selection automation entirely.">
            <Toggle on={c.disableAutoLogin} onChange={(v) => patchConfig({ disableAutoLogin: v })} />
          </Row>
        )}
        <Row label="Fast Login" desc="Skips the PlayOnline news fetch so the login screen loads instantly. Works on all regions.">
          <Toggle on={c.usePolProxy} onChange={(v) => patchConfig({ usePolProxy: v })} />
        </Row>
      </Group>

      <Group title="INGAME CHARACTER LOGIN">
        <Row label="Log In Character Automatically" desc="Selects the account's ingame slot when FFXI starts.">
          <Toggle on={c.autoLoginCharacter} onChange={(v) => patchConfig({ autoLoginCharacter: v })} />
        </Row>
        {c.autoLoginCharacter && (
          <Row label="Enable SendInput Fallback (Requires Focus)" desc="OS-level keystrokes if the normal method fails.">
            <Toggle on={c.autoLoginSendInputFallback} onChange={(v) => patchConfig({ autoLoginSendInputFallback: v })} />
          </Row>
        )}
      </Group>

      <Group title="Multi-Launch Game Resolution Correction (Windower)">
        <Row label="Fix FFXI Resolution On Launch (Recommended)" desc="Intercepts PlayOnline Viewer's registry read attempt and returns the correct values for the profile's game resolution.">
          <Toggle on={c.overrideFFXiResolution} onChange={(v) => patchConfig({
            overrideFFXiResolution: v,
            ...(v ? { waitForFFXiRegistryReadBetweenLaunches: false } : {}),
          })} />
        </Row>
        <Row label="Fix FFXI Resolution On Launch (Legacy)" desc="Wait until the registry reads the proper resolution before launching the next client in multi-launch sequences.">
          <Toggle on={c.waitForFFXiRegistryReadBetweenLaunches} onChange={(v) => patchConfig({
            waitForFFXiRegistryReadBetweenLaunches: v,
            ...(v ? { overrideFFXiResolution: false } : {}),
          })} />
        </Row>
      </Group>

      <Group title="DIAGNOSTICS">
        <Row label="Enable Debug Logging" desc="Verbose logs to help diagnose problems.">
          <Toggle on={c.debugLogging} onChange={(v) => patchConfig({ debugLogging: v })} />
        </Row>
        <RowStacked label="Logs & Support" desc="Diagnostics zip is sanitized (account names redacted) and safe to share.">
          <div className="flex gap-1.5">
            <Button onClick={() => api.openLogs()}>Open Logs Folder</Button>
            <Button onClick={async () => { const p = await api.exportDiag(); setExportMsg(p ? `Saved: ${p}` : ''); }}>Export Diagnostics</Button>
          </div>
          {exportMsg && <div className="mt-2 text-[11px] text-emerald-300">{exportMsg}</div>}
        </RowStacked>
      </Group>
    </div>
    </div>
  );
}
