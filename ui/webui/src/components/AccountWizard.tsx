import { useState } from 'react';
import { Modal } from '../widgets';
import { Button, Segmented, Select, TextField } from '../ui';
import { api } from '../bridge';
import type { Account, Config } from '../types';

const STEPS = [
  {
    title: 'Register in PlayOnline',
    desc: 'First, register this account in the PlayOnline Viewer. Forest logs into an account that already exists in PlayOnline — it does not create one for you.',
    img: 'registeraccount.png',
  },
  {
    title: 'Name the Account',
    desc: 'Give the account a name to identify it inside Forest (for example: Tank, Healer, Mule1).',
    img: null,
  },
  {
    title: 'Square Enix Password',
    desc: 'Enter the password for this account’s Square Enix login. It is stored encrypted on this PC and only decrypted during login.',
    img: 'sepassword.png',
  },
  {
    title: 'Launcher & Profile',
    desc: 'Choose the launcher this account uses, then enter its Windower profile name or Ashita boot config (.ini). Leave it blank to use the launcher default.',
    img: null,
  },
  {
    title: 'POL Member List Slot',
    desc: 'Select which slot this account sits on in the PlayOnline member list.',
    img: 'polaccountexample.png',
  },
  {
    title: 'Ingame Character Slot',
    desc: 'Select the slot of the character you want to log into once in-game.',
    img: 'characterslotexample.png',
  },
];
const LAST = STEPS.length - 1;

function Shot({ name }: { name: string }) {
  const [ok, setOk] = useState(true);
  if (!ok) return null;
  return (
    <img
      src={`/wizard/${name}`}
      onError={() => setOk(false)}
      alt=""
      className="block w-full h-auto rounded-lg border border-line bg-black/20 mb-3"
    />
  );
}

function PasswordField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [show, setShow] = useState(false);
  return (
    <div className="flex gap-1.5">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Square Enix password"
        className="flex-1 min-w-0 bg-field border border-line rounded-md px-2.5 py-1.5 text-xs text-fg-2 placeholder-fg-4 outline-none focus:border-accent/50"
      />
      <Button onClick={() => setShow((s) => !s)}>{show ? 'Hide' : 'Show'}</Button>
    </div>
  );
}

export function AccountWizard({ accounts, config, onClose, onSaved, onQuickAdd }:
  { accounts: Account[]; config: Config | null; onClose: () => void; onSaved: () => void; onQuickAdd: () => void }) {
  const [phase, setPhase] = useState<'choose' | number | 'done'>('choose');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [launcher, setLauncher] = useState<'Windower' | 'Ashita'>(config?.defaultLauncher ?? 'Windower');
  const [windower, setWindower] = useState('');
  const [polSlot, setPolSlot] = useState('1');
  const [ingameSlot, setIngameSlot] = useState('1');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  function stepError(idx: number): string | null {
    if (idx === 1) {
      const n = name.trim();
      if (!n) return 'Please enter an account name.';
      if (accounts.some((a) => a.profile.toLowerCase() === n.toLowerCase())) return `An account named "${n}" already exists.`;
    }
    if (idx === 2 && !password) return 'Please enter the Square Enix password.';
    return null;
  }

  async function save() {
    setBusy(true);
    try {
      await api.saveAccount({
        profile: name.trim(),
        windower: windower.trim() || (launcher === 'Ashita' ? 'default.ini' : 'Default Profile'),
        polSlot: Number(polSlot) || 1,
        ingameSlot: Number(ingameSlot) || 1,
        launcher,
        launchArgs: '',
        password,
      });
      onSaved();
      setPhase('done');
    } catch (e) {
      setErr(String((e as Error).message ?? e));
      setBusy(false);
    }
  }

  function proceed() {
    if (typeof phase !== 'number') return;
    const e = stepError(phase);
    if (e) { setErr(e); return; }
    setErr('');
    if (phase === LAST) { save(); return; }
    setPhase(phase + 1);
  }
  function back() {
    if (typeof phase === 'number' && phase > 0) { setErr(''); setPhase(phase - 1); }
  }

  if (phase === 'choose') {
    return (
      <Modal open width={460} title="Add Account" onClose={onClose} dismissable={false}
        footer={<>
          <Button onClick={onQuickAdd}>Quick Account Add</Button>
          <Button variant="accent" onClick={() => { setErr(''); setPhase(0); }}>Use Wizard</Button>
        </>}>
        <div className="text-[13px] text-fg-2 leading-relaxed">
          Would you like to use the Account Registration Wizard to guide you through adding an account?
        </div>
        <div className="mt-2 text-[11px] text-fg-4 leading-relaxed">
          New to Forest? The wizard walks you through each setting with screenshots. Already comfortable? Quick Account Add opens the single settings screen.
        </div>
      </Modal>
    );
  }

  if (phase === 'done') {
    return (
      <Modal open width={460} title="Account Added" onClose={onClose} dismissable={false}
        footer={<Button variant="accent" onClick={onClose}>Finish</Button>}>
        <div className="text-center py-4">
          <div className="grid place-items-center w-12 h-12 mx-auto mb-3 rounded-full bg-accent/15 text-accent text-2xl">✓</div>
          <div className="text-[15px] font-bold text-fg-2">Done!</div>
          <div className="mt-1 text-[12px] text-fg-3"><b className="text-fg">{name.trim()}</b> has been added to Forest.</div>
        </div>
      </Modal>
    );
  }

  const step = STEPS[phase];
  return (
    <Modal open width={560} title={`Add Account Wizard — Step ${phase + 1} of ${STEPS.length}`} onClose={onClose} dismissable={false}
      footer={<>
        {phase > 0 && <Button onClick={back}>Back</Button>}
        <Button variant="accent" onClick={busy ? undefined : proceed}>{busy ? 'Saving…' : 'Proceed'}</Button>
      </>}>
      <div className="flex items-center gap-1.5 mb-3">
        {STEPS.map((_, i) => (
          <span key={i} className={`h-1.5 flex-1 rounded-full transition-colors ${i <= phase ? 'bg-accent' : 'bg-line'}`} />
        ))}
      </div>
      <h3 className="text-[14px] font-bold text-fg-2 mb-1">{step.title}</h3>
      <p className="text-[12px] text-fg-3 leading-relaxed mb-3">{step.desc}</p>
      {step.img && <Shot name={step.img} />}
      {err && <div className="mb-3 text-[11px] rounded-md px-3 py-2 text-red-300 bg-red-500/12 border border-red-500/40">{err}</div>}

      {phase === 1 && <TextField value={name} onChange={setName} placeholder="e.g. Tank" />}
      {phase === 2 && <PasswordField value={password} onChange={setPassword} />}
      {phase === 3 && (
        <div className="space-y-2">
          <Segmented<'Windower' | 'Ashita'> full value={launcher} onChange={setLauncher}
            options={[{ v: 'Windower', label: 'Windower' }, { v: 'Ashita', label: 'Ashita v4' }]} />
          <TextField value={windower} onChange={setWindower} placeholder={launcher === 'Ashita' ? 'default.ini' : 'Default Profile'} />
        </div>
      )}
      {phase === 4 && (
        <Select full value={`Account Slot #${polSlot}`} onChange={(v) => setPolSlot(v.replace('Account Slot #', ''))}
          options={Array.from({ length: 20 }, (_, i) => `Account Slot #${i + 1}`)} />
      )}
      {phase === 5 && (
        <Select full value={`Character Slot #${ingameSlot}`} onChange={(v) => setIngameSlot(v.replace('Character Slot #', ''))}
          options={Array.from({ length: 16 }, (_, i) => `Character Slot #${i + 1}`)} />
      )}
    </Modal>
  );
}
