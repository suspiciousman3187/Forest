import { Modal } from '../widgets';
import { Button } from '../ui';

export interface ConfirmOpts {
  title: string;
  message: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  infoOnly?: boolean;          // single OK button
  onConfirm?: () => void;
}

export function ConfirmModal({ opts, onClose }: { opts: ConfirmOpts | null; onClose: () => void }) {
  if (!opts) return null;
  const confirm = () => { opts.onConfirm?.(); onClose(); };
  return (
    <Modal
      open
      title={opts.title}
      onClose={onClose}
      footer={
        opts.infoOnly ? (
          <Button variant="accent" onClick={onClose}>{opts.confirmText ?? 'OK'}</Button>
        ) : (
          <>
            <Button onClick={onClose}>{opts.cancelText ?? 'Cancel'}</Button>
            <button
              onClick={confirm}
              className={`text-[12px] font-semibold rounded-md px-3 py-1.5 transition-colors ${
                opts.danger ? 'bg-red-600 text-white hover:bg-red-500' : 'bg-accent text-on-accent hover:bg-accent-hover'
              }`}
            >
              {opts.confirmText ?? 'Confirm'}
            </button>
          </>
        )
      }
    >
      <div className="text-[13px] text-fg-2 leading-relaxed">{opts.message}</div>
    </Modal>
  );
}
