// Forest uses a single locked theme (multi-theme switching was dropped by design).
// The palette for this id lives in styles.css under [data-theme="forest"].
export type ThemeId = 'forest';

const THEME: ThemeId = 'forest';
if (typeof document !== 'undefined') document.documentElement.dataset.theme = THEME;

export function useTheme() {
  return [THEME] as const;
}
