// Webkit scrollbars don't repaint when a CSS variable changes, so we drive them
// through a managed <style> whose text we rewrite — that forces the repaint and
// works on every Chromium/WebView2 version (unlike the newer scrollbar-color).
let el: HTMLStyleElement | null = null;

export function applyScrollbar(color: string) {
  if (typeof document === 'undefined' || !color) return;
  if (!el) {
    el = document.createElement('style');
    el.id = 'le-scrollbar';
    document.head.appendChild(el);
  }
  el.textContent =
    '::-webkit-scrollbar{width:10px;height:10px}' +
    `::-webkit-scrollbar-thumb{background:${color};border-radius:8px;border:2px solid transparent;background-clip:content-box}` +
    '::-webkit-scrollbar-track{background:transparent}';
}

export function syncScrollbarFromVar() {
  if (typeof document === 'undefined') return;
  const c = getComputedStyle(document.documentElement).getPropertyValue('--color-scrollbar').trim();
  if (c) applyScrollbar(c);
}
