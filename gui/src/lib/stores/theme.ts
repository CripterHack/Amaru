import { writable } from 'svelte/store';

export type Theme = 'light' | 'dark' | 'system';
export const theme = writable<Theme>('system');

export function applyThemePreference() {
  const key = 'amaru.appearance.theme';
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let preference: Theme = 'system';
  try {
    const saved = localStorage.getItem(key);
    if (saved === 'light' || saved === 'dark') preference = saved;
  } catch { /* WebView storage can be unavailable in a restricted profile. */ }
  theme.set(preference);
  const apply = () => document.documentElement.classList.toggle(
    'dark', preference === 'system' ? media.matches : preference === 'dark'
  );
  const unsubscribe = theme.subscribe((value) => {
    preference = value;
    apply();
    try { localStorage.setItem(key, value); } catch { /* Keep this session's preference. */ }
  });
  media.addEventListener('change', apply);
  return () => {
    unsubscribe();
    media.removeEventListener('change', apply);
  };
}
