import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

export type Theme = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';
export type ColorTheme =
  | 'default'
  | 'blue'
  | 'green'
  | 'purple'
  | 'violet'
  | 'rose'
  | 'orange'
  | 'red'
  | 'yellow'
  | 'zinc'
  | 'neutral'
  | 'slate'
  | 'stone';

type ThemeContextValue = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  resolvedTheme: ResolvedTheme;
  colorTheme: ColorTheme;
  setColorTheme: (theme: ColorTheme) => void;
  radius: number;
  setRadius: (radius: number) => void;
};

const THEME_KEY = 'primevpn-ui-theme';
const COLOR_THEME_KEY = 'primevpn-ui-color-theme';
const RADIUS_KEY = 'primevpn-ui-radius';

const getSystemTheme = (): ResolvedTheme => {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

const readStorage = <T extends string>(key: string, fallback: T): T => {
  if (typeof window === 'undefined') return fallback;

  try {
    return (window.localStorage.getItem(key) as T | null) || fallback;
  } catch {
    return fallback;
  }
};

const writeStorage = (key: string, value: string) => {
  if (typeof window === 'undefined') return;

  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable in private/locked-down contexts.
  }
};

const defaultValue: ThemeContextValue = {
  theme: 'system',
  setTheme: () => {},
  resolvedTheme: 'light',
  colorTheme: 'default',
  setColorTheme: () => {},
  radius: 0.5,
  setRadius: () => {},
};

const ThemeContext = createContext<ThemeContextValue>(defaultValue);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => readStorage<Theme>(THEME_KEY, 'system'));
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => getSystemTheme());
  const [colorTheme, setColorThemeState] = useState<ColorTheme>(() => readStorage<ColorTheme>(COLOR_THEME_KEY, 'default'));
  const [radius, setRadiusState] = useState<number>(() => {
    const raw = readStorage<string>(RADIUS_KEY, '0.5');
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : 0.5;
  });

  const resolvedTheme: ResolvedTheme = theme === 'system' ? systemTheme : theme;

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;

    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => setSystemTheme(getSystemTheme());

    media.addEventListener?.('change', onChange);
    return () => media.removeEventListener?.('change', onChange);
  }, []);

  useEffect(() => {
    const root = typeof document === 'undefined' ? null : document.documentElement;
    if (!root) return;

    root.classList.toggle('dark', resolvedTheme === 'dark');
    root.dataset.theme = resolvedTheme;
    root.dataset.colorTheme = colorTheme;
    root.style.setProperty('--radius', `${radius}rem`);
  }, [resolvedTheme, colorTheme, radius]);

  const setTheme = (nextTheme: Theme) => {
    setThemeState(nextTheme);
    writeStorage(THEME_KEY, nextTheme);
  };

  const setColorTheme = (nextTheme: ColorTheme) => {
    setColorThemeState(nextTheme);
    writeStorage(COLOR_THEME_KEY, nextTheme);
  };

  const setRadius = (nextRadius: number) => {
    const safeRadius = Number.isFinite(nextRadius) ? nextRadius : 0.5;
    setRadiusState(safeRadius);
    writeStorage(RADIUS_KEY, String(safeRadius));
  };

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      setTheme,
      resolvedTheme,
      colorTheme,
      setColorTheme,
      radius,
      setRadius,
    }),
    [theme, resolvedTheme, colorTheme, radius],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}
