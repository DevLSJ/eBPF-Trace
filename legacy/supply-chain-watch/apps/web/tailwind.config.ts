import type { Config } from 'tailwindcss';

// 토큰은 CSS 변수(globals.css)에 두고 Tailwind는 var()로 참조 — 프로토타입(docs/prototype) 이식.
const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)',
        surface: 'var(--surface)',
        'surface-2': 'var(--surface-2)',
        line: 'var(--line)',
        'line-strong': 'var(--line-strong)',
        fg: 'var(--fg)',
        'fg-2': 'var(--fg-2)',
        'fg-3': 'var(--fg-3)',
        accent: 'var(--accent)',
        'accent-soft': 'var(--accent-soft)',
        'accent-ink': 'var(--accent-ink)',
        crit: 'var(--crit)',
        warn: 'var(--warn)',
        good: 'var(--good)',
        info: 'var(--info)',
      },
      fontFamily: {
        sans: ['var(--font-sans)'],
        mono: ['var(--font-mono)'],
      },
      boxShadow: { card: 'var(--shadow)' },
    },
  },
  plugins: [],
};
export default config;
