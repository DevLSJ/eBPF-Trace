import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../lib/theme';

// 테마 단추(11/09 G01) — 셸 머리 오른쪽 묶음 · 로그인 화면 오른쪽 위에 그대로 둔다(props 없음, 자리는 감싸는 쪽이 정함).
// 이름 · 툴팁 = 누르면 할 동작(「밝은 화면으로」/「어두운 화면으로」 — 켜짐 상태 단추가 아니라 aria-pressed 없음), 아이콘도 갈 쪽(해 = 밝게 · 달 = 어둡게)
export function ThemeToggle() {
  const [theme, toggle] = useTheme();
  const name = theme === 'dark' ? '밝은 화면으로' : '어두운 화면으로';
  const Icon = theme === 'dark' ? Sun : Moon;
  return (
    <button
      type="button"
      data-part="theme-toggle"
      data-theme-now={theme}
      aria-label={name}
      title={name}
      onClick={toggle}
      className="inline-flex shrink-0 rounded-md p-1.5 text-text-3 hover:bg-surface-2 hover:text-text"
    >
      <Icon className="size-5" aria-hidden />
    </button>
  );
}
