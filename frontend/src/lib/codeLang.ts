// 코드 창 종류 태그(11/04f 목업 U.codeLang) — lang 이 있으면 그 이름(별칭 정리), 없으면 파일명 확장자에서. 모르면 text
const LANGS: [RegExp, string][] = [
  [/\.py$/i, 'python'],
  [/\.ya?ml$/i, 'YAML'],
  [/\.json$/i, 'JSON'],
  [/\.(sh|bash)$/i, 'shell'],
  [/\.log$/i, 'log'],
  [/\.[cm]?js$/i, 'javascript'],
  [/\.tsx?$/i, 'typescript'],
  [/\.toml$/i, 'TOML'],
  [/\.rs$/i, 'rust'],
  [/\.(cfg|ini)$/i, 'ini'],
  [/\.txt$/i, 'text'],
];
const ALIAS: Record<string, string> = {
  py: 'python',
  python: 'python',
  yaml: 'YAML',
  yml: 'YAML',
  json: 'JSON',
  sh: 'shell',
  bash: 'shell',
  shell: 'shell',
  log: 'log',
  js: 'javascript',
  javascript: 'javascript',
  ts: 'typescript',
  typescript: 'typescript',
  toml: 'TOML',
  text: 'text',
  txt: 'text',
};
export function codeLang(name?: string | null, lang?: string | null): string {
  if (lang) return ALIAS[lang.toLowerCase()] ?? lang;
  const hit = name ? LANGS.find(([re]) => re.test(name)) : undefined;
  return hit ? hit[1] : 'text';
}
