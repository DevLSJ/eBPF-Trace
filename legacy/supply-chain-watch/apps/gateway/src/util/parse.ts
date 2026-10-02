// "owner/repo" | "https://github.com/owner/repo(.git)" | "github.com/owner/repo" → {owner,name}
export function parseRepoInput(input: string): { owner: string; name: string } | null {
  const s = input.trim();
  const m = s.match(/(?:github\.com\/)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[#?].*)?$/);
  if (!m) return null;
  const owner = m[1];
  const name = m[2];
  if (!owner || !name || owner === 'github.com') return null;
  return { owner, name };
}
