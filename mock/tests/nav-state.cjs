/* 10/21b 회귀 공통 — 목록 필터는 주소에 남지 않는다(화면 상태만).
   예전 검사가 「#/installs?status=all」처럼 주소로 필터를 넣던 곳은 필터 키를 상태로 떼어 화면 안 링크(UI.go(href, state))처럼 연다.
   주소에 남는 링크용 키: id · proposal · tab · view · node. 주소로 들어온 필터를 한 번 읽는 동작 자체는 url-1021.cjs 가 따로 본다 */
const LINK_KEYS = ['id', 'proposal', 'tab', 'view', 'node'];
// '/installs?status=all&id=x' → ['/installs?id=x', { status: 'all' }] (필터가 없으면 state = null)
function splitHash(hash) {
  const [p, qs] = String(hash).replace(/^#/, '').split('?');
  const keep = new URLSearchParams(), st = {};
  for (const [k, v] of new URLSearchParams(qs || '')) { if (LINK_KEYS.includes(k)) keep.set(k, v); else st[k] = v; }
  return [p + ([...keep].length ? '?' + keep.toString() : ''), Object.keys(st).length ? st : null];
}
// 이미 열린 페이지에서 화면 안 링크처럼 이동(필터는 상태로)
async function goState(pg, hash, wait = 450) {
  const [h, st] = splitHash(hash);
  await pg.evaluate(([x, s]) => UI.go('#' + x, s), [h, st]);
  await pg.waitForTimeout(wait);
}
module.exports = { LINK_KEYS, splitHash, goState };
