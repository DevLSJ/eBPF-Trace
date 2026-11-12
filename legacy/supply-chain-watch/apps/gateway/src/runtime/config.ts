// 런타임 축 운영 설정 (docs/13 §12 설정 "런타임" 탭). gateway 메모리 보관 — 데모 단순화.
let autoBlock = false;
let currentWhitelist: unknown = null;

export const getAutoBlock = (): boolean => autoBlock;
export const setAutoBlock = (v: boolean): void => {
  autoBlock = v;
};
export const getWhitelist = (): unknown => currentWhitelist;
export const setWhitelist = (w: unknown): void => {
  currentWhitelist = w;
};
