import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// env 미지정 시 브라우저가 접속한 호스트의 :4000을 사용 → LAN IP(폰)로 접속해도 쿠키 호스트가 web과 일치
function sameHost(scheme: 'http' | 'ws'): string | undefined {
  if (typeof window === 'undefined') return undefined;
  const s = window.location.protocol === 'https:' ? `${scheme}s` : scheme;
  return `${s}://${window.location.hostname}:4000`;
}

export const GATEWAY_URL =
  process.env.NEXT_PUBLIC_GATEWAY_URL || sameHost('http') || 'http://localhost:4000';
export const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL || (sameHost('ws') ? `${sameHost('ws')}/ws` : 'ws://localhost:4000/ws');
