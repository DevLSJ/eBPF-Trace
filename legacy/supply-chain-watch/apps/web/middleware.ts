import { NextResponse, type NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const authed = req.cookies.has('scw_session');
  const { pathname } = req.nextUrl;
  if (pathname === '/login') {
    if (authed) return NextResponse.redirect(new URL('/', req.url));
    return NextResponse.next();
  }
  if (!authed) {
    const url = new URL('/login', req.url);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  // 정적 자원·Next 내부 경로 제외
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
