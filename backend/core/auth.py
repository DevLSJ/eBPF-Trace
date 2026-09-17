import secrets

from fastapi import Header, HTTPException, Request


async def require_admin(request: Request, authorization: str = Header(default='')):
    expected = request.app.state.settings.admin_token.get_secret_value()
    if not expected or not secrets.compare_digest(authorization, f'Bearer {expected}'):
        raise HTTPException(401, 'Administrator token required')
