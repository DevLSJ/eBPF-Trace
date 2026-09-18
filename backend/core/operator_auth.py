"""Individual identities, revocable HttpOnly sessions and CSRF-protected writes."""

import asyncio
import hashlib
import hmac
import secrets
from datetime import timedelta, timezone
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import HTTPException, Request
from sqlalchemy import delete, select

from backend.db.models import Operator, OperatorSession, utcnow

ROLES = {"viewer", "analyst", "responder", "approver", "admin"}
PERMISSIONS = {
    "read": ROLES,
    "investigate": {"analyst", "responder", "approver", "admin"},
    "respond": {"responder", "admin"},
    "approve": {"approver", "admin"},
    "admin": {"admin"},
}
COOKIE = "ebpf_operator"


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def aware(value):
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def password_hash(password):
    salt = secrets.token_hex(16)
    value = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return f"scrypt${salt}${value.hex()}"


def check_password(password, encoded):
    try:
        kind, salt, expected = encoded.split("$")
        if kind != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
        return hmac.compare_digest(actual.hex(), expected)
    except (ValueError, TypeError):
        return False


def check_transport(request):
    if request.url.scheme == "https":
        return
    settings = request.app.state.settings
    if settings.ops_allow_insecure_local and request.url.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
        "testserver",
    }:
        return
    raise HTTPException(403, "HTTPS is required for operator sessions")


def check_origin(request):
    origin = request.headers.get("origin")
    settings = request.app.state.settings
    allowed = {settings.public_base_url.rstrip("/"), *settings.allowed_origins.split(",")}
    if origin and origin.rstrip("/") not in allowed:
        raise HTTPException(403, "Untrusted request origin")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site session request rejected")
    if origin and urlparse(origin).scheme not in {"http", "https"}:
        raise HTTPException(403, "Invalid request origin")


def operator_dict(row):
    return {
        "id": row.id,
        "username": row.username,
        "name": row.name,
        "role": row.role,
        "active": row.active,
        "is_test_account": row.is_test_account,
        "slack_user_id": row.slack_user_id,
    }


def authorize(actor, permission):
    if not actor.active or actor.role not in PERMISSIONS[permission]:
        raise HTTPException(403, f"Permission required: {permission}")


async def current_operator(request: Request):
    check_transport(request)
    token = request.cookies.get(COOKIE, "")
    if not token:
        raise HTTPException(401, "Sign in with your operator account")
    async with request.app.state.db.sessions() as session:
        login = await session.get(OperatorSession, digest(token))
        if not login or aware(login.expires_at) <= utcnow():
            raise HTTPException(401, "Session expired; sign in again")
        actor = await session.get(Operator, login.operator_id)
        if (
            not actor
            or not actor.active
            or (actor.is_test_account and not request.app.state.settings.ops_test_account_mode)
        ):
            raise HTTPException(401, "Account is disabled")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            check_origin(request)
            csrf = request.headers.get("x-csrf-token", "")
            if not hmac.compare_digest(digest(csrf), login.csrf_hash):
                raise HTTPException(403, "CSRF token required")
        return actor


async def provision_operator(
    session, username, name, role, password, slack_user_id=None, *, test_account=False
):
    if test_account and (username, password, role) != ("admin", "admin", "admin"):
        raise ValueError("The restricted test identity must be admin/admin with the admin role")
    if role not in ROLES or (len(password) < 12 and not test_account):
        raise ValueError("A valid role and a password of at least 12 characters are required")
    row = await session.scalar(select(Operator).where(Operator.username == username))
    if row is None:
        row = Operator(id=str(uuid4()), username=username, name=name, role=role, active=True)
        session.add(row)
    row.name, row.role, row.active = name, role, True
    row.is_test_account = test_account
    row.password_hash = await asyncio.to_thread(password_hash, password)
    row.slack_user_id = slack_user_id
    await session.execute(delete(OperatorSession).where(OperatorSession.operator_id == row.id))
    await session.flush()
    return row


async def new_session(session, actor, hours):
    token = secrets.token_urlsafe(32)
    csrf = digest(token + ":csrf")
    session.add(
        OperatorSession(
            token_hash=digest(token),
            operator_id=actor.id,
            csrf_hash=digest(csrf),
            expires_at=utcnow() + timedelta(hours=hours),
        )
    )
    return token, csrf
