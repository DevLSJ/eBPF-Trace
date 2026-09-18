"""Leased PostgreSQL/SQLite outbox; provider acceptance is not human acknowledgement."""

import asyncio
import logging
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage
from uuid import uuid4

import httpx
from sqlalchemy import select, update

from backend.db.models import Incident, NotificationDelivery, utcnow
from backend.services.incidents import CLOSED, audit, queue_notifications
from backend.services.response import sweep_responses

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
MAX_ATTEMPTS = 5


def slack_message(row):
    p = row.payload
    text = f"[eBPF Trace] {p['priority']} · {p['title']} · {p['kind']}"
    return {
        "channel": row.destination,
        "text": text,
        "client_msg_id": row.id,
        "unfurl_links": False,
        "unfurl_media": False,
        "blocks": [
            {"type": "section", "text": {"type": "plain_text", "text": text}},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "plain_text",
                        "text": f"LIVE · {p['asset']} · 사건 {p['incident_id']} · 담당자 확인 필요",
                    }
                ],
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "확인하고 맡기"},
                        "action_id": "incident_ack",
                        "value": p["incident_id"],
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "사건 조사"},
                        "url": p["url"],
                    },
                ],
            },
        ],
    }


def send_email(settings, row):
    message = EmailMessage()
    p = row.payload
    message["Subject"] = f"[eBPF Trace] {p['priority']} {p['title']}"
    message["From"], message["To"] = settings.smtp_from, row.destination
    message["Message-ID"] = f"<{row.id}@ebpf-trace.local>"
    message.set_content(
        f"{p['title']}\nPriority: {p['priority']}\nIncident: {p['incident_id']}\n"
        f"Open the authenticated workspace to acknowledge or investigate:\n{p['url']}\n"
    )
    context = ssl.create_default_context()
    if settings.smtp_port == 465:
        server = smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=10, context=context
        )
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
    with server:
        if settings.smtp_port != 465:
            server.starttls(context=context)
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password.get_secret_value())
        refused = server.send_message(message)
        if refused:
            return {"status": "failed", "error": "Recipient rejected by mail server"}
    return {"status": "provider_accepted", "provider_id": str(message["Message-ID"])}


async def deliver(settings, row):
    if not settings.ops_notifications_enabled or row.payload.get("source") != "live":
        return {"status": "not_configured", "error": "External delivery disabled"}
    try:
        if row.channel == "email":
            return await asyncio.to_thread(send_email, settings, row)
        if row.channel != "slack" or not settings.slack_bot_token.get_secret_value():
            return {"status": "not_configured", "error": "Channel not configured"}
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            response = await client.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {settings.slack_bot_token.get_secret_value()}"},
                json=slack_message(row),
            )
        if response.status_code == 429:
            try:
                delay = max(1, min(86400, int(response.headers.get("retry-after", "60"))))
            except ValueError:
                delay = 60
            return {"status": "retrying", "error": "Provider rate limit", "delay": delay}
        if response.status_code >= 500:
            return {"status": "unknown", "error": "Provider server error; acceptance not confirmed"}
        if response.status_code >= 400:
            return {"status": "failed", "error": f"Provider HTTP {response.status_code}"}
        data = response.json()
        if data.get("ok") is not True:
            return {"status": "failed", "error": "Slack rejected delivery"}
        return {"status": "provider_accepted", "provider_id": str(data.get("ts", ""))}
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return {"status": "retrying", "error": "Could not connect to provider"}
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPRecipientsRefused):
        return {"status": "failed", "error": "Mail authentication or recipient rejected"}
    except Exception:
        # An interrupted response may follow successful acceptance. Never claim exactly-once.
        return {
            "status": "unknown",
            "error": "Delivery result unknown; inspect provider before retry",
        }


async def claim(db):
    now, lease = utcnow(), str(uuid4())
    async with db.sessions() as session:
        # A crashed sender might have reached the provider: do not blindly send it twice.
        await session.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.status == "sending", NotificationDelivery.lease_until < now)
            .values(
                status="unknown",
                lease_token=None,
                last_error="Worker lease expired; provider acceptance unknown",
            )
        )
        row = await session.scalar(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.status.in_(["queued", "retrying"]),
                NotificationDelivery.next_attempt_at <= now,
            )
            .order_by(NotificationDelivery.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if row is None:
            await session.commit()
            return None
        result = await session.execute(
            update(NotificationDelivery)
            .where(
                NotificationDelivery.id == row.id,
                NotificationDelivery.status.in_(["queued", "retrying"]),
            )
            .values(
                status="sending",
                lease_token=lease,
                lease_until=now + timedelta(seconds=60),
                attempts=NotificationDelivery.attempts + 1,
            )
        )
        if result.rowcount != 1:
            await session.rollback()
            return None
        await session.commit()
        await session.refresh(row)
        return row


async def finish(db, row, outcome):
    async with db.sessions() as session:
        status = outcome["status"]
        if status == "retrying" and row.attempts >= MAX_ATTEMPTS:
            status = "failed"
        delay = outcome.get("delay", min(900, 2**row.attempts * 5))
        result = await session.execute(
            update(NotificationDelivery)
            .where(
                NotificationDelivery.id == row.id,
                NotificationDelivery.status == "sending",
                NotificationDelivery.lease_token == row.lease_token,
            )
            .values(
                status=status,
                lease_token=None,
                lease_until=None,
                last_error=outcome.get("error"),
                provider_id=outcome.get("provider_id"),
                next_attempt_at=utcnow() + timedelta(seconds=delay),
                accepted_at=utcnow() if status == "provider_accepted" else None,
            )
        )
        if result.rowcount:
            audit(
                session,
                "notification." + status,
                {
                    "delivery_id": row.id,
                    "channel": row.channel,
                    "attempt": row.attempts,
                    "error": outcome.get("error"),
                },
                incident_id=row.incident_id,
            )
        await session.commit()


async def maintenance(app):
    async with app.state.db.sessions() as session:
        from backend.services.rehearsal import tick

        await tick(session, app.state.settings)
        now = utcnow()
        rows = list(
            await session.scalars(
                select(Incident).where(
                    Incident.status.not_in(CLOSED),
                    Incident.acknowledged_at.is_(None),
                    Incident.ack_due_at < now,
                    Incident.escalated_at.is_(None),
                )
            )
        )
        for row in rows:
            result = await session.execute(
                update(Incident)
                .where(Incident.id == row.id, Incident.escalated_at.is_(None))
                .values(escalated_at=now)
            )
            if result.rowcount:
                await queue_notifications(session, row, app.state.settings, "escalated")
                audit(
                    session,
                    "incident.escalated",
                    {"reason": "Acknowledgement deadline exceeded"},
                    incident_id=row.id,
                )
        await sweep_responses(session, app.state.settings)
        await session.commit()


async def work_once(app, sender=None):
    await maintenance(app)
    row = await claim(app.state.db)
    if row:
        # Do not call providers from simulations or when disabled, even with an injected sender.
        if row.payload.get("source") != "live" or not app.state.settings.ops_notifications_enabled:
            outcome = {"status": "not_configured", "error": "External delivery disabled"}
        else:
            outcome = await (sender or deliver)(app.state.settings, row)
        await finish(app.state.db, row, outcome)
    return row is not None


async def worker(app):
    while True:
        try:
            busy = await work_once(app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Operations worker cycle failed; durable jobs retained")
            busy = False
        await asyncio.sleep(0.2 if busy else 2)
