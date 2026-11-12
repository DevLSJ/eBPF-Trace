import logging

import httpx

logger = logging.getLogger(__name__)
# HTTPX logs full request URLs at INFO; webhook paths contain credentials.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


async def send_alert(webhook: str, event: dict) -> bool:
    if not webhook or event["severity"] != "critical":
        return False
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                webhook,
                json={
                    "text": (
                        f"[eBPF Trace] CRITICAL {event['attack_type']} | "
                        f"{event['flow']['src_ip']} → {event['flow']['dst_ip']} | "
                        f"{event['detected_at']} | event #{event['event_id']}"
                    )
                },
            )
            response.raise_for_status()
            if response.text.strip() != "ok":
                logger.error(
                    "Slack returned an unexpected response for event %s", event["event_id"]
                )
                return False
            logger.info(
                "Slack delivered for event %s (HTTP %s)", event["event_id"], response.status_code
            )
            return True
    except Exception as error:
        # URLs contain credentials: do not log the exception or request URL.
        logger.error("Slack delivery failed (%s)", type(error).__name__)
        return False
