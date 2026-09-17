"""Explicit interpretation of the supplied CICIDS2017 TrafficLabelling export.

This export has minute precision and a 12-hour clock without AM/PM. The known
working-hours capture spans 08:00–18:00 America/Halifax; 01–07 mean afternoon.
The interval is uncertain by 60 seconds. Never treat :00 as an exact start.
"""

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo


@lru_cache(maxsize=4096)
def timestamp(value):
    parsed = datetime.strptime(value.strip(), "%d/%m/%Y %H:%M")
    if parsed.hour < 8:
        parsed = parsed.replace(hour=parsed.hour + 12)
    if not (8 <= parsed.hour <= 18 and parsed.year == 2017 and parsed.month == 7
            and 3 <= parsed.day <= 7):
        raise ValueError("Outside CICIDS2017 working-hours capture")
    return parsed.replace(tzinfo=ZoneInfo("America/Halifax")).timestamp()


def belongs_to_capture(name, day):
    return Path(name).name.lower().startswith(day.lower() + "-")
