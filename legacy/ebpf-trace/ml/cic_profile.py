"""Explicit interpretation of the supplied CICIDS2017 TrafficLabelling export.

Monday uses second precision. Other supplied days use minute precision.
Both supplied formats use a working-hours 12-hour clock without AM/PM;
explicit 13–18 hour values are also accepted. Preserve source resolution.
"""

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

CAPTURE_DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")


def timestamp_uncertainty(value):
    return 1 if value.strip().count(":") == 2 else 60


@lru_cache(maxsize=4096)
def timestamp(value):
    precision = timestamp_uncertainty(value)
    parsed = datetime.strptime(value.strip(), "%d/%m/%Y %H:%M:%S" if precision == 1 else "%d/%m/%Y %H:%M")
    if parsed.hour < 8:
        parsed = parsed.replace(hour=parsed.hour + 12)
    if not (8 <= parsed.hour <= 18 and parsed.year == 2017 and parsed.month == 7
            and 3 <= parsed.day <= 7):
        raise ValueError("Outside CICIDS2017 working-hours capture")
    return parsed.replace(tzinfo=ZoneInfo("America/Halifax")).timestamp()


def belongs_to_capture(name, day):
    return Path(name).name.lower().startswith(day.lower() + "-")
