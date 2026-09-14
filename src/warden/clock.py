"""Injectable clocks, so the server, not the caller, decides what time it is."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


class Clock(Protocol):

    def now(self) -> datetime: ...


@dataclass(frozen=True)
class FixedClock:

    instant: datetime

    def now(self) -> datetime:
        if self.instant.tzinfo is None:
            return self.instant.replace(tzinfo=timezone.utc)
        return self.instant.astimezone(timezone.utc)


@dataclass(frozen=True)
class SystemClock:

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
