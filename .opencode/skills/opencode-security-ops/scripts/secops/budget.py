"""Hard-stop time budget helpers."""

from datetime import datetime, timedelta, timezone


def stop_at(minutes: int) -> str:
    if minutes <= 0:
        raise ValueError("minutes must be positive")
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def budget_status(stop_at_value: str, now: datetime | None = None) -> dict:
    end = datetime.fromisoformat(stop_at_value)
    if end.tzinfo is None:
        raise ValueError("stop_at must include a timezone")
    current = now or datetime.now(timezone.utc)
    remaining = max(0, int((end - current).total_seconds()))
    return {
        "expired": remaining == 0,
        "remaining_seconds": remaining,
        "directive": "STOP_ACTIVE_WORK_AND_HANDOFF" if remaining == 0 else "CONTINUE_WITHIN_SCOPE",
    }
