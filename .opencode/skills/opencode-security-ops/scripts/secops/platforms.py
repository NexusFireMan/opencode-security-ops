"""Generic platform metadata; no platform API access or submission automation."""

from __future__ import annotations


PROFILES = {
    "hackerone": {
        "display_name": "HackerOne",
        "ratings": ["critical", "high", "medium", "low", "none"],
        "closure_labels": ["duplicate", "informative", "not-applicable", "spam", "resolved"],
    },
    "bugcrowd": {
        "display_name": "Bugcrowd",
        "ratings": ["p1", "p2", "p3", "p4", "p5"],
        "closure_labels": ["duplicate", "not-applicable", "out-of-scope", "wont-fix", "resolved"],
    },
    "yeswehack": {
        "display_name": "YesWeHack",
        "ratings": ["critical", "high", "medium", "low", "info"],
        "closure_labels": ["duplicate", "rtfs", "out-of-scope", "wont-fix", "resolved"],
    },
    "intigriti": {
        "display_name": "Intigriti",
        "ratings": ["critical", "high", "medium", "low", "informational"],
        "closure_labels": ["duplicate", "not-applicable", "out-of-scope", "accepted", "resolved"],
    },
    "private": {
        "display_name": "Private engagement",
        "ratings": ["critical", "high", "medium", "low", "informational"],
        "closure_labels": ["accepted", "risk-accepted", "fixed", "duplicate", "out-of-scope"],
    },
    "other": {
        "display_name": "Other / unspecified",
        "ratings": [],
        "closure_labels": [],
    },
}


def normalize_platform(value: str) -> str:
    normalized = value.strip().lower().replace(" ", "").replace("-", "")
    aliases = {
        "h1": "hackerone", "hackerone": "hackerone",
        "bc": "bugcrowd", "bugcrowd": "bugcrowd",
        "ywh": "yeswehack", "yeswehack": "yeswehack",
        "intigriti": "intigriti", "private": "private", "other": "other",
    }
    if normalized not in aliases:
        raise ValueError(f"unsupported platform: {value}")
    return aliases[normalized]


def profile(value: str) -> dict:
    platform = normalize_platform(value)
    return {"id": platform, **PROFILES[platform]}


def validate_platform_rating(platform: str, rating: str | None) -> None:
    if not rating:
        return
    allowed = PROFILES[normalize_platform(platform)]["ratings"]
    if allowed and rating.lower() not in allowed:
        raise ValueError(f"invalid {platform} rating {rating!r}; expected one of: {', '.join(allowed)}")


def validate_intake(data: dict) -> dict:
    if data.get("version") != 1:
        raise ValueError("intake.version must be 1")
    platform = normalize_platform(data.get("platform", "other"))
    program = data.get("program")
    if not isinstance(program, str) or not program.strip():
        raise ValueError("intake.program is required")
    constraints = data.get("constraints", {})
    if not isinstance(constraints, dict):
        raise ValueError("intake.constraints must be an object")
    allowed = {
        "submission_limit", "user_agent", "account_requirements", "automation_rules",
        "rate_limit_note", "excluded_techniques", "notes",
    }
    unknown = set(constraints) - allowed
    if unknown:
        raise ValueError(f"unknown intake constraint(s): {sorted(unknown)}")
    for key, value in constraints.items():
        if key == "submission_limit":
            if not isinstance(value, int) or value < 0:
                raise ValueError("constraints.submission_limit must be a non-negative integer")
        elif key == "excluded_techniques":
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError("constraints.excluded_techniques must be a list of strings")
        elif not isinstance(value, str):
            raise ValueError(f"constraints.{key} must be a string")
    return {**data, "platform": platform, "program": program.strip()}
