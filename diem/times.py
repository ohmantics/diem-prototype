"""Times as people read them: UTC, to the minute.   # draft: #lifecycle"""

from datetime import datetime, timezone


def moment(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def day(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d")


def validity_problem(record, now):
    """(why the emblem is not valid now, or None; a sentence about its validity period)

    The emblem's own validity period is the issuer's statement, and not the
    signatures' lifetime.
    """
    if "valid" not in record:
        return None, "the emblem carries no validity period"
    start, end = (moment_.seconds for moment_ in record["valid"])
    if now < start:
        return f"the emblem is not valid until {day(start)}", None
    if now > end:
        return f"the emblem's validity ended on {day(end)}", None
    return None, f"current ({day(now)} is within {day(start)} to {day(end)})"
