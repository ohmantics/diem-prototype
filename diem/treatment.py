"""What an emblem asks of the person who reads it.   # draft: #treatment

Treatment says what a modality (prohibit, request, require) applies to. What
to do about it is for the validator's framework to decide, not this protocol;
this only says it in words.
"""

from dataclasses import replace

from diem import names

REQUESTS = {"prohibit": "do not {}", "request": "{} (requested)", "require": "you must {}"}


def asks(record, key="treatment"):
    """One sentence for the entries under a map key, with the basis the emblem cites."""
    requests = [
        REQUESTS[modality].format(action)
        for entry in record.get(key, [])
        for modality, action in entry.items()
    ]
    cited = [entry["text"].text for entry in record.get("basis", []) if "text" in entry]
    if not requests:
        return ""
    return f"It asks: {', '.join(requests)}" + (
        f" ({'; '.join(cited)})." if cited else "."
    )


def say_what_to_do(out, task, source, now, check):
    """An emblem that does not validate cannot be trusted, nor can any instructions on it.

    The profile says where its issuer publishes what to do instead: an emblem of
    its own, validated separately by check (draft #ex-peacekeepers).
    """
    name = names.emblem_zone(task.emblem_name)
    issuer = check(
        replace(
            task,
            emblem_name=name,
            how_named="the emblem zone of the name that failed",
            profile=None,
            evidence={},
            needs=(),
            trail=(task.emblem_name,),
        ),
        source,
        now,
    )
    if issuer.result != "valid":
        why = issuer.steps[-1].text
        out.notes.append(
            f"The issuer's own emblem at {name} is not usable either: {why}"
        )
        return
    contact = issuer.record.get("contact")
    out.notes.append(
        f"Nothing on an emblem that does not validate can be trusted, including any "
        f"instructions. The issuer's own emblem at {name}, validated separately, says "
        f"what to do. {asks(issuer.record, 'if-invalid')}"
        + (f" Contact: {contact.uri}." if contact else "")
    )
