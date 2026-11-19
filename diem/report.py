"""Plain-language printing of a walkthrough.   # draft: #examples

Output is for people: names, records in diagnostic notation, and every
validation step with its result in a sentence. Names of zones and of records
are printed as absolute names, with the final dot; names inside sentences are
printed without it.
"""

import copy
import re
import textwrap

from diem import edn
from diem.outcome import STEP_NAMES

STEP_INDENT = 18
NAME_WIDTH = 13  # the longest step name


def heading(text):
    """A paragraph; a timestamp in parentheses is never broken across lines."""
    fixed = re.sub(
        r"\((\d{4}-\d\d-\d\d) (\d\d:\d\d) UTC\)", "(\\1\u00a0\\2\u00a0UTC)", text
    )
    print("\n" + textwrap.fill(fixed, width=79).replace("\u00a0", " "))


def hierarchy(hierarchy):
    heading(
        "The DNS hierarchy in this example (simulated: its root is not the real root, "
        "and every key is derived from a public name, so worthless)"
    )
    width = max(len(name) for name, _ in hierarchy.outline()) + 2
    for name, role in hierarchy.outline():
        print(f"  {name:<{width}}{role}")


def _absolute(name):
    return name if name.endswith(".") else name + "."


def published(owner, rrtype, record):
    print(f"  {_absolute(owner)}  {rrtype}")
    print(textwrap.indent(edn.render(record), "    "))


def listed(owner, rrtype, what):
    print(f"  {_absolute(owner)}  {rrtype}  ({what})")


def outcome(outcome, first=None):
    """Print the steps; stretches that are as in the first run are each summarized in one line."""
    earlier = {step.number: step for step in first.steps} if first else {}
    same = []
    for step in outcome.steps:
        if earlier.get(step.number) == step:
            same.append(step.number)
            continue
        _as_before(same)
        same = []
        _step(step, first)
    _as_before(same)
    _ending(outcome)


def _ending(result):
    if result.result != "valid":
        print(
            f"{' ' * STEP_INDENT}=> {result.result.upper()} at step {result.ended_at}"
        )
    for note in result.notes:
        print()
        _say(note)


def _step(step, first):
    label = f"{step.number:>3} {STEP_NAMES[step.number]:<{NAME_WIDTH}} "
    print(
        textwrap.fill(
            step.text,
            width=79,
            initial_indent=label,
            subsequent_indent=" " * STEP_INDENT,
        )
    )
    shared = _shared_details(step, first)
    if shared:
        _say(f"({shared} lines as in the first run)", " " * STEP_INDENT)
    for line in step.details[shared:]:
        _say(line, " " * STEP_INDENT)


def _range(numbers):
    """'Step 3', 'Steps 3 and 4' or 'Steps 3 to 7'."""
    if len(numbers) == 1:
        return f"Step {numbers[0]}"
    joiner = "and" if len(numbers) == 2 else "to"
    return f"Steps {numbers[0]} {joiner} {numbers[-1]}"


def _as_before(numbers):
    if numbers:
        print(f"{_range(numbers)} as in the first run.")


def _shared_details(step, first):
    """How many lines under a step are as under the same step of the first run, when its text is."""
    earlier = (
        next((s for s in first.steps if s.number == step.number), None)
        if first
        else None
    )
    if earlier is None or earlier.text != step.text:
        return 0
    count = 0
    for line, before in zip(step.details, earlier.details):
        if line != before:
            break
        count += 1
    return count


def who_saw(log, emblem_name):
    """Which servers were asked, and which saw the emblem's own label, in any name."""
    if not log:
        print("\n  Who saw a query: nobody. A bundle or a cache held everything.")
        return
    label = emblem_name.split(".")[0]
    servers = list(dict.fromkeys(query.server for query in log))
    named = list(
        dict.fromkeys(
            query.server
            for query in log
            if label in query.name.to_text(omit_final_dot=True).split(".")
        )
    )
    only = "only " if len(named) == 1 and len(servers) > 1 else ""
    saw = f"{only}{_join(named)} saw" if named else "none of them saw"
    print()
    _say(f"Who saw a query: {_join(servers)}; {saw} the emblem's own label.")


def _say(text, indent="  "):
    print(
        textwrap.fill(
            text, width=79, initial_indent=indent, subsequent_indent=indent + "  "
        )
    )


def _join(items):
    return ", ".join(items[:-1]) + (" and " if len(items) > 1 else "") + items[-1]


def opened(outcome):
    """What a validator read from the values that were encrypted to it."""
    for key, plaintext in outcome.opened.items():
        print(f'\n  Decrypted "{key}":')
        print(textwrap.indent(edn.render(plaintext, key_spaces=(key,)), "    "))


def brief(result, keep=()):
    """A run whose other steps pass as expected: the steps in keep and the last are
    printed, and the rest are said to pass."""
    shown = copy.copy(result)
    passing = [s.number for s in result.steps[:-1] if s.number not in keep]
    shown.steps = [s for s in result.steps[:-1] if s.number in keep] + result.steps[-1:]
    for step in shown.steps:
        before = [n for n in passing if n < step.number]
        passing = [n for n in passing if n >= step.number]
        if before:
            print(f"{_range(before)} pass{'es' if len(before) == 1 else ''}.")
        _step(step, None)
    _ending(result)
