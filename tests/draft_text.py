"""Reading the draft's own diagnostic notation, to compare with what the code prints.

The draft is looked for next to this repository, or at $DIEM_DRAFT.
"""

import os
import re
from pathlib import Path

DEFAULT = (
    Path(__file__).resolve().parents[2]
    / "diem-architecture"
    / "draft-rosenberg-diem-architecture.md"
)
DRAFT = Path(os.environ.get("DIEM_DRAFT", DEFAULT))
BLOCK = re.compile(r"~~~ cbor-diag\n(.*?)\n~~~", re.S)


def available():
    return DRAFT.exists()


def blocks(section_start, section_end=None):
    """The cbor-diag blocks between two headings."""
    text = DRAFT.read_text()
    start = text.index(section_start)
    end = text.index(section_end, start) if section_end else len(text)
    return BLOCK.findall(text[start:end])


def strip_comments(text):
    """Remove /.../ comments, taking each to run to the end of its line.

    The draft's examples never continue a line after a comment, and
    sometimes put a slash inside one (UN/LOCODE).
    """
    return "\n".join(_strip_line(line) for line in text.splitlines())


def _strip_line(line):
    kept, quoted = [], False
    for i, char in enumerate(line):
        if char == '"' and (i == 0 or line[i - 1] != "\\"):
            quoted = not quoted
        if char == "/" and not quoted:
            break
        kept.append(char)
    return "".join(kept)


def squeeze(text):
    """Remove whitespace that is outside strings."""
    out, quoted = [], False
    for i, char in enumerate(text):
        if char == '"' and (i == 0 or text[i - 1] != "\\"):
            quoted = not quoted
        if quoted or not char.isspace():
            out.append(char)
    return "".join(out)


def maps(block):
    """The top-level maps in a block, comments removed, whitespace squeezed."""
    text, depth, quoted, found, start = squeeze(strip_comments(block)), 0, False, [], 0
    for i, char in enumerate(text):
        if char == '"' and text[i - 1] != "\\":
            quoted = not quoted
        if quoted:
            continue
        if char == "{":
            start = i if depth == 0 else start
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                found.append(text[start : i + 1])
    return found
