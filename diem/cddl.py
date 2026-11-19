"""Reading the profiles' CDDL.   # draft: #profiles, #validation

CDDL (RFC 8610) is the published schema of a profile, and step 4 of the
validation outline checks each value against it (diem/type_checks.py). This
reader understands the subset the files in profiles/ use and nothing more:
named rules, choices (/), maps whose members are `name: type` or
`type => type`, arrays, the occurrences ? + *, literals, tags (#6.n(type)),
.size and .regexp. Rules come back as small tuples: ("map", members),
("array", members), ("choice", alternatives), ("tag", number, type),
("literal", text), ("regexp", pattern), ("size", low, high), ("name", name).
"""

import re

_TOKEN = re.compile(
    r'\s+|;[^\n]*|"(?:[^"\\]|\\.)*"|#6\.\d+|=>|\.\.|[={}\[\](),:/?+*]|\d+|[A-Za-z.][\w.-]*'
)


def _tokens(text):
    position, tokens = 0, []
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None:
            raise ValueError(f"cannot read CDDL at {text[position:position + 20]!r}")
        position = match.end()
        if not match.group().isspace() and not match.group().startswith(";"):
            tokens.append(match.group())
    return tokens


def _unquote(token):
    return re.sub(r"\\(.)", r"\1", token[1:-1])


class _Parser:
    """Turns tokens into rules: a dict from a name to a tuple tree like ("map", members)."""

    def __init__(self, tokens):
        self.tokens, self.at = tokens, 0

    def peek(self, ahead=0):
        return (
            self.tokens[self.at + ahead] if self.at + ahead < len(self.tokens) else ""
        )

    def take(self, expected=None):
        token = self.peek()
        if expected is not None and token != expected:
            raise ValueError(f"CDDL: expected {expected!r}, found {token!r}")
        self.at += 1
        return token

    def rules(self):
        rules = {}
        while self.peek():
            name = self.take()
            self.take("=")
            rules[name] = self.type()
        return rules

    def type(self):
        alternatives = [self.alternative()]
        while self.peek() == "/":
            self.take()
            alternatives.append(self.alternative())
        return alternatives[0] if len(alternatives) == 1 else ("choice", alternatives)

    def alternative(self):
        token = self.take()
        if token.startswith('"'):
            return ("literal", _unquote(token))
        if token.startswith("#6."):
            self.take("(")
            content = self.type()
            self.take(")")
            return ("tag", int(token[3:]), content)
        if token == "{":
            return ("map", self.members("}"))
        if token == "[":
            return ("array", self.members("]"))
        if self.peek() == ".regexp":
            self.take()
            return ("regexp", _unquote(self.take()))
        if self.peek() == ".size":
            return self.size()
        return ("name", token)

    def size(self):
        self.take()
        ranged = self.peek() == "("
        if ranged:
            self.take()
        low = high = int(self.take())
        if ranged:
            self.take("..")
            high = int(self.take())
            self.take(")")
        return ("size", low, high)

    def members(self, close):
        """(occurrence, key, type) for each member; the key is None in an array."""
        members = []
        while self.peek() != close:
            occurrence = self.take() if self.peek() in ("?", "+", "*") else ""
            key = None
            if self.peek(1) == ":":
                name = self.take()
                key = ("literal", _unquote(name) if name.startswith('"') else name)
                self.take()
                value = self.type()
            else:
                value = self.type()
                if self.peek() == "=>":
                    self.take()
                    key, value = value, self.type()
            members.append((occurrence, key, value))
            if self.peek() == ",":
                self.take()
        self.take(close)
        return members


def read_rules(directory):
    text = "".join(path.read_text() for path in sorted(directory.glob("*.cddl")))
    return _Parser(_tokens(text)).rules()
