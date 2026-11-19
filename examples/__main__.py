"""Print every example record as the draft shows it, after checking its types.

python -m examples
"""

from diem import edn, profile
from examples.records import ALL


def heading(example):
    if example.plaintext:
        return f'plaintext of "{example.plaintext}", encrypted in the EMBLEM at {example.owner}'
    return f"{example.rrtype} at {example.owner}"


def verdict(example):
    checker = profile.load(example.profile_name)
    problems = checker.check_types(example.record, example.plaintext or None)
    if problems:
        return "; ".join(problems)
    if example.plaintext:
        return f"every value has the type profile {checker.name} gives it"
    return checker.describe_types(example.record)


def main():
    for example in ALL:
        print(f"/ {heading(example)}   (draft {example.anchor}) /")
        print(edn.render(example.record, key_spaces=example.key_spaces))
        print(f"/ {verdict(example)} /\n")


if __name__ == "__main__":
    main()
