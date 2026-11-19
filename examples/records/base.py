"""What each example record carries besides its data."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Example:
    anchor: str  # the draft section the record appears in
    rrtype: str  # EMBLEM or ENDORSE
    owner: str  # the DNS name it is published at (for a plaintext, the ciphertext's)
    record: dict
    profile: str = ""  # needed only for a plaintext, which has no "profile" key
    plaintext: str = ""  # the name of the encrypted value this is the plaintext of

    @property
    def profile_name(self):
        return self.profile or self.record["profile"]

    @property
    def key_spaces(self):
        return (self.plaintext,) if self.plaintext else None
