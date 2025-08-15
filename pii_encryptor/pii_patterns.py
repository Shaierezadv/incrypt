import re
from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class PIIMatch:
    kind: str
    value: str
    start: int
    end: int


# Regex patterns tuned to minimize false positives while covering common cases
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# E.164 like +972501234567 or local formats like 050-123-4567, 03-1234567
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:0?\d{1,3}[\s-]?)?\d{3}[\s-]?\d{4}(?:\d{0,3})\b")
# Credit card 13-19 digits with optional spaces/dashes, Luhn-validated later
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
# Israeli Teudat Zehut (9 digits) heuristic
IL_ID_RE = re.compile(r"\b\d{9}\b")


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _is_valid_il_id(number: str) -> bool:
    if not re.fullmatch(r"\d{9}", number):
        return False
    digits = [int(ch) for ch in number]
    total = 0
    for idx, d in enumerate(digits):
        mult = 1 if idx % 2 == 0 else 2
        val = d * mult
        if val > 9:
            val -= 9
        total += val
    return total % 10 == 0


def iter_pii(text: str) -> Iterable[PIIMatch]:
    for m in EMAIL_RE.finditer(text):
        yield PIIMatch(kind="email", value=m.group(0), start=m.start(), end=m.end())
    for m in PHONE_RE.finditer(text):
        yield PIIMatch(kind="phone", value=m.group(0), start=m.start(), end=m.end())
    for m in CC_RE.finditer(text):
        raw = m.group(0)
        digits = ''.join(ch for ch in raw if ch.isdigit())
        if _luhn_check(digits):
            yield PIIMatch(kind="credit_card", value=raw, start=m.start(), end=m.end())
    for m in IL_ID_RE.finditer(text):
        if _is_valid_il_id(m.group(0)):
            yield PIIMatch(kind="il_id", value=m.group(0), start=m.start(), end=m.end())


def find_all_pii(text: str) -> List[PIIMatch]:
    return sorted(list(iter_pii(text)), key=lambda x: x.start)