"""Password generator and strength checker."""

import math
import random
import secrets
import string
from pathlib import Path

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"
AMBIGUOUS = "Il1O0o"
MIN_LENGTH = 8
MAX_LENGTH = 128
COMMON_FILE = Path(__file__).with_name("common_passwords.txt")

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_LEET = str.maketrans({
    "@": "a",
    "0": "o",
    "3": "e",
    "$": "s",
    "5": "s",
    "!": "i",
    "7": "t",
    "1": "i",
})


class PasswordGenerationError(Exception):
    pass


class StrengthResult:
    def __init__(self, rating, score, entropy_bits, is_common, suggestions):
        self.rating = rating
        self.score = score
        self.entropy_bits = entropy_bits
        self.is_common = is_common
        self.suggestions = suggestions


def generate_password(length=16, use_upper=True, use_lower=True,
                     use_digits=True, use_symbols=True,
                     exclude_ambiguous=False):
    if not isinstance(length, int):
        raise PasswordGenerationError("Length must be a whole number.")
    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise PasswordGenerationError(
            "Length must be between %s and %s." % (MIN_LENGTH, MAX_LENGTH)
        )

    pools = []
    checks = [
        (use_upper, string.ascii_uppercase),
        (use_lower, string.ascii_lowercase),
        (use_digits, string.digits),
        (use_symbols, SYMBOLS),
    ]

    for enabled, chars in checks:
        if enabled:
            pool = chars
            if exclude_ambiguous:
                pool = ""
                for ch in chars:
                    if ch not in AMBIGUOUS:
                        pool += ch
            pools.append(pool)

    if not pools:
        raise PasswordGenerationError("Choose at least one character type.")

    chars = []
    for pool in pools:
        chars.append(secrets.choice(pool))

    all_chars = ""
    for pool in pools:
        all_chars += pool

    while len(chars) < length:
        chars.append(secrets.choice(all_chars))

    random.shuffle(chars)
    return "".join(chars)


def load_common_passwords():
    try:
        text = COMMON_FILE.read_text(encoding="utf-8")
    except OSError:
        return set()

    words = set()
    for line in text.splitlines():
        word = line.strip().lower()
        if word:
            words.add(word)
    return words


def _is_common(password, common):
    lowered = password.lower()
    stripped = lowered.rstrip(string.digits + string.punctuation)
    parts = [lowered, stripped]

    leet = lowered.translate(_LEET)
    parts.append(leet)
    parts.append(leet.rstrip(string.digits + string.punctuation))

    for item in parts:
        if item and item in common:
            return True
    return False


def _has_repeats(password, run=3):
    if len(password) < run:
        return False

    for i in range(0, len(password) - run + 1):
        chunk = password[i:i + run]
        first = chunk[0]
        same = True
        for ch in chunk:
            if ch != first:
                same = False
                break
        if same:
            return True
    return False


def _has_sequence(password, run=4):
    lowered = password.lower()
    for i in range(0, len(lowered) - run + 1):
        chunk = lowered[i:i + run]
        codes = []
        for ch in chunk:
            codes.append(ord(ch))

        steps = set()
        for a, b in zip(codes, codes[1:]):
            steps.add(b - a)

        if steps == {1} or steps == {-1}:
            return True

        for row in _KEYBOARD_ROWS:
            if chunk in row or chunk[::-1] in row:
                return True
    return False


def _entropy_bits(password):
    pool = 0
    if any(ch.islower() for ch in password):
        pool += 26
    if any(ch.isupper() for ch in password):
        pool += 26
    if any(ch.isdigit() for ch in password):
        pool += 10
    if any(not ch.isalnum() for ch in password):
        pool += 32

    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def check_strength(password, common=None):
    if common is None:
        common = load_common_passwords()

    if password == "":
        return StrengthResult("Weak", 0, 0.0, False, ["Password cannot be empty."])

    # Score depends on length and the types of characters used.
    n = len(password)
    has_lower = any(ch.islower() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    classes = 0
    if has_lower:
        classes += 1
    if has_upper:
        classes += 1
    if has_digit:
        classes += 1
    if has_symbol:
        classes += 1

    if n < 8:
        score = 0
    elif n < 12:
        score = 1
    elif n < 16:
        score = 2
    elif n < 20:
        score = 3
    else:
        score = 4

    score += classes
    is_common = _is_common(password, common)
    repeats = _has_repeats(password)
    sequence = _has_sequence(password)
    score -= int(repeats) + int(sequence)
    if score < 0:
        score = 0
    if score > 8:
        score = 8

    entropy = _entropy_bits(password)
    tips = []

    if is_common:
        tips.append("This is (or is a small variation of) a very common password - never use it.")
    if n < 12:
        tips.append("Use at least 12 characters; 16 or more is better.")
    if not has_upper:
        tips.append("Add uppercase letters.")
    if not has_lower:
        tips.append("Add lowercase letters.")
    if not has_digit:
        tips.append("Add digits.")
    if not has_symbol:
        tips.append("Add symbols such as ! @ # $ %.")
    if repeats:
        tips.append("Avoid repeated characters like 'aaa'.")
    if sequence:
        tips.append("Avoid sequences like 'abcd', '1234' or 'qwer'.")

    if is_common or score <= 3:
        rating = "Weak"
    elif score >= 6 and entropy >= 50:
        rating = "Strong"
    else:
        rating = "Medium"

    return StrengthResult(rating, score, round(entropy, 1), is_common, tips)
