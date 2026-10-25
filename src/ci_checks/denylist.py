"""Match denylisted terms in text and binary content.

Matching ignores case, accents and invisible characters, respects word
boundaries, and lets the words of a term be separated by any punctuation,
underscores or line breaks. Numbers are stricter, so that dates, times and
versions do not spell terms made of numbers. Text that writes characters as
escapes (\\u, \\x and \\n escapes, percent-encoding or HTML entities) is
also matched as it reads once decoded.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from collections.abc import Iterable, Iterator, MutableMapping
from itertools import pairwise, product
from pathlib import PurePosixPath

from ci_checks._common import LEGACY, CheckError

# Every secret and environment variable whose name starts with this holds a
# denylist, so that lists can be added and replaced one by one.
SOURCE_PREFIX = "PRIVACY_DENYLIST"
# The environment variable that holds the secrets context of the workflow as JSON.
SECRETS_VARIABLE = "CI_SECRETS"
# Letters a term needs to be looked for anywhere in the readable strings of
# binary content, and the shortest term looked for at all there: random
# bytes spell short words by chance.
MIN_BINARY_TERM = 5
MIN_PHRASE_TERM = 3
# The shortest phrase, a part of a readable string with several words, in
# which shorter terms count.
MIN_PHRASE_LENGTH = 8
# Spellings of each term masked in the job log: separators placed between
# the words, and terms whose separators are all varied independently.
MASK_SEPARATORS = (" ", "_", "-", ".", "")
MAX_MIXED_SEPARATOR_WORDS = 3

# Readable strings of binary content: printable ASCII or UTF-8 text, single
# byte Latin text, and UTF-16 text in either byte order.
_TEXT_RUN = re.compile(
    rb"(?:[\t\n\r\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]"
    rb"|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]"
    rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2}"
    rb"){%d,}" % MIN_BINARY_TERM
)
_LATIN_RUN = re.compile(rb"[\t\n\r\x20-\x7e\xa0-\xff]{%d,}" % MIN_BINARY_TERM)
_HIGH_BYTE = re.compile(rb"[\xa0-\xff]")
_UTF16LE_RUN = re.compile(rb"(?:[\t\n\r\x20-\x7e\xa0-\xff]\x00){%d,}" % MIN_BINARY_TERM)
_UTF16BE_RUN = re.compile(rb"(?:\x00[\t\n\r\x20-\x7e\xa0-\xff]){%d,}" % MIN_BINARY_TERM)
_NOT_PHRASE = re.compile(r"[^\w .,'/:-]+|_+")
_ESCAPE = re.compile(r"\\[uUx][0-9A-Fa-f]|\\[nrt\\]|%[0-9A-Fa-f]{2}|&#?\w+;")
# The escapes of a line, read from left to right as a string literal is.
_ESCAPES = re.compile(
    r"(?P<backslash>\\\\)|(?P<json>(?:\\u[0-9A-Fa-f]{4})+)|\\U(?P<long>[0-9A-Fa-f]{8})"
    r"|(?P<bytes>(?:\\x[0-9A-Fa-f]{2})+|(?:%[0-9A-Fa-f]{2})+)|(?P<space>\\[nrt])"
)
# An escape right before or after a word in the text as written: "Marc\\u00e8le"
# is one word, not the name "Marc", so such words are only matched decoded.
_ESCAPE_AFTER = re.compile(r"\\u[0-9a-f]{4}|\\x[0-9a-f]{2}|%[0-9a-f]{2}|&#?\w+;")
_ESCAPE_BEFORE = re.compile(rf"(?:{_ESCAPE_AFTER.pattern}|\\u[0-9a-f]{{8}})\Z")
# A lower case letter followed by a capital, as in "getName".
_CAMEL = re.compile(r"(?<=[a-z\xdf-\xf6\xf8-\xff])(?=[A-Z\xc0-\xd6\xd8-\xde])")
# What may separate two words of a term, besides the separator the term
# itself uses there. Between letters: anything but letters and digits, or
# nothing, so that "First Last" also matches "first_last" and "FirstLast".
# Before a number, no comma or colon, which separate the values of a list
# or a mapping: "step 12" does not match '"step": 12'. After a number, no
# colon, but a comma, as in "12, Main Street". Between two numbers, exactly
# one space, dot, dash or underscore, so that "12 3 0" does not match
# "2026-12-30", "12:30", "1230" or numbers listed one per line.
_LETTERS_GAP = r"[\W_]*"
_BEFORE_NUMBER_GAP = r"(?:[^\w,:]|_)*"
_AFTER_NUMBER_GAP = r"(?:[^\w:]|_)*"
_NUMBERS_GAP = r"[ ._-]"
_SEPARATORS = re.compile(r"[\W_]+")
# The digits of hexadecimal numbers: hashes spell terms made only of them.
_HEX_DIGITS = frozenset("0123456789abcdef")
# Letters that Unicode does not decompose into a base letter and an accent.
_FOLD = str.maketrans(
    {
        "\N{LATIN SMALL LETTER O WITH STROKE}": "o",
        "\N{LATIN SMALL LETTER AE}": "ae",
        "\N{LATIN SMALL LIGATURE OE}": "oe",
        "\N{LATIN SMALL LETTER L WITH STROKE}": "l",
        "\N{LATIN SMALL LETTER D WITH STROKE}": "d",
        "\N{LATIN SMALL LETTER ETH}": "d",
        "\N{LATIN SMALL LETTER THORN}": "th",
        "\N{LATIN SMALL LETTER DOTLESS I}": "i",
        "\N{LEFT SINGLE QUOTATION MARK}": "'",
        "\N{RIGHT SINGLE QUOTATION MARK}": "'",
        "\N{MODIFIER LETTER APOSTROPHE}": "'",
    }
)
_APOSTROPHES = ("'", "\N{RIGHT SINGLE QUOTATION MARK}")


def normalize(text: str) -> str:
    """Fold case, accents, special letters and invisible characters.

    Line feeds are kept, so that line numbers can be counted in the result.
    """
    if text.isascii():
        return text.lower()
    decomposed = unicodedata.normalize("NFKD", text)
    kept = "".join(
        char
        for char in decomposed
        if not unicodedata.combining(char) and unicodedata.category(char) != "Cf"
    )
    return kept.casefold().translate(_FOLD)


def unescape(text: str) -> str | None:
    """Return text with its escapes decoded, or None when it has none.

    Each line is decoded on its own and keeps its place, so that matches can
    still be reported by line.
    """
    if not _ESCAPE.search(text):
        return None
    return "\n".join(_unescape_line(line) for line in text.split("\n"))


def _unescape_line(line: str) -> str:
    line = html.unescape(_ESCAPES.sub(_decode, line))
    return line.replace("\n", " ").replace("\r", " ")


def _decode(match: re.Match[str]) -> str:
    if match.group("backslash"):
        return "\\"
    if match.group("json"):
        return (
            json.loads(f'"{match.group("json")}"')
            .encode("utf-16", "surrogatepass")
            .decode("utf-16", errors="replace")
        )
    if match.group("long"):
        return _character(int(match.group("long"), 16))
    if match.group("bytes"):
        digits = match.group("bytes").replace("\\x", "").replace("%", "")
        return bytes.fromhex(digits).decode("utf-8", LEGACY)
    return " "


def _character(code: int) -> str:
    return chr(code) if code <= 0x10FFFF else "\N{REPLACEMENT CHARACTER}"


def _term_pattern(words: list[str], separators: list[str], glued: bool) -> str:
    """Return the pattern of a term made of words, with its boundaries.

    A term never touches a letter. Where it starts or ends with a number, it
    touches no digit either, nor a dot followed by a digit, as in a longer
    version or address. Where it starts or ends with a letter, a glued term
    may touch digits, as in "name42" or "v2name".
    """
    pattern = re.escape(words[0])
    for (before, word), own in zip(pairwise(words), separators, strict=True):
        if before[-1].isdecimal() and word[0].isdecimal():
            gap = _NUMBERS_GAP
        elif before[-1].isdecimal():
            gap = _AFTER_NUMBER_GAP
        elif word[0].isdecimal():
            gap = _BEFORE_NUMBER_GAP
        else:
            gap = _LETTERS_GAP
        if gap != _LETTERS_GAP:
            # A term always matches as it is written.
            gap = f"(?:{re.escape(own)}|{gap})"
        pattern += gap + re.escape(word)
    if words[0][0].isdecimal():
        start = r"(?<![^\W_])(?<!\d\.)"
    else:
        start = r"(?<![^\W\d_])" if glued else r"(?<![^\W_])"
    if words[-1][-1].isdecimal():
        end = r"(?![^\W_])(?!\.\d)"
    else:
        end = r"(?![^\W\d_])" if glued else r"(?![^\W_])"
    return start + pattern + end


def _alternation(terms: Iterable[tuple[str, str]]) -> re.Pattern[str] | None:
    """Compile term patterns, each with its first character, into one.

    The terms are grouped by their first character, and each group first
    checks what every term in it needs before it: no letter, and for terms
    that start with a number, no digit either. Most places in a text then
    fail without trying each term.
    """
    groups: dict[str, list[str]] = {}
    for pattern, first in terms:
        groups.setdefault(first, []).append(pattern)
    if not groups:
        return None
    alternatives = []
    for first, patterns in sorted(groups.items()):
        guard = r"(?<!\d)" if first.isdecimal() else ""
        patterns.sort(key=len, reverse=True)
        alternatives.append(f"(?={re.escape(first)}){guard}(?:{'|'.join(patterns)})")
    firsts = "".join(map(re.escape, sorted(groups)))
    return re.compile(rf"(?<![^\W\d_])(?=[{firsts}])(?:{'|'.join(alternatives)})")


def _split(text: str) -> tuple[list[str], list[str]]:
    """Return the words of a text and the separators between them."""
    core = re.sub(r"\A[\W_]+|[\W_]+\Z", "", text)
    if not core:
        return [], []
    return _SEPARATORS.split(core), _SEPARATORS.findall(core)


class Denylist:
    """Terms that must never appear.

    "First Last" also matches "first_last", "First-Last", "FirstLast" and
    "First\\nLast", and the term "FirstLast" matches all of them. Terms of at least
    MIN_BINARY_TERM letters also match as a part of a camel case name, as in
    "getFirstLast", and next to digits, as in "FirstLast2". "12.3.0" matches
    "12 3 0" and "12_3_0", but not "2026-12-30", "12:30", "1230" or "v1.12.3.0".
    """

    def __init__(self, raw: str) -> None:
        terms = []
        for line in raw.splitlines():
            term = line.strip().lstrip("\N{ZERO WIDTH NO-BREAK SPACE}").strip()
            if term and not term.startswith("#"):
                terms.append(term)
        self.terms = list(dict.fromkeys(terms))
        # The most words in a term, which is how many lines a term can span.
        self.longest_term = 0
        # The pattern of each term, with its size and its first character.
        letters: dict[str, tuple[int, str]] = {}
        for term in self.terms:
            # Camel case is split before case is folded, so that "FirstLast"
            # also matches "First Last".
            words, separators = _split(normalize(_CAMEL.sub(" ", term)))
            if words:
                size = sum(map(len, words))
                # Short terms, and terms that hexadecimal numbers spell,
                # would match inside identifiers and hashes if glued.
                glued = size >= MIN_BINARY_TERM and not set("".join(words)) <= _HEX_DIGITS
                letters[_term_pattern(words, separators, glued)] = (size, words[0][0])
                self.longest_term = max(self.longest_term, len(words))
        self._pattern = _alternation((p, first) for p, (_, first) in letters.items())
        # Random bytes spell short words by chance, so in binary content
        # shorter terms only count inside phrases (see matches_binary).
        self._long = _alternation(
            (p, first) for p, (size, first) in letters.items() if size >= MIN_BINARY_TERM
        )
        self._phrase = _alternation(
            (p, first)
            for p, (size, first) in letters.items()
            if MIN_PHRASE_TERM <= size < MIN_BINARY_TERM
        )

    def __bool__(self) -> bool:
        return self._pattern is not None

    def matches(self, text: str) -> bool:
        """Return whether a piece of text contains a term."""
        return any(True for _ in self._matches(text))

    def spans(self, text: str) -> list[tuple[int, int]]:
        """Return the first and last line of each term, terms spanning lines included."""
        found = set()
        # Lines are counted as the matches come, one form of the text after
        # the other.
        current, position, line = -1, 0, 1
        for view, folded, match in self._matches(text):
            if view != current:
                current, position, line = view, 0, 1
            line += folded.count("\n", position, match.start())
            position = match.start()
            found.add((line, line + folded.count("\n", match.start(), match.end())))
        return sorted(found)

    def _matches(self, text: str) -> Iterator[tuple[int, str, re.Match[str]]]:
        """Yield the terms found in a text as written and in its decoded form.

        Both keep the lines of the text. As written, a word next to an escape
        is skipped, because the escape may stand for a letter of that word.
        Each form is also searched with its camel case names split, for the
        longer terms.
        """
        if not self._pattern:
            return
        decoded = unescape(text)
        view = 0
        for source, guarded in ((text, decoded is not None), (decoded, False)):
            if source is None:
                continue
            views = [(self._pattern, normalize(source))]
            if self._long and _CAMEL.search(source):
                views.append((self._long, normalize(_CAMEL.sub(" ", source))))
            for pattern, folded in views:
                view += 1
                for match in pattern.finditer(folded):
                    if not (guarded and _next_to_escape(folded, match)):
                        yield view, folded, match

    def matches_binary(self, data: bytes) -> bool:
        """Return whether the readable strings of binary content contain a term.

        Terms of at least MIN_BINARY_TERM letters count anywhere in a string.
        Shorter ones, down to MIN_PHRASE_TERM letters, count only in a
        phrase: a part of a string, between symbols, with several words and
        only letters, digits, spaces and common punctuation, such as a title
        in a document. Single byte Latin strings are only searched for the
        longer terms.
        """
        if not self._pattern:
            return False
        runs = [run.decode("utf-8") for run in _TEXT_RUN.findall(data)]
        runs += [run.decode("utf-16-le") for run in _UTF16LE_RUN.findall(data)]
        runs += [run.decode("utf-16-be") for run in _UTF16BE_RUN.findall(data)]
        latin = [
            run.decode("latin-1") for run in _LATIN_RUN.findall(data) if _HIGH_BYTE.search(run)
        ]
        for run in runs:
            if self._long and self._long.search(normalize(run)):
                return True
            if self._phrase and self._in_phrase(run):
                return True
        return bool(self._long) and any(self._long.search(normalize(run)) for run in latin)

    def _in_phrase(self, run: str) -> bool:
        # Split before folding, which turns symbols such as U+00A8 into spaces.
        assert self._phrase is not None  # noqa: S101 - checked by the caller.
        for part in _NOT_PHRASE.split(run):
            phrase = part.strip()
            if (
                len(phrase) >= MIN_PHRASE_LENGTH
                and " " in phrase
                and self._phrase.search(normalize(phrase))
            ):
                return True
        return False

    def redact_path(self, path: str) -> str:
        """Return a path with the parts that contain a term replaced."""
        parts = ["[redacted]" if self.matches(part) else part for part in PurePosixPath(path).parts]
        redacted = "/".join(parts)
        return "[redacted path]" if self.matches(redacted) else redacted

    def mask_values(self) -> set[str]:
        """Return the spellings of each term that the runner should mask in logs.

        Masking cannot cover every spelling: the checks never print a term,
        and redact the file paths they print.
        """
        values = set()
        for term in self.terms:
            for base in (term, normalize(term)):
                values.update(_apostrophe_variants(base))
                words = _words(_CAMEL.sub(" ", base))
                if not words:
                    continue
                gaps = len(words) - 1
                separators = (
                    product(MASK_SEPARATORS, repeat=gaps)
                    if len(words) <= MAX_MIXED_SEPARATOR_WORDS
                    else ((separator,) * gaps for separator in MASK_SEPARATORS)
                )
                for chosen in separators:
                    values.update(_join(cased, chosen) for cased in _casings(words))
        return {value for value in values if len(value) >= MIN_PHRASE_TERM}


def _next_to_escape(folded: str, match: re.Match[str]) -> bool:
    before = folded[max(0, match.start() - 40) : match.start()]
    return bool(_ESCAPE_BEFORE.search(before) or _ESCAPE_AFTER.match(folded, match.end()))


def _words(text: str) -> list[str]:
    return [word for word in re.split(r"[\W_]+", text) if word]


def _join(words: list[str], separators: tuple[str, ...]) -> str:
    return words[0] + "".join(map(str.__add__, separators, words[1:]))


def _casings(words: list[str]) -> list[list[str]]:
    return [
        words,
        [word.lower() for word in words],
        [word.upper() for word in words],
        [word.capitalize() for word in words],
        [words[0].capitalize(), *(word.lower() for word in words[1:])],
    ]


def _apostrophe_variants(text: str) -> set[str]:
    return {text, *(text.replace(a, b) for a in _APOSTROPHES for b in _APOSTROPHES)}


def location(denylist: Denylist, path: str) -> tuple[str, str | None]:
    """Return the path to show and the path to annotate, hiding denylisted parts.

    The annotation is dropped when the path is redacted, because the runner
    prints it as given.
    """
    if denylist.matches(path):
        return denylist.redact_path(path), None
    return path, path


def denylist_sources(environ: MutableMapping[str, str]) -> list[str]:
    """Return every denylist: the secrets and variables named PRIVACY_DENYLIST*.

    The secrets come as the JSON of the workflow secrets context, which holds
    other secrets too, so it is removed from the environment before any
    subprocess can inherit it, and this code never prints it.
    """
    found: dict[str, str] = {}
    raw = environ.pop(SECRETS_VARIABLE, "")
    if raw:
        try:
            secrets = json.loads(raw)
        except ValueError:
            raise CheckError(f"{SECRETS_VARIABLE} does not hold valid JSON.") from None
        if not isinstance(secrets, dict):
            raise CheckError(f"{SECRETS_VARIABLE} does not hold a JSON object.")
        for name, value in secrets.items():
            if name.upper().startswith(SOURCE_PREFIX) and isinstance(value, str):
                found[name.upper()] = value
    for name, value in environ.items():
        if name.upper().startswith(SOURCE_PREFIX):
            found.setdefault(name.upper(), value)
    return [found[name] for name in sorted(found)]
