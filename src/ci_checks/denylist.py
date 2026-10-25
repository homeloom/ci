"""Match denylisted terms in text and binary content.

Matching ignores case, accents and invisible characters, respects word
boundaries, and lets the words of a term be separated by any punctuation,
underscores or line breaks. Numbers follow stricter rules, so that versions
such as "v1.12.3.0", lists such as "[12, 3, 0]" and SVG coordinates do not
match the term "12 3 0", while phone numbers and other terms of eight digits
or more also match their usual spellings. Text that writes characters as
escapes (\\u, \\x and \\n escapes, percent-encoding or HTML entities) is
also matched as it reads decoded once and twice.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
from collections import Counter
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
_ESCAPE = re.compile(r"\\[uUx][0-9A-Fa-f]|\\[nrtbfv\\]|%[0-9A-Fa-f]{2}|&#?\w")
# The escapes of a line, read from left to right as a string literal is.
_ESCAPES = re.compile(
    r"(?P<backslash>\\\\)|(?P<json>(?:\\u[0-9A-Fa-f]{4})+)|\\U(?P<long>[0-9A-Fa-f]{8})"
    r"|(?P<bytes>(?:\\x[0-9A-Fa-f]{2})+|(?:%[0-9A-Fa-f]{2})+)|(?P<space>\\[nrtbfv])"
)
# An escape right before or after a word in the text as written: "Marc\\u00e8le"
# is one word, not the name "Marc", so such words are only matched decoded.
# Before a word, an escape that has at least one digit may also end with the
# first letters of the word, as in "%2Bluefinch", which reads "+luefinch".
_ESCAPE_AFTER = re.compile(r"\\u[0-9a-f]{4}|\\x[0-9a-f]{2}|%[0-9a-f]{2}|&#?\w+;")
_ESCAPE_BEFORE = re.compile(rf"(?:{_ESCAPE_AFTER.pattern}|\\u[0-9a-f]{{8}})\Z")
_PARTIAL_ESCAPE_BEFORE = re.compile(r"(?:\\u(?P<unicode>[0-9a-f]{1,7})|\\x[0-9a-f]|%[0-9a-f])\Z")
_ENTITY = re.compile(r"&#?\w+;")
# Numeric character references, whose digits html.unescape converts to an
# integer: Python refuses to convert more than 4,300 digits.
_NUMERIC_REFERENCE = re.compile(r"&#(?:([xX])([0-9A-Fa-f]+)|([0-9]+))")
# A lower case letter followed by a capital, as in "getName". Camel case
# names are split with a mark that text does not hold, so that a term can tell
# these places from white space. Escapes are kept whole, since a capital
# can be one of their hexadecimal digits, as in "\\xA9".
_CAMEL = re.compile(r"(?<=[a-z\xdf-\xf6\xf8-\xff])(?=[A-Z\xc0-\xd6\xd8-\xde])")
_CAMEL_MARK = "\x00"
# A mark placed inside an escape, before a capital hexadecimal digit.
_MARK_IN_ESCAPE = re.compile(
    r"(\\x[0-9A-Fa-f]?|\\u[0-9A-Fa-f]{0,3}|\\U[0-9A-Fa-f]{0,7}|%[0-9a-f]|&#x[0-9A-Fa-f]{0,5})"
    r"\x00(?=[0-9A-F])"
)
# Where a letter meets a digit in a term, as in "Name5G", which also matches
# "Name 5G".
_LETTER_DIGIT = re.compile(r"(?<=[^\W\d_])(?=\d)")
# What may separate two words of a term, besides the separator the term
# itself uses there. Between letters: anything but letters and digits, or
# nothing, so that "First Last" also matches "first_last" and "FirstLast".
# Where a term written in camel case has a part of three letters or less,
# as in "LeBlanc", no white space there, so that it does not match the
# words "le blanc" of a sentence. Before a number, a comma or a colon only
# right after the word and followed by white space, as in "Quillmore
# Lane, 12": they also separate the values of a list or a mapping, and
# "step 12" does not match '"step": 12' or '["step", 12]'. After a number,
# no colon, but a comma, as in "12, Main Street". Between two numbers, exactly
# one space, dot, dash or underscore, so that "12 3 0" does not match
# "2026-12-30", "12:30", "1230" or numbers listed one per line. In terms of
# eight digits or more, such as phone numbers, the numbers may also be
# glued or separated by any run of spaces, any dash with or without spaces
# around it, or a line break and its indentation, the ways such numbers are
# written.
_LETTERS_GAP = r"[\W_]*"
_SHORT_CAMEL_GAP = r"(?:[^\w\s]|_)?"
MAX_SHORT_CAMEL_PART = 3
_BEFORE_NUMBER_GAP = r"(?:[,:][ \t]++)?+(?:[^\w,:]|_)*+"
_AFTER_NUMBER_GAP = r"(?:[^\w:]|_)*"
_NUMBERS_GAP = r"[ ._-]"
_DASHES = r"[\-\u2010-\u2015\u2212]"
_LONG_NUMBERS_SEPARATOR = rf"(?:[ \t]*+{_DASHES}[ \t]*+|[._]|[ \t]++(?:\r?\n[ \t]*+)?|\r?\n[ \t]*+)"
_LONG_NUMBERS_GAP = _LONG_NUMBERS_SEPARATOR + "?"
LONG_NUMBER_DIGITS = 8
# The same separators as fixed-width patterns, for lookbehinds, with up to
# four spaces of indentation.
_INDENTS = [rf"[ \t]{{{count}}}" if count else "" for count in range(5)]
_LONG_NUMBERS_BEHIND = [
    r"[._\-\u2010-\u2015\u2212]",
    rf"[ \t]{_DASHES}",
    rf"{_DASHES}[ \t]",
    rf"[ \t]{_DASHES}[ \t]",
    *_INDENTS[1:],
] + [
    newline + indent
    for newline in (r"\n", r"\r\n", r"[ \t]\n", r"[ \t]\r\n")
    for indent in _INDENTS
]
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
# Invisible characters and marks, including the marks that have no combining
# class, such as the combining grapheme joiner and the variation selectors.
_DROPPED = frozenset({"Cf", "Mn", "Me"})


class _Marks(dict[int, str]):
    """A translation table that removes marks and invisible characters, filled as needed."""

    def __missing__(self, code: int) -> str:
        char = chr(code)
        dropped = unicodedata.combining(char) or unicodedata.category(char) in _DROPPED
        self[code] = "" if dropped else char
        return self[code]


_MARKS = _Marks()


def normalize(text: str) -> str:
    """Fold case, accents, special letters and invisible characters.

    Line feeds are kept, so that line numbers can be counted in the result.
    """
    if text.isascii():
        return text.lower()
    kept = unicodedata.normalize("NFKD", text).translate(_MARKS)
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
    line = _unescape_html(_ESCAPES.sub(_decode, line))
    return line.replace("\n", " ").replace("\r", " ")


def _unescape_html(text: str) -> str:
    """Decode HTML references, reading numbers too large for a character as invalid."""
    return html.unescape(_NUMERIC_REFERENCE.sub(_short_reference, text))


def _short_reference(match: re.Match[str]) -> str:
    hexadecimal = match.group(1) or ""
    digits = (match.group(2) or match.group(3)).lstrip("0") or "0"
    if len(digits) > (6 if hexadecimal else 7):
        digits = "110000" if hexadecimal else "1114112"
    return f"&#{hexadecimal}{digits}"


def split_camel(text: str) -> str:
    """Split the camel case names of a text with a mark, keeping escapes whole."""
    split, count = _CAMEL.subn(_CAMEL_MARK, text)
    if not count or not _ESCAPE.search(text):
        return split
    # An escape holds at most four such marks, as in "\\UaBcDeFaB".
    while (repaired := _MARK_IN_ESCAPE.sub(r"\1", split)) != split:
        split = repaired
    return split


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


# Where a term that starts with a number may start: after no letter or
# digit, or after letters when the number is dotted, as in "v12.3.0".
_NUMBER_START = r"(?:(?<![^\W_])|(?<=[^\W\d_])(?=\d+\.\d))"


def _term_pattern(words: list[str], separators: list[str], glued: bool) -> str:
    """Return the pattern of a term made of words, with its boundaries.

    A term never touches a letter, except that letters may come right before
    two numbers separated by a dot, as in "v12.3.0". Where it starts or ends
    with a number, it touches no digit either, nor a dot followed by a digit,
    as in a longer version or address. Where it starts or ends with two numbers, it is not
    part of a longer run of numbers either, as in the coordinates of an SVG
    path. Where it starts or ends with a letter, a glued term may touch
    digits, as in "name42" or "v2name".
    """
    long = sum(map(str.isdecimal, "".join(words))) >= LONG_NUMBER_DIGITS
    numbers_gap = _LONG_NUMBERS_GAP if long else _NUMBERS_GAP
    pattern = re.escape(words[0])
    for (before, word), own in zip(pairwise(words), separators, strict=True):
        between_numbers = before[-1].isdecimal() and word[0].isdecimal()
        if between_numbers:
            gap = numbers_gap
        elif before[-1].isdecimal():
            gap = _AFTER_NUMBER_GAP
        elif word[0].isdecimal():
            gap = _BEFORE_NUMBER_GAP
        elif own == _CAMEL_MARK and min(len(before), len(word)) <= MAX_SHORT_CAMEL_PART:
            gap = _SHORT_CAMEL_GAP
        else:
            gap = _LETTERS_GAP
        if gap not in (_LETTERS_GAP, _SHORT_CAMEL_GAP) and not re.fullmatch(gap, own):
            # A term always matches as it is written. A separator that the
            # gap already accepts is not added, since two ways to match the
            # same text make a failed match retry every combination. Two
            # numbers separated by a comma, as in coordinates, may also have
            # any white space around it or none.
            if between_numbers and "," in own:
                written = r"\s*+,\s*+".join(re.escape(part.strip()) for part in own.split(","))
            else:
                written = re.escape(own)
            gap = f"(?:{written}|{gap})"
        pattern += gap + re.escape(word)
    if words[0][0].isdecimal():
        start = r"(?<![^\W_])(?<!\d\.)"
        if len(words) > 1 and words[0][-1].isdecimal() and words[1][0].isdecimal():
            start = _NUMBER_START + r"(?<!\d\.)"
            # Checked once the first number is found, so that the
            # lookbehinds only run there.
            first = re.escape(words[0])
            for separator in _LONG_NUMBERS_BEHIND if long else [_NUMBERS_GAP]:
                pattern = pattern.replace(first, first + _not_after_number(separator, first), 1)
    else:
        start = r"(?<![^\W\d_])" if glued else r"(?<![^\W_])"
    if words[-1][-1].isdecimal():
        end = r"(?![^\W_])(?!\.\d)"
        if len(words) > 1 and words[-1][0].isdecimal() and words[-2][-1].isdecimal():
            separator = _LONG_NUMBERS_SEPARATOR if long else _NUMBERS_GAP
            end += rf"(?:(?!{separator}\d)|(?={separator}\d{{1,3}}[^\W\d_]))"
    else:
        end = r"(?![^\W\d_])" if glued else r"(?![^\W_])"
    return start + pattern + end


def _not_after_number(separator: str, first: str) -> str:
    """Return a check that the first number of a term follows no other number.

    A number that ends a word, as in "IPv4" or "eth0", does not count.
    """
    ending = rf"{separator}{first}"
    return (
        rf"(?:(?<!\d{ending})|(?<=[^\W\d_]\d{ending})"
        rf"|(?<=[^\W\d_]\d\d{ending})|(?<=[^\W\d_]\d\d\d{ending}))"
    )


def _alternation(terms: Iterable[tuple[str, int, str]]) -> re.Pattern[str] | None:
    """Compile term patterns, with their size and first character, into one.

    Terms are grouped by their first character, behind the check that every
    term starting with a letter needs (no letter before it) or that every
    term starting with a number needs (no letter or digit before it, except
    letters before a dotted number), so
    most places in a text fail without trying each term. In a group, longer
    terms come first, so that a term that extends another is found whole.
    """
    groups: dict[str, list[tuple[int, str]]] = {}
    for pattern, size, first in terms:
        groups.setdefault(first, []).append((size, pattern))
    branches = []
    for numbers, guard in ((False, r"(?<![^\W\d_])"), (True, _NUMBER_START)):
        alternatives = []
        for first, patterns in sorted(groups.items()):
            if first.isdecimal() == numbers:
                patterns.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
                joined = "|".join(pattern for _, pattern in patterns)
                alternatives.append(f"(?={re.escape(first)})(?:{joined})")
        if alternatives:
            firsts = "".join(
                re.escape(first) for first in sorted(groups) if first.isdecimal() == numbers
            )
            branches.append(f"{guard}(?=[{firsts}])(?:{'|'.join(alternatives)})")
    return re.compile("|".join(branches)) if branches else None


def _split(text: str) -> tuple[list[str], list[str]]:
    """Return the words of a text and the separators between them."""
    core = re.sub(r"\A[\W_]+|[\W_]+\Z", "", text)
    if not core:
        return [], []
    return _SEPARATORS.split(core), _SEPARATORS.findall(core)


class Denylist:
    """Terms that must never appear.

    "First Last" also matches "first_last", "First-Last", "FirstLast" and
    "First\\nLast", and the term "FirstLast" matches all of them. Terms of at
    least MIN_BINARY_TERM letters and digits also match as a part of a camel
    case name, as in "getFirstLast", and, unless only hexadecimal digits
    spell them, next to digits, as in "FirstLast2". Short parts of a camel
    case term are not separated by white space: "LeBlanc" does not match
    "le blanc". "Name5G" also matches "Name 5G". "12.3.0" matches "12 3 0",
    "12_3_0" and "v12.3.0", but not "2026-12-30", "12:30", "1230" or
    "v1.12.3.0".
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
            # also matches "First Last", and so are letters followed by digits.
            marked = _LETTER_DIGIT.sub(_CAMEL_MARK, _CAMEL.sub(_CAMEL_MARK, term))
            words, separators = _split(normalize(marked))
            if words:
                size = sum(map(len, words))
                # Short terms, and terms that hexadecimal numbers spell,
                # would match inside identifiers and hashes if glued.
                glued = size >= MIN_BINARY_TERM and not set("".join(words)) <= _HEX_DIGITS
                letters[_term_pattern(words, separators, glued)] = (size, words[0][0])
                self.longest_term = max(self.longest_term, len(words))
        self._pattern = _alternation((p, size, first) for p, (size, first) in letters.items())
        # Each term on its own, longest first and by first character, for
        # the places where the longest term found touches an escape. The
        # second table only has the terms that camel case names may hold.
        self._singles: dict[bool, dict[str, list[re.Pattern[str]]]] = {False: {}, True: {}}
        for p, (size, first) in sorted(letters.items(), key=lambda item: item[1][0], reverse=True):
            single = re.compile(p)
            self._singles[False].setdefault(first, []).append(single)
            if size >= MIN_BINARY_TERM:
                self._singles[True].setdefault(first, []).append(single)
        # Random bytes spell short words by chance, so in binary content
        # shorter terms only count inside phrases (see matches_binary).
        self._long = _alternation(
            (p, size, first) for p, (size, first) in letters.items() if size >= MIN_BINARY_TERM
        )
        self._phrase = _alternation(
            (p, size, first)
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
        """Yield the terms found in a text as written and in its decoded forms.

        Text is decoded twice, for escapes that were themselves escaped, as in
        "&amp;quot;". Every form keeps the lines of the text. A word next to
        an escape is skipped, because the escape may stand for a letter of
        that word. Each form is also searched with its camel case names
        split, for the longer terms.
        """
        if not self._pattern:
            return
        decoded = unescape(text)
        sources = [(text, decoded is not None)]
        if decoded is not None:
            sources.append((decoded, True))
            twice = unescape(decoded)
            if twice is not None and twice != decoded:
                sources.append((self._changed_lines(decoded, twice), True))
        view = 0
        for source, guarded in sources:
            views = [(self._pattern, False, normalize(source))]
            if self._long and _CAMEL.search(source):
                views.append((self._long, True, normalize(split_camel(source))))
            # Folding merges entities that differ by case, accents or invisible
            # characters, so an entity of the folded text counts only when
            # each of its occurrences comes from one that decodes as written.
            decoding = Counter(
                normalize(entity)
                for entity in _ENTITY.findall(source)
                if _unescape_html(entity) != entity
            )
            occurrences = Counter(_ENTITY.findall(views[0][2]))
            entities = {key for key, count in decoding.items() if occurrences[key] == count}
            for pattern, long_only, folded in views:
                view += 1
                singles = self._singles[long_only]
                for match in self._search(pattern, singles, folded, guarded, entities):
                    yield view, folded, match

    def _changed_lines(self, before: str, after: str) -> str:
        """Return the lines that decoding changed, with the lines a term can span around them.

        The other lines are left empty, so that line numbers stay the same.
        """
        old, new = before.split("\n"), after.split("\n")
        reach = max(self.longest_term - 1, 0)
        kept = set()
        for number, (line, decoded) in enumerate(zip(old, new, strict=True)):
            if line != decoded:
                kept.update(range(number - reach, number + reach + 1))
        return "\n".join(line if number in kept else "" for number, line in enumerate(new))

    @staticmethod
    def _search(
        pattern: re.Pattern[str],
        singles: dict[str, list[re.Pattern[str]]],
        folded: str,
        guarded: bool,
        entities: set[str],
    ) -> Iterator[re.Match[str]]:
        """Yield the terms of a text, skipping those next to an escape.

        Only the longest term is found at each place. When it touches an
        escape, the other terms that start there are tried, longest first.
        When none of them is clear of escapes, the search goes on right after
        that place, so that the terms inside the longest one are found.
        """
        position = 0
        while match := pattern.search(folded, position):
            if guarded and _next_to_escape(folded, match, entities):
                found = None
                for single in singles.get(folded[match.start()], ()):
                    other = single.match(folded, match.start())
                    if other and not _next_to_escape(folded, other, entities):
                        found = other
                        break
                if found is None:
                    position = match.start() + 1
                    continue
                match = found
            yield match
            position = max(match.end(), match.start() + 1)

    def matches_binary(self, data: bytes) -> bool:
        """Return whether the readable strings of binary content contain a term.

        Terms of at least MIN_BINARY_TERM letters count anywhere in a string,
        camel case names included.
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
            if self._long and self._in_long(run):
                return True
            if self._phrase and self._in_phrase(run):
                return True
        return bool(self._long) and any(self._in_long(run) for run in latin)

    def _in_long(self, run: str) -> bool:
        assert self._long is not None  # noqa: S101 - checked by the caller.
        if self._long.search(normalize(run)):
            return True
        # A camel case name holds a term and at least one more letter.
        if len(run) <= MIN_BINARY_TERM:
            return False
        split = split_camel(run)
        return split != run and bool(self._long.search(normalize(split)))

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
                words, own = _split(_CAMEL.sub(" ", base))
                if not words:
                    continue
                # Between two numbers of a short term, only the separator of
                # the term and a space: "1230" and "12-30" are common in logs.
                long = sum(map(str.isdecimal, "".join(words))) >= LONG_NUMBER_DIGITS
                choices = [
                    tuple(dict.fromkeys((written, " ")))
                    if not long and before[-1].isdecimal() and word[0].isdecimal()
                    else MASK_SEPARATORS
                    for (before, word), written in zip(pairwise(words), own, strict=True)
                ]
                separators = (
                    product(*choices)
                    if len(words) <= MAX_MIXED_SEPARATOR_WORDS
                    else (
                        tuple(separator if separator in choice else choice[0] for choice in choices)
                        for separator in MASK_SEPARATORS
                    )
                )
                for chosen in separators:
                    values.update(_join(cased, chosen) for cased in _casings(words))
        return {value for value in values if len(value) >= MIN_PHRASE_TERM}


def _next_to_escape(folded: str, match: re.Match[str], entities: set[str]) -> bool:
    """Return whether an escape that decodes touches a match.

    Entities count when they are in entities, the folded entities whose
    every occurrence decodes as written. An escape cut short before the
    match, after at least one digit, counts when the first letters of the
    match are the hexadecimal digits it is missing.
    """
    before = folded[max(0, match.start() - 40) : match.start()]
    for escape in (_ESCAPE_BEFORE.search(before), _ESCAPE_AFTER.match(folded, match.end())):
        if escape and (escape[0][0] != "&" or escape[0] in entities):
            return True
    partial = _PARTIAL_ESCAPE_BEFORE.search(before)
    if partial is None:
        return False
    digits = len(partial["unicode"] or "")
    missing = 1 if partial["unicode"] is None else (4 if digits < 4 else 8) - digits
    return set(folded[match.start() : match.start() + missing]) <= _HEX_DIGITS


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
