"""Tests for matching denylisted terms. Every term here is invented."""

from __future__ import annotations

import random
import time

import pytest

from ci_checks._common import CheckError
from ci_checks.denylist import (
    Denylist,
    denylist_sources,
    location,
    normalize,
    split_camel,
    unescape,
)

TERMS = """\ufeff# Invented terms only.

Bluefinch
rue des Lilas
Pré-Vert
bus 917
Ren
Chloé
Quillène Zorbefort
Ørsted Lane
Straße Nord
Bedeline
  Bluefinch
"""
DENYLIST = Denylist(TERMS)
# Short first names, which random bytes spell by chance.
SHORT_NAMES = "\n".join(
    "Ugo Leo Eli Luna Max Mia Noa Zoe Tom Eva Lou Ana Ben Sam Kim Ivy Ada Ari Bo Jo".split()
)


def test_terms_skip_comments_blank_lines_and_duplicates() -> None:
    assert DENYLIST.terms == [
        "Bluefinch",
        "rue des Lilas",
        "Pré-Vert",
        "bus 917",
        "Ren",
        "Chloé",
        "Quillène Zorbefort",
        "Ørsted Lane",
        "Straße Nord",
        "Bedeline",
    ]
    assert DENYLIST.longest_term == 3
    assert DENYLIST
    assert not Denylist("")
    assert not Denylist("# only a comment\n\n   \n")
    assert not Denylist("!!!\n--")
    assert Denylist("!!!\n--").mask_values() == {"!!!"}
    assert Denylist("\ufeffBluefinch").matches("bluefinch")


@pytest.mark.parametrize(
    "text",
    [
        # Case, accents and letters without a decomposition, both ways.
        "Hello BLUEFINCH!",
        "bluefínch with an accent",
        "pre vert",
        "PRÉ VERT",
        "chloe",
        "CHLOÉ",
        "quillene zorbefort",
        "orsted_lane",
        "ØRSTED LANE",
        "strasse nord",
        "STRASSE-NORD",
        # Words glued with underscores, hyphens, dots or nothing.
        "rue_des_lilas",
        "rue-des-lilas",
        "RUE_DES-lilas",
        "rue.des.lilas",
        "ruedeslilas",
        "pre_vert",
        "prevert",
        "bus_917",
        "bus-917",
        "bus917",
        "QuilleneZorbefort",
        "quillene.zorbefort@example.com",
        # Several spaces, tabs and line breaks between the words.
        "rue   des    lilas",
        "Rue  des\tLilas",
        "lives rue des\nLilas",
        "lives rue des\r\nlilas",
        "bus\n\n917",
        "Quillène\n    Zorbefort",
        # Inside identifiers, paths and URLs.
        "sensor.bluefinch_door",
        "https://zorb.example/rue-des-lilas",
        "docs/Bluefinch/notes.md",
        "getBluefinch()",
        "BluefinchSensor",
        # Longer terms glued to digits, as in numbered names.
        "bluefinch2",
        "Bluefinch42",
        "v2Bluefinch",
        "sensor2bluefinch",
        "bluefinch_5g",
        # Invisible characters inside a word.
        "Blue\N{SOFT HYPHEN}finch",
        "Blue\N{ZERO WIDTH SPACE}finch",
        "Chlo\N{ZERO WIDTH JOINER}é",
        # Escapes, matched once decoded.
        '"name": "Chlo\\u00e9"',
        '"holder": "Quill\\u00e8ne Zorbefort"',
        "Chlo&eacute;",
        "Chlo&#233;",
        "Chlo&#xe9;",
        "Chlo%C3%A9",
        "q=rue%20des%20Lilas",
        "b'Chlo\\xc3\\xa9'",
        "\\U0001F600Bluefinch",
        '"text": "First line.\\nBluefinch"',
        "\\tBluefinch",
        "Bluefinch\\u0027s",
        "Bluefinch&amp;co",
        # Backslashes that are path separators, not escapes.
        "d:\\notes\\rue des lilas.txt",
        '"path": "C:\\\\Users\\\\rue des lilas"',
        "50%Bedeline",
    ],
)
def test_matches(text: str) -> None:
    assert DENYLIST.matches(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "bluefinches",
        "superbluefinch",
        "superbluefinch2",
        "prevertical",
        "bus 9170",
        "bus917x",
        "rue des lilasx",
        "Chlo",
        "Renée",
        # A word that an escape goes on with is another word.
        "Ren\\u00e9e",
        "ren&eacute;e",
        "ren%C3%A9e",
        "\\u00e9bluefinch",
        "bluefinch%61",
        "&eacute;bluefinch",
        # Short terms are not split out of camel case names.
        "isRen",
    ],
)
def test_does_not_match(text: str) -> None:
    assert not DENYLIST.matches(text)


NUMBERS = Denylist("12.3.0\nstep 12\nbus 917")


@pytest.mark.parametrize(
    "text",
    [
        "12.3.0",
        "Code: 12-3-0.",
        "12 3 0",
        "12_3_0",
        "(12.3.0)",
        "step 12",
        "step_12",
        "Step-12",
        "step12",
        "bus 917.",
        # A comma or a colon right after the word, followed by a space or a tab.
        "step: 12",
        "Step, 12",
        "step:\t12",
        # So unquoted lists and mappings hold the term, a trade-off for
        # addresses such as "Quillmore Lane, 12".
        "[bus, 917]",
        "{bus: 917}",
    ],
)
def test_numbers_match_with_their_separators(text: str) -> None:
    assert NUMBERS.matches(text)


@pytest.mark.parametrize(
    "text",
    [
        # Dates, times and longer numbers.
        "## [1.4.0] - 2026-12-30",
        "chore: release 1.4.0 on 2026-12-30",
        "datetime(2026, 12, 3, 0, 0)",
        "Retry after 12:30.",
        "1230",
        "12.30",
        "112.3.0",
        "12.3.01",
        # Longer versions and addresses.
        "v1.12.3.0",
        "12.3.0.1",
        "10.12.3.0",
        # Lists, mappings and numbers one per line.
        "[12, 3, 0]",
        "12,3,0",
        "12\n3\n0",
        "12. 3. 0",
        "matrix(12,3,0,1,5,5)",
        '"step": 12',
        "'step': 12",
        '["step", 12]',
        "step:12",
        "step ,12",
        "step:\n  12",
        "step,\n12",
        "steps 12",
        "step 120",
        '["bus", 917]',
    ],
)
def test_numbers_do_not_match_dates_times_and_lists(text: str) -> None:
    assert not NUMBERS.matches(text)


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("00:00:5E:00:53:9D", "mac 00:00:5e:00:53:9d here"),
        ("(202) 555-0143", "call (202) 555-0143"),
        ("03/12/1985", "born 03/12/1985"),
        ("32.87336, -117.22743", "at 32.87336, -117.22743"),
        ("12, rue Quillmore", "12, rue Quillmore"),
        ("12 rue Quillmore", "Address: 12, rue Quillmore"),
        ("Bluefinch: 4471", "Bluefinch: 4471"),
        ("12:30", "Retry after 12:30."),
        ("Quillmore Road 12", "Quillmore Road, 12"),
        ("Via Quillmore 12", "Via Quillmore, 12"),
        ("Quillmore Lane 12", "Quillmore Lane: 12"),
    ],
)
def test_terms_with_numbers_match_as_written(term: str, text: str) -> None:
    assert Denylist(term).matches(text)


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("03/12/1985", "03/12/19850"),
        ("12 rue Quillmore", "12: rue Quillmore"),
        ("Quillmore Road 12", "Quillmore Road,12"),
        ("Flat 3 12 Quillmore Road", "Flat 3, 12 Quillmore Road"),
    ],
)
def test_terms_with_numbers_keep_their_limits(term: str, text: str) -> None:
    assert not Denylist(term).matches(text)


@pytest.mark.parametrize(
    ("term", "text"),
    [
        # Coordinates in SVG paths and transforms are runs of numbers.
        ("12.3.0", "matrix(12 3 0 1 5 5)"),
        ("4.7.21", "matrix(4 7 21 0 0)"),
        ("4.7.21", "matrix(0 4 7 21 0)"),
        ("4.7.21", 'points="4 7 21 3 3"'),
        ("4.7.21", "path 2_4_7_21"),
    ],
)
def test_numbers_inside_a_longer_run_of_numbers(term: str, text: str) -> None:
    assert not Denylist(term).matches(text)


@pytest.mark.parametrize(
    ("term", "text"),
    [
        # Only a term that starts or ends with two numbers is part of a run.
        ("bus 917", "bus 917 2 stops"),
        ("12 rue Quillmore", "5 12 rue Quillmore"),
        ("12.3.0", "(12 3 0) and 4"),
        ("4.7.21", "version 4.7.21, build 9"),
        # A number that ends or starts a word is not part of a run.
        ("4.7.21", "Bluefinch2 4.7.21"),
        ("4.7.21", "IPv4 4.7.21"),
        ("12.3.0", "eth0 12.3.0"),
        ("12.3.0", "x12 12.3.0"),
        ("12.3.0", "12.3.0 2nd try"),
        ("06 39 98 12 34", "room B2 06 39 98 12 34"),
        ("06 39 98 12 34", "call 06 39 98 12 34 3x"),
        # A blank line ends the run.
        ("06 39 98 12 34", "Tel 06 39 98 12 34\n\n2. Next"),
    ],
)
def test_terms_next_to_numbers_that_are_not_a_run(term: str, text: str) -> None:
    assert Denylist(term).matches(text)


LONG_NUMBERS = Denylist("06 39 98 12 34\n3e:22:fb:12:34:56")


@pytest.mark.parametrize(
    "text",
    [
        "0639981234",
        "06\N{EN DASH}39\N{EN DASH}98\N{EN DASH}12\N{EN DASH}34",
        "06\N{MINUS SIGN}39\N{EM DASH}98-12_34",
        "06\N{HYPHEN}39\N{FIGURE DASH}98\N{HORIZONTAL BAR}12 34",
        "06  39 98 12 34",
        "06\N{NO-BREAK SPACE}39\N{NARROW NO-BREAK SPACE}98 12 34",
        "06 39 98\n    12 34",
        "06 39 98 \r\n\t12 34",
        "06.39.98.12.34",
        "06 - 39 98 12 34",
        # A dash with spaces around it does not continue a run of numbers.
        "1 - 06 39 98 12 34",
        "2026-10-25 - 06 39 98 12 34",
        "06 39 98 12 34 - 56",
        "06  -  39 98 12 34",
        "06 \N{EN DASH} 39 \N{EN DASH} 98 \N{EN DASH} 12 \N{EN DASH} 34",
        "3e22fb123456",
        "3e22.fb12.3456",
        "3E-22-FB-12-34-56",
    ],
)
def test_long_numbers_match_their_usual_spellings(text: str) -> None:
    assert LONG_NUMBERS.matches(text)


@pytest.mark.parametrize(
    "text",
    [
        "106399812345",
        "06 39 98 12 345",
        "06 39 98 12 34 56",
        "06 39 98 / 12 34",
        "06 39 98\n\n12 34",
        # Longer runs, written with the separators of long numbers.
        "06\N{EN DASH}39\N{EN DASH}98\N{EN DASH}12\N{EN DASH}34\N{EN DASH}56",
        "1\N{EN DASH}06\N{EN DASH}39\N{EN DASH}98\N{EN DASH}12\N{EN DASH}34",
        "06  39  98  12  34  56",
        "06\t39\t98\t12\t34\t56",
        "06 39 98 12 34\n56",
        "56\n    06 39 98 12 34",
        "+33 06 39 98 12 34",
    ],
)
def test_long_numbers_keep_their_limits(text: str) -> None:
    assert not LONG_NUMBERS.matches(text)


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("12.3.0", "12  3 0"),
        ("12.3.0", "12\N{EN DASH}3\N{EN DASH}0"),
        ("12.3.0", "12 3\n0"),
        ("12.3.0", "1230"),
        # Seven digits are still a short number.
        ("192.0.2.47", "1920247"),
        ("192.0.2.47", "192  0 2 47"),
        # Only the digits count, not the letters of the term.
        ("Quillmore 12 34 Bluefinch", "Quillmore 1234 Bluefinch"),
    ],
)
def test_short_numbers_keep_the_strict_rule(term: str, text: str) -> None:
    assert not Denylist(term).matches(text)


def test_eight_digits_make_a_long_number() -> None:
    assert Denylist("192.0.2.147").matches("19202147")


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("32.87336, -117.22743", "32.87336,-117.22743"),
        ("32.87336, -117.22743", "geo:32.87336,-117.22743"),
        ("32.87336, -117.22743", "center: [32.87336 , -117.22743]"),
        ("32.87336,-117.22743", "32.87336, -117.22743"),
        ("12,5", "12 , 5"),
    ],
)
def test_numbers_separated_by_a_comma(term: str, text: str) -> None:
    assert Denylist(term).matches(text)


def test_numbers_separated_by_a_comma_keep_the_rest_of_the_separator() -> None:
    assert not Denylist("32.87336, -117.22743").matches("32.87336, 117.22743")
    assert not Denylist("12.3.0").matches("12, 3, 0")
    # Only between two numbers: a word and a number keep their rule.
    assert not Denylist("Quillmore, 12").matches("Quillmore , 12")


def test_terms_are_grouped_by_their_first_character() -> None:
    denylist = Denylist("Zorble\nzorblequix\n12 rue Quillmore\n192.0.2.47\n-Bluefinch-\n#x\n!!!")
    text = "a zorble, 192.0.2.47, ZORBLEQUIX and 12 rue quillmore; bluefinch\n"
    assert len(list(denylist._matches(text))) == 5
    assert not denylist.matches("xzorble 1192.0.2.47 192.0.2.470 v1.192.0.2.47")
    assert denylist.matches("v192.0.2.47")


def test_terms_with_many_numbers_fail_fast() -> None:
    words = [f"zorble{chr(97 + i)}" if i % 2 == 0 else str(10 + i) for i in range(21)]
    denylist = Denylist(" ".join(words))
    near = " ".join(words[:-1]) + " qqq"
    start = time.perf_counter()
    for _ in range(100):
        assert not denylist.matches(near)
    assert time.perf_counter() - start < 1
    assert denylist.matches(" ".join(words))
    numbers = [str(10 + i) for i in range(20)]
    denylist = Denylist(" ".join(numbers))
    start = time.perf_counter()
    for separator in (" ", "  ", "\n  ", ""):
        near = separator.join(numbers[:-1]) + separator + "99"
        for _ in range(100):
            assert not denylist.matches(near * 20)
    assert time.perf_counter() - start < 1
    assert denylist.matches("  ".join(numbers))


def test_a_term_that_extends_another_is_found_whole() -> None:
    denylist = Denylist("Zorblequix 5G\nZorblequix5G Guest")
    assert denylist.spans("ssid = Zorblequix5G\nGuest network") == [(1, 2)]


@pytest.mark.parametrize(
    ("term", "text"),
    [
        # The first letter of the word completes an escape before it.
        ("Bluefinch", "q=a%2Bluefinch"),
        ("Bluefinch", 'name = "\\x2Bluefinch"'),
        # An escape left after decoding once stands for a letter of the word.
        ("Finch", '"brand": "Blu\\\\xe9finch"'),
    ],
)
def test_escapes_next_to_glued_terms(term: str, text: str) -> None:
    assert not Denylist(term).matches(text)


@pytest.mark.parametrize("text", ["%20Zorblequix", "%32Zorblequix", "\\x2B Zorblequix"])
def test_glued_terms_after_complete_escapes(text: str) -> None:
    assert Denylist("Zorblequix").matches(text)


@pytest.mark.parametrize(
    "text",
    [
        # Entities that do not decode as written are text, whatever they
        # would decode to in lower case.
        "Quillmore&Sons;Zorblequix",
        "R&D;Zorblequix;2024",
        "R&Deg;Zorblequix",
        "Zorblequix&Ltd;",
        "Zorblequix&Notes;",
        # Even when the text also writes them in a spelling that decodes,
        # before or after them, as written or once decoded.
        "&Hat; &amp;Hat;\nZorblequix&hat;",
        "Zorblequix&hat; &Hat; &amp;Hat;",
        "Zorblequix&amp;hat; &amp;Hat;",
        "&Hat; &amp;Hat; Zorblequix&hat\N{GREEK QUESTION MARK}",
        "&Hat; &amp;Hat; &h\N{ZERO WIDTH SPACE}at;Zorblequix",
        # Partial escapes that the next letters do not complete.
        "\\x1Zorblequix",
        "%2Zorblequix",
        "\\u12Zorblequix",
    ],
)
@pytest.mark.parametrize("rest", ["", " caf\\u00e9"])
def test_glued_terms_after_text_that_looks_like_an_escape(text: str, rest: str) -> None:
    # With an escape elsewhere on the line, both forms of the text are
    # checked for escapes next to the term.
    assert Denylist("Zorblequix").matches(text + rest)


@pytest.mark.parametrize(
    ("text", "found"),
    [
        # A \u escape takes four digits, a \U escape eight. The term is
        # found when its first letters cannot be the digits that are missing.
        ("\\u123Bluefinch", False),
        ("\\u12Bluefinch", True),
        ("\\U1234567Bluefinch", False),
        ("\\U12345Bluefinch", True),
        ("\\U000000C9Bluefinch", False),
        # A legacy entity that decodes in lower case as written.
        ("Bluefinch&ltd;", True),
        ("Bluefinch&eacute;", False),
    ],
)
def test_escapes_cut_short_before_a_term(text: str, found: bool) -> None:
    assert Denylist("Bluefinch").matches(text + " caf\\u00e9") is found


def test_terms_next_to_an_escape_are_still_found() -> None:
    # The longest match ends before an escape, so the shorter terms at the
    # same place are tried, longest first.
    denylist = Denylist("Bluefinch\nBluefinch Quillmore")
    assert denylist.matches("Bluefinch Quillmore&amp;amp;eacute;")
    denylist = Denylist("Zorblequix 5G\nZorblequix5G Guest")
    assert denylist.spans("ssid = Zorblequix5G Guest&amp;amp;eacute;") == [(1, 1)]
    denylist = Denylist("Bluefinch\nBluefinch Quillmore\nBluefinch Quillmore Zorble")
    assert denylist.spans("Bluefinch\nQuillmore Zorble&amp;amp;eacute;") == [(1, 2)]
    # When no term at that place is clear of escapes, the terms inside the
    # longest one are still found.
    denylist = Denylist("Bluefinch Quillmore Zorble\nQuillmore")
    assert denylist.matches("Bluefinch Quillmore Zorble&amp;amp;eacute;")


def test_short_terms_stay_out_of_camel_case_names_next_to_escapes() -> None:
    denylist = Denylist("Ren\nRen Quillmore")
    assert not denylist.matches("getRenQuillmore&amp;amp;eacute;")
    assert denylist.matches("getRenQuillmore")


def test_numbers_in_binary_content() -> None:
    assert NUMBERS.matches_binary(b"\x00Code 12.3.0 here\x00")
    assert not NUMBERS.matches_binary(b"\x00DateTime\x002026:12:30 12:30:00\x00")


def test_long_terms_glued_to_digits() -> None:
    denylist = Denylist("Zorblequix\nFacade")
    for text in ("ssid: Zorblequix5G", "zorblequix2", "2zorblequix", "sensor2Zorblequix"):
        assert denylist.matches(text), text
    assert not denylist.matches("Zorblequixes")
    assert not denylist.matches("xzorblequix2")
    # Terms that hexadecimal digits spell stay whole words, so that hashes
    # do not match them.
    assert denylist.matches("facade_2")
    assert not denylist.matches("3e9facade21")
    assert not denylist.matches("facade2")


def test_camel_case_terms_match_their_words() -> None:
    denylist = Denylist("ZorbleQuixCorp")
    for text in (
        "ZorbleQuixCorp",
        "zorblequixcorp",
        "Copyright Zorble Quix Corp",
        "zorble-quix-corp",
        "zorble_quix_corp",
        "getZorbleQuixCorp()",
    ):
        assert denylist.matches(text), text
    assert not denylist.matches("Zorble Quix")
    values = denylist.mask_values()
    assert {"ZorbleQuixCorp", "Zorble Quix Corp", "zorble-quix-corp", "zorble_quix_corp"} <= values


def test_empty_denylist_matches_nothing() -> None:
    empty = Denylist("")
    assert not empty.matches("anything")
    assert not empty.matches_binary(b"anything")
    assert empty.spans("anything") == []
    assert empty.mask_values() == set()


def test_spans_count_lines_and_terms_over_line_breaks() -> None:
    denylist = Denylist("rue des Lilas")
    text = "one\nwe live rue des\nLilas now\nrue des lilas, rue des lilas\n"
    assert denylist.spans(text) == [(2, 3), (4, 4)]
    assert denylist.spans(text.replace("\n", "\r\n")) == [(2, 3), (4, 4)]
    # Escapes are decoded line by line, so line numbers stay right.
    assert DENYLIST.spans('{"a": "x\\nBluefinch"}\nBluefinch\n"\\u00e9"\nChlo\\u00e9') == [
        (1, 1),
        (2, 2),
        (4, 4),
    ]


@pytest.mark.parametrize(
    ("unit", "times", "count"),
    [
        ("bluefinch\n", 200_000, 200_000),
        ("bluefinch ", 500_000, 1),
        ("rue ", 300_000, 0),
        ("getMaxValue camelCase \\n%41 ", 50_000, 0),
    ],
)
def test_spans_are_linear(unit: str, times: int, count: int) -> None:
    # Each case takes about a second, and minutes if the search is quadratic.
    denylist = Denylist("Bluefinch\nrue des Lilas")
    start = time.perf_counter()
    assert len(denylist.spans(unit * times)) == count
    assert time.perf_counter() - start < 5


def test_normalize_and_unescape() -> None:
    assert normalize("ASCII Text") == "ascii text"
    assert normalize("Ærø Œuvre ß\N{SOFT HYPHEN}x\nY") == "aero oeuvre ssx\ny"
    assert unescape("plain text") is None
    assert unescape("a\\\\nb") == "a\\nb"
    assert unescape("x\\u000ay\nz") == "x y\nz"
    assert unescape("\\ud83d\\ude00 \\U00110000 %ff &lt;") == "\N{GRINNING FACE} \ufffd \xff <"


def test_binary_content() -> None:
    denylist = Denylist(f"Bluefinch\nQuillène Zorbefort\n{SHORT_NAMES}")
    assert denylist.matches_binary(b"\x00\x01Artist\x00Bluefinch\x00")
    assert denylist.matches_binary(b"\x00<dc:title>Leo on the sofa</dc:title>")
    assert denylist.matches_binary(b"\xff\xfe" + "Bluefinch".encode("utf-16-le"))
    assert denylist.matches_binary(b"\x00" + "Quillène Zorbefort".encode("utf-16-be"))
    assert denylist.matches_binary(b"\x00" + "Quillène Zorbefort".encode() + b"\x00")
    assert denylist.matches_binary(b"\x00" + "Quillène Zorbefort".encode("latin-1") + b"\x00")
    assert denylist.matches_binary(b"\x00" + "Leo on the sofa".encode("utf-16-le"))
    assert not denylist.matches_binary(b"\x00IDATxd%Leo#q\x00")
    assert not denylist.matches_binary(b"\x00Leo\x00")
    # Short terms are not looked for in single byte Latin strings, and a
    # symbol that folds into a space does not make a phrase.
    assert not denylist.matches_binary(b"\x00Le\xf3 on the sofa\x00")
    assert not denylist.matches_binary(b"\x00$t-aN\xe0\x92\xa8cL\x00")


def test_short_terms_do_not_match_random_binary_content() -> None:
    denylist = Denylist(f"{SHORT_NAMES}\nbus 917\nrue des Lilas")
    generator = random.Random(1)
    blobs = [generator.randbytes(200_000) for _ in range(50)]
    assert not any(denylist.matches_binary(blob) for blob in blobs)


def test_redact_path_hides_every_spelling() -> None:
    assert DENYLIST.redact_path("docs/BLUEFINCH/notes.md") == "docs/[redacted]/notes.md"
    assert DENYLIST.redact_path("a/rue_des_lilas.yaml") == "a/[redacted]"
    assert DENYLIST.redact_path("a/ruedeslilas.md") == "a/[redacted]"
    assert DENYLIST.redact_path("rue/des/lilas.md") == "[redacted path]"
    assert DENYLIST.redact_path("docs/ok.md") == "docs/ok.md"


def test_location() -> None:
    assert location(DENYLIST, "docs/ok.md") == ("docs/ok.md", "docs/ok.md")
    assert location(DENYLIST, "docs/Bluefinch.md") == ("docs/[redacted]", None)


def test_mask_values_cover_spelling_variants() -> None:
    values = Denylist(
        "Rue des Lilas\nÉté\nZoé\nab\nl\N{RIGHT SINGLE QUOTATION MARK}Orée\nOne Two Three Four"
    ).mask_values()
    assert {"Rue des Lilas", "rue des lilas", "RUE DES LILAS", "rue_des_lilas"} <= values
    assert {"Rue-des-Lilas", "rue.des.lilas", "ruedeslilas", "rue_des-lilas"} <= values
    assert {"Été", "ete", "Ete", "ETE", "Zoé", "zoe", "Zoe", "ZOE"} <= values
    assert {
        "l\N{RIGHT SINGLE QUOTATION MARK}Orée",
        "l'Orée",
        "l'oree",
        "l_oree",
        "L Oree",
    } <= values
    assert {"one_two_three_four", "OneTwoThreeFour"} <= values
    assert "one_two-three_four" not in values
    assert "ab" not in values


def test_denylist_sources() -> None:
    environ = {
        "CI_SECRETS": '{"github_token": "x", "PRIVACY_DENYLIST": "Bluefinch",'
        ' "privacy_denylist_extra": "rue des Lilas", "PRIVACY_DENYLIST_NUMBER": 3,'
        ' "OTHER": "secret"}',
        "PRIVACY_DENYLIST": "ignored, the secret wins",
        "PRIVACY_DENYLIST_LOCAL": "Pré-Vert",
        "PATH": "/usr/bin",
    }
    assert denylist_sources(environ) == ["Bluefinch", "rue des Lilas", "Pré-Vert"]
    assert "CI_SECRETS" not in environ
    assert denylist_sources({"PATH": "/usr/bin"}) == []
    assert denylist_sources({"CI_SECRETS": ""}) == []


@pytest.mark.parametrize("value", ["{not json", '["PRIVACY_DENYLIST"]'])
def test_denylist_sources_reject_bad_json(value: str) -> None:
    environ = {"CI_SECRETS": value}
    with pytest.raises(CheckError, match="CI_SECRETS") as error:
        denylist_sources(environ)
    assert value not in str(error.value)
    assert "CI_SECRETS" not in environ


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("v12.3.0", True),
        ("Release V12.3.0.", True),
        ("tag release-v12.3.0", True),
        ("v1.12.3.0", False),
        ("v12.3.01", False),
        # Only a "v" that starts a word, before a number that the text writes
        # with a dot, so that SVG paths and identifiers do not match.
        ("M12 3 0 L5", False),
        ("M12.3 0 L5", False),
        ("x12_3_0", False),
        ("v12-3-0", False),
        ("dev12.3.0", False),
    ],
)
def test_a_version_prefix_before_a_dotted_number(text: str, found: bool) -> None:
    assert NUMBERS.matches(text) is found


def test_letters_before_decimal_numbers() -> None:
    assert not Denylist("12 3\n1 5\n18 5").matches("l12.3,5 A1.5 l18.5,13.06")
    assert not Denylist("3 14\n22 04").matches("python3.14 ubuntu22.04")
    assert Denylist("3 14").matches("v3.14")


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("Zorblequix5G", True),
        ("Zorblequix 5G", True),
        ("zorblequix-5g", True),
        ("ZORBLEQUIX_5G", True),
        ("Zorblequix 5", False),
        ("Zorblequix 5Gx", False),
        ("Zorblequix 15G", False),
    ],
)
def test_terms_with_letters_and_digits_match_them_separated(text: str, found: bool) -> None:
    assert Denylist("Zorblequix5G").matches(text) is found
    assert Denylist("ZORBLEQUIX5G").matches(text) is found


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("LeBlanc", True),
        ("leblanc", True),
        ("le-blanc", True),
        ("LE_BLANC", True),
        ("getLeBlanc()", True),
        # The next part written with a capital after white space, as a name is.
        ("Le Blanc", True),
        ("LE BLANC", True),
        ("le Blanc", True),
        ("Le\nBlanc", True),
        ("Van Bluefinch", True),
        ("van-bluefinch", True),
        # The words of a sentence.
        ("le blanc", False),
        ("Le blanc", False),
        ("le\nblanc", False),
        ("van bluefinch", False),
        ("le--blanc", False),
        ("le._blanc", False),
    ],
)
def test_short_parts_of_camel_case_terms(text: str, found: bool) -> None:
    assert Denylist("LeBlanc\nVanBluefinch").matches(text) is found


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("BobQuillmore", "Bob Quillmore"),
        ("QuillmoreNAS", "Quillmore NAS"),
        ("DeLaZorble", "De La Zorble"),
        ("VanQuill", "Van Quill"),
        ("McFinch", "Mc Finch"),
    ],
)
def test_short_camel_case_parts_written_as_a_name(term: str, text: str) -> None:
    denylist = Denylist(term)
    assert denylist.matches(text)
    assert denylist.matches_binary(b"\x00" + text.encode("utf-16-le"))
    assert location(denylist, f"docs/{text}.md") == ("docs/[redacted]", None)
    assert not denylist.matches(text.lower())


def test_short_camel_case_parts_in_binary_phrases() -> None:
    denylist = Denylist("LeBo")
    assert denylist.matches_binary(b"\x00<dc:title>Le Bo on a sofa</dc:title>")
    assert not denylist.matches_binary(b"\x00<dc:title>le bo on a sofa</dc:title>")


def test_camel_case_names_in_binary_content() -> None:
    denylist = Denylist("Bluefinch")
    assert denylist.matches_binary(b"\x00\x01setBluefinch\x00")
    assert denylist.matches_binary(b"\x00" + "setBluefinch".encode("latin-1") + b"\xe9\x00")
    assert not denylist.matches_binary(b"\x00\x01setBluefinches\x00")
    assert Denylist("Quill").matches_binary(b"\x00aQuill\x00")


@pytest.mark.parametrize(
    "text",
    [
        "&amp;quot;Zorblequix&amp;quot;",
        "Zorble%2520Quix",
        "Zorble&amp;nbsp;Quix",
        "&amp;#90;orblequix",
        # References without a semicolon, which browsers decode too.
        "&ampzorblequix",
        # Escapes for control characters in string literals.
        "\\bzorblequix",
        "\\fzorblequix",
        "\\vzorblequix",
    ],
)
def test_terms_hidden_by_escapes(text: str) -> None:
    denylist = Denylist("Zorblequix\nZorble Quix")
    assert denylist.matches(text)
    assert location(denylist, f"docs/{text}.md") == ("docs/[redacted]", None)


@pytest.mark.parametrize(
    "text",
    [
        "<pre>C:\\Users\\brindle&gt; dir</pre>",
        "C:\\Users\\brindle%20files",
        "C:\\Users\\brindle\\u0020files",
        "C:\\\\Users\\\\brindle%20files",
        "C:\\Users\\nimblewick\\brindle%20files",
    ],
)
def test_words_after_a_backslash_next_to_an_escape(text: str) -> None:
    denylist = Denylist("Brindle\nNimblewick")
    assert denylist.matches(text)
    assert denylist.matches(text.replace("brindle", "nimblewick").replace("Brindle", "Nimblewick"))


@pytest.mark.parametrize(
    "text",
    ["Zorble\N{COMBINING GRAPHEME JOINER}quix", "Zorble\N{VARIATION SELECTOR-16}quix"],
)
def test_marks_without_a_combining_class_are_ignored(text: str) -> None:
    assert Denylist("Zorblequix").matches(text)


@pytest.mark.parametrize(
    "text",
    [
        "get\N{COMBINING GRAPHEME JOINER}Bluefinch",
        "get\N{VARIATION SELECTOR-16}Bluefinch",
        "get\U000e0100Bluefinch",
        "get\N{ZERO WIDTH SPACE}Bluefinch",
        "get\N{SOFT HYPHEN}Bluefinch",
        "getRene\N{COMBINING ACUTE ACCENT}Bluefinch",
    ],
)
def test_invisible_characters_do_not_glue_camel_case_names(text: str) -> None:
    denylist = Denylist("Bluefinch")
    assert denylist.matches(text)
    assert denylist.matches_binary(b"\x00" + text.encode() + b"\x00")
    assert location(denylist, f"src/{text}.py") == ("src/[redacted]", None)


@pytest.mark.parametrize("text", ["get&#x34f;Bluefinch", "get\\u034FBluefinch"])
def test_escaped_invisible_characters_do_not_glue_camel_case_names(text: str) -> None:
    denylist = Denylist("Bluefinch")
    assert denylist.matches(text)
    assert location(denylist, f"src/{text}.py") == ("src/[redacted]", None)


def test_keycaps_separate_numbers() -> None:
    keycap = "\N{VARIATION SELECTOR-16}\N{COMBINING ENCLOSING KEYCAP}"
    assert LONG_NUMBERS.matches(f"1{keycap} 06 39 98 12 34")
    assert NUMBERS.matches(f"1{keycap} 12.3.0")
    # A term spelled with keycaps is not read as its digits.
    assert not LONG_NUMBERS.matches("".join(digit + keycap for digit in "0639981234"))


def test_terms_over_lines_that_decode_twice() -> None:
    # Terms on or next to a line that decodes twice are found.
    denylist = Denylist("Bluefinch Quillmore")
    assert denylist.spans("intro\nBluefinch\n&amp;#81;uillmore\nend") == [(2, 3)]
    assert denylist.spans("intro\n&amp;#66;luefinch\nQuillmore\nend") == [(2, 3)]
    assert denylist.spans("Bluefinch&amp;nbsp;\nQuillmore") == [(1, 2)]
    assert denylist.spans("intro\nBluefinch\n\n\n&amp;#81;uillmore") == [(2, 5)]
    assert denylist.spans("Bluefinch\n---\n &amp;#42;\n&amp;#81;uillmore") == [(1, 4)]
    # The other lines stay in place, so that they still separate words.
    text = "&amp;#66;luefinch\n---\nThe quick brown fox\n---\n&amp;#81;uillmore"
    assert not denylist.matches(text)
    assert not denylist.matches("&amp;#81;x\nBluefinch\nwords\nQuillmore\n&amp;#81;y")
    # Terms that the decoded text holds are found once.
    assert denylist.spans("&amp;#81;x\nBluefinch Quillmore\n\n\nBluefinch Quillmore") == [
        (2, 2),
        (5, 5),
    ]


@pytest.mark.parametrize(
    ("unit", "times"),
    [("%2520\n", 100_000), ("&amp;#45;\n", 50_000), ("C:\\Users\\bob%20x\n", 50_000)],
)
def test_lines_that_decode_twice_are_linear(unit: str, times: int) -> None:
    denylist = Denylist("Bluefinch Quillmore")
    start = time.perf_counter()
    assert denylist.spans(unit * times) == []
    assert time.perf_counter() - start < 5


def test_upper_case_escapes_stay_whole_in_camel_case_names() -> None:
    # The escape stands for a letter of the word, whatever the case of its
    # digits.
    denylist = Denylist("Bluefinch")
    for text in ("Ren\\xC9Bluefinch", "Ren&#XcB;Bluefinch", "Ren&#x000000cB;Bluefinch"):
        assert not denylist.matches(text)
        assert not denylist.matches(text.lower().replace("bluefinch", "Bluefinch"))
    assert denylist.matches("Ren\\xA9Bluefinch")


def test_split_camel_keeps_escapes_whole() -> None:
    assert split_camel("getName") == "get\x00Name"
    for escape in ("\\xA9", "\\uaBcD", "\\UaBcDeFaB", "%aB", "&#xaBcD;", "&#XaB;", "&#x0000aBcD;"):
        assert split_camel(f"{escape}Quix") == f"{escape}Quix"
        assert split_camel(f"fooBar{escape}") == f"foo\x00Bar{escape}"


def test_numeric_references_of_any_length() -> None:
    denylist = Denylist("Zorblequix")
    assert denylist.matches("&#" + "0" * 5000 + "90;orblequix")
    assert denylist.matches("&#x" + "0" * 5000 + "5a;orblequix")
    assert denylist.matches("&#" + "9" * 5000 + ";Zorblequix")
    assert unescape("&#" + "9" * 5000 + "; &#x0000041; &#00065;") == "\ufffd A A"
    assert unescape("&#x1234567; &#1234567;") == "\ufffd \ufffd"


def test_mask_values_of_numbers() -> None:
    values = Denylist("12.30\n12.3.0\n06 39 98 12 34").mask_values()
    assert {"12.30", "12 30", "12_30", "12.3.0", "12 3 0", "12-3-0", "12_3.0"} <= values
    assert not {"1230", "12-30", "123.0", "12.30.0"} & values
    assert {"06 39 98 12 34", "0639981234", "06-39-98-12-34", "06.39.98.12.34"} <= values
    # A term of two numbers keeps its dash when it is written so.
    assert "12-30" in Denylist("12-30").mask_values()
    # Terms with words keep the dash, as in branch names.
    values = Denylist("Brindlewood 7 4\nfix 12 14 Quillmore").mask_values()
    assert {"brindlewood-7-4", "Brindlewood 7 4", "fix-12-14-quillmore"} <= values
    assert not {"brindlewood-74", "fix-1214-quillmore"} & values
    # Terms of more than three words use one separator everywhere.
    values = Denylist("192.0.2.47\nZorble 1 2 Quix").mask_values()
    assert {"192.0.2.47", "192-0-2-47", "zorble_1_2_quix", "zorble-1-2-quix"} <= values
    assert not {"1920247", "zorble12quix"} & values


def test_mask_values_split_letters_from_digits() -> None:
    values = Denylist("Zorblequix5G").mask_values()
    assert {"Zorblequix5G", "zorblequix-5g", "Zorblequix 5G", "ZORBLEQUIX_5G"} <= values
