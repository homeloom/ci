"""Tests for matching denylisted terms. Every term here is invented."""

from __future__ import annotations

import random
import time

import pytest

from ci_checks._common import CheckError
from ci_checks.denylist import Denylist, denylist_sources, location, normalize, unescape

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
        "step: 12",
        "steps 12",
        "step 120",
        "[bus, 917]",
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
    ],
)
def test_terms_with_numbers_match_as_written(term: str, text: str) -> None:
    assert Denylist(term).matches(text)


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("03/12/1985", "03/12/19850"),
        ("12 rue Quillmore", "12: rue Quillmore"),
        ("Quillmore Road 12", "Quillmore Road, 12"),
        ("Flat 3 12 Quillmore Road", "Flat 3, 12 Quillmore Road"),
    ],
)
def test_terms_with_numbers_keep_their_limits(term: str, text: str) -> None:
    assert not Denylist(term).matches(text)


def test_terms_are_grouped_by_their_first_character() -> None:
    denylist = Denylist("Zorble\nzorblequix\n12 rue Quillmore\n192.0.2.47\n-Bluefinch-\n#x\n!!!")
    text = "a zorble, 192.0.2.47, ZORBLEQUIX and 12 rue quillmore; bluefinch\n"
    assert len(list(denylist._matches(text))) == 5
    assert not denylist.matches("xzorble 1192.0.2.47 192.0.2.470 v192.0.2.47")


def test_terms_with_many_numbers_fail_fast() -> None:
    words = [f"zorble{chr(97 + i)}" if i % 2 == 0 else str(10 + i) for i in range(21)]
    denylist = Denylist(" ".join(words))
    near = " ".join(words[:-1]) + " qqq"
    start = time.perf_counter()
    for _ in range(100):
        assert not denylist.matches(near)
    assert time.perf_counter() - start < 1
    assert denylist.matches(" ".join(words))


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
        # Entities that do not decode are text.
        "Smith&Sons;Zorblequix",
        "R&D;Zorblequix;2024",
        # Partial escapes that the next letters do not complete.
        "\\x1Zorblequix",
        "%2Zorblequix",
        "\\u12Zorblequix",
    ],
)
def test_glued_terms_after_text_that_looks_like_an_escape(text: str) -> None:
    assert Denylist("Zorblequix").matches(text)


def test_terms_next_to_an_escape_are_still_found() -> None:
    # The longest match ends before an escape, so the shorter terms at the
    # same place are tried.
    denylist = Denylist("Bluefinch\nBluefinch Quillmore")
    assert denylist.matches("Bluefinch Quillmore&amp;amp;eacute;")
    denylist = Denylist("Zorblequix 5G\nZorblequix5G Guest")
    assert denylist.spans("ssid = Zorblequix5G Guest&amp;amp;eacute;") == [(1, 1)]


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


def test_spans_are_linear() -> None:
    denylist = Denylist("Bluefinch\nrue des Lilas")
    start = time.perf_counter()
    assert len(denylist.spans("bluefinch\n" * 200_000)) == 200_000
    assert denylist.spans("bluefinch " * 500_000) == [(1, 1)]
    assert denylist.spans("rue " * 300_000) == []
    assert not denylist.matches("getMaxValue camelCase \\n%41 " * 50_000)
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
