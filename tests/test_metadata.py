"""Tests for reading the metadata of image and document files."""

from __future__ import annotations

import random
import struct
import zlib

import pytest

from ci_checks.metadata import read_metadata
from media import (
    ARTIST,
    BYTE,
    EXIF_IFD,
    LONG,
    UNDEFINED,
    USER_COMMENT,
    XP_AUTHOR,
    ascii_field,
    exif_segment,
    gps_position,
    iptc_segment,
    jpeg,
    jpeg_segment,
    pdf,
    png,
    png_chunk,
    rational_field,
    tiff,
    webp,
    xmp,
)


@pytest.mark.parametrize("order", ["<", ">"])
def test_tiff_text_fields_and_position(order: str) -> None:
    structure = tiff(
        [
            ascii_field(ARTIST, "Ada Bluefinch"),
            (XP_AUTHOR, BYTE, 18, "Pré-Vert".encode("utf-16-le") + b"\0\0"),
            (0x0110, 3, 1, struct.pack(order + "H", 7)),  # A number, not text.
        ],
        gps_position(order),
        order,
    )
    metadata = read_metadata(structure)
    assert metadata.texts == ("Ada Bluefinch", "Pré-Vert")
    assert metadata.location


def test_gps_directory_without_a_position() -> None:
    zero = [rational_field(2, "<", (0, 1), (0, 1), (0, 1)), ascii_field(1, "N")]
    assert not read_metadata(tiff([ascii_field(ARTIST, "x")], zero)).location
    assert read_metadata(tiff([], gps_position(degrees=0))).location


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"UNICODE\0" + "rue des Lilas".encode("utf-16-le"), "rue des Lilas"),
        (b"ASCII\0\0\0bus 917\0", "bus 917"),
    ],
)
def test_user_comment_in_the_exif_directory(value: bytes, expected: str) -> None:
    # The first directory, at offset 8, points to the EXIF directory at 26,
    # whose comment is stored at 44.
    structure = b"II*\0" + struct.pack("<IH", 8, 1)
    structure += struct.pack("<HHII", EXIF_IFD, LONG, 1, 26) + b"\0\0\0\0"
    structure += struct.pack("<H", 1)
    structure += struct.pack("<HHII", USER_COMMENT, UNDEFINED, len(value), 44) + b"\0\0\0\0"
    assert read_metadata(structure + value).texts == (expected,)


def test_png_text_chunks() -> None:
    data = png(
        png_chunk(b"tEXt", b"Author\0Bluefinch"),
        png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"jane@example-corp.fr")),
        png_chunk(b"zTXt", b"Broken\0\0not zlib"),
        png_chunk(b"iTXt", b"Title\0\0\0fr\0Titre\0Chlo\xc3\xa9"),
        png_chunk(b"iTXt", b"Description\0\x01\0en\0\0" + zlib.compress(b"rue des Lilas")),
        png_chunk(b"eXIf", tiff([ascii_field(ARTIST, "Pre-Vert")])),
    )
    texts = read_metadata(data).texts
    assert texts == (
        "Bluefinch",
        "jane@example-corp.fr",
        "Titre",
        "Chloé",
        "rue des Lilas",
        "Pre-Vert",
    )


def test_jpeg_segments() -> None:
    data = jpeg(
        b"\xff\xff",  # A fill byte.
        jpeg_segment(0xE0, b"JFIF\0\x01\x02"),
        exif_segment(tiff([ascii_field(ARTIST, "Bluefinch")], gps_position())),
        jpeg_segment(0xFE, b"taken at home"),
        iptc_segment((2, 80, b"Ada Lovelace"), (1, 90, b"\x1b%G"), (2, 120, b"caption")),
        b"\xff\xd0",  # A marker without a length.
    )
    metadata = read_metadata(data)
    assert sorted(metadata.texts) == ["Ada Lovelace", "Bluefinch", "caption", "taken at home"]
    assert metadata.location


def test_iptc_stops_at_extended_lengths() -> None:
    segment = iptc_segment((2, 80, b"first"))
    extended = segment.replace(b"\x1c\x02\x50\x00\x05", b"\x1c\x02\x50\x80\x05")
    assert read_metadata(jpeg(segment)).texts == ("first",)
    assert read_metadata(jpeg(extended)).texts == ()


def test_webp_exif_with_and_without_header() -> None:
    bare = webp((b"VP8 ", b"\0" * 10), (b"EXIF", tiff([ascii_field(ARTIST, "Bluefinch")])))
    prefixed = webp((b"EXIF", b"Exif\0\0" + tiff([ascii_field(ARTIST, "Bluefinch")])))
    assert read_metadata(bare).texts == ("Bluefinch",)
    assert read_metadata(prefixed).texts == ("Bluefinch",)


def test_exif_found_in_other_containers() -> None:
    heif = b"\0\0\0\x18ftypheic" + b"\0" * 20 + b"Exif\0\0" + tiff([], gps_position())
    assert read_metadata(heif).location


def test_xmp_packets() -> None:
    located = xmp('dc:creator="Bluefinch" exif:GPSLatitude="48,51.4N"')
    nowhere = xmp('exif:GPSLatitude="0,0.0N" exif:GPSLongitude=""')
    element = b"<x:xmpmeta><exif:GPSLongitude>2,21.1E</exif:GPSLongitude></x:xmpmeta>"
    metadata = read_metadata(b"\0\0" + located)
    assert "Bluefinch" in metadata.texts[0]
    assert metadata.location
    assert not read_metadata(nowhere).location
    assert read_metadata(element).location


def test_pdf_information_fields() -> None:
    data = pdf(
        b"/Author (Blue\\146inch) /Title (\\376\\377\\000C\\000h\\000l\\000o\\000\\351)"
        b" /Subject (a \\(b\\) c\\nd \\q) /Creator <4142> /Keywords ()"
    )
    assert read_metadata(data).texts == ("Bluefinch", "Chloé", "a (b) c\nd q")
    assert read_metadata(b"not a pdf /Author (Bluefinch)").texts == ()


def test_no_metadata() -> None:
    assert read_metadata(b"").texts == ()
    assert read_metadata(png()) == read_metadata(b"\0")
    assert not read_metadata(jpeg()).location


@pytest.mark.parametrize(
    "data",
    [
        png(png_chunk(b"tEXt", b"Author\0Bluefinch")),
        jpeg(
            exif_segment(tiff([ascii_field(ARTIST, "Bluefinch")], gps_position())),
            iptc_segment((2, 80, b"Ada")),
            jpeg_segment(0xFE, b"comment"),
        ),
        webp((b"EXIF", tiff([ascii_field(ARTIST, "Bluefinch")], gps_position(">"), ">"))),
        tiff([ascii_field(ARTIST, "Bluefinch")], gps_position()),
        pdf(b"/Author (Bluefinch)"),
    ],
)
def test_malformed_files_are_skipped(data: bytes) -> None:
    generator = random.Random(len(data))
    for end in range(len(data)):
        read_metadata(data[:end])
    for _ in range(300):
        broken = bytearray(data)
        for _ in range(generator.randint(1, 4)):
            broken[generator.randrange(len(broken))] = generator.randrange(256)
        read_metadata(bytes(broken))


def test_hostile_structures_stay_bounded() -> None:
    # A directory that points to itself, and counts and offsets past the end.
    looping = b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1)
    looping += struct.pack("<HHII", EXIF_IFD, LONG, 1, 8) + struct.pack("<I", 8)
    assert read_metadata(looping).texts == ()
    huge = b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 65535) + b"\0" * 12 * 1100
    assert read_metadata(huge).texts == ()
    pointer = b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1)
    pointer += struct.pack("<HHII", ARTIST, 2, 0xFFFFFFF, 0xFFFFFF00) + b"\0" * 4
    assert read_metadata(pointer).texts == ()
    bomb = png(png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"a" * 50_000_000)))
    assert len(read_metadata(bomb).texts[0]) == 1_000_000
    many = b"\xff\xd8" + b"\xff\xfe\x00\x02" * 20_000
    assert len(read_metadata(many).texts) == 0
