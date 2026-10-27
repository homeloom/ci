"""Tests for reading the metadata of image, document and video files."""

from __future__ import annotations

import random
import struct
import time
import zlib
from collections.abc import Callable

import pytest

from ci_checks.metadata import (
    MAX_EXIF_BLOCKS,
    MAX_FIELD_BYTES,
    MAX_IFD_ENTRIES,
    MAX_IFDS,
    MAX_SEGMENTS,
    MAX_TEXT_CHARS,
    read_metadata,
)
from media import (
    ARTIST,
    ASCII,
    BYTE,
    EXIF_IFD,
    GPS_IFD,
    GPS_LATITUDE,
    LONG,
    RATIONAL,
    UNDEFINED,
    USER_COMMENT,
    UTF8,
    XP_AUTHOR,
    ascii_field,
    atom,
    data_atom,
    exif_segment,
    gps_position,
    iptc_segment,
    jpeg,
    jpeg_segment,
    location_atom,
    movie,
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
            ascii_field(0x010E, "Zélèbe Quillmore", UTF8),  # EXIF 3.0 UTF-8 text.
        ],
        gps_position(order),
        order,
    )
    metadata = read_metadata(structure)
    assert metadata.texts == ("Ada Bluefinch", "Pré-Vert", "Zélèbe Quillmore")
    assert metadata.location
    assert not metadata.truncated


def test_gps_directory_without_a_position() -> None:
    zero = [rational_field(2, "<", (0, 1), (0, 1), (0, 1)), ascii_field(1, "N")]
    assert not read_metadata(tiff([ascii_field(ARTIST, "x")], zero)).location
    assert read_metadata(tiff([], gps_position(minutes=1, seconds=0))).location


@pytest.mark.parametrize("order", ["<", ">"])
@pytest.mark.parametrize(
    ("charset", "expected"),
    [(b"UNICODE\0", "rue des Lilas"), (b"ASCII\0\0\0", "bus 917")],
)
def test_user_comment_in_the_exif_directory(order: str, charset: bytes, expected: str) -> None:
    encoding = "utf-16-le" if order == "<" else "utf-16-be"
    value = charset + (expected.encode(encoding) if charset == b"UNICODE\0" else expected.encode())
    # The first directory, at offset 8, points to the EXIF directory at 26,
    # whose comment is stored at 44.
    structure = (b"II*\0" if order == "<" else b"MM\0*") + struct.pack(order + "IH", 8, 1)
    structure += struct.pack(order + "HHII", EXIF_IFD, LONG, 1, 26) + b"\0\0\0\0"
    structure += struct.pack(order + "H", 1)
    structure += struct.pack(order + "HHII", USER_COMMENT, UNDEFINED, len(value), 44) + b"\0\0\0\0"
    assert read_metadata(structure + value).texts == (expected,)


def test_png_text_chunks() -> None:
    data = png(
        png_chunk(b"tEXt", b"Author\0Bluefinch"),
        png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"jane@zorble.internal")),
        png_chunk(b"zTXt", b"Broken\0\0not zlib"),
        png_chunk(b"iTXt", b"Title\0\0\0fr\0Titre\0Chlo\xc3\xa9"),
        png_chunk(b"iTXt", b"Description\0\x01\0en\0\0" + zlib.compress(b"rue des Lilas")),
        png_chunk(b"eXIf", tiff([ascii_field(ARTIST, "Pre-Vert")])),
    )
    texts = read_metadata(data).texts
    assert texts == (
        "Bluefinch",
        "jane@zorble.internal",
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
        b"\xff\xd0",  # A marker without a length.
        jpeg_segment(0xFE, b"taken at home"),
        iptc_segment((2, 80, b"Quillmore Bluefinch"), (1, 90, b"\x1b%G"), (2, 120, b"caption")),
    )
    metadata = read_metadata(data)
    assert sorted(metadata.texts) == [
        "Bluefinch",
        "Quillmore Bluefinch",
        "caption",
        "taken at home",
    ]
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
    located = xmp('dc:creator="Bluefinch" exif:GPSLatitude="35,30.0N"')
    nowhere = xmp('exif:GPSLatitude="0,0.0N" exif:GPSLongitude=""')
    element = b"<x:xmpmeta><exif:GPSLongitude>160,15.0E</exif:GPSLongitude></x:xmpmeta>"
    metadata = read_metadata(b"\0\0" + located + b"\0" + element + b"<x:xmpmeta unclosed")
    assert "Bluefinch" in metadata.texts[0]
    assert metadata.texts[1] == element.decode()
    assert len(metadata.texts) == 2
    assert metadata.location
    assert not read_metadata(nowhere).location
    assert read_metadata(element).location


def test_xmp_openings_without_an_end_are_read_in_linear_time() -> None:
    start = time.perf_counter()
    assert read_metadata(b"\0\1" + b"<x:xmpmeta " * 40_000).texts == ()
    assert time.perf_counter() - start < 1


def test_pdf_information_fields() -> None:
    data = pdf(
        b"/Author (Blue\\146inch) /Title (\\376\\377\\000C\\000h\\000l\\000o\\000\\351)"
        b" /Subject (a \\(b\\) c\\nd \\q) /Creator <4142> /Keywords ()"
        b" /Producer (Notes (draft, v2) for Zorbel\\\nQuill\\\r\nmore)"
    )
    assert read_metadata(data).texts == (
        "Bluefinch",
        "Chloé",
        "a (b) c\nd q",
        "AB",
        "Notes (draft, v2) for ZorbelQuillmore",
    )
    assert read_metadata(b"not a pdf /Author (Bluefinch)").texts == ()


def test_pdf_hexadecimal_strings() -> None:
    utf16 = ("FEFF" + "Zélèbe Quillmore".encode("utf-16-be").hex()).encode()
    data = pdf(
        b"/Author <" + utf16 + b"> /Title < 4 2 6c\n7565 > /Subject <5A6F7>"
        b" /Keywords <not hex> /Creator <<>> /Producer <>"
    )
    assert read_metadata(data).texts == ("Zélèbe Quillmore", "Blue", "Zop")
    assert not read_metadata(data).truncated


def test_no_metadata() -> None:
    assert read_metadata(b"").texts == ()
    assert read_metadata(png()) == read_metadata(b"\0")
    assert not read_metadata(jpeg()).location


def test_video_location_in_user_data() -> None:
    located = read_metadata(movie(atom(b"udta", location_atom(b"+35.5000+160.2500/"))))
    assert located.texts == ("+35.5000+160.2500/",)
    assert located.location
    nowhere = read_metadata(movie(atom(b"udta", location_atom(b"+00.0000-000.0000/"))))
    assert nowhere.texts == ("+00.0000-000.0000/",)
    assert not nowhere.location
    assert not read_metadata(movie(atom(b"udta", location_atom(b"somewhere 12")))).location
    other = movie(atom(b"trak", location_atom(b"+35.5+160.25/")), atom(b"udta", atom(b"free")))
    assert read_metadata(other) == read_metadata(b"")


@pytest.mark.parametrize("version", [b"", b"\0\0\0\0"])
def test_video_location_in_metadata_items(version: bytes) -> None:
    # As iTunes and FFmpeg write it, in the user data, with the item named
    # by its type; MP4 metadata atoms start with a version and flags.
    items = atom(
        b"ilst", atom(b"\xa9nam", data_atom(b"Clip")), atom(b"\xa9xyz", data_atom(b"-35.5+160.25/"))
    )
    named = read_metadata(
        movie(atom(b"udta", atom(b"meta", version, atom(b"hdlr", b"\0" * 25), items)))
    )
    assert named.texts == ("-35.5+160.25/",)
    assert named.location
    # As Apple tools write it, in the movie atom, with the item named by a key.
    keys = atom(
        b"keys",
        struct.pack(">II", 0, 2),
        atom(b"mdta", b"com.apple.quicktime.make"),
        atom(b"mdta", b"com.apple.quicktime.location.ISO6709"),
    )
    values = atom(
        b"ilst",
        atom(struct.pack(">I", 1), data_atom(b"Zorblequix")),
        atom(struct.pack(">I", 2), atom(b"free"), data_atom(b"+35.5+160.25+12.0/")),
        atom(struct.pack(">I", 3), data_atom(b"+35.5+160.25/")),
    )
    keyed = read_metadata(movie(atom(b"meta", version, keys, values)))
    assert keyed.texts == ("+35.5+160.25+12.0/",)
    assert keyed.location


def test_video_atoms_with_large_and_open_sizes() -> None:
    location = atom(b"moov", atom(b"udta", location_atom(b"+35.5+160.25/")))
    large = struct.pack(">I4sQ", 1, b"mdat", 24) + b"\0" * 8
    assert read_metadata(atom(b"ftyp", b"mp42") + large + location).location
    # An atom of size zero runs to the end of the file.
    assert read_metadata(atom(b"ftyp", b"mp42") + b"\0\0\0\0" + location[4:]).location
    assert not read_metadata(atom(b"ftyp", b"mp42") + struct.pack(">I4s", 4, b"moov")).location


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
        pdf(b"/Author (Bluefinch) /Title <FEFF0042> /Subject (a (b) c)"),
        movie(atom(b"udta", location_atom(b"+35.5+160.25/"), atom(b"meta", b"\0" * 4))),
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


def test_malformed_structures_are_not_truncated() -> None:
    # A directory that points to itself, and counts and offsets past the end.
    looping = b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1)
    looping += struct.pack("<HHII", EXIF_IFD, LONG, 1, 8) + struct.pack("<I", 8)
    pointer = b"II*\0" + struct.pack("<I", 8) + struct.pack("<H", 1)
    pointer += struct.pack("<HHII", ARTIST, ASCII, 0xFFFFFFF, 0xFFFFFF00) + b"\0" * 4
    unterminated = pdf(b"/Author (Bluefinch") + b"\0" * 10
    for data in (looping, pointer, b"%PDF /Title <4142"):
        assert read_metadata(data) == read_metadata(b"")
    assert read_metadata(unterminated).texts[0].startswith("Bluefinch >>")
    assert not read_metadata(unterminated).truncated


def ifd_chain(count: int) -> bytes:
    """Return a TIFF structure with a chain of directories that each hold one name."""
    structure = b"II*\0" + struct.pack("<I", 8)
    for index in range(count):
        following = 8 + 18 * (index + 1) if index + 1 < count else 0
        structure += struct.pack("<HHHI", 1, ARTIST, ASCII, 4) + b"Zib\0"
        structure += struct.pack("<I", following)
    return structure


def png_chunks(count: int) -> bytes:
    """Return a PNG file of count chunks, three of which hold no text."""
    return png(*[png_chunk(b"tEXt", b"k\0x")] * (count - 3))


def webp_chunks(count: int) -> bytes:
    """Return a WebP file whose last of count chunks holds EXIF data."""
    return webp(*[(b"JUNK", b"")] * (count - 1), (b"EXIF", tiff([ascii_field(ARTIST, "x")])))


def location_items(text: bytes) -> bytes:
    """Return a video whose metadata items hold a location."""
    items = atom(b"ilst", atom(b"\xa9xyz", data_atom(text)))
    return movie(atom(b"udta", atom(b"meta", b"\0\0\0\0", items)))


# How to build a file with as many structures, or as long a field, as a
# bound allows; the bound; and how many texts are read at and past it.
BOUNDS: list[tuple[Callable[[int], bytes], int, int, int]] = [
    (
        lambda count: b"\xff\xd8" + b"\xff\xfe\x00\x03x" * count,
        MAX_SEGMENTS,
        MAX_SEGMENTS,
        MAX_SEGMENTS,
    ),
    (png_chunks, MAX_SEGMENTS, MAX_SEGMENTS - 3, MAX_SEGMENTS - 2),
    (webp_chunks, MAX_SEGMENTS, 1, 0),
    (
        lambda count: jpeg(iptc_segment(*[(2, 80, b"x")] * count)),
        MAX_SEGMENTS,
        MAX_SEGMENTS,
        MAX_SEGMENTS,
    ),
    (
        lambda count: movie(atom(b"udta", *[location_atom(b"+1+1/")] * count)),
        MAX_SEGMENTS,
        MAX_SEGMENTS,
        MAX_SEGMENTS,
    ),
    (ifd_chain, MAX_IFDS, MAX_IFDS, MAX_IFDS),
    (
        lambda count: tiff([ascii_field(ARTIST, "Zib")] * count),
        MAX_IFD_ENTRIES,
        MAX_IFD_ENTRIES,
        MAX_IFD_ENTRIES,
    ),
    (
        lambda count: (b"Exif\0\0" + tiff([ascii_field(ARTIST, "Zib")])) * count,
        MAX_EXIF_BLOCKS,
        MAX_EXIF_BLOCKS,
        MAX_EXIF_BLOCKS,
    ),
    # The terminating zero of an ASCII field counts in its size.
    (lambda size: tiff([ascii_field(ARTIST, "x" * (size - 1))]), MAX_FIELD_BYTES, 1, 1),
    (
        lambda size: png(png_chunk(b"zTXt", b"k\0\0" + zlib.compress(b"x" * size))),
        MAX_FIELD_BYTES,
        1,
        1,
    ),
    (
        lambda size: png(png_chunk(b"iTXt", b"k\0\x01\0\0\0" + zlib.compress(b"x" * size))),
        MAX_FIELD_BYTES,
        1,
        1,
    ),
    (lambda size: pdf(b"/Title (" + b"x" * size + b")"), MAX_FIELD_BYTES, 1, 1),
    (lambda size: pdf(b"/Title <" + b"41" * size + b">"), MAX_FIELD_BYTES, 1, 1),
    (lambda size: location_items(b"+" * size), MAX_FIELD_BYTES, 1, 1),
]


@pytest.mark.parametrize(("build", "bound", "at_bound", "past_bound"), BOUNDS)
def test_bounds_mark_the_metadata_truncated(
    build: Callable[[int], bytes], bound: int, at_bound: int, past_bound: int
) -> None:
    within = read_metadata(build(bound))
    assert len(within.texts) == at_bound
    assert not within.truncated
    cut = read_metadata(build(bound + 1))
    assert len(cut.texts) == past_bound
    assert all(len(text) <= MAX_FIELD_BYTES for text in cut.texts)
    assert cut.truncated


def test_text_kept_per_file_is_bounded() -> None:
    bomb = png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"a" * MAX_FIELD_BYTES))
    many = read_metadata(png(*[bomb] * (MAX_TEXT_CHARS // MAX_FIELD_BYTES + 2)))
    assert sum(map(len, many.texts)) == MAX_TEXT_CHARS
    assert many.truncated
    exact = read_metadata(png(*[bomb] * (MAX_TEXT_CHARS // MAX_FIELD_BYTES)))
    assert sum(map(len, exact.texts)) == MAX_TEXT_CHARS
    assert not exact.truncated
    # Once the room is used up, a TIFF text field marks the metadata truncated.
    entries = [ascii_field(ARTIST, "x" * 1_000)] * MAX_IFD_ENTRIES
    fields = read_metadata(
        png(*[bomb] * (MAX_TEXT_CHARS // MAX_FIELD_BYTES), png_chunk(b"eXIf", tiff(entries)))
    )
    assert sum(map(len, fields.texts)) == MAX_TEXT_CHARS
    assert fields.truncated


def shared_value(tag: int, kind: int, count: int, gps: bool = False) -> bytes:
    """Return a TIFF structure whose fields, as many as allowed, all point at the same zeros.

    The zeros take count items of the field type. With gps, the fields are
    in the GPS directory.
    """
    start = 26 if gps else 8
    value = start + 2 + 12 * MAX_IFD_ENTRIES + 4
    structure = b"II*\0" + struct.pack("<I", 8)
    if gps:
        structure += struct.pack("<HHHII", 1, GPS_IFD, LONG, 1, start) + b"\0" * 4
    structure += struct.pack("<H", MAX_IFD_ENTRIES)
    structure += struct.pack("<HHII", tag, kind, count, value) * MAX_IFD_ENTRIES
    return structure + b"\0" * (4 + count * (8 if kind == RATIONAL else 1))


def test_padding_uses_up_the_room() -> None:
    # Nulls that pad a field keep no text, but reading them takes room.
    metadata = read_metadata(shared_value(ARTIST, ASCII, MAX_FIELD_BYTES))
    assert metadata.texts == ()
    assert metadata.truncated


@pytest.mark.parametrize(
    ("tag", "kind", "count", "gps"),
    [
        (ARTIST, ASCII, MAX_FIELD_BYTES, False),
        (XP_AUTHOR, BYTE, MAX_FIELD_BYTES, False),
        (GPS_LATITUDE, RATIONAL, MAX_FIELD_BYTES // 8, True),
    ],
)
def test_fields_that_share_a_value_are_read_in_linear_time(
    tag: int, kind: int, count: int, gps: bool
) -> None:
    data = b"\0\1" + (b"Exif\0\0" + shared_value(tag, kind, count, gps)) * MAX_EXIF_BLOCKS
    start = time.perf_counter()
    assert read_metadata(data).texts == ()
    assert time.perf_counter() - start < 1
