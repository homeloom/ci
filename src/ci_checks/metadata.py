"""Read the text fields and the location that image, document and video files carry.

Cameras, phones and editors write the author, a title, comments and often a
GPS position into image files. This module reads PNG text chunks, JPEG
comments, EXIF (in JPEG, PNG, WebP, TIFF and HEIF files), IPTC records, XMP
packets, the information dictionary of PDF files and the location of
QuickTime and MP4 videos, without decoding the images themselves. Every
length and offset is checked, so malformed data is skipped. Bounds keep
hostile files cheap to read, and the result says when one of them cut
content, so that a caller can fail closed.
"""

from __future__ import annotations

import re
import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

from ci_checks._common import LEGACY

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
EXIF_HEADER = b"Exif\x00\x00"
PHOTOSHOP_HEADER = b"Photoshop 3.0\x00"
# Bounds that keep hostile files cheap to read: the bytes read of one field,
# the characters kept for one file, and the structures read.
MAX_FIELD_BYTES = 1_000_000
MAX_TEXT_CHARS = 4_000_000
MAX_SEGMENTS = 10_000
MAX_EXIF_BLOCKS = 16
MAX_IFDS = 16
MAX_IFD_ENTRIES = 1_000
# TIFF field types and their sizes in bytes; type 129 is the UTF-8 text of EXIF 3.0.
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 129: 1}
_BYTE, _ASCII, _RATIONAL, _UNDEFINED, _UTF8 = 1, 2, 5, 7, 129
_EXIF_IFD, _GPS_IFD = 0x8769, 0x8825
_GPS_LATITUDE, _GPS_LONGITUDE = 2, 4
# The bytes of a GPS coordinate: three rationals, its degrees, minutes and seconds.
_COORDINATE_BYTES = 24
# Windows XPTitle, XPComment, XPAuthor, XPKeywords and XPSubject, in UTF-16.
_XP_TAGS = range(0x9C9B, 0x9CA0)
_USER_COMMENT = 0x9286
_IPTC_RESOURCE = 0x0404
_XMP_START, _XMP_END = b"<x:xmpmeta", b"</x:xmpmeta>"
_XMP_LOCATION = re.compile(r"exif:GPS(?:Latitude|Longitude)(?:=[\"']|>)([^\"'<]*)")
_PDF_FIELD = re.compile(rb"/(?:Author|Creator|Keywords|Producer|Subject|Title)\s*(?=[(<])")
# The parts of a PDF literal string: plain bytes, an escape, or a parenthesis.
_PDF_LITERAL = re.compile(rb"[^()\\]+|\\.?|[()]", re.DOTALL)
_PDF_HEX = re.compile(rb"[0-9A-Fa-f\s]*")
# An escape, or a backslash that continues the string on the next line.
_PDF_ESCAPE = re.compile(rb"\\(\r\n|[0-7]{1,3}|.)", re.DOTALL)
_PDF_ESCAPES = {
    b"n": b"\n",
    b"r": b"\r",
    b"t": b"\t",
    b"b": b"\b",
    b"f": b"\f",
    b"\r\n": b"",
    b"\r": b"",
    b"\n": b"",
}
# The first atom types of QuickTime and MP4 files.
_MOVIE_ATOMS = (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip")
# The location of a video, as user data, as an item of iTunes metadata, or
# as a key of Apple metadata, in ISO 6709 form such as "+12.3456-045.6789/".
_LOCATION_ATOM = b"\xa9xyz"
_LOCATION_KEY = b"com.apple.quicktime.location.ISO6709"
_ISO6709 = re.compile(r"[+-][\d.]+[+-][\d.]+")


@dataclass(frozen=True)
class Metadata:
    """The text fields of a file, whether it records a location, and whether a bound cut it."""

    texts: tuple[str, ...]
    location: bool
    truncated: bool


def read_metadata(data: bytes, pdf_stream: bool = False) -> Metadata:
    """Return the metadata found in the content of a binary file.

    With `pdf_stream`, the content is an inflated stream of a PDF file, which
    may hold its information dictionary.
    """
    reader = _Reader()
    if data.startswith(PNG_SIGNATURE):
        reader.png(data)
    elif data.startswith(b"\xff\xd8"):
        reader.jpeg(data)
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        reader.webp(data)
    elif data.startswith((b"II*\x00", b"MM\x00*")):
        reader.tiff(data)
    elif data[4:8] in _MOVIE_ATOMS:
        reader.movie(data)
    reader.exif_blocks(data)
    reader.xmp_packets(data)
    if pdf_stream or data.startswith(b"%PDF"):
        reader.pdf(data)
    texts = tuple(text for text in reader.texts if text.strip())
    return Metadata(texts, reader.location, reader.truncated)


class _Reader:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.location = False
        self.truncated = False
        # The characters of text still kept for the file.
        self.room = MAX_TEXT_CHARS

    def add(self, text: str, cut: bool = False) -> None:
        """Keep a text field, as far as the characters left for the file allow.

        Nulls that pad the end of a field are dropped but take room, so that
        fields that all point at the same zeros are not read over and over.
        """
        if cut or len(text) > self.room:
            self.truncated = True
        kept = text[: self.room]
        self.room -= len(kept)
        kept = kept.rstrip("\x00")
        if kept:
            self.texts.append(kept)

    def limit(self) -> int:
        """Return how many bytes of a field to read: a character takes up to four."""
        return min(MAX_FIELD_BYTES, 4 * self.room)

    def png(self, data: bytes) -> None:
        position = len(PNG_SIGNATURE)
        for _ in range(MAX_SEGMENTS):
            if position + 8 > len(data):
                return
            size, kind = struct.unpack(">I4s", data[position : position + 8])
            body = data[position + 8 : position + 8 + size]
            position += 12 + size
            _keyword, _, rest = body.partition(b"\x00")
            if kind == b"tEXt":
                self.add(rest.decode("latin-1"))
            elif kind == b"zTXt" and rest[:1] == b"\x00":
                text, cut = _inflate(rest[1:], self.limit())
                self.add(text.decode("latin-1"), cut)
            elif kind == b"iTXt" and len(rest) >= 2:
                self.itxt(rest)
            elif kind == b"eXIf":
                self.tiff(body)
            elif kind == b"IEND":
                return
        self.truncated |= position + 8 <= len(data)

    def itxt(self, rest: bytes) -> None:
        """Read an international PNG text chunk, after its keyword."""
        compressed = rest[0] == 1
        _language, _, rest = rest[2:].partition(b"\x00")
        translated, _, text = rest.partition(b"\x00")
        self.add(translated.decode("utf-8", LEGACY))
        cut = False
        if compressed:
            text, cut = _inflate(text, self.limit())
        self.add(text.decode("utf-8", LEGACY), cut)

    def jpeg(self, data: bytes) -> None:
        position = 2
        for _ in range(MAX_SEGMENTS):
            if position + 2 > len(data) or data[position] != 0xFF:
                return
            marker = data[position + 1]
            if marker == 0xFF:  # Fill byte.
                position += 1
                continue
            if marker in (0xD9, 0xDA):  # End of image, or start of the image data.
                return
            if marker == 0x01 or 0xD0 <= marker <= 0xD8:  # Markers without a length.
                position += 2
                continue
            if position + 4 > len(data):
                return
            size = struct.unpack(">H", data[position + 2 : position + 4])[0]
            body = data[position + 4 : position + 2 + size]
            position += 2 + size
            if marker == 0xFE:
                self.add(body.decode("utf-8", LEGACY))
            elif marker == 0xED and body.startswith(PHOTOSHOP_HEADER):
                self.photoshop(body[len(PHOTOSHOP_HEADER) :])
        self.truncated |= position + 2 <= len(data)

    def webp(self, data: bytes) -> None:
        position = 12
        for _ in range(MAX_SEGMENTS):
            if position + 8 > len(data):
                return
            kind, size = struct.unpack("<4sI", data[position : position + 8])
            body = data[position + 8 : position + 8 + size]
            position += 8 + size + size % 2
            if kind == b"EXIF" and not body.startswith(EXIF_HEADER):
                self.tiff(body)
        self.truncated |= position + 8 <= len(data)

    def photoshop(self, data: bytes) -> None:
        """Read the IPTC records of Photoshop image resources, such as the by-line."""
        position = 0
        for _ in range(MAX_SEGMENTS):
            if position + 7 > len(data) or data[position : position + 4] != b"8BIM":
                return
            resource = struct.unpack(">H", data[position + 4 : position + 6])[0]
            name = data[position + 6]
            position += 6 + name + 1 + (name + 1) % 2
            if position + 4 > len(data):
                return
            size = struct.unpack(">I", data[position : position + 4])[0]
            body = data[position + 4 : position + 4 + size]
            position += 4 + size + size % 2
            if resource == _IPTC_RESOURCE:
                self.iptc(body)

    def iptc(self, data: bytes) -> None:
        position = 0
        for _ in range(MAX_SEGMENTS):
            if position + 5 > len(data) or data[position] != 0x1C:
                return
            record = data[position + 1]
            size = struct.unpack(">H", data[position + 3 : position + 5])[0]
            if size & 0x8000:  # Extended length, only used for large binary records.
                return
            if record == 2:
                value = data[position + 5 : position + 5 + size]
                self.add(value.decode("utf-8", LEGACY))
            position += 5 + size
        self.truncated |= position + 5 <= len(data)

    def exif_blocks(self, data: bytes) -> None:
        """Read the EXIF blocks found anywhere: JPEG, WebP and HEIF files and videos embed them."""
        start = data.find(EXIF_HEADER)
        for _ in range(MAX_EXIF_BLOCKS):
            if start < 0:
                return
            self.tiff(data[start + len(EXIF_HEADER) :])
            start = data.find(EXIF_HEADER, start + 1)
        self.truncated |= start >= 0

    def xmp_packets(self, data: bytes) -> None:
        """Read every XMP packet, scanning the data once."""
        start = data.find(_XMP_START)
        while start >= 0:
            end = data.find(_XMP_END, start)
            if end < 0:
                return
            end += len(_XMP_END)
            self.xmp(data[start:end].decode("utf-8", LEGACY))
            start = data.find(_XMP_START, end)

    def xmp(self, packet: str) -> None:
        self.add(packet)
        for value in _XMP_LOCATION.findall(packet):
            if any(char in "123456789" for char in value):
                self.location = True

    def tiff(self, data: bytes) -> None:
        """Read the text fields and the GPS position of a TIFF structure, as in EXIF."""
        order = {b"II": "<", b"MM": ">"}.get(data[:2])
        if order is None or len(data) < 8 or struct.unpack(order + "H", data[2:4])[0] != 42:
            return
        pending = [(struct.unpack(order + "I", data[4:8])[0], False)]
        seen: set[int] = set()
        entries = 0
        while pending:
            offset, gps = pending.pop()
            if offset in seen or offset < 8 or offset + 2 > len(data):
                continue
            if len(seen) == MAX_IFDS:
                self.truncated = True
                return
            seen.add(offset)
            count = struct.unpack(order + "H", data[offset : offset + 2])[0]
            for index in range(count):
                entry = offset + 2 + 12 * index
                if entry + 12 > len(data):
                    return
                entries += 1
                if entries > MAX_IFD_ENTRIES:
                    self.truncated = True
                    return
                tag, kind, number = struct.unpack(order + "HHI", data[entry : entry + 8])
                size = _TYPE_SIZES.get(kind, 0) * number
                start = entry + 8
                if size > 4:
                    start = struct.unpack(order + "I", data[entry + 8 : entry + 12])[0]
                if tag in (_EXIF_IFD, _GPS_IFD) and not gps and size >= 4:
                    pointer = data[start : start + 4].ljust(4, b"\x00")
                    pending.append((struct.unpack(order + "I", pointer)[0], tag == _GPS_IFD))
                elif gps and tag in (_GPS_LATITUDE, _GPS_LONGITUDE) and kind == _RATIONAL:
                    value = data[start : start + min(size, _COORDINATE_BYTES)]
                    self.location = self.location or _has_value(value, order)
                elif encoding := _text_encoding(tag, kind):
                    available = max(0, min(size, len(data) - start))
                    value = data[start : start + min(available, self.limit())]
                    self._field(encoding, value, order, len(value) < available)
            end = offset + 2 + 12 * count
            if not gps and end + 4 <= len(data):
                pending.append((struct.unpack(order + "I", data[end : end + 4])[0], False))

    def _field(self, encoding: str, value: bytes, order: str, cut: bool) -> None:
        """Read a TIFF text field, as _text_encoding names its encoding."""
        if encoding == "comment":
            charset, value = value[:8], value[8:]
            encoding = "utf-8"
            if charset.startswith(b"UNICODE"):
                encoding = "utf-16-le" if order == "<" else "utf-16-be"
        self.add(value.decode(encoding, LEGACY if encoding == "utf-8" else "replace"), cut)

    def atoms(self, data: bytes) -> Iterator[tuple[bytes, bytes]]:
        """Yield the type and body of each atom of a QuickTime or MP4 container."""
        position = 0
        for _ in range(MAX_SEGMENTS):
            if position + 8 > len(data):
                return
            size, kind = struct.unpack(">I4s", data[position : position + 8])
            header = 8
            if size == 1 and position + 16 <= len(data):  # A 64-bit size follows.
                size, header = struct.unpack(">Q", data[position + 8 : position + 16])[0], 16
            elif size == 0:  # The last atom, which runs to the end.
                size = len(data) - position
            if size < header:
                return
            yield kind, data[position + header : position + size]
            position += size
        self.truncated |= position + 8 <= len(data)

    def movie(self, data: bytes) -> None:
        """Read the location of a QuickTime or MP4 video, from its user data and metadata."""
        for kind, body in self.atoms(data):
            if kind != b"moov":
                continue
            for child, value in self.atoms(body):
                if child == b"meta":  # As Apple tools write it.
                    self.movie_meta(value)
                elif child == b"udta":
                    self.user_data(value)

    def user_data(self, data: bytes) -> None:
        """Read the location in the user data of a video, directly or as metadata."""
        for kind, body in self.atoms(data):
            if kind == _LOCATION_ATOM:
                # A string length and a language code come first.
                self.iso6709(body[4 : 4 + int.from_bytes(body[:2], "big")])
            elif kind == b"meta":  # As iTunes and FFmpeg write it.
                self.movie_meta(body)

    def movie_meta(self, data: bytes) -> None:
        """Read the location in the item list of a metadata atom."""
        # A version and flags come first in MP4 files, not in QuickTime files.
        if data[:4] == b"\x00\x00\x00\x00":
            data = data[4:]
        keys: list[bytes] = []
        for kind, body in self.atoms(data):
            if kind == b"keys":
                # A version, flags and a count, then a namespace and a name per key.
                keys = [name for _namespace, name in self.atoms(body[8:])]
            elif kind == b"ilst":
                for item, value in self.atoms(body):
                    index = int.from_bytes(item, "big")
                    name = keys[index - 1] if 0 < index <= len(keys) else item
                    if name in (_LOCATION_ATOM, _LOCATION_KEY):
                        for child, text in self.atoms(value):
                            # A type and a locale come first.
                            if child == b"data":
                                self.iso6709(text[8:])

    def iso6709(self, value: bytes) -> None:
        """Read a location written in ISO 6709 form."""
        limit = self.limit()
        text = value[:limit].decode("utf-8", LEGACY)
        self.add(text, len(value) > limit)
        match = _ISO6709.match(text)
        if match and any(char in "123456789" for char in match.group()):
            self.location = True

    def pdf(self, data: bytes) -> None:
        """Read the information fields of a PDF file, as literal or hexadecimal strings."""
        position = 0
        while match := _PDF_FIELD.search(data, position):
            reader = _pdf_literal if data[match.end()] == ord("(") else _pdf_hex
            text, position, cut = reader(data, match.end())
            if text is not None:
                self.add(text, cut)


def _text_encoding(tag: int, kind: int) -> str | None:
    """Return how a TIFF field stores text, or None when it holds no text."""
    if kind in (_ASCII, _UTF8):
        return "utf-8"
    if tag in _XP_TAGS and kind == _BYTE:
        return "utf-16-le"
    if tag == _USER_COMMENT and kind == _UNDEFINED:
        return "comment"
    return None


def _has_value(rationals: bytes, order: str) -> bool:
    """Return whether degrees, minutes or seconds of a GPS coordinate are not zero."""
    count = len(rationals) // 8
    numbers = struct.unpack(f"{order}{2 * count}I", rationals[: 8 * count])
    return any(numbers[0::2])


def _inflate(data: bytes, limit: int) -> tuple[bytes, bool]:
    """Return up to limit bytes of zlib data, and whether more was left."""
    try:
        text = zlib.decompressobj().decompress(data, limit + 1)
    except zlib.error:
        return b"", False
    return text[:limit], len(text) > limit


def _pdf_literal(data: bytes, start: int) -> tuple[str | None, int, bool]:
    """Return the literal string at start, where it ends, and whether a bound cut it.

    A literal string can hold balanced parentheses without escapes.
    """
    end = min(len(data), start + MAX_FIELD_BYTES + 2)
    depth = 0
    for part in _PDF_LITERAL.finditer(data, start, end):
        if part.group() == b"(":
            depth += 1
        elif part.group() == b")":
            depth -= 1
            if not depth:
                return _pdf_string(data[start + 1 : part.start()]), part.end(), False
    body = data[start + 1 : start + 1 + MAX_FIELD_BYTES]
    return _pdf_string(body), end, end < len(data)


def _pdf_hex(data: bytes, start: int) -> tuple[str | None, int, bool]:
    """Return the hexadecimal string at start, where it ends, and whether a bound cut it.

    Whitespace between the digits is ignored, and an odd last digit is
    followed by a zero. A string with other characters is skipped.
    """
    end = min(len(data), start + 2 * MAX_FIELD_BYTES + 2)
    digits = _PDF_HEX.match(data, start + 1, end)
    assert digits is not None  # noqa: S101 - the pattern also matches nothing.
    if digits.end() == end < len(data):
        return _pdf_text(_hex_bytes(digits.group())[:MAX_FIELD_BYTES]), end, True
    if data[digits.end() : digits.end() + 1] != b">":
        return None, digits.end(), False
    return _pdf_text(_hex_bytes(digits.group())), digits.end() + 1, False


def _hex_bytes(digits: bytes) -> bytes:
    digits = re.sub(rb"\s", b"", digits)
    return bytes.fromhex((digits + b"0" * (len(digits) % 2)).decode("ascii"))


def _pdf_string(field: bytes) -> str:
    """Decode the body of a PDF literal string: its escapes, then its text."""

    def escape(match: re.Match[bytes]) -> bytes:
        value = match.group(1)
        if value[:1] in b"01234567":
            return bytes([int(value, 8) & 0xFF])
        return _PDF_ESCAPES.get(value, value)

    return _pdf_text(_PDF_ESCAPE.sub(escape, field))


def _pdf_text(raw: bytes) -> str:
    """Decode the bytes of a PDF string: UTF-16 when it starts with a byte order mark."""
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    return raw.decode("utf-8", LEGACY)
