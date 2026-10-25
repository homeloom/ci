"""Read the text fields and the location that image and document files carry.

Cameras, phones and editors write the author, a title, comments and often a
GPS position into image files. This module reads PNG text chunks, JPEG
comments, EXIF (in JPEG, PNG, WebP, TIFF and HEIF files), IPTC records, XMP
packets and the information dictionary of PDF files, without decoding the
images themselves. Every length and offset is checked, so malformed data is
skipped.
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass

from ci_checks._common import LEGACY

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
EXIF_HEADER = b"Exif\x00\x00"
PHOTOSHOP_HEADER = b"Photoshop 3.0\x00"
# Bounds that keep hostile files cheap to read.
MAX_FIELD_BYTES = 1_000_000
MAX_SEGMENTS = 10_000
MAX_EXIF_BLOCKS = 16
MAX_IFDS = 16
MAX_IFD_ENTRIES = 1_000
# TIFF field types and their sizes in bytes.
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
_BYTE, _ASCII, _RATIONAL, _UNDEFINED = 1, 2, 5, 7
_EXIF_IFD, _GPS_IFD = 0x8769, 0x8825
_GPS_LATITUDE, _GPS_LONGITUDE = 2, 4
# Windows XPTitle, XPComment, XPAuthor, XPKeywords and XPSubject, in UTF-16.
_XP_TAGS = range(0x9C9B, 0x9CA0)
_USER_COMMENT = 0x9286
_IPTC_RESOURCE = 0x0404
_XMP = re.compile(rb"<x:xmpmeta\b.*?</x:xmpmeta>", re.DOTALL)
_XMP_LOCATION = re.compile(r"exif:GPS(?:Latitude|Longitude)(?:=[\"']|>)([^\"'<]*)")
_PDF_FIELD = re.compile(
    rb"/(?:Author|Creator|Keywords|Producer|Subject|Title)\s*\(((?:[^()\\]|\\.){0,4096})\)",
    re.DOTALL,
)
_PDF_ESCAPE = re.compile(rb"\\([0-7]{1,3}|.)", re.DOTALL)
_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}


@dataclass(frozen=True)
class Metadata:
    """The text fields of a file and whether it records a location."""

    texts: tuple[str, ...]
    location: bool


def read_metadata(data: bytes) -> Metadata:
    """Return the metadata found in the content of a binary file."""
    reader = _Reader()
    if data.startswith(PNG_SIGNATURE):
        reader.png(data)
    elif data.startswith(b"\xff\xd8"):
        reader.jpeg(data)
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        reader.webp(data)
    elif data.startswith((b"II*\x00", b"MM\x00*")):
        reader.tiff(data)
    # EXIF blocks start with the same header in JPEG, WebP and HEIF files,
    # and in the videos that embed them.
    start = data.find(EXIF_HEADER)
    for _ in range(MAX_EXIF_BLOCKS):
        if start < 0:
            break
        reader.tiff(data[start + len(EXIF_HEADER) :])
        start = data.find(EXIF_HEADER, start + 1)
    for packet in _XMP.findall(data):
        reader.xmp(packet.decode("utf-8", LEGACY))
    if data.startswith(b"%PDF"):
        reader.texts.extend(_pdf_string(field) for field in _PDF_FIELD.findall(data))
    return Metadata(tuple(text for text in reader.texts if text.strip()), reader.location)


class _Reader:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.location = False

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
                self.texts.append(rest.decode("latin-1"))
            elif kind == b"zTXt" and rest[:1] == b"\x00":
                self.texts.append(_inflate(rest[1:]).decode("latin-1"))
            elif kind == b"iTXt" and len(rest) >= 2:
                compressed = rest[0] == 1
                _language, _, rest = rest[2:].partition(b"\x00")
                translated, _, text = rest.partition(b"\x00")
                self.texts.append(translated.decode("utf-8", LEGACY))
                self.texts.append((_inflate(text) if compressed else text).decode("utf-8", LEGACY))
            elif kind == b"eXIf":
                self.tiff(body)
            elif kind == b"IEND":
                return

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
                self.texts.append(body.decode("utf-8", LEGACY))
            elif marker == 0xED and body.startswith(PHOTOSHOP_HEADER):
                self.photoshop(body[len(PHOTOSHOP_HEADER) :])

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
                self.texts.append(value.decode("utf-8", LEGACY))
            position += 5 + size

    def xmp(self, packet: str) -> None:
        self.texts.append(packet)
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
        while pending and len(seen) < MAX_IFDS:
            offset, gps = pending.pop()
            if offset in seen or offset < 8 or offset + 2 > len(data):
                continue
            seen.add(offset)
            count = struct.unpack(order + "H", data[offset : offset + 2])[0]
            for index in range(count):
                entries += 1
                entry = offset + 2 + 12 * index
                if entries > MAX_IFD_ENTRIES or entry + 12 > len(data):
                    return
                tag, kind, number = struct.unpack(order + "HHI", data[entry : entry + 8])
                size = _TYPE_SIZES.get(kind, 0) * number
                if size <= 4:
                    value = data[entry + 8 : entry + 8 + size]
                else:
                    pointer = struct.unpack(order + "I", data[entry + 8 : entry + 12])[0]
                    value = data[pointer : pointer + min(size, MAX_FIELD_BYTES)]
                if tag in (_EXIF_IFD, _GPS_IFD) and not gps and len(value) >= 4:
                    pending.append((struct.unpack(order + "I", value[:4])[0], tag == _GPS_IFD))
                elif gps and tag in (_GPS_LATITUDE, _GPS_LONGITUDE) and kind == _RATIONAL:
                    self.location = self.location or _has_value(value, order)
                else:
                    self._field(tag, kind, value, order)
            end = offset + 2 + 12 * count
            if not gps and end + 4 <= len(data):
                pending.append((struct.unpack(order + "I", data[end : end + 4])[0], False))

    def _field(self, tag: int, kind: int, value: bytes, order: str) -> None:
        if kind == _ASCII:
            self.texts.append(value.rstrip(b"\x00").decode("utf-8", LEGACY))
        elif tag in _XP_TAGS and kind == _BYTE:
            self.texts.append(value.decode("utf-16-le", errors="replace").rstrip("\x00"))
        elif tag == _USER_COMMENT and kind == _UNDEFINED:
            charset, text = value[:8], value[8:]
            if charset.startswith(b"UNICODE"):
                encoding = "utf-16-le" if order == "<" else "utf-16-be"
                self.texts.append(text.decode(encoding, errors="replace").rstrip("\x00"))
            else:
                self.texts.append(text.rstrip(b"\x00").decode("utf-8", LEGACY))


def _has_value(rationals: bytes, order: str) -> bool:
    """Return whether degrees, minutes or seconds of a GPS coordinate are not zero."""
    count = len(rationals) // 8
    numbers = struct.unpack(f"{order}{2 * count}I", rationals[: 8 * count])
    return any(numbers[0::2])


def _inflate(data: bytes) -> bytes:
    try:
        return zlib.decompressobj().decompress(data, MAX_FIELD_BYTES)
    except zlib.error:
        return b""


def _pdf_string(field: bytes) -> str:
    """Decode a PDF literal string: its escapes, and UTF-16 when it starts with a BOM."""

    def escape(match: re.Match[bytes]) -> bytes:
        value = match.group(1)
        if value[:1] in b"01234567":
            return bytes([int(value, 8) & 0xFF])
        return _PDF_ESCAPES.get(value, value)

    raw = _PDF_ESCAPE.sub(escape, field)
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    return raw.decode("utf-8", LEGACY)
