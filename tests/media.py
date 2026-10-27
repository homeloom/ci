"""Build small image, document and video files with metadata, for the tests."""

from __future__ import annotations

import io
import struct
import zipfile
import zlib
from collections.abc import Sequence

ASCII, RATIONAL, BYTE, LONG, UNDEFINED, UTF8 = 2, 5, 1, 4, 7, 129
ARTIST, XP_AUTHOR, USER_COMMENT, EXIF_IFD, GPS_IFD = 0x013B, 0x9C9D, 0x9286, 0x8769, 0x8825
GPS_LATITUDE, GPS_LONGITUDE = 2, 4
# A field of an image file directory: tag, type, count and value bytes.
Field = tuple[int, int, int, bytes]


def ascii_field(tag: int, text: str, kind: int = ASCII) -> Field:
    value = text.encode() + b"\0"
    return tag, kind, len(value), value


def rational_field(tag: int, order: str, *numbers: tuple[int, int]) -> Field:
    value = b"".join(struct.pack(order + "II", *number) for number in numbers)
    return tag, RATIONAL, len(numbers), value


def _ifd(fields: Sequence[Field], offset: int, order: str) -> bytes:
    data_offset = offset + 2 + 12 * len(fields) + 4
    entries = b""
    data = b""
    for tag, kind, count, value in fields:
        if len(value) <= 4:
            entries += struct.pack(order + "HHI", tag, kind, count) + value.ljust(4, b"\0")
        else:
            entries += struct.pack(order + "HHII", tag, kind, count, data_offset + len(data))
            data += value
    return struct.pack(order + "H", len(fields)) + entries + b"\0\0\0\0" + data


def tiff(fields: Sequence[Field] = (), gps: Sequence[Field] = (), order: str = "<") -> bytes:
    """Return a TIFF structure, as EXIF stores it, with an optional GPS directory."""
    header = (b"II" if order == "<" else b"MM") + struct.pack(order + "HI", 42, 8)
    main = list(fields)
    if not gps:
        return header + _ifd(main, 8, order)
    main.append((GPS_IFD, LONG, 1, b"\0\0\0\0"))
    gps_offset = 8 + len(_ifd(main, 8, order))
    main[-1] = (GPS_IFD, LONG, 1, struct.pack(order + "I", gps_offset))
    return header + _ifd(main, 8, order) + _ifd(gps, gps_offset, order)


def gps_position(order: str = "<", minutes: int = 0, seconds: int = 1) -> list[Field]:
    """Return GPS fields north and east of 0, 0, one second away by default, in the open sea."""
    angle = ((0, 1), (minutes, 1), (seconds * 100, 100))
    return [
        rational_field(GPS_LATITUDE, order, *angle),
        rational_field(GPS_LONGITUDE, order, *angle),
    ]


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def png(*chunks: bytes) -> bytes:
    header = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    image = png_chunk(b"IDAT", zlib.compress(b"\0\0"))
    return b"\x89PNG\r\n\x1a\n" + header + b"".join(chunks) + image + png_chunk(b"IEND", b"")


def jpeg_segment(marker: int, body: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(body) + 2) + body


def jpeg(*segments: bytes) -> bytes:
    return b"\xff\xd8" + b"".join(segments) + b"\xff\xda\x00\x02\x12\x34\xff\xd9"


def exif_segment(structure: bytes) -> bytes:
    return jpeg_segment(0xE1, b"Exif\0\0" + structure)


def iptc_segment(*records: tuple[int, int, bytes]) -> bytes:
    """Return a Photoshop APP13 segment holding IPTC records (record, dataset, value)."""
    iptc = b"".join(
        bytes((0x1C, record, dataset)) + struct.pack(">H", len(value)) + value
        for record, dataset, value in records
    )
    resource = b"8BIM" + struct.pack(">H", 0x0404) + b"\0\0" + struct.pack(">I", len(iptc))
    return jpeg_segment(0xED, b"Photoshop 3.0\0" + resource + iptc + b"\0" * (len(iptc) % 2))


def webp(*chunks: tuple[bytes, bytes]) -> bytes:
    body = b"WEBP" + b"".join(
        kind + struct.pack("<I", len(data)) + data + b"\0" * (len(data) % 2)
        for kind, data in chunks
    )
    return b"RIFF" + struct.pack("<I", len(body)) + body


def xmp(attributes: str) -> bytes:
    return (
        '<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>'
        f'<rdf:Description {attributes}/></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
    ).encode()


def pdf(info: bytes) -> bytes:
    return b"%PDF-1.4\n1 0 obj\n<< " + info + b" >>\nendobj\ntrailer << /Info 1 0 R >>\n%%EOF\n"


def atom(kind: bytes, *children: bytes) -> bytes:
    """Return a QuickTime or MP4 atom holding the given bodies or child atoms."""
    body = b"".join(children)
    return struct.pack(">I", 8 + len(body)) + kind + body


def location_atom(text: bytes) -> bytes:
    """Return the user data atom of a video location, with its length and language."""
    return atom(b"\xa9xyz", struct.pack(">HH", len(text), 0x15C7), text)


def data_atom(text: bytes) -> bytes:
    """Return the value of a metadata item: UTF-8 text in the default locale."""
    return atom(b"data", struct.pack(">II", 1, 0), text)


def movie(*children: bytes) -> bytes:
    """Return a QuickTime file whose movie atom holds the given atoms."""
    return atom(b"ftyp", b"qt  \0\0\0\0qt  ") + atom(b"mdat", b"\0" * 8) + atom(b"moov", *children)


def make_zip(*members: tuple[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        archive.writestr("folder/", b"")
        for name, data in members:
            archive.writestr(name, data)
    return buffer.getvalue()


def pdf_stream(content: bytes, filters: bytes = b"/Filter /FlateDecode") -> bytes:
    return (
        b"4 0 obj\n<< /Length 9 " + filters + b" >>\nstream\n" + content + b"\nendstream\nendobj\n"
    )


def make_pdf(*streams: bytes) -> bytes:
    return b"%PDF-1.7\n" + b"".join(streams) + b"%%EOF\n"
