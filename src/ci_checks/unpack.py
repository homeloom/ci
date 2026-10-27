"""Read the content that files hold compressed or encoded.

ZIP archives (and the formats built on them: Office, OpenDocument, EPUB,
wheels), gzip data, the Flate streams of PDF files and base64 `data:` URIs
hide their text from a plain read. This module inflates them, nested up to
MAX_DEPTH levels, within MAX_UNPACKED_BYTES for each file, so that an
archive bomb stays cheap. The result says when content could not be read
or a bound cut it, so that a caller can fail closed.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import zipfile
import zlib
from dataclasses import dataclass

# The bytes inflated for one file, the levels of nesting read, and the
# members read in one archive.
MAX_UNPACKED_BYTES = 20_000_000
MAX_DEPTH = 4
MAX_MEMBERS = 10_000

ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")
GZIP_SIGNATURE = b"\x1f\x8b"
# The content that this module reads further.
PACKED_SIGNATURES = (*ZIP_SIGNATURES, GZIP_SIGNATURE, b"%PDF")
# A stream of a PDF file, after its dictionary; "endstream" is not one.
_PDF_STREAM = re.compile(rb"(?<!end)stream\r?\n")
# A filter that names Flate alone, as a name or as an array of one name.
_PDF_FLATE = re.compile(rb"/Filter\s*(?:/FlateDecode|\[\s*/FlateDecode\s*\])")
_PDF_FILTER = re.compile(rb"/Filter\b")
# How far before a stream its dictionary is looked for.
_PDF_DICTIONARY_BYTES = 4_096
# A base64 data URI on one line. Shorter payloads hold too little to check.
_DATA_URI = re.compile(
    r"data:[\w.+-]*/?[\w.+-]*(?:;[\w.+-]+=[\w.+-]+)*;base64,([A-Za-z0-9+/]{16,}=*)"
)


@dataclass(frozen=True)
class Part:
    """Content read out of a file, and whether it is a stream of a PDF file."""

    data: bytes
    pdf: bool = False


@dataclass(frozen=True)
class Unpacked:
    """The content read out of a file, and why some of it could not be read."""

    parts: tuple[Part, ...]
    problem: str | None


def unpack(data: bytes) -> Unpacked:
    """Return the content that a ZIP, gzip or PDF file holds compressed."""
    unpacker = _Unpacker()
    unpacker.inner(data, 1)
    return Unpacked(tuple(unpacker.parts), unpacker.problem)


def data_uris(text: str) -> list[tuple[int, bytes]]:
    """Return the offset and the decoded content of each base64 data URI of a text.

    A payload that is not valid base64 is skipped: it is text that only looks
    like a data URI, and the text itself is checked.
    """
    found = []
    for match in _DATA_URI.finditer(text):
        try:
            found.append((match.start(), base64.b64decode(match.group(1), validate=True)))
        except binascii.Error:
            continue
    return found


class _Unpacker:
    def __init__(self) -> None:
        self.parts: list[Part] = []
        self.problem: str | None = None
        self.room = MAX_UNPACKED_BYTES

    def fail(self, problem: str) -> None:
        if self.problem is None:
            self.problem = problem

    def take(self, data: bytes, depth: int, pdf: bool = False) -> None:
        self.parts.append(Part(data, pdf))
        if data.startswith(PACKED_SIGNATURES):
            if depth == MAX_DEPTH:
                self.fail(f"is nested more than {MAX_DEPTH} levels deep")
            else:
                self.inner(data, depth + 1)

    def inner(self, data: bytes, depth: int) -> None:
        if data.startswith(ZIP_SIGNATURES):
            self.zip(data, depth)
        elif data.startswith(GZIP_SIGNATURE):
            self.gzip(data, depth)
        elif data.startswith(b"%PDF"):
            self.pdf(data, depth)

    def inflate(self, data: bytes | memoryview, wbits: int) -> tuple[bytes, bytes] | None:
        """Return zlib or gzip data inflated and the bytes after it.

        Return None when the data cannot be read whole.
        """
        inflater = zlib.decompressobj(wbits)
        try:
            content = inflater.decompress(data, self.room + 1)
        except zlib.error:
            self.fail("is not valid compressed data")
            return None
        if len(content) > self.room:
            self.fail(f"inflates to more than {MAX_UNPACKED_BYTES} bytes")
            return None
        if not inflater.eof:
            self.fail("is cut short")
            return None
        self.room -= len(content)
        return content, inflater.unused_data

    def zip(self, data: bytes, depth: int) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = [info for info in archive.infolist() if not info.is_dir()]
                if len(members) > MAX_MEMBERS:
                    self.fail(f"has more than {MAX_MEMBERS} members")
                    return
                for info in members:
                    if info.flag_bits & 0x1:
                        self.fail("has an encrypted member")
                        continue
                    with archive.open(info) as member:
                        content = member.read(self.room + 1)
                    if len(content) > self.room:
                        self.fail(f"inflates to more than {MAX_UNPACKED_BYTES} bytes")
                        return
                    self.room -= len(content)
                    self.take(content, depth)
        except (zipfile.BadZipFile, NotImplementedError, EOFError, OSError, zlib.error):
            self.fail("is not a readable ZIP archive")

    def gzip(self, data: bytes, depth: int) -> None:
        # A gzip file may hold several members one after the other, as
        # `gzip -c a b` writes them, and may end with zero bytes of padding.
        rest = data
        for _ in range(MAX_MEMBERS):
            inflated = self.inflate(rest, 31)
            if inflated is None:
                return
            content, rest = inflated
            self.take(content, depth)
            rest = rest.lstrip(b"\0")
            if not rest:
                return
        self.fail(f"has more than {MAX_MEMBERS} members")

    def pdf(self, data: bytes, depth: int) -> None:
        for match in _PDF_STREAM.finditer(data):
            head = data[max(0, match.start() - _PDF_DICTIONARY_BYTES) : match.start()]
            dictionary = head[max(0, head.rfind(b"obj")) :]
            if not _PDF_FLATE.search(dictionary):
                # Images and fonts use other filters, and a chain of filters
                # starts with an encoding that is not compression.
                if _PDF_FILTER.search(dictionary) and b"/FlateDecode" in dictionary:
                    self.fail("has a stream with a chain of filters")
                continue
            inflated = self.inflate(memoryview(data)[match.end() :], 15)
            if inflated is None:
                return
            self.take(inflated[0], depth, pdf=True)
