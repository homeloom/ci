from __future__ import annotations

import base64
import gzip
import zipfile
import zlib

import pytest

from ci_checks import unpack as unpack_module
from ci_checks.unpack import MAX_DEPTH, MAX_UNPACKED_BYTES, Part, data_uris, unpack
from media import make_pdf, make_zip, pdf_stream


def test_zip_members_are_read() -> None:
    archive = make_zip(("word/document.xml", b"<w:t>Bluefinch</w:t>"), ("empty.txt", b""))
    found = unpack(archive)
    assert found.parts == (Part(b"<w:t>Bluefinch</w:t>"), Part(b""))
    assert found.problem is None


def test_gzip_and_nested_archives_are_read() -> None:
    inner = make_zip(("notes.txt", gzip.compress(b"Quillmore")))
    found = unpack(gzip.compress(inner))
    assert [part.data for part in found.parts] == [inner, gzip.compress(b"Quillmore"), b"Quillmore"]
    assert found.problem is None


def test_nesting_is_bounded() -> None:
    data = b"Quillmore"
    for _ in range(MAX_DEPTH):
        data = gzip.compress(data)
    assert unpack(data).problem is None
    deeper = unpack(gzip.compress(data))
    assert deeper.problem == f"is nested more than {MAX_DEPTH} levels deep"
    assert b"Quillmore" not in [part.data for part in deeper.parts]


def test_inflated_size_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unpack_module, "MAX_UNPACKED_BYTES", 1_000)
    assert unpack(gzip.compress(b"\0" * 1_000)).problem is None
    assert unpack(gzip.compress(b"\0" * 1_001)).problem == "inflates to more than 1000 bytes"
    members = (("a", b"\0" * 600), ("b", b"\0" * 600))
    assert unpack(make_zip(*members)).problem == "inflates to more than 1000 bytes"
    assert MAX_UNPACKED_BYTES == 20_000_000


def test_member_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unpack_module, "MAX_MEMBERS", 2)
    assert unpack(make_zip(("a", b"1"), ("b", b"2"))).problem is None
    assert unpack(make_zip(("a", b"1"), ("b", b"2"), ("c", b"3"))).problem == (
        "has more than 2 members"
    )


def test_unreadable_content_is_reported() -> None:
    archive = bytearray(make_zip(("secret.txt", b"Quillmore")))
    archive[6] |= 0x1  # The encryption flag of the local header.
    central = archive.rfind(b"PK\x01\x02")
    archive[central + 8] |= 0x1
    assert unpack(bytes(archive)).problem == "has an encrypted member"
    assert unpack(b"PK\x03\x04 cut short").problem == "is not a readable ZIP archive"
    unsupported = bytearray(make_zip(("a.txt", b"Quillmore"), method=zipfile.ZIP_STORED))
    unsupported[8] = 99  # A compression method that zipfile does not know.
    unsupported[unsupported.rfind(b"PK\x01\x02") + 10] = 99
    assert unpack(bytes(unsupported)).problem == "is not a readable ZIP archive"
    assert unpack(b"\x1f\x8b not gzip").problem == "is not valid compressed data"
    assert unpack(gzip.compress(b"Quillmore" * 100)[:-12]).problem == "is cut short"


def test_pdf_flate_streams_are_read() -> None:
    document = make_pdf(
        pdf_stream(zlib.compress(b"<< /Author (Bluefinch) >>")),
        pdf_stream(zlib.compress(b"[0 1]"), b"/Filter [ /FlateDecode ]"),
        pdf_stream(b"\xff\xd8 image", b"/Filter /DCTDecode"),
        pdf_stream(b"BT (plain) Tj ET", b""),
    )
    found = unpack(document)
    assert found.parts == (Part(b"<< /Author (Bluefinch) >>", pdf=True), Part(b"[0 1]", pdf=True))
    assert found.problem is None


def test_pdf_streams_that_cannot_be_read_are_reported() -> None:
    chained = make_pdf(pdf_stream(b"GhVa", b"/Filter [/ASCII85Decode /FlateDecode]"))
    assert unpack(chained).problem == "has a stream with a chain of filters"
    broken = make_pdf(pdf_stream(b"not zlib"), pdf_stream(zlib.compress(b"Quillmore")))
    assert unpack(broken).problem == "is not valid compressed data"
    assert unpack(broken).parts == ()


def test_other_content_is_left_alone() -> None:
    assert unpack(b"\x89PNG\r\n\x1a\n").parts == ()
    assert unpack(b"plain text").problem is None


def test_data_uris_are_decoded() -> None:
    payload = base64.b64encode(b"Brindle Nimblewick").decode()
    text = (
        f'<img src="data:image/png;base64,{payload}">\n'
        f"url(data:;base64,{payload}) data:text/plain;charset=utf-8;base64,{payload}\n"
        "data:image/png;base64,ThisIsNotBase64!== and data:image/png;base64,c2hvcnQ=\n"
        "data:image/png;base64,QUJDREVGR0hJSktMTU5PUA= is padded wrongly\n"
    )
    found = data_uris(text)
    assert [data for _, data in found] == [b"Brindle Nimblewick"] * 3
    assert [text[offset : offset + 5] for offset, _ in found] == ["data:"] * 3
