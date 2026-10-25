"""Tests for the privacy check. Every name, address and number here is invented."""

from __future__ import annotations

import codecs
import json
import os
import time
import zlib
from pathlib import Path

import pytest

from ci_checks import privacy
from ci_checks._common import Change, Commit, PullRequest, Reporter, changes
from helpers import DEPENDABOT, NOREPLY, EventWriter, Repo, pr_event
from media import ARTIST, ascii_field, exif_segment, gps_position, jpeg, pdf, png, png_chunk, tiff

ALLOWED = privacy.DEFAULT_ALLOWED_DOMAINS
APACHE_LICENSE = """
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS.
"""
Capture = pytest.CaptureFixture[str]


@pytest.fixture
def fiction_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Report values reserved for fiction and documentation like real ones.

    Detection tests use those values, so that no test value can belong to a
    real person, device or place. Only the reserved ranges are emptied: the
    code that applies them still runs.
    """
    monkeypatch.setattr(privacy, "FICTION_PHONE_PREFIXES", ())
    monkeypatch.setattr(privacy, "FICTION_NORTH_AMERICA", ())
    monkeypatch.setattr(privacy, "DOCUMENTATION_MAC", ())
    monkeypatch.setattr(privacy, "DOCUMENTATION_EUI64", ())
    monkeypatch.setattr(privacy, "PLACEHOLDER_COORDINATES", set())
    monkeypatch.setattr(privacy, "RESERVED_DOMAINS", ())


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("host = '10.1.2.3'", "private-ip"),
        ("gateway 192.168.1.1/24", "private-ip"),
        ("subnet 192.168.1.0/24", "private-ip"),
        ("padded 192.168.001.010", "private-ip"),
        ("peer 172.20.0.5", "private-ip"),
        ("tailnet 100.100.1.1", "private-ip"),
        ("prefix fd12:3456:789a::1", "private-ip"),
        ("link fe80::1c2b:3a4d:5e6f:7081%eth0", "private-ip"),
        ("snake host_10.0.0.7_backup", "private-ip"),
        # Documentation addresses are exempt, so public addresses come from
        # reserved blocks that are routed but belong to no connection: ORCHIDv2
        # (RFC 7343) and the deprecated 6to4 relay anycast (RFC 7526).
        ("home 2001:20:1f2:3b40::1", "public-ip"),
        ("contact jane.doe@mail.zorble.internal", "email"),
        ("author jane.doe+noreply@mail.zorble.internal", "email"),
        ("author noreply@family.internal", "email"),
        ("idn mail jane@zörble.internal", "email"),
        ("call +33 6 39 98 27 58", "phone"),
        ("call 0033 6 39 98 27 58", "phone"),
        ("call +33\N{NO-BREAK SPACE}6\N{NO-BREAK SPACE}39\N{NO-BREAK SPACE}98 27 58", "phone"),
        ("call +1-202-555-0143", "phone"),
        ("call (202) 555-0143", "phone"),
        ("call 06 39 98 27 58", "phone"),
        ("call 06.39.98.27.58", "phone"),
        ("call 0639982758", "phone"),
        ("call +44 20 7946 0738", "phone"),
        ("see https://myhome.zorble.internal/api", "url"),
        ("see http://user:pw@nas.lan:8080/x", "url"),
        ("wan http://192.88.99.34:8123/api", "url"),
        ("wan http://[2001:20::1]:8123", "url"),
        ("ws wss://zorblequix.internal/api/websocket", "url"),
        ("cam rtsp://cam.family.internal/live", "url"),
        ("broker mqtt://broker.family.internal:1883", "url"),
        ("idn https://maison-zorblé.internal", "url"),
        ("footnote https://nas.zorble.internal\N{SUPERSCRIPT ONE}", "url"),
        ("see https://nas.example.net/api", "url"),
        ("cd /home/alice/projects", "home-path"),
        ("open /Users/bob/Library", "home-path"),
        (r"C:\Users\carol\Desktop", "home-path"),
        (r"C:\\Users\\carol\\Desktop", "home-path"),
        ("C:/Users/carol/Desktop", "home-path"),
        ("c:/users/carol/Desktop", "home-path"),
        ("file:///C%3A/Users/carol/x", "home-path"),
        ("wsl /mnt/c/Users/alice/x", "home-path"),
        (r"share \\wsl$\Ubuntu\home\alice\x", "home-path"),
        (r"share \\wsl.localhost\Ubuntu\home\alice\x", "home-path"),
        ("silverblue /var/home/alice/x", "home-path"),
        ("usb /run/media/alice/disk", "home-path"),
        ("mac 00:00:5e:00:53:9d", "mac"),
        ("mac 00-00-5E-00-53-9D", "mac"),
        ("cisco 0000.5e00.539d", "mac"),
        ('"mac": "00005E00539D"', "mac"),
        ("ble_address=00005e00539d", "mac"),
        ('wifiMac: "00005e00539d"', "mac"),
        ("bssid=00005e00539d", "mac"),
        ("ieee 0x00005eef10a3f4c7", "device-id"),
        ("eui 00:00:5e:ef:10:a3:f4:c7", "device-id"),
        ("ieee_address: 00005eef10a3f4c7", "device-id"),
        ("extendedAddress=00005eef10a3f4c7", "device-id"),
        ("node_0x00005eef10a3f4c7", "device-id"),
        ('"latitude": 32.87336', "coordinates"),
        ("lon=-117.22743", "coordinates"),
        ("CONF_LATITUDE: 32.87336", "coordinates"),
        ("home_longitude = -117.22743", "coordinates"),
        ("homeLat: 32.87336", "coordinates"),
        ("center: [32.87336, -117.22743]", "coordinates"),
        ("geojson [-117.22743, 32.87336]", "coordinates"),
        ("range [123.45678, 2.12345]", "coordinates"),
        ("pinned at 32.87336, -117.22743 on the map", "coordinates"),
        ("geo:32.8734,-117.2274", "coordinates"),
    ],
)
@pytest.mark.usefixtures("fiction_detected")
def test_generic_findings_detect(text: str, category: str) -> None:
    assert category in privacy.generic_findings(text, ALLOWED)


@pytest.mark.parametrize(
    ("text", "category"),
    [
        # Next to the reserved ranges, with the real exemptions: an unassigned
        # country code (ITU), a North American line outside 555-0100 to
        # 555-0199, and IANA hardware addresses outside the documentation
        # ranges. None of them can belong to anyone.
        ("call +999 41 27 93 58", "phone"),
        ("call +1-202-555-0243", "phone"),
        ("mac 00:00:5e:00:54:9d", "mac"),
        ("mac 00:00:5e:ef:10:9d", "mac"),
        ("bssid=00005eef109d", "mac"),
        ("cisco 0000.5eef.109d", "mac"),
        ("eui 00:00:5e:ef:11:a3:f4:c7", "device-id"),
        ("eui 00:00:5e:00:53:9d:a3:f4", "device-id"),
        ('"latitude": 1.23456', "coordinates"),
        ('"latitude": 0.00123', "coordinates"),
        ("see https://nas.zorble.internal/api", "url"),
    ],
)
def test_generic_findings_detect_next_to_reserved_ranges(text: str, category: str) -> None:
    assert category in privacy.generic_findings(text, ALLOWED)


@pytest.mark.parametrize(
    "text",
    [
        "version 1.10.0.1",
        "listen on 0.0.0.0 and 127.0.0.1",
        "public 8.8.8.8 and doc 192.0.2.10",
        "release 10.0.0.1.2",
        "router fe80::1, loopback ::1, doc 2001:db8::1, and std::io::Result",
        "ranges 10.0.0.0/8, 192.168.0.0/16, fc00::/7, fd00::/8, fe80::/10 and 2000::/3",
        "docker 172.17.0.1, supervisor 172.30.32.1 and 172.30.33.4, tailscale 100.100.100.100",
        "resolvers 2606:4700:4700::1111 and 2001:4860:4860::8888 and doc 3fff::1",
        "time 12:34:56, mac-like aa:bb:cc:dd:ee:ff, ratio 1:2:3",
        "author noreply@example.com and 1+me@users.noreply.github.com",
        "bot no-reply@github.com and noreply@github.com",
        "decorator @pytest.fixture and pkg@1.2.3",
        "remote git@github.com:owner/repo.git",
        "retina icon@2x.png and logo@3x.webp",
        "docs https://www.home-assistant.io/integrations/ and https://github.com/x/y",
        "local http://homeassistant.local:8123 and http://localhost:8123",
        "test http://api.example.com/v1 and https://foo.test",
        "app http://supervisor/core/api and http://homeassistant:8123/",
        "template http://{host}:{port}/ and http://$HOST/ and http://%s/",
        "literal http://[fe80::1]/ and http://127.0.0.1:8123/ and http://192.0.2.1/",
        "resolver https://1.1.1.1/dns-query and file:///etc/hosts",
        "build 20240101 and +3 votes and timestamp +0100",
        "count 123456789",
        "fiction +33 1 99 00 12 34, 01 99 00 12 34, +1-202-555-0143 and +44 7700 900123",
        "placeholder 06 12 34 56 78, 0612345678, +33 6 12 34 56 78, 06 00 00 00 00",
        "bytes 01 02 03 04 05 06 07 08 and 0a 0b 0c 0d 0e 0f",
        "runner /home/runner/work, /home/user/app and /Users/username/x",
        "devcontainer /home/vscode/.cache and ~/home/x and ./home/x",
        "media /media/recordings/cam.mp4 and /config/www and /Volumes/Data/x",
        "placeholder aa:bb:cc:dd:ee:ff and 00:00:5e:00:53:01",
        "bssid=00005e00539d and cisco 0000.5e00.539d and eui 00:00:5e:ef:10:a3:f4:c7",
        "ieee 0x00005eef10a3f4c7, MAC 00:00:5E:00:53:9D and EUI 00:00:5E:EF:10:A3:F4:C7",
        "fiction mobile 06 39 98 27 58 and +44 20 7946 0738",
        "fiction range edges +1-202-555-0100 and +1-202-555-0199",
        "reserved https://nas.example.net/x and https://a.invalid/x",
        "sequential 3e:22:fb:12:34:56 and 02:11:22:33:44:55 and de:ad:be:ef:ca:fe",
        "frame 01:03:00:0a:00:02 and mask ff:ff:ff:ff:ff:00",
        "sha a6c1381a2b3c and commit 1234567890ab",
        "zigbee 0x0000000000000000 and 0x0123456789abcdef and 0x02158d0001a2b3c4",
        "colors 0xff00ff00ff00ff00",
        '"latitude": 32.87336, "longitude": -117.22743',
        "latitude: 0.000 and ratio lat: 1.5 and flat: 2.345",
        "point [0.00000, 0.00000] and offset [0.12345, 0.54321]",
        'transform="translate(12.34567, 45.67891)" and rotate (12.34567, 45.67891)',
        "list 1.23456, 2.34567, 3.45678",
        "angle [190.12345, 95.12345]",
    ],
)
def test_generic_findings_ignore(text: str) -> None:
    assert privacy.generic_findings(text, ALLOWED) == []


# The telephone blocks that regulators reserve for fiction, as they publish
# them: ARCEP for France, Ofcom for the United Kingdom.
FICTION_BLOCKS = [
    "+33 1 99 00",
    "+33 2 61 91",
    "+33 3 53 01",
    "+33 4 65 71",
    "+33 5 36 49",
    "+33 6 39 98",
    "+44 113 496 0",
    "+44 115 496 0",
    "+44 117 496 0",
    "+44 118 496 0",
    "+44 121 496 0",
    "+44 131 496 0",
    "+44 141 496 0",
    "+44 151 496 0",
    "+44 161 496 0",
    "+44 191 498 0",
    "+44 20 7946 0",
    "+44 7700 900",
]


def test_fiction_phone_blocks_are_the_published_ones() -> None:
    blocks = {block.replace(" ", "").removeprefix("+") for block in FICTION_BLOCKS}
    assert set(privacy.FICTION_PHONE_PREFIXES) == blocks


@pytest.mark.parametrize("block", FICTION_BLOCKS)
def test_fiction_phone_blocks_are_exempt_and_nothing_next_to_them(block: str) -> None:
    digits = block.replace(" ", "").removeprefix("+")
    length = 12 if digits.startswith("44") else 11
    for end in ("0000", "9999"):
        number = (digits + end)[:length]
        assert privacy.generic_findings(f"call +{number[:2]} {number[2:]}", ALLOWED) == []
    # The first number of the next block, built here and written nowhere.
    following = str(int(digits) + 1)
    number = following + "0" * (length - len(following))
    assert "phone" in privacy.generic_findings(f"call +{number[:2]} {number[2:]}", ALLOWED)


def test_extra_allowed_domain() -> None:
    assert privacy.generic_findings("https://api.vendor.io/x", ("vendor.io",)) == []


def test_generic_findings_stay_fast_on_hostile_lines() -> None:
    lines = [
        "a" * 200_000 + "@",
        "1." * 100_000,
        "+1 " * 70_000,
        ("+1" + "2" * 40 + " ") * 20_000,
        "00 " * 70_000,
        "/home/" * 40_000,
        "\\\\wsl$\\" * 30_000,
        "0a:" * 70_000,
        "0a:1b-" * 40_000,
        "lat=" * 50_000,
        "http://" + "a" * 200_000,
        "[1.123456, " * 50_000,
        "1.123456, " * 50_000,
        "f:" * 100_000,
        "geo:1" * 50_000,
    ]
    start = time.perf_counter()
    for line in lines:
        privacy.generic_findings(line, ALLOWED)
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("noreply@github.com", True),
        ("41898282+github-actions[bot]@users.noreply.github.com", True),
        ("no-reply@github.com", True),
        ("donotreply@github.com", True),
        ("someone@example.org", True),
        ("noreply@vendor.io", False),
        ("build.noreply@github.com", False),
        ("jean.dupont+noreply@gmail.com", False),
        ("noreply.jean.dupont@gmail.com", False),
        ("someone@vendor.io", False),
        ("not-an-address", False),
    ],
)
def test_is_noreply_email(address: str, expected: bool) -> None:
    assert privacy.is_noreply_email(address) is expected


def test_noreply_at_an_allowed_domain() -> None:
    assert privacy.is_noreply_email("noreply@vendor.io", ("vendor.io",))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("LICENSE", True),
        ("LICENSE.md", True),
        ("LICENSE-APACHE", True),
        ("vendor/licence.txt", True),
        ("COPYING.LESSER", True),
        ("NOTICE.txt", True),
        ("docs/licensing.md", False),
        ("licensed_devices.json", False),
        ("notice_board.md", False),
        ("license_plate.py", False),
        ("src/ci_checks/licenses.py", False),
        ("license.py", False),
    ],
)
def test_is_license_file(path: str, expected: bool) -> None:
    assert privacy.is_license_file(path) is expected


LFS_POINTER = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 9\n"


def test_is_lfs_pointer() -> None:
    assert privacy.is_lfs_pointer(LFS_POINTER)
    assert not privacy.is_lfs_pointer(LFS_POINTER + b"x" * 1024)
    assert not privacy.is_lfs_pointer(b"# Notes\n")


def make_check(
    repo: Repo | None, denylist: str = "Bluefinch", exclude: tuple[str, ...] = ()
) -> privacy.PrivacyCheck:
    root = repo.root if repo else Path()
    return privacy.PrivacyCheck(root, privacy.Denylist(denylist), (), exclude, Reporter("Privacy"))


@pytest.mark.usefixtures("fiction_detected")
def test_findings_apply_pragmas_to_every_line_of_a_match() -> None:
    check = make_check(None)
    text = "center: [32.87336,\n    -117.22743]  # ci-allow: coordinates\n"
    assert check.findings(text, generic=True) == []
    found = check.findings(text.replace("ci-allow", "see"), generic=True)
    assert found == [privacy.Finding(1, 2, "coordinates")]
    denylisted = [privacy.Finding(1, 1, "denylist")]
    assert check.findings("Bluefinch 10.0.0.2", generic=False) == denylisted


def test_check_files(repo: Repo, capsys: Capture) -> None:
    repo.write("ok.py", "x = 1\n")
    repo.write("leak.py", "a = 1\nowner = 'bluefinch'\nhost = '10.0.0.2'\n")
    repo.write("allowed.py", "host = '10.0.0.2'  # ci-allow: private-ip\n")
    repo.write("fixtures/data.txt", "host 10.0.0.2\n")
    repo.write("LICENSE", APACHE_LICENSE)
    repo.write("image.bin", b"\0\0 Artist: BlueFinch \0")
    repo.write("utf16.txt", codecs.BOM_UTF16_LE + "ok\nBluefinch 10.0.0.3\n".encode("utf-16-le"))
    repo.commit()
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(
        ["ok.py", "leak.py", "allowed.py", "fixtures/data.txt", "LICENSE", "image.bin", "utf16.txt"]
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 5
    assert "file=leak.py,line=2::leak.py:2: denylisted term." in out
    assert "file=leak.py,line=3::leak.py:3: possible personal data (private-ip)" in out
    assert "file=image.bin::image.bin: binary content contains a denylisted term." in out
    assert "file=utf16.txt,line=2::utf16.txt:2: denylisted term." in out
    assert "file=utf16.txt,line=2::utf16.txt:2: possible personal data (private-ip)" in out
    assert "bluefinch" not in out.lower()


def test_check_files_reads_legacy_encodings(repo: Repo, capsys: Capture) -> None:
    repo.write("contacts.csv", "name;place\nQuillène Zorbefort;Ørsted Lane\n".encode("cp1252"))
    repo.write("notes.txt", "ok\r\nhost 10.0.0.2\r\n".encode("utf-16-le"))
    check = make_check(repo, denylist="Quillène Zorbefort")
    check.check_files(["contacts.csv", "notes.txt"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert "contacts.csv:2: denylisted term." in out
    assert "notes.txt:2: possible personal data (private-ip)" in out


def test_check_files_reads_mid_sized_text_files(repo: Repo, capsys: Capture) -> None:
    repo.write("export.csv", ("x" * 999 + "\n") * 1_100 + "10.0.0.2\n")
    check = make_check(repo)
    check.check_files(["export.csv"])
    assert check.reporter.count == 1
    assert "export.csv:1101: possible personal data (private-ip)" in capsys.readouterr().out


def test_check_files_redacts_denylisted_paths(repo: Repo, capsys: Capture) -> None:
    repo.write("docs/BlueFinch/notes.md", "host 10.0.0.2\n")
    repo.commit()
    check = make_check(repo)
    check.check_files(["docs/BlueFinch/notes.md"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert "docs/[redacted]/notes.md: the file path contains a denylisted term." in out
    assert "docs/[redacted]/notes.md:1: possible personal data (private-ip)" in out
    assert "file=" not in out
    assert "bluefinch" not in out.lower()


def test_check_files_follows_symlink_targets(repo: Repo, capsys: Capture) -> None:
    (repo.root / "config").symlink_to("/home/alice/bluefinch/config")
    (repo.root / "data").symlink_to("data-dir")
    check = make_check(repo)
    check.check_files(["config", "data"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert "config: the link target contains a denylisted term." in out
    assert "config: the link target may contain personal data (home-path)." in out


def test_check_files_reports_files_it_cannot_scan(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 10)
    repo.write("big.txt", "x" * 11)
    (repo.root / "submodule").mkdir()
    check = make_check(repo)
    check.check_files(["big.txt", "missing.txt", "submodule"])
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert "::warning::big.txt: larger than 10 bytes, not scanned." in out
    assert "missing.txt: tracked but missing from the checkout." in out
    assert "submodule" not in out


def test_check_files_rejects_lfs_pointers(repo: Repo, capsys: Capture) -> None:
    repo.write("data/devices.csv", LFS_POINTER)
    check = make_check(repo)
    check.check_files(["data/devices.csv"])
    assert check.reporter.count == 1
    assert "data/devices.csv: stored with Git LFS" in capsys.readouterr().out


def test_check_files_reads_binary_metadata(repo: Repo, capsys: Capture) -> None:
    photo = jpeg(exif_segment(tiff([ascii_field(ARTIST, "jane@zorble.internal")], gps_position())))
    repo.write("photo.jpg", photo)
    repo.write("fixtures/photo.jpg", photo)
    repo.write("doc.pdf", pdf(b"/Author (Blue\\146inch)"))
    hidden = png(png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"Bluefinch")))
    repo.write("icon.png", hidden)
    repo.write("clean.png", png(png_chunk(b"tEXt", b"Software\0Inkscape")))
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(["photo.jpg", "fixtures/photo.jpg", "doc.pdf", "icon.png", "clean.png"])
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert "photo.jpg: the file metadata may contain personal data (email)." in out
    assert "photo.jpg: the file metadata may contain personal data (coordinates)." in out
    assert "doc.pdf: binary content contains a denylisted term." in out
    assert "icon.png: binary content contains a denylisted term." in out
    assert "fixtures/photo.jpg" not in out


def test_pragma_on_one_line_does_not_cover_the_file(repo: Repo, capsys: Capture) -> None:
    repo.write("a.py", "x = '10.0.0.2'  # ci-allow: private-ip\ny = '10.0.0.3'\n")
    check = make_check(repo)
    check.check_files(["a.py"])
    assert check.reporter.count == 1
    assert "a.py:2: possible personal data (private-ip)" in capsys.readouterr().out


def test_denylist_ignores_exclusions_and_pragmas(repo: Repo, capsys: Capture) -> None:
    repo.write("fixtures/data.txt", "Bluefinch  # ci-allow: denylist, private-ip\n")
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(["fixtures/data.txt"])
    assert check.reporter.count == 1
    assert "denylisted term" in capsys.readouterr().out


@pytest.mark.parametrize(
    "content",
    [
        "We meet at rue des\nLilas, then\n",
        "We meet at rue   des\n\n  lilas, then\n",
        "slug: rue_des-lilas\n",
        "slug: ruedeslilas\n",
        '"text": "rue des\\nLilas"\n',
        "Rue des Lîlas\n",
    ],
)
def test_denylist_finds_every_spelling_of_a_term(repo: Repo, capsys: Capture, content: str) -> None:
    repo.write("notes.md", content)
    check = make_check(repo, denylist="rue des Lilas")
    check.check_files(["notes.md"])
    assert check.reporter.count == 1
    assert "notes.md:1: denylisted term." in capsys.readouterr().out


def history(repo: Repo, base: str) -> list[Change]:
    return changes(repo.root, [f"{base}..HEAD"])


def test_check_changes_finds_content_removed_later(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write(
        "notes.md",
        "kept 10.0.0.2\nremoved 10.0.0.3\nask Bluefinch\n10.0.0.4  # ci-allow: private-ip\n"
        "token  # gitleaks:allow\n",
    )
    repo.write("fixtures/data.txt", "10.0.0.5\n")
    repo.write("LICENSE", "https://nas.zorble.internal\n")
    repo.write("image.bin", b"\0 Artist: Bluefinch \0")
    repo.write("docs/bluefinch.md", "ok\n")
    repo.write("docs/wrapped.md", "We meet at rue des\nLilas.\n")
    repo.write("photo.jpg", jpeg(exif_segment(tiff([], gps_position()))))
    leak = repo.commit()
    repo.write("notes.md", "kept 10.0.0.2\n")
    for path in ("image.bin", "docs/bluefinch.md", "docs/wrapped.md", "photo.jpg"):
        repo.git("rm", "--quiet", path)
    repo.commit()
    check = make_check(repo, denylist="Bluefinch\nrue des Lilas", exclude=("fixtures/*",))
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    short = leak[:12]
    assert check.reporter.count == 6
    assert f"Commit {short}: notes.md:2: an added line may contain personal data" in out
    assert f"Commit {short}: notes.md:3: an added line has a denylisted term." in out
    assert f"Commit {short}: notes.md:5: gitleaks:allow hides the line" in out
    assert out.count(f"Commit {short}: a file path contains a denylisted term.") == 1
    assert f"Commit {short}: image.bin: binary content contains a denylisted term." in out
    assert f"Commit {short}: docs/wrapped.md:1: an added line has a denylisted term." in out
    assert f"Commit {short}: photo.jpg: the file metadata may contain personal data" in out
    assert "notes.md:1:" not in out
    assert "bluefinch" not in out.lower()


def test_check_changes_blame_only_the_commit_that_added_a_line(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("notes.md", "title\nhost 10.0.0.2\nend\n")
    first = repo.commit()
    repo.write("notes.md", "new title\nhost 10.0.0.2\nend\n")
    repo.commit()
    repo.write("notes.md", "new title\nend\n")
    repo.commit()
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert f"Commit {first[:12]}: notes.md:2: an added line may contain personal data" in out


def test_check_changes_reads_lines_with_carriage_returns(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("devices.csv", b"name,ip\rnas,10.0.0.2\rBluefinch,x\r")
    repo.write("log.txt", b"progress 10%\r\x1edone\nhost 10.0.0.3\n")
    leak = repo.commit()
    repo.git("rm", "--quiet", "devices.csv", "log.txt")
    repo.commit()
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    assert check.reporter.count == 3
    assert f"Commit {leak[:12]}: devices.csv:1: an added line has a denylisted term." in out
    assert f"Commit {leak[:12]}: devices.csv:1: an added line may contain personal data" in out
    assert f"Commit {leak[:12]}: log.txt:2: an added line may contain personal data" in out


def test_check_changes_reads_files_git_does_not_diff(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("notes.txt", codecs.BOM_UTF16_LE + "ok\nhost 10.0.0.2\n".encode("utf-16-le"))
    repo.write("devices.csv", LFS_POINTER)
    leak = repo.commit()
    repo.write("notes.txt", "ok\n")
    repo.commit()
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert f"Commit {leak[:12]}: notes.txt:2: an added line may contain personal data" in out
    assert f"Commit {leak[:12]}: devices.csv: stored with Git LFS" in out


def test_check_changes_skip_submodules(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.git("update-index", "--add", "--cacheinfo", f"160000,{base},vendor/lib")
    repo.commit()
    (repo.root / "vendor" / "lib").mkdir(parents=True)
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
    check.check_files(["vendor/lib"])
    assert check.reporter.count == 0
    assert capsys.readouterr().out == ""


def test_check_changes_report_blobs_it_cannot_scan(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    repo.write("big.txt", "x" * 11)
    repo.commit()
    big = repo.git("rev-parse", "HEAD:big.txt").strip()
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 10)
    sha = "a" * 40
    check = make_check(repo)
    check.check_changes(
        [
            Change(sha, "big.txt", big, "100644", frozenset({1})),
            Change(sha, "gone.txt", "c" * 40, "100644", frozenset({1})),
            Change(sha, "deleted.txt", "", "100644", frozenset()),
        ],
        exempt=set(),
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert "::warning::Commit aaaaaaaaaaaa: big.txt: larger than 10 bytes, not scanned." in out
    assert "Commit aaaaaaaaaaaa: gone.txt: the content could not be read" in out


def test_check_changes_exempt_commits_skip_generic_patterns(repo: Repo, capsys: Capture) -> None:
    repo.write("requirements.txt", "x==1\n")
    base = repo.commit()
    repo.write("requirements.txt", "x==2  # https://pkgs.vendor.io/x\n")
    bot = repo.commit(name="dependabot[bot]", email=DEPENDABOT)
    repo.write("requirements.txt", "x==2  # https://pkgs.vendor.io/x Bluefinch\n")
    person = repo.commit()
    repo.write("requirements.txt", "x==2\n")
    repo.commit()
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt={bot})
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert f"Commit {person[:12]}: requirements.txt:1: an added line has a denylisted term" in out
    assert f"Commit {person[:12]}: requirements.txt:1: an added line may contain" in out
    assert f"Commit {bot[:12]}" not in out


def commit(**changes: str) -> Commit:
    fields = {
        "sha": "a" * 40,
        "author_name": "octocat",
        "author_email": NOREPLY,
        "committer_name": "GitHub",
        "committer_email": "noreply@github.com",
        "message": "feat: add a thing",
    }
    fields.update(changes)
    return Commit(**fields)


def test_check_identities(capsys: Capture) -> None:
    check = make_check(None)
    check.check_identities(
        [
            commit(),
            commit(author_name="Bluefinch"),
            commit(author_email="someone@vendor.io"),
            commit(author_email="noreply@family.internal"),
            commit(committer_email="1+bluefinch@users.noreply.github.com"),
            commit(message="fix: thanks bluefinch"),
            commit(message="docs: see https://nas.zorble.internal"),
        ]
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 5
    assert out.count("author e-mail is not a noreply address") == 2
    assert "author contains a denylisted term" in out
    assert "committer contains a denylisted term" in out
    assert "message contains a denylisted term" in out
    assert "vendor.io" not in out


def test_check_messages(capsys: Capture) -> None:
    check = make_check(None)
    trailer = "chore(deps): bump x\n\nSigned-off-by: dependabot[bot] <support@github.com>"
    check.check_messages(
        [
            commit(),
            commit(message="docs: see https://nas.zorble.internal"),
            commit(message="docs: link\n\nhttps://docs.vendor.io/x  ci-allow: url"),
            commit(sha="b" * 40, message=trailer, author_email=DEPENDABOT),
        ],
        exempt={"b" * 40},
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert "message may contain personal data (url)" in out


def pr(**changes: str | bool) -> PullRequest:
    fields: dict[str, str | bool] = {
        "title": "feat: add a thing",
        "body": "Adds a thing.",
        "head_ref": "feature",
        "author_login": "octocat",
        "from_fork": False,
    }
    fields.update(changes)
    return PullRequest(**fields)


def test_check_pull_request(capsys: Capture) -> None:
    check = make_check(None)
    check.check_pull_request(pr())
    check.check_pull_request(pr(body="Docs at https://docs.vendor.io <!-- ci-allow: url -->"))
    assert check.reporter.count == 0

    check.check_pull_request(
        pr(title="feat: bluefinch", body="host 10.0.0.2", head_ref="bluefinch")
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 3
    assert "title contains a denylisted term" in out
    assert "branch name contains a denylisted term" in out
    assert "body may contain personal data (private-ip)" in out


def test_dependency_bot_body_skips_generic_patterns_but_not_denylist() -> None:
    check = make_check(None)
    check.check_pull_request(pr(author_login="dependabot[bot]", body="see https://docs.vendor.io"))
    assert check.reporter.count == 0
    check.check_pull_request(pr(author_login="dependabot[bot]", body="thanks Bluefinch"))
    assert check.reporter.count == 1
    check.check_pull_request(pr(author_login="other[bot]", body="see https://docs.vendor.io"))
    assert check.reporter.count == 2


def run_main(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, denylist: str | dict | None, *args: str
) -> int:
    if isinstance(denylist, dict):
        monkeypatch.setenv("CI_SECRETS", json.dumps(denylist))
    elif denylist is not None:
        monkeypatch.setenv("PRIVACY_DENYLIST", denylist)
    return privacy.main(["--root", str(repo.root), *args])


def test_main_clean_push(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n\nSee https://docs.vendor.io.\n")
    repo.write("LICENSE", APACHE_LICENSE)
    repo.commit()
    event({})
    assert run_main(repo, monkeypatch, "Bluefinch", "--allowed-domains", "vendor.io") == 0
    out = capsys.readouterr().out
    assert out.startswith("::add-mask::")
    assert "::add-mask::Bluefinch" in out
    assert "Privacy: 1 denylist secret(s) read." in out
    assert "Privacy: no problem found." in out


def test_main_mask_only(repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture) -> None:
    secrets = {"PRIVACY_DENYLIST_A": "Bluefinch", "PRIVACY_DENYLIST_B": "rue des Lilas"}
    assert run_main(repo, monkeypatch, secrets, "--mask-only") == 0
    out = capsys.readouterr().out
    assert "::add-mask::BLUEFINCH" in out
    assert "::add-mask::rue_des_lilas" in out
    assert "Privacy" not in out
    assert "CI_SECRETS" not in os.environ


def test_main_reads_every_denylist_secret(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("notes.md", "Ask Bluefinch.\nMeet at rue des\nLilas.\n")
    repo.commit()
    event({})
    secrets = {
        "github_token": "unrelated",
        "DEPLOY_KEY": "unrelated",
        "PRIVACY_DENYLIST": "Bluefinch",
        "PRIVACY_DENYLIST_2": "rue des Lilas",
        "PRIVACY_DENYLIST_EMPTY": "# nothing yet\n",
    }
    assert run_main(repo, monkeypatch, secrets) == 1
    out = capsys.readouterr().out
    assert "Privacy: 3 denylist secret(s) read." in out
    assert "::warning::1 of the 3 denylist secrets are empty." in out
    assert "notes.md:1: denylisted term." in out
    assert "notes.md:2: denylisted term." in out
    assert "PRIVACY_DENYLIST_2" not in out
    assert "unrelated" not in out


def test_main_rejects_secrets_that_are_not_json(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setenv("CI_SECRETS", "{oops")
    assert privacy.main(["--root", str(repo.root)]) == 1
    assert "CI_SECRETS does not hold valid JSON." in capsys.readouterr().err


def test_main_pull_request(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("notes.md", "Ask Bluefinch.\n")
    head = repo.commit("feat: add notes")
    event(pr_event(base, head, body="Host 192.168.0.4"))
    assert run_main(repo, monkeypatch, "Bluefinch") == 1
    out = capsys.readouterr().out
    assert "file=notes.md,line=1::notes.md:1: denylisted term." in out
    assert "message contains" not in out
    assert "Pull request body may contain personal data (private-ip)." in out


def test_main_finds_content_added_then_removed(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("README.md", "# Demo\nAsk BLUEFINCH at 10.0.0.2.\n")
    repo.write("photo.jpg", b"\xff\xd8\0 Artist: Bluefinch \0")
    leak = repo.commit("docs: add contact")
    repo.write("README.md", "# Demo\n")
    repo.git("rm", "--quiet", "photo.jpg")
    head = repo.commit("docs: remove contact")
    event(pr_event(base, head))
    assert run_main(repo, monkeypatch, "Bluefinch") == 1
    out = capsys.readouterr().out
    assert f"Commit {leak[:12]}: README.md:2: an added line has a denylisted term." in out
    assert f"Commit {leak[:12]}: README.md:2: an added line may contain personal data" in out
    assert f"Commit {leak[:12]}: photo.jpg: binary content contains a denylisted term." in out
    assert "bluefinch" not in out.lower().replace("::add-mask::bluefinch", "")


def test_main_reads_files_with_odd_names(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    (repo.root / "notes\r.txt").write_text("owner Bluefinch\n", encoding="utf-8")
    (repo.root / os.fsdecode(b"caf\xe9.txt")).write_text("host 10.0.0.2\n", encoding="utf-8")
    repo.commit()
    event({})
    assert run_main(repo, monkeypatch, "Bluefinch") == 1
    out = capsys.readouterr().out
    assert "notes%0D.txt:1: denylisted term." in out
    assert "café.txt:1: possible personal data (private-ip)" in out
    assert "missing" not in out


def test_main_scans_the_whole_first_push(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n10.0.0.2\n")
    first = repo.commit()
    repo.write("README.md", "# Demo\n")
    head = repo.commit()
    event({"before": "0" * 40, "after": head})
    assert run_main(repo, monkeypatch, "Bluefinch") == 1
    assert f"Commit {first[:12]}: README.md:2:" in capsys.readouterr().out


def test_main_exempts_dependabot_commits(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("requirements.txt", "x==1\n")
    base = repo.commit()
    repo.write("requirements.txt", "x==2\n")
    head = repo.commit(
        "chore(deps): bump x from 1 to 2\n\n"
        "Release notes: https://pkgs.vendor.io/x\n\n"
        "Signed-off-by: dependabot[bot] <support@github.com>",
        name="dependabot[bot]",
        email=DEPENDABOT,
    )
    body = "Release notes at https://pkgs.vendor.io/x"
    event(pr_event(base, head, login="dependabot[bot]", body=body))
    assert run_main(repo, monkeypatch, "Bluefinch") == 0
    assert "Privacy: no problem found." in capsys.readouterr().out

    # The same commit in a pull request opened by someone else is checked.
    event(pr_event(base, head, body="Bump x."))
    assert run_main(repo, monkeypatch, "Bluefinch") == 1
    assert "message may contain personal data" in capsys.readouterr().out


def test_main_rejects_shallow_clones(
    repo: Repo,
    monkeypatch: pytest.MonkeyPatch,
    event: EventWriter,
    tmp_path: Path,
    capsys: Capture,
) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    repo.commit()
    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    event({})
    monkeypatch.setenv("PRIVACY_DENYLIST", "Bluefinch")
    assert privacy.main(["--root", str(clone)]) == 1
    assert "fetch-depth: 0" in capsys.readouterr().err


def test_main_missing_denylist(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    head = repo.commit()
    event({})
    assert run_main(repo, monkeypatch, None) == 1
    out = capsys.readouterr().out
    assert "No denylist found." in out
    assert "secrets: inherit" in out

    assert run_main(repo, monkeypatch, {"PRIVACY_DENYLIST": "", "PRIVACY_DENYLIST_X": " "}) == 1
    assert "No denylist found." in capsys.readouterr().out
    assert run_main(repo, monkeypatch, "", "--require-denylist", "false") == 0

    monkeypatch.delenv("PRIVACY_DENYLIST")
    event(pr_event(head, head, fork=True))
    assert run_main(repo, monkeypatch, None) == 1
    out = capsys.readouterr().out
    assert "not available to pull requests from forks" in out
    assert "reviews the whole diff: any change under .github/" in out
    assert run_main(repo, monkeypatch, None, "--require-denylist", "false") == 0


def test_random_bytes_are_binary() -> None:
    assert privacy.decode_text(b"\0" + os.urandom(100)) is None
