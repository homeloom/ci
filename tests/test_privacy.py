"""Tests for the privacy check. Every name, address and number here is invented."""

from __future__ import annotations

import base64
import codecs
import json
import os
import time
import zlib
from pathlib import Path

import pytest

from ci_checks import metadata, privacy
from ci_checks._common import Change, Commit, PullRequest, Reporter, changes
from helpers import DEPENDABOT, NOREPLY, EventWriter, Repo, merge_resolving_a_submodule, pr_event
from media import (
    ARTIST,
    ascii_field,
    exif_segment,
    gps_position,
    jpeg,
    make_pdf,
    make_zip,
    pdf,
    pdf_stream,
    png,
    png_chunk,
    tiff,
    xmp,
)

ALLOWED = privacy.DEFAULT_ALLOWED_DOMAINS
ALL = privacy.GENERIC_CATEGORIES
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
        ("host 10.4.1.12", "private-ip"),
        ("fw: 192.168.1.1", "private-ip"),
        ("core-sw: 10.20.0.2", "private-ip"),
        ("FW = 172.16.5.1", "private-ip"),
        ("firmware fd12:3456:789a::1", "private-ip"),
        ('"wan_ip": "192.88.99.201"', "public-ip"),
        ("host: 192.88.99.7", "public-ip"),
        ('"ip_address": "192.88.99.201",', "public-ip"),
        ('external_ip = "192.88.99.201"', "public-ip"),
        ("ipAddress=192.88.99.201:8123", "public-ip"),
        ("MQTT_BROKER: 192.88.99.7", "public-ip"),
        ("dns-server = 192.88.99.7", "public-ip"),
        ("IP address: 192.88.99.7", "public-ip"),
        ("IPAddress : 192.88.99.7", "public-ip"),
        ('"IPAddress":"192.88.99.7"', "public-ip"),
        ("IPADDR=192.88.99.7", "public-ip"),
        ("DNS1=192.88.99.53", "public-ip"),
        ("DNSServer: 192.88.99.53", "public-ip"),
        ("nameserver 192.88.99.53", "public-ip"),
        ("contact zorble.quix@mail.zorble.internal", "email"),
        ("author zorble+noreply@mail.zorble.internal", "email"),
        ("author noreply@zorble.internal", "email"),
        ("idn mail zorble@qu\N{LATIN SMALL LETTER I WITH DIAERESIS}llmore.fr", "email"),
        ("italics _zorble@zorble.internal_ and more", "email"),
        ("bold __zorble@zorble.internal__", "email"),
        ("contact: zorble@zorble.internal_", "email"),
        ("https://example.com/account?email=zorble%40zorble.internal", "email"),
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
        ("call 202-555-0143", "phone"),
        ("call 202.555.0143", "phone"),
        ("call 1-202-555-0143", "phone"),
        ("call 1.202.555.0143", "phone"),
        ("call 06 39 98 27 58 de 9h", "phone"),
        ("call 06 39 98 27 58 de 14 \N{LATIN SMALL LETTER A WITH GRAVE} 18 h", "phone"),
        ("call 06 39 98 27 58 de 10 \N{LATIN SMALL LETTER A WITH GRAVE} 12h", "phone"),
        ("call 06 39 98 27 58 ab", "phone"),
        ("see https://zorblequix.zorble.internal/api", "url"),
        ("ws wss://zorblequix.family.internal/api/websocket", "url"),
        ("idn https://maison-quillmor\N{LATIN SMALL LETTER E WITH ACUTE}.fr", "url"),
        ("cd /home/zorblequix/projects", "home-path"),
        ("open /Users/quillmore/Library", "home-path"),
        (r"C:\Users\bluefinch\Desktop", "home-path"),
        (r"C:\\Users\\bluefinch\\Desktop", "home-path"),
        ("C:/Users/bluefinch/Desktop", "home-path"),
        ("c:/users/bluefinch/Desktop", "home-path"),
        ("file:///C%3A/Users/bluefinch/x", "home-path"),
        ("wsl /mnt/c/Users/zorblequix/x", "home-path"),
        (r"share \\wsl$\Ubuntu\home\zorblequix\x", "home-path"),
        (r"share \\wsl.localhost\Ubuntu\home\zorblequix\x", "home-path"),
        ("silverblue /var/home/zorblequix/x", "home-path"),
        ("usb /run/media/zorblequix/disk", "home-path"),
        ("GPSLatitude: 32.87336", "coordinates"),
        ("home_lat: 32.87336", "coordinates"),
        ("HOME_LAT = 32.8734", "coordinates"),
        ("home_lat: 32.873", "coordinates"),
        ("home_lon: -0.41273", "coordinates"),
        ("device_lng = -0.4127", "coordinates"),
        ('"long": -0.41273', "coordinates"),
        ("long: -117.227", "coordinates"),
        ("home_lat: 0.512", "coordinates"),
        ("home_long: -117.2274", "coordinates"),
        ("range [-151.23456, 12.34567]", "coordinates"),
        ("Location: [32.8734, -117.2274]", "coordinates"),
        ("center: [32.87336, -117.227434]", "coordinates"),
        ("The buoy sits at (32.8734, -117.2274).", "coordinates"),
        ("coordinates (32.8734, -117.2274)", "coordinates"),
        ("position [32.8734, -117.2274]", "coordinates"),
        ('origin: "32.87336,-117.22743"', "coordinates"),
        ("https://github.com/search?latlng=32.87336,-117.22743", "coordinates"),
        ("https://example.com/forecast?q=32.8734,-117.2274&units=si", "coordinates"),
        ("https://example.com/forecast?location=32.87336%2C-117.22743", "coordinates"),
        ("https://maps.example.com/@32.87336,-117.22743,15z", "coordinates"),
        ("https://maps.example.com/@32.87336,-117.22743,500m/data=!3m1!1e3", "coordinates"),
        ("https://maps.example.com/@32.87336,-117.22743,3a,75y,90t", "coordinates"),
        ("<coordinates>-117.22743,32.87336,0</coordinates>", "coordinates"),
        ("<kml:coordinates>\n  -117.2274,32.8734,12.5\n</kml:coordinates>", "coordinates"),
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
        'sw_version: "10.4.1.12", firmware 10.2.0.15 and "firmware_version": "10.2.0.15"',
        "swVersion=10.1.2.3 and FW_VER: 10.0.0.7",
        "router fe80::1, loopback ::1, doc 2001:db8::1, and std::io::Result",
        "ranges 10.0.0.0/8, 192.168.0.0/16, fc00::/7, fd00::/8, fe80::/10 and 2000::/3",
        "docker 172.17.0.1, supervisor 172.30.32.1 and 172.30.33.4, tailscale 100.100.100.100",
        "resolvers 2606:4700:4700::1111 and 2001:4860:4860::8888 and doc 3fff::1",
        'dns: 8.8.8.8 and "host": "0.0.0.0" and server=127.0.0.1',
        "time 12:34:56, mac-like aa:bb:cc:dd:ee:ff, ratio 1:2:3",
        "author noreply@example.com and 1+me@users.noreply.github.com",
        "bot no-reply@github.com and noreply@github.com",
        "decorator @pytest.fixture and pkg@1.2.3",
        "remote git@github.com:owner/repo.git",
        "retina icon@2x.png and logo@3x.webp",
        "encoded noreply%40example.com and %40scope/package",
        "docs https://www.home-assistant.io/integrations/ and https://github.com/x/y",
        "local http://homeassistant.local:8123 and http://localhost:8123",
        "test http://api.example.com/v1 and https://foo.test",
        "app http://supervisor/core/api and http://homeassistant:8123/",
        "template http://{host}:{port}/ and http://$HOST/ and http://%s/",
        "literal http://[fe80::1]/ and http://127.0.0.1:8123/ and http://192.0.2.1/",
        "resolver https://1.1.1.1/dns-query and file:///etc/hosts",
        'xmlns:serif="http://www.serif.com/" xmlns:bx="https://boxy-svg.com"',
        "<!-- Generator: Sketch 64 (93537) - https://sketch.com -->",
        "<!-- Generator: Sketch 53.2 (72643) - https://sketchapp.com -->",
        'xmlns:sketch="http://www.bohemiancoding.com/sketch/ns"',
        '<a xlink:href="https://www.drawio.com/doc/faq/svg-export-text-problems">',
        '<a xlink:href="https://www.diagrams.net/doc/faq/svg-export-text-problems">',
        "build 20240101 and +3 votes and timestamp +0100",
        "count 123456789",
        "fiction +33 1 99 00 12 34, 01 99 00 12 34, +1-202-555-0143 and +44 7700 900123",
        # +999 is a spare country code, which no number can belong to.
        "placeholder +999 12 34 56 78, +999 1234 5678, 06 00 00 00 00 and 0600000000",
        "placeholder 202-123-4567 and 555-555-5555",
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
        "DELAY_LONG = 1.500, PRESS_LONG: 0.750, HOLD_LONG: 0.7500 and SAVE_DELAY_LONG = 180.0",
        "home_lat: 0.0000 and home_lon: -0.000",
        "point [0.00000, 0.00000] and offset [0.12345, 0.54321]",
        'transform="translate(12.34567, 45.67891)" and rotate (12.34567, 45.67891)',
        "list 1.23456, 2.34567, 3.45678",
        "angle [190.12345, 95.12345]",
        'path d="M 12.3456,45.6789 L 13.4567,46.789 Z" and d="M12.3456,45.6789L13.4567,46.789"',
        'polygon points="12.3456,45.6789 13.4567,46.7890 14.5678,47.8901"',
        "values 12.3456,45.6789,78.9012 and 12.3456,45.6789, 78.9012",
        "call test(20.3423, 3.1427) and Point(20.3423, 3.1427)",
        "matrix [[20.3423, 3.1427],\n                [3.8994, 4.1248]]",
        "call test(20.3423,3.1427) and rows [[20.3423,3.1427],[3.8994,4.1248]]",
        "// for x in[4.5453,2.8571] and for x in [4.5454,2.8571] = 1/[0.2199,0.35001]",
        'frame = DataFrame({"values": [1.4245, 2.32441]}) and floats (1.4245,2.32441)',
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
    "+44 114 496 0",
    "+44 115 496 0",
    "+44 116 496 0",
    "+44 117 496 0",
    "+44 118 496 0",
    "+44 121 496 0",
    "+44 131 496 0",
    "+44 141 496 0",
    "+44 151 496 0",
    "+44 161 496 0",
    "+44 1632 960",
    "+44 191 498 0",
    "+44 20 7946 0",
    "+44 28 9649 6",
    "+44 29 2018 0",
    "+44 3069 990",
    "+44 7700 900",
    "+44 8081 570",
    "+44 909 879 0",
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
    # The last number of the block before and the first of the block after,
    # built here and written nowhere.
    before = str(int(digits) - 1)
    after = str(int(digits) + 1)
    for number in (before.ljust(length, "9"), after.ljust(length, "0")):
        assert "phone" in privacy.generic_findings(f"call +{number[:2]} {number[2:]}", ALLOWED)


def test_trunk_prefix_after_the_country_code_is_dropped() -> None:
    fiction = "+44 (0)20 7946 0739, +33 (0)6 39 98 27 58, 0033 (0)6 39 98 27 58"
    assert privacy.generic_findings(fiction, ALLOWED) == []
    assert "phone" in privacy.generic_findings("+44 (0)20 7946 1739", ALLOWED)


def test_fiction_number_with_more_digits_is_not_exempt() -> None:
    # The digits after a fiction number could be a real number written next to it.
    for text in ("+33 6 39 98 27 58 42", "+44 20 7946 0739 4", "+1 202 555 0143 7"):
        assert "phone" in privacy.generic_findings(text, ALLOWED), text


def test_documentation_and_fiction_values_are_exempt() -> None:
    text = (
        "home 2001:db8:1f2:3b40::1, wan_ip: 203.0.113.201, host: 198.51.100.7, IPADDR=203.0.113.7, "
        "nameserver 198.51.100.53, "
        "http://203.0.113.34:8123/api, http://[2001:db8::1]:8123, +33 6 39 98 27 58, "
        "06 39 98 27 58, (202) 555-0143, 202-555-0143, 202.555.0143, 1-202-555-0143, "
        "+44 20 7946 0739"
    )
    assert privacy.generic_findings(text, ALLOWED) == []


@pytest.mark.usefixtures("fiction_detected")
@pytest.mark.parametrize(
    "text",
    [
        '"version": "192.88.99.201" and release 192.88.99.7',
        "host 192.88.99.7 without a separator, hosts: 192.88.99.7",
        "dump 06 39 98 27 58 de ad, 06 39 98 27 58 de 4f, 06 39 98 27 58 de 14 2f",
        "dump ff 06 39 98 27 58",
        "date 2024-10-24, id x202-555-0143, 202-555-0143-7 and 1-202.555.0143",
        "version 3.202.555.0143 and 11-202-555-0143",
        "version 202.555.0143.2, serial 202-555-01432 and 202-555.0143",
        "area 102-555-0143 and exchange 202-155-0143",
    ],
)
def test_generic_findings_ignore_shapes_without_exemptions(text: str) -> None:
    assert privacy.generic_findings(text, ALLOWED) == []


def test_extra_allowed_domain() -> None:
    assert privacy.generic_findings("https://api.vendor.io/x", ("vendor.io",)) == []


def test_generic_findings_by_category() -> None:
    text = "host 10.0.0.2, see https://nas.zorble.internal"
    assert privacy.generic_findings(text, ALLOWED, {"url"}) == ["url"]
    assert privacy.generic_findings(text, ALLOWED, ()) == []


# Each line takes a fraction of a second; a quadratic pattern would take minutes.
HOSTILE_LINES = [
    "a" * 200_000 + "@",
    "a%40" * 50_000,
    "1." * 100_000,
    "+1 " * 70_000,
    ("+1" + "2" * 40 + " ") * 20_000,
    "00 " * 70_000,
    "202-555-" * 30_000,
    "/home/" * 40_000,
    "\\\\wsl$\\" * 30_000,
    "0a:" * 70_000,
    "0a:1b-" * 40_000,
    "lat=" * 50_000,
    "ip=" * 70_000,
    "version 10.0.0.1 " * 12_000,
    "http://" + "a" * 200_000,
    "[1.123456, " * 50_000,
    "[1.1234, 2.1234] " * 12_000,
    "1.123456, " * 50_000,
    "1.1234,2.1234 " * 15_000,
    "1.1234,2.1234" + ",1z" * 70_000,
    "<coordinates>" + " " * 200_000,
    "f:" * 100_000,
    "geo:1" * 50_000,
]


@pytest.mark.parametrize("line", HOSTILE_LINES, ids=lambda line: repr(line[:12]))
def test_generic_findings_stay_fast_on_hostile_lines(line: str) -> None:
    start = time.perf_counter()
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
        ("zorble.quix+noreply@zorble.internal", False),
        ("noreply.zorble.quix@zorble.internal", False),
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
    assert check.findings(text, ALL) == []
    found = check.findings(text.replace("ci-allow", "see"), ALL)
    assert found == [privacy.Finding(1, 2, "coordinates")]
    denylisted = [privacy.Finding(1, 1, "denylist")]
    assert check.findings("Bluefinch 10.0.0.2", frozenset()) == denylisted


def test_check_files(repo: Repo, capsys: Capture) -> None:
    repo.write("ok.py", "x = 1\n")
    repo.write("leak.py", "a = 1\nowner = 'bluefinch'\nhost = '10.0.0.2'\n")
    repo.write("allowed.py", "host = '10.0.0.2'  # ci-allow: private-ip\n")
    repo.write("fixtures/data.txt", "host 10.0.0.2\n")
    repo.write("LICENSE", APACHE_LICENSE)
    repo.write("image.bin", b"\xff\0\x01\x02 Artist: BlueFinch \0\x03\x04")
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


def test_check_files_reads_text_with_a_stray_nul(repo: Repo, capsys: Capture) -> None:
    repo.write("pets.csv", b"name,pet\0\nQuillmore,Vrix\nconst k = getZorblequix();\n")
    # A spreadsheet export in Windows-1252, which is not UTF-8.
    repo.write("legacy.csv", b"name;pet\0\nQuillm\xf6re;Vrix\nconst k = getZorblequix();\n")
    repo.write("table.bin", b"\0\x01\x02\x03\x04 Vrix and Zorblequix \x05\x06\x0e\x0f\x10\x11\0")
    check = make_check(repo, denylist="Vrix\nZorblequix")
    check.check_files(["pets.csv", "legacy.csv", "table.bin"])
    out = capsys.readouterr().out
    assert check.reporter.count == 5
    for name in ("pets.csv", "legacy.csv"):
        assert f"{name}:2: denylisted term." in out
        assert f"{name}:3: denylisted term." in out
    assert "table.bin: binary content contains a denylisted term." in out


def test_check_files_reads_images_as_binary_even_when_mostly_text(
    repo: Repo, capsys: Capture
) -> None:
    # Only the metadata reader finds the position in the XMP packet, which
    # makes up most of the file.
    packet = xmp('exif:GPSLatitude="41,16.31S" dc:description="' + "Zorblequix " * 400 + '"')
    repo.write("icon.png", png(png_chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0" + packet)))
    check = make_check(repo)
    check.check_files(["icon.png"])
    assert check.reporter.count == 1
    assert "icon.png: the file metadata may contain personal data (coordinates)." in (
        capsys.readouterr().out
    )


def test_check_files_reads_mid_sized_text_files(repo: Repo, capsys: Capture) -> None:
    repo.write("export.csv", ("x" * 999 + "\n") * 1_100 + "10.0.0.2\n")
    check = make_check(repo)
    check.check_files(["export.csv"])
    assert check.reporter.count == 1
    assert "export.csv:1101: possible personal data (private-ip)" in capsys.readouterr().out


def test_check_files_redact_denylisted_paths_everywhere(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 200)
    folder = repo.root / "docs" / "BlueFinch"
    repo.write("docs/BlueFinch/notes.md", "host 10.0.0.2\n")
    repo.write("docs/BlueFinch/icon.png", png(png_chunk(b"tEXt", b"Comment\0Bluefinch")))
    repo.write("docs/BlueFinch/devices.csv", LFS_POINTER)
    repo.write("docs/BlueFinch/export.csv", "x" * 201)
    (folder / "config").symlink_to("/home/zorblequix/bluefinch")
    names = ("notes.md", "icon.png", "devices.csv", "export.csv", "config", "gone.txt")
    check = make_check(repo)
    check.check_files([f"docs/BlueFinch/{name}" for name in names])
    out = capsys.readouterr().out
    shown = "docs/[redacted]"
    assert check.reporter.count == 13
    assert out.count("the file path contains a denylisted term.") == 6
    assert f"{shown}/notes.md:1: possible personal data (private-ip)" in out
    assert f"{shown}/icon.png: binary content contains a denylisted term." in out
    assert f"{shown}/devices.csv: stored with Git LFS" in out
    assert f"{shown}/export.csv: larger than 200 bytes, so its content cannot be checked." in out
    assert f"{shown}/config: the link target contains a denylisted term." in out
    assert f"{shown}/config: the link target may contain personal data (home-path)." in out
    assert f"{shown}/gone.txt: tracked but missing from the checkout." in out
    assert "file=" not in out
    assert "bluefinch" not in out.lower()


def test_check_files_report_personal_data_in_paths(repo: Repo, capsys: Capture) -> None:
    repo.write("docs/3e-71-bf-4e-92-d5.json", "{}\n")
    repo.write("docs/10.11.12.13 zorble@quillmore.fr.md", "host 10.0.0.2\n")
    repo.write("fixtures/3e-71-bf-4e-92-d5.json", "{}\n")
    paths = ["docs/3e-71-bf-4e-92-d5.json", "docs/10.11.12.13 zorble@quillmore.fr.md"]
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files([*paths, "fixtures/3e-71-bf-4e-92-d5.json"])
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    for category in ("mac", "private-ip", "email"):
        assert (
            f"docs/[redacted]: the file path may contain personal data ({category}). Rename "
            "the file, or exclude it from the generic patterns if the name is not personal."
        ) in out
    assert "docs/[redacted]:1: possible personal data (private-ip)" in out
    assert "file=" not in out
    assert "3e-71" not in out
    assert "quillmore" not in out
    assert "10.11.12.13" not in out


def test_paths_hide_a_term_split_across_folders(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    # The file name that ends the term also holds an address.
    path = "docs/Quillmore/Lane 10.11.12.13.md"
    repo.write(path, "ok\n")
    leak = repo.commit()
    check = make_check(repo, denylist="Quillmore Lane")
    check.check_files([path])
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    for where in ("", f"Commit {leak[:12]}: "):
        assert f"::error::{where}[redacted path]: the file path contains a denylisted term." in out
        assert f"::error::{where}[redacted path]: the file path may contain personal data" in out
    assert "quillmore" not in out.lower()


def test_check_files_follows_symlink_targets(repo: Repo, capsys: Capture) -> None:
    (repo.root / "config").symlink_to("/home/zorblequix/bluefinch/config")
    (repo.root / "data").symlink_to("data-dir")
    check = make_check(repo)
    check.check_files(["config", "data"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert "file=config::config: the link target contains a denylisted term." in out
    assert "file=config::config: the link target may contain personal data (home-path)." in out


def test_check_files_reports_files_it_cannot_scan(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 10)
    repo.write("big.txt", "x" * 11)
    (repo.root / "submodule").mkdir()
    check = make_check(repo)
    check.check_files(["big.txt", "missing.txt", "submodule"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert (
        "::error file=big.txt::big.txt: larger than 10 bytes, so its content cannot be checked. "
        "Keep large files out of the repository"
    ) in out
    assert "missing.txt: tracked but missing from the checkout." in out
    assert "submodule" not in out


def test_check_files_rejects_lfs_pointers(repo: Repo, capsys: Capture) -> None:
    repo.write("data/devices.csv", LFS_POINTER)
    check = make_check(repo)
    check.check_files(["data/devices.csv"])
    assert check.reporter.count == 1
    assert "file=data/devices.csv::data/devices.csv: stored with Git LFS" in capsys.readouterr().out


def test_check_files_reads_binary_metadata(repo: Repo, capsys: Capture) -> None:
    photo = jpeg(exif_segment(tiff([ascii_field(ARTIST, "jane@zorble.internal")], gps_position())))
    repo.write("photo.jpg", photo)
    repo.write("fixtures/photo.jpg", photo)
    repo.write("doc.pdf", pdf(b"/Author (Blue\\146inch)"))
    hidden = png(png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"Bluefinch")))
    repo.write("icon.png", hidden)
    repo.write("clean.png", png(png_chunk(b"tEXt", b"Software\0Inkscape")))
    # Metadata formats name their schemas with URLs, which are not personal.
    schema = xmp('xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/" dc:title="Maps"')
    repo.write("schema.png", png(png_chunk(b"iTXt", b"XML:com.adobe.xmp\0\0\0\0\0" + schema)))
    check = make_check(repo, exclude=("fixtures/*",))
    paths = ["photo.jpg", "fixtures/photo.jpg", "doc.pdf", "icon.png", "clean.png", "schema.png"]
    check.check_files(paths)
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert "photo.jpg: the file metadata may contain personal data (email)." in out
    assert "photo.jpg: the file metadata may contain personal data (coordinates)." in out
    assert "doc.pdf: binary content contains a denylisted term." in out
    assert "icon.png: binary content contains a denylisted term." in out
    assert "fixtures/photo.jpg" not in out
    assert "schema.png" not in out


def test_check_files_reads_compressed_content(repo: Repo, capsys: Capture) -> None:
    photo = jpeg(exif_segment(tiff([], gps_position())))
    repo.write(
        "report.docx", make_zip(("docProps/core.xml", b"<dc:creator>Bluefinch</dc:creator>"))
    )
    repo.write("photos.zip", make_zip(("a.jpg", photo)))
    repo.write("fixtures/photos.zip", make_zip(("a.jpg", photo)))
    info = zlib.compress(b"<< /Author (jane@zorble.internal) >>")
    repo.write("doc.pdf", make_pdf(pdf_stream(info)))
    repo.write("broken.pdf", make_pdf(pdf_stream(b"not zlib")))
    repo.write("clean.zip", make_zip(("a.txt", b"hello")))
    check = make_check(repo, exclude=("fixtures/*",))
    paths = ["report.docx", "photos.zip", "fixtures/photos.zip", "doc.pdf", "broken.pdf"]
    check.check_files([*paths, "clean.zip"])
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert "report.docx: binary content contains a denylisted term." in out
    assert "photos.zip: the file metadata may contain personal data (coordinates)." in out
    assert "fixtures/photos.zip" not in out
    assert "doc.pdf: the file metadata may contain personal data (email)." in out
    assert (
        "broken.pdf: the compressed content is not valid compressed data, so it cannot be "
        "checked." in out
    )


def test_check_files_fails_on_metadata_cut_by_a_bound(
    repo: Repo, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(metadata, "MAX_TEXT_CHARS", 10)
    repo.write("icon.png", png(png_chunk(b"tEXt", b"Comment\0" + b"x" * 11)))
    repo.write("small.png", png(png_chunk(b"tEXt", b"Comment\0" + b"x" * 10)))
    check = make_check(repo)
    check.check_files(["icon.png", "small.png"])
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert "icon.png: the file metadata is too large to be checked whole." in out


def test_check_files_reads_data_uris(repo: Repo, capsys: Capture) -> None:
    hidden = png(png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"Bluefinch")))
    photo = jpeg(exif_segment(tiff([], gps_position())))
    uri = "data:image/png;base64,{}".format
    repo.write(
        "icon.svg",
        f'<svg>\n<image href="{uri(base64.b64encode(hidden).decode())}"/>\n'
        f'<image href="{uri(base64.b64encode(photo).decode())}"/>\n</svg>\n',
    )
    check = make_check(repo)
    check.check_files(["icon.svg"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert "icon.svg:2: embedded data: binary content contains a denylisted term." in out
    assert (
        "icon.svg:3: embedded data: the file metadata may contain personal data (coordinates)."
        in out
    )


def test_check_changes_reads_data_uris_of_added_lines(repo: Repo, capsys: Capture) -> None:
    hidden = png(png_chunk(b"zTXt", b"Comment\0\0" + zlib.compress(b"Bluefinch")))
    line = f'<img src="data:image/png;base64,{base64.b64encode(hidden).decode()}">\n'
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("page.html", "<p>one</p>\n" + line)
    first = repo.commit()
    repo.write("page.html", "<p>two</p>\n" + line)
    repo.commit()
    repo.write("removed.html", line)
    removed = repo.commit()
    repo.git("rm", "--quiet", "removed.html")
    repo.commit()
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    # The line still in page.html is reported with the files, not with its commit.
    assert check.reporter.count == 1
    assert f"Commit {first[:12]}" not in out
    assert (
        f"Commit {removed[:12]}: removed.html:1: embedded data: binary content contains a "
        "denylisted term." in out
    )


def test_license_files_skip_only_urls_and_emails(repo: Repo, capsys: Capture) -> None:
    repo.write("LICENSE", "MIT License\n\n(c) 2026 Zorblequix <zorble@quillmore.fr>, 10.11.12.13\n")
    repo.write("LICENSE-DOCS.md", "See https://quillmore.fr for zorble@quillmore.fr.\n")
    repo.write(
        "custom_components/zorble/NOTICE.md",
        "Tested at -41.27183, -132.58291 on 3e:71:bf:4e:92:d5,\nlogs in /home/zorblequix/x.\n",
    )
    check = make_check(repo)
    check.check_files(["LICENSE", "LICENSE-DOCS.md", "custom_components/zorble/NOTICE.md"])
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert "LICENSE:3: possible personal data (private-ip)" in out
    assert "NOTICE.md:1: possible personal data (coordinates)" in out
    assert "NOTICE.md:1: possible personal data (mac)" in out
    assert "NOTICE.md:2: possible personal data (home-path)" in out


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
        "We meet at rue des\nZorbles, then\n",
        "We meet at rue   des\n\n  zorbles, then\n",
        "slug: rue_des-zorbles\n",
        "slug: ruedeszorbles\n",
        '"text": "rue des\\nZorbles"\n',
        "Rue des Zörbles\n",
    ],
)
def test_denylist_finds_every_spelling_of_a_term(repo: Repo, capsys: Capture, content: str) -> None:
    repo.write("notes.md", content)
    check = make_check(repo, denylist="rue des Zorbles")
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
    repo.write("image.bin", b"\xff\0\x01\x02 Artist: Bluefinch \0 gitleaks:allow \0\x03\x04")
    repo.write("pets.csv", b"name,pet\0\nBluefinch,10.0.0.6\n")
    repo.write("docs/bluefinch.md", "ok\n")
    repo.write("docs/wrapped.md", "We meet at rue des\nZorbles.\n")
    repo.write("photo.jpg", jpeg(exif_segment(tiff([], gps_position()))))
    leak = repo.commit()
    repo.write("notes.md", "kept 10.0.0.2\n")
    for path in ("image.bin", "pets.csv", "docs/bluefinch.md", "docs/wrapped.md", "photo.jpg"):
        repo.git("rm", "--quiet", path)
    repo.commit()
    check = make_check(repo, denylist="Bluefinch\nrue des Zorbles", exclude=("fixtures/*",))
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    short = leak[:12]
    assert check.reporter.count == 8
    assert out.count("gitleaks:allow") == 2
    assert f"Commit {short}: notes.md:2: an added line may contain personal data" in out
    assert f"Commit {short}: notes.md:3: an added line has a denylisted term." in out
    assert f"Commit {short}: notes.md:5: gitleaks:allow hides the line" in out
    assert (
        out.count(f"Commit {short}: docs/[redacted]: the file path contains a denylisted term.")
        == 1
    )
    assert f"Commit {short}: image.bin: binary content contains a denylisted term." in out
    assert f"Commit {short}: image.bin: gitleaks:allow in binary content hides lines" in out
    assert f"Commit {short}: pets.csv:2: an added line has a denylisted term." in out
    assert f"Commit {short}: pets.csv:2: an added line may contain personal data" in out
    assert f"Commit {short}: docs/wrapped.md:1: an added line has a denylisted term." in out
    assert f"Commit {short}: photo.jpg: the file metadata may contain personal data" in out
    assert "notes.md:1:" not in out
    assert "bluefinch" not in out.lower()


def test_check_changes_redact_denylisted_paths_everywhere(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("docs/BlueFinch/notes.md", "host 10.0.0.2\n")
    repo.write("docs/BlueFinch/icon.png", png(png_chunk(b"tEXt", b"Comment\0Bluefinch")))
    repo.write("docs/BlueFinch/devices.csv", LFS_POINTER)
    repo.write("docs/BlueFinch/export.csv", "x" * 201)
    (repo.root / "docs" / "BlueFinch" / "config").symlink_to("/home/zorblequix/config")
    leak = repo.commit()
    repo.git("rm", "--quiet", "-r", "docs")
    repo.commit()
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 200)
    gone = Change(leak, "docs/BlueFinch/gone.txt", "c" * 40, "100644", frozenset({1}))
    check = make_check(repo)
    check.check_changes([*history(repo, base), gone], exempt=set())
    out = capsys.readouterr().out
    where = f"Commit {leak[:12]}: docs/[redacted]"
    assert check.reporter.count == 12
    assert out.count("the file path contains a denylisted term.") == 6
    assert f"{where}/notes.md:1: an added line may contain personal data (private-ip)" in out
    assert f"{where}/icon.png: binary content contains a denylisted term." in out
    assert f"{where}/devices.csv: stored with Git LFS" in out
    assert f"{where}/export.csv: larger than 200 bytes, so its content cannot be checked." in out
    assert f"{where}/config:1: an added line may contain personal data (home-path)" in out
    assert f"{where}/gone.txt: the content could not be read from the repository." in out
    assert "file=" not in out
    assert "bluefinch" not in out.lower()


def test_check_changes_report_personal_data_in_paths(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("docs/3e-71-bf-4e-92-d5.json", "{}\n")
    repo.write("fixtures/3e-71-bf-4e-92-d5.json", "{}\n")
    leak = repo.commit()
    repo.git("mv", "docs/3e-71-bf-4e-92-d5.json", "docs/device.json")
    repo.commit()
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert (
        f"Commit {leak[:12]}: docs/[redacted]: the file path may contain personal data (mac), "
        "even if a later commit renamed the file."
    ) in out
    assert "3e-71" not in out


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


def test_check_changes_compare_with_the_file_as_check_files_reads_it(
    repo: Repo, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("notes.txt", "plain\nconst who = getBluefinch();\n")
    added = repo.commit()
    # The checkout now reads as a PDF document, so the line it still holds
    # is not one of its text lines, and the commit that added it reports it.
    repo.write("notes.txt", "%PDF-1.4 notes\nconst who = getBluefinch();\n")
    repo.commit()
    check = make_check(repo)
    check.check_files(["notes.txt"])
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    # The file and the commit that wrote it report the binary content.
    assert check.reporter.count == 3
    assert f"Commit {added[:12]}: notes.txt:2: an added line has a denylisted term." in out


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


def test_check_changes_skip_submodules_resolved_by_a_merge(repo: Repo, capsys: Capture) -> None:
    base, _ = merge_resolving_a_submodule(repo)
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
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
    assert check.reporter.count == 2
    assert (
        "::error::Commit aaaaaaaaaaaa: big.txt: larger than 10 bytes, so its content cannot be "
        "checked. Keep large files out of the repository"
    ) in out
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
    check.check_pull_request(pr(head_ref="fix/zigbee-firmware-10.2.0.15"))
    assert check.reporter.count == 0

    check.check_pull_request(
        pr(title="feat: bluefinch", body="host 10.0.0.2", head_ref="bluefinch")
    )
    check.check_pull_request(pr(head_ref="fix/zorble@quillmore.fr/3e:71:bf:4e:92:d5"))
    out = capsys.readouterr().out
    assert check.reporter.count == 5
    assert "title contains a denylisted term" in out
    assert "branch name contains a denylisted term" in out
    assert "body may contain personal data (private-ip)" in out
    assert "Pull request branch name may contain personal data (email)." in out
    assert "Pull request branch name may contain personal data (mac)." in out


def test_dependency_bot_body_skips_generic_patterns_but_not_denylist() -> None:
    check = make_check(None)
    check.check_pull_request(pr(author_login="dependabot[bot]", body="see https://docs.vendor.io"))
    check.check_pull_request(pr(author_login="dependabot[bot]", head_ref="dependabot/x-10.1.2.3"))
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
    secrets = {"PRIVACY_DENYLIST_A": "Bluefinch", "PRIVACY_DENYLIST_B": "rue des Zorbles"}
    assert run_main(repo, monkeypatch, secrets, "--mask-only") == 0
    out = capsys.readouterr().out
    assert "::add-mask::BLUEFINCH" in out
    assert "::add-mask::rue_des_zorbles" in out
    assert "Privacy" not in out
    assert "CI_SECRETS" not in os.environ


def test_main_reads_every_denylist_secret(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("notes.md", "Ask Bluefinch.\nMeet at rue des\nZorbles.\n")
    repo.commit()
    event({})
    secrets = {
        "github_token": "unrelated",
        "DEPLOY_KEY": "unrelated",
        "PRIVACY_DENYLIST": "Bluefinch",
        "PRIVACY_DENYLIST_2": "rue des Zorbles",
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
    assert "force pushed" not in out


def test_main_warns_about_commits_a_force_push_replaced(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, event: EventWriter, capsys: Capture
) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("notes.md", "Notes.\n")
    head = repo.commit("docs: add notes")
    # The previous head is gone from the checkout, as after an amended commit.
    event(pr_event(base, head, before="e" * 40))
    assert run_main(repo, monkeypatch, "Bluefinch") == 0
    out = capsys.readouterr().out
    assert (
        "::warning::The pull request branch was force pushed. The commits it replaced, up to "
        "eeeeeeeeeeee, stay reachable on GitHub but are not checked again: if they held "
        "personal data or a secret, tell a maintainer."
    ) in out
    assert "Privacy: no problem found." in out


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


def test_gitleaks_allow_in_binary_content_is_reported_once(repo: Repo, capsys: Capture) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    shas = []
    for tail, marker in (("one", "a"), ("two", "a"), ("three", "b")):
        repo.write(
            "data.bin", f"\xff\0\x01head\nkey {marker} gitleaks:allow\n\0{tail}\n".encode("latin-1")
        )
        shas.append(repo.commit())
    repo.write("data.bin", b"\xff\0\x01head\n\0four\n")
    repo.commit()
    check = make_check(repo)
    check.check_changes(history(repo, base), exempt=set())
    out = capsys.readouterr().out
    assert out.count("gitleaks:allow in binary content") == 2
    assert f"Commit {shas[0][:12]}: data.bin: gitleaks:allow" in out
    assert f"Commit {shas[2][:12]}: data.bin: gitleaks:allow" in out


def test_text_with_nul_bytes() -> None:
    assert privacy._text(b"name,pet\0\nVrix\n") == "name,pet\nVrix\n"
    assert privacy._text(b"name;place\0\n\xd8rsted Lane\n") == "name;place\n\xd8rsted Lane\n"
    assert privacy._text(b"\0\x01\x02\x03 text") is None
    assert privacy._text(b"\0\xff\x01\x02 text") is None
    assert privacy._text(b"%PDF-1.4\0") is None
