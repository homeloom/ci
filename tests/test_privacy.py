"""Tests for the privacy check."""

from __future__ import annotations

import codecs
import os
import random
import time
from pathlib import Path

import pytest

from ci_checks import privacy
from ci_checks._common import Change, Commit, PullRequest, Reporter
from helpers import DEPENDABOT, NOREPLY, EventWriter, Repo, pr_event

ALLOWED = privacy.DEFAULT_ALLOWED_DOMAINS
APACHE_LICENSE = """
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS.
"""
# Short first names, which random bytes spell by chance.
SHORT_NAMES = "\n".join(
    "Ugo Leo Eli Luna Max Mia Noa Zoe Tom Eva Lou Ana Ben Sam Kim Ivy Ada Ari Bo Jo".split()
)
Capture = pytest.CaptureFixture[str]


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
        ("home 2a01:e0a:1f2:3b40::1", "public-ip"),
        ("contact jane.doe@mail.example-corp.fr", "email"),
        ("author jane.doe+noreply@mail.example-corp.fr", "email"),
        ("author noreply@family-domain.fr", "email"),
        ("call +33 6 12 34 56 78", "phone"),
        ("call +1-202-555-0143", "phone"),
        ("call 06 12 34 56 78", "phone"),
        ("call 0612345678", "phone"),
        ("see https://myhome.example-corp.fr/api", "url"),
        ("see http://user:pw@nas.lan:8080/x", "url"),
        ("wan http://82.65.12.34:8123/api", "url"),
        ("wan http://[2a01:e0a::1]:8123", "url"),
        ("ws wss://myhome.duckdns.org/api/websocket", "url"),
        ("cam rtsp://cam.family-domain.net/live", "url"),
        ("broker mqtt://broker.family-domain.net:1883", "url"),
        ("idn https://maison-dupré.fr", "url"),
        ("cd /home/alice/projects", "home-path"),
        ("open /Users/bob/Library", "home-path"),
        (r"C:\Users\carol\Desktop", "home-path"),
        (r"C:\\Users\\carol\\Desktop", "home-path"),
        ("C:/Users/carol/Desktop", "home-path"),
        ("wsl /mnt/c/Users/alice/x", "home-path"),
        ("silverblue /var/home/alice/x", "home-path"),
        ("usb /run/media/alice/disk", "home-path"),
        ("mac /Volumes/AliceBackup/x", "home-path"),
        ("mac 3c:22:fb:12:34:56", "mac"),
        ("mac 3C-22-FB-12-34-56", "mac"),
        ("cisco a4c1.381a.2b3c", "mac"),
        ('"mac": "A4C1381A2B3C"', "mac"),
        ("ble_address=a4c1381a2b3c", "mac"),
        ("ieee 0x00124b0012a3b4c5", "device-id"),
        ("eui 00:12:4b:00:12:a3:b4:c5", "device-id"),
        ('"latitude": 48.85661', "coordinates"),
        ("lon=2.35222", "coordinates"),
        ("CONF_LATITUDE: 48.85661", "coordinates"),
        ("home_longitude = 2.35222", "coordinates"),
        ("center: [48.85661, 2.35222]", "coordinates"),
    ],
)
def test_generic_findings_detect(text: str, category: str) -> None:
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
        "time 12:34:56, mac-like aa:bb:cc:dd:ee:ff, ratio 1:2:3",
        "author noreply@example.com and 1+me@users.noreply.github.com",
        "bot no-reply@github.com and noreply@github.com",
        "decorator @pytest.fixture and pkg@1.2.3",
        "remote git@github.com:owner/repo.git",
        "docs https://www.home-assistant.io/integrations/ and https://github.com/x/y",
        "local http://homeassistant.local:8123 and http://localhost:8123",
        "test http://api.example.com/v1 and https://foo.test",
        "app http://supervisor/core/api and http://homeassistant:8123/",
        "template http://{host}:{port}/ and http://$HOST/ and http://%s/",
        "literal http://[fe80::1]/ and http://127.0.0.1:8123/ and http://192.0.2.1/",
        "resolver https://1.1.1.1/dns-query and file:///etc/hosts",
        "build 20240101 and +3 votes and timestamp +0100",
        "count 123456789",
        "runner /home/runner/work, /home/user/app and /Users/username/x",
        "devcontainer /home/vscode/.cache and ~/home/x and ./home/x",
        "media /media/recordings/cam.mp4 and /config/www",
        "placeholder aa:bb:cc:dd:ee:ff and 00:00:5e:00:53:01",
        "sha a4c1381a2b3c and commit 1234567890ab",
        "zigbee 0x0000000000000000 and 0x0123456789abcdef",
        '"latitude": 32.87336, "longitude": -117.22743',
        "latitude: 0.000 and ratio lat: 1.5 and flat: 2.345",
        "point [0.00000, 0.00000] and range [123.45678, 2.12345]",
    ],
)
def test_generic_findings_ignore(text: str) -> None:
    assert privacy.generic_findings(text, ALLOWED) == []


def test_extra_allowed_domain() -> None:
    assert privacy.generic_findings("https://api.vendor.io/x", ("vendor.io",)) == []


def test_generic_findings_stay_fast_on_hostile_lines() -> None:
    lines = [
        "a" * 200_000 + "@",
        "1." * 100_000,
        "+1 " * 70_000,
        ("+1" + "2" * 40 + " ") * 20_000,
        "/home/" * 40_000,
        "0a:" * 70_000,
        "lat=" * 50_000,
        "http://" + "a" * 200_000,
        "[1.123456, " * 50_000,
        "f:" * 100_000,
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


def test_denylist_matching() -> None:
    denylist = privacy.Denylist(
        "# comment\n\nBluefinch\nrue des Lilas\nzorb.example-corp.fr\nØrsted Lane\n"
    )
    assert denylist
    assert denylist.terms == ["Bluefinch", "rue des Lilas", "zorb.example-corp.fr", "Ørsted Lane"]
    assert denylist.matches("Hello BLUEFINCH!")
    assert denylist.matches("bluefínch with an accent")
    assert denylist.matches("lives at Rue  des\tlilas")
    assert denylist.matches("slug rue_des_lilas and rue-des-lilas")
    assert denylist.matches("https://zorb.example-corp.fr/x")
    assert denylist.matches("orsted_lane")
    assert denylist.matches("sensor.bluefinch_door")
    assert not denylist.matches("bluefinches are birds")
    assert not denylist.matches("superbluefinch")
    assert not privacy.Denylist("")
    assert not privacy.Denylist("").matches("anything")
    assert not privacy.Denylist("").matches_binary(b"anything")
    assert privacy.Denylist("").matching_lines("anything") == []


def test_denylist_matching_lines_spans_line_breaks() -> None:
    denylist = privacy.Denylist("rue des Lilas")
    text = "one\nwe live rue des\nLilas now\nrue des lilas, rue des lilas\n"
    assert denylist.matching_lines(text) == [2, 4]


def test_denylist_matching_lines_is_linear() -> None:
    denylist = privacy.Denylist("Bluefinch")
    start = time.perf_counter()
    assert len(denylist.matching_lines("bluefinch\n" * 200_000)) == 200_000
    assert denylist.matching_lines("bluefinch " * 500_000) == [1]
    assert time.perf_counter() - start < 5


def test_denylist_in_binary_content() -> None:
    denylist = privacy.Denylist(f"Bluefinch\n{SHORT_NAMES}")
    assert denylist.matches_binary(b"\x00\x01Artist\x00Bluefinch\x00")
    assert denylist.matches_binary(b"\x00<dc:title>Leo on the sofa</dc:title>")
    assert denylist.matches_binary(b"\xff\xfe" + "Bluefinch".encode("utf-16-le"))
    assert not denylist.matches_binary(b"\x00IDATxd%Leo#q\x00")
    assert not denylist.matches_binary(b"\x00Leo\x00")


def test_short_terms_do_not_match_random_binary_content() -> None:
    denylist = privacy.Denylist(SHORT_NAMES)
    generator = random.Random(1)
    blobs = [generator.randbytes(200_000) for _ in range(50)]
    assert not any(denylist.matches_binary(blob) for blob in blobs)


def test_redact_path_hides_every_spelling() -> None:
    denylist = privacy.Denylist("Bluefinch\nrue des Lilas")
    assert denylist.redact_path("docs/BLUEFINCH/notes.md") == "docs/[redacted]/notes.md"
    assert denylist.redact_path("a/rue_des_lilas.yaml") == "a/[redacted]"
    assert denylist.redact_path("rue/des/lilas.md") == "[redacted path]"
    assert denylist.redact_path("docs/ok.md") == "docs/ok.md"


def test_mask_values_cover_spelling_variants() -> None:
    denylist = privacy.Denylist("Rue des Lilas\nÉté\nZoé\nab")
    masks = list(privacy.mask_terms(denylist))
    values = {line.removeprefix("::add-mask::") for line in masks}
    assert {"Rue des Lilas", "rue des lilas", "RUE DES LILAS", "rue_des_lilas"} <= values
    assert {"Rue-des-Lilas", "rue.des.lilas", "Été", "ete", "Ete", "ETE"} <= values
    assert {"Zoé", "zoe", "Zoe", "ZOE"} <= values
    assert "ab" not in values
    assert masks == sorted(masks)


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


def make_check(
    repo: Repo | None, denylist: str = "Bluefinch", exclude: tuple[str, ...] = ()
) -> privacy.PrivacyCheck:
    root = repo.root if repo else Path()
    return privacy.PrivacyCheck(root, privacy.Denylist(denylist), (), exclude, Reporter("Privacy"))


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


def test_check_files_warns_about_files_too_large_to_scan(
    repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 10)
    repo.write("big.txt", "x" * 11)
    check = make_check(repo)
    check.check_files(["big.txt", "missing.txt"])
    out = capsys.readouterr().out
    assert check.reporter.count == 0
    assert "::warning::big.txt: larger than 10 bytes, not scanned." in out
    assert "missing.txt" not in out


def test_pragma_on_one_line_does_not_cover_the_file(repo: Repo, capsys: Capture) -> None:
    repo.write("a.py", "x = '10.0.0.2'  # ci-allow: private-ip\ny = '10.0.0.3'\n")
    check = make_check(repo)
    check.check_files(["a.py"])
    assert check.reporter.count == 1
    assert "a.py:2: possible personal data (private-ip)" in capsys.readouterr().out


def test_denylist_ignores_exclusions_and_pragmas(repo: Repo, capsys: Capture) -> None:
    repo.write("fixtures/data.txt", "Bluefinch  # ci-allow: private-ip\n")
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(["fixtures/data.txt"])
    assert check.reporter.count == 1
    assert "denylisted term" in capsys.readouterr().out


def test_denylist_matches_terms_wrapped_over_lines(repo: Repo, capsys: Capture) -> None:
    repo.write("notes.md", "We meet at rue des\nLilas, then rue_des_lilas.\n")
    check = make_check(repo, denylist="rue des Lilas")
    check.check_files(["notes.md"])
    assert check.reporter.count == 2
    out = capsys.readouterr().out
    assert "notes.md:1: denylisted term." in out
    assert "notes.md:2: denylisted term." in out


def test_check_changes(repo: Repo, capsys: Capture) -> None:
    repo.write("notes.md", "kept 10.0.0.2\n")
    repo.write("image.bin", b"\0 Artist: Bluefinch \0")
    repo.write("big.txt", "x")
    repo.commit()
    blob = repo.git("rev-parse", "HEAD:image.bin").strip()
    text_blob = repo.git("rev-parse", "HEAD:notes.md").strip()
    big_blob = repo.git("rev-parse", "HEAD:big.txt").strip()
    sha, bot = "a" * 40, "b" * 40
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_changes(
        [
            Change(
                sha,
                "notes.md",
                text_blob,
                (
                    (1, "kept 10.0.0.2"),
                    (2, "removed 10.0.0.3"),
                    (3, "ask Bluefinch"),
                    (4, "10.0.0.4  # ci-allow: private-ip"),
                    (5, "token  # gitleaks:allow"),
                ),
            ),
            Change(sha, "docs/bluefinch.md", text_blob, ((1, "ok"),)),
            Change(sha, "docs/bluefinch.md", "", ()),
            Change(sha, "fixtures/data.txt", text_blob, ((1, "10.0.0.5"),)),
            Change(sha, "LICENSE", text_blob, ((1, "https://nas.example-corp.fr"),)),
            Change(sha, "image.bin", blob, ()),
            Change(sha, "huge.bin", "c" * 40, ()),
            Change(bot, "requirements.txt", text_blob, ((1, "x==1  # https://pkgs.vendor.io"),)),
        ],
        exempt={bot},
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert (
        "Commit aaaaaaaaaaaa: notes.md:2: an added line may contain personal data (private-ip)"
        in out
    )
    assert "Commit aaaaaaaaaaaa: notes.md:3: an added line has a denylisted term." in out
    assert "Commit aaaaaaaaaaaa: notes.md:5: gitleaks:allow hides the line" in out
    assert out.count("Commit aaaaaaaaaaaa: a file path contains a denylisted term.") == 1
    assert "Commit aaaaaaaaaaaa: image.bin: binary content contains a denylisted term." in out
    assert "::warning::Commit aaaaaaaaaaaa: huge.bin: larger than" in out
    assert big_blob
    assert "bluefinch" not in out.lower()


def test_check_changes_reads_utf16_files_whole(repo: Repo, capsys: Capture) -> None:
    repo.write("notes.txt", codecs.BOM_UTF16_LE + "ok\nhost 10.0.0.2\n".encode("utf-16-le"))
    repo.commit()
    blob = repo.git("rev-parse", "HEAD:notes.txt").strip()
    repo.write("notes.txt", "ok\n")
    check = make_check(repo)
    check.check_changes([Change("a" * 40, "notes.txt", blob, ((1, "garbled"),))], set())
    assert check.reporter.count == 1
    assert "notes.txt:2: an added line may contain personal data" in capsys.readouterr().out


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
            commit(author_email="noreply@family-domain.fr"),
            commit(committer_email="1+bluefinch@users.noreply.github.com"),
            commit(message="fix: thanks bluefinch"),
            commit(message="docs: see https://nas.example-corp.fr"),
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
            commit(message="docs: see https://nas.example-corp.fr"),
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


def run_main(repo: Repo, monkeypatch: pytest.MonkeyPatch, denylist: str | None, *args: str) -> int:
    if denylist is None:
        monkeypatch.delenv("PRIVACY_DENYLIST", raising=False)
    else:
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
    assert "Privacy: no problem found." in out


def test_main_mask_only(repo: Repo, monkeypatch: pytest.MonkeyPatch, capsys: Capture) -> None:
    assert run_main(repo, monkeypatch, "Bluefinch", "--mask-only") == 0
    out = capsys.readouterr().out
    assert "::add-mask::BLUEFINCH" in out
    assert "Privacy" not in out


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
    assert "PRIVACY_DENYLIST is empty" in capsys.readouterr().out

    assert run_main(repo, monkeypatch, "", "--require-denylist", "false") == 0

    event(pr_event(head, head, fork=True))
    assert run_main(repo, monkeypatch, None) == 1
    assert "not available to pull requests from forks" in capsys.readouterr().out
    assert run_main(repo, monkeypatch, None, "--require-denylist", "false") == 0


def test_random_bytes_are_binary() -> None:
    assert privacy.decode_text(b"\0" + os.urandom(100)) is None
