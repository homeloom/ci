"""Tests for the privacy check."""

from __future__ import annotations

import time

import pytest

from ci_checks import privacy
from ci_checks._common import Addition, Commit, PullRequest, Reporter
from helpers import NOREPLY, Repo, pr_event

ALLOWED = privacy.DEFAULT_ALLOWED_DOMAINS
DEPENDABOT = "49699333+dependabot[bot]@users.noreply.github.com"
APACHE_LICENSE = """
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS.
"""


@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("host = '10.1.2.3'", "private-ip"),
        ("gateway 192.168.1.1/24", "private-ip"),
        ("peer 172.20.0.5", "private-ip"),
        ("tailnet 100.100.1.1", "private-ip"),
        ("prefix fd12:3456:789a::1", "private-ip"),
        ("contact jane.doe@mail.example-corp.fr", "email"),
        ("call +33 6 12 34 56 78", "phone"),
        ("call +1-202-555-0143", "phone"),
        ("call 06 12 34 56 78", "phone"),
        ("call 0612345678", "phone"),
        ("see https://myhome.example-corp.fr/api", "url"),
        ("see http://user:pw@nas.lan:8080/x", "url"),
        ("cd /home/alice/projects", "home-path"),
        ("open /Users/bob/Library", "home-path"),
        (r"C:\Users\carol\Desktop", "home-path"),
        (r"C:\\Users\\carol\\Desktop", "home-path"),
        ("mac 3c:22:fb:12:34:56", "mac"),
        ("mac 3C-22-FB-12-34-56", "mac"),
        ("ieee 0x00124b0012a3b4c5", "device-id"),
        ("eui 00:12:4b:00:12:a3:b4:c5", "device-id"),
        ('"latitude": 48.85661', "coordinates"),
        ("lon=2.35222", "coordinates"),
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
        "author noreply@example.com and 1+me@users.noreply.github.com",
        "bot no-reply@service.io, noreply@vendor.io and do-not-reply@vendor.io",
        "decorator @pytest.fixture and pkg@1.2.3",
        "remote git@github.com:owner/repo.git",
        "docs https://www.home-assistant.io/integrations/ and https://github.com/x/y",
        "local http://homeassistant.local:8123 and http://localhost:8123",
        "test http://api.example.com/v1 and https://foo.test",
        "app http://supervisor/core/api and http://homeassistant:8123/",
        "template http://{host}:{port}/ and http://$HOST/ and http://%s/",
        "literal http://[fe80::1]/ and http://127.0.0.1:8123/",
        "build 20240101 and +3 votes and timestamp +0100",
        "count 123456789",
        "runner /home/runner/work, /home/user/app and /Users/username/x",
        "devcontainer /home/vscode/.cache and ~/home/x and ./home/x",
        "placeholder aa:bb:cc:dd:ee:ff and 00:00:5e:00:53:01",
        "zigbee 0x0000000000000000 and 0x0123456789abcdef",
        "time 12:34:56",
        '"latitude": 32.87336, "longitude": -117.22743',
        "ratio lat: 1.5",
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
        "/home/" * 40_000,
        "0a:" * 70_000,
        "lat=" * 50_000,
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
        ("no-reply@vendor.io", True),
        ("donotreply@vendor.io", True),
        ("build.noreply@vendor.io", True),
        ("someone@example.org", True),
        ("someone@vendor.io", False),
        ("noreplyfan@vendor.io", False),
        ("not-an-address", False),
    ],
)
def test_is_noreply_email(address: str, expected: bool) -> None:
    assert privacy.is_noreply_email(address) is expected


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
    assert privacy.Denylist("").matching_lines("anything") == []


def test_denylist_matching_lines_spans_line_breaks() -> None:
    denylist = privacy.Denylist("rue des Lilas")
    assert denylist.matching_lines("one\nwe live rue des\nLilas now\nrue des lilas\n") == [2, 4]


def test_redact_path_hides_every_spelling() -> None:
    denylist = privacy.Denylist("Bluefinch\nrue des Lilas")
    assert denylist.redact_path("docs/BLUEFINCH/notes.md") == "docs/[redacted]/notes.md"
    assert denylist.redact_path("a/rue_des_lilas.yaml") == "a/[redacted]"
    assert denylist.redact_path("rue/des/lilas.md") == "[redacted path]"
    assert denylist.redact_path("docs/ok.md") == "docs/ok.md"


def test_mask_values_cover_spelling_variants() -> None:
    denylist = privacy.Denylist("Rue des Lilas\nÉté\nab")
    masks = list(privacy.mask_terms(denylist))
    values = {line.removeprefix("::add-mask::") for line in masks}
    assert {"Rue des Lilas", "rue des lilas", "RUE DES LILAS", "rue_des_lilas"} <= values
    assert {"Rue-des-Lilas", "Été", "ete"} <= values
    assert "ab" not in values
    assert masks == sorted(masks)


def test_is_license_file() -> None:
    assert privacy.is_license_file("LICENSE")
    assert privacy.is_license_file("vendor/licence.txt")
    assert privacy.is_license_file("NOTICE.md")
    assert not privacy.is_license_file("docs/licensing.md")


def make_check(repo: Repo | None, denylist: str = "Bluefinch", exclude=()) -> privacy.PrivacyCheck:
    root = repo.root if repo else None
    return privacy.PrivacyCheck(root, privacy.Denylist(denylist), (), exclude, Reporter("Privacy"))


def test_check_files(repo: Repo, capsys) -> None:
    repo.write("ok.py", "x = 1\n")
    repo.write("leak.py", "a = 1\nowner = 'bluefinch'\nhost = '10.0.0.2'\n")
    repo.write("allowed.py", "host = '10.0.0.2'  # ci-allow: private-ip\n")
    repo.write("fixtures/data.txt", "host 10.0.0.2\n")
    repo.write("LICENSE", APACHE_LICENSE)
    repo.write("image.bin", "\0\0 BlueFinch \0")
    repo.commit()
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(
        ["ok.py", "leak.py", "allowed.py", "fixtures/data.txt", "LICENSE", "image.bin"]
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 3
    assert "file=leak.py,line=2::leak.py:2: denylisted term." in out
    assert "file=leak.py,line=3::leak.py:3: possible personal data (private-ip)" in out
    assert "file=image.bin,line=1::image.bin:1: denylisted term." in out
    assert "bluefinch" not in out.lower()


def test_check_files_redacts_denylisted_paths(repo: Repo, capsys) -> None:
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


def test_check_files_follows_symlink_targets(repo: Repo, capsys) -> None:
    (repo.root / "config").symlink_to("/home/alice/bluefinch/config")
    (repo.root / "data").symlink_to("data-dir")
    check = make_check(repo)
    check.check_files(["config", "data"])
    out = capsys.readouterr().out
    assert check.reporter.count == 2
    assert "config: the link target contains a denylisted term." in out
    assert "config: the link target may contain personal data (home-path)." in out


def test_check_files_warns_about_files_too_large_to_scan(repo: Repo, monkeypatch, capsys) -> None:
    monkeypatch.setattr(privacy, "MAX_SCAN_BYTES", 10)
    repo.write("big.txt", "x" * 11)
    check = make_check(repo)
    check.check_files(["big.txt", "missing.txt"])
    out = capsys.readouterr().out
    assert check.reporter.count == 0
    assert "::warning::big.txt: larger than 10 bytes, not scanned." in out
    assert "missing.txt" not in out


def test_denylist_ignores_exclusions_and_pragmas(repo: Repo, capsys) -> None:
    repo.write("fixtures/data.txt", "Bluefinch  # ci-allow: private-ip\n")
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(["fixtures/data.txt"])
    assert check.reporter.count == 1
    assert "denylisted term" in capsys.readouterr().out


def test_denylist_matches_terms_wrapped_over_lines(repo: Repo, capsys) -> None:
    repo.write("notes.md", "We meet at rue des\nLilas, then rue_des_lilas.\n")
    check = make_check(repo, denylist="rue des Lilas")
    check.check_files(["notes.md"])
    assert check.reporter.count == 2
    out = capsys.readouterr().out
    assert "notes.md:1: denylisted term." in out
    assert "notes.md:2: denylisted term." in out


def addition(text: str, path: str = "notes.md", line: int = 1, sha: str = "a" * 40) -> Addition:
    return Addition(sha, path, line, text)


def test_check_additions(repo: Repo, capsys) -> None:
    repo.write("notes.md", "kept 10.0.0.2\n")
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_additions(
        [
            addition("kept 10.0.0.2"),
            addition("removed 10.0.0.3", line=2),
            addition("ask Bluefinch", line=3),
            addition("ok", path="docs/bluefinch.md"),
            addition("10.0.0.4  # ci-allow: private-ip", line=4),
            addition("10.0.0.5", path="fixtures/data.txt"),
            addition("https://nas.example-corp.fr", path="LICENSE"),
            addition("Signed-off-by: x <support@github.com>", sha="b" * 40),
        ],
        bots={"b" * 40},
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 3
    assert (
        "Commit aaaaaaaaaaaa: notes.md: an added line may contain personal data (private-ip)" in out
    )
    assert "Commit aaaaaaaaaaaa: notes.md: an added line has a denylisted term." in out
    assert "Commit aaaaaaaaaaaa: a file path contains a denylisted term." in out
    assert "bluefinch" not in out.lower()


def commit(**changes) -> Commit:
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


def test_check_identities(capsys) -> None:
    check = make_check(None)
    check.check_identities(
        [
            commit(),
            commit(author_name="Bluefinch"),
            commit(author_email="someone@vendor.io"),
            commit(committer_email="1+bluefinch@users.noreply.github.com"),
            commit(message="fix: thanks bluefinch"),
            commit(message="docs: see https://nas.example-corp.fr"),
        ]
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert "author contains a denylisted term" in out
    assert "author e-mail is not a noreply address" in out
    assert "committer contains a denylisted term" in out
    assert "message contains a denylisted term" in out
    assert "vendor.io" not in out


def test_check_messages(capsys) -> None:
    check = make_check(None)
    check.check_messages(
        [
            commit(),
            commit(message="docs: see https://nas.example-corp.fr"),
            commit(
                message=(
                    "chore(deps): bump x\n\nSigned-off-by: dependabot[bot] <support@github.com>"
                ),
                author_name="dependabot[bot]",
                author_email=DEPENDABOT,
            ),
        ]
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 1
    assert "message may contain personal data (url)" in out


def pr(**changes) -> PullRequest:
    fields = {
        "title": "feat: add a thing",
        "body": "Adds a thing.",
        "head_ref": "feature",
        "author_is_bot": False,
        "from_fork": False,
    }
    fields.update(changes)
    return PullRequest(**fields)


def test_check_pull_request(capsys) -> None:
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


def test_bot_body_skips_generic_patterns_but_not_denylist() -> None:
    check = make_check(None)
    check.check_pull_request(pr(author_is_bot=True, body="see https://docs.vendor.io"))
    assert check.reporter.count == 0
    check.check_pull_request(pr(author_is_bot=True, body="thanks Bluefinch"))
    assert check.reporter.count == 1


def run_main(repo: Repo, monkeypatch, denylist: str | None, *args: str) -> int:
    if denylist is None:
        monkeypatch.delenv("PRIVACY_DENYLIST", raising=False)
    else:
        monkeypatch.setenv("PRIVACY_DENYLIST", denylist)
    return privacy.main(["--root", str(repo.root), *args])


def test_main_clean_push(repo: Repo, monkeypatch, event, capsys) -> None:
    repo.write("README.md", "# Demo\n\nSee https://docs.vendor.io.\n")
    repo.write("LICENSE", APACHE_LICENSE)
    repo.commit()
    event({})
    assert run_main(repo, monkeypatch, "Bluefinch", "--allowed-domains", "vendor.io") == 0
    out = capsys.readouterr().out
    assert out.startswith("::add-mask::")
    assert "::add-mask::Bluefinch" in out
    assert "Privacy: no problem found." in out


def test_main_pull_request(repo: Repo, monkeypatch, event, capsys) -> None:
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


def test_main_finds_lines_added_then_removed(repo: Repo, monkeypatch, event, capsys) -> None:
    repo.write("README.md", "# Demo\n")
    base = repo.commit()
    repo.write("README.md", "# Demo\nAsk BLUEFINCH at 10.0.0.2.\n")
    leak = repo.commit("docs: add contact")
    repo.write("README.md", "# Demo\n")
    head = repo.commit("docs: remove contact")
    event(pr_event(base, head))
    assert run_main(repo, monkeypatch, "Bluefinch") == 1
    out = capsys.readouterr().out
    assert f"Commit {leak[:12]}: README.md: an added line has a denylisted term." in out
    assert f"Commit {leak[:12]}: README.md: an added line may contain personal data" in out
    assert "bluefinch" not in out.lower().replace("::add-mask::bluefinch", "")


def test_main_exempts_dependabot_commits(repo: Repo, monkeypatch, event, capsys) -> None:
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
    event(pr_event(base, head, bot=True, body="Release notes at https://pkgs.vendor.io/x"))
    assert run_main(repo, monkeypatch, "Bluefinch") == 0
    assert "Privacy: no problem found." in capsys.readouterr().out


def test_main_rejects_shallow_clones(repo: Repo, monkeypatch, event, tmp_path, capsys) -> None:
    repo.write("README.md", "# Demo\n")
    repo.commit()
    repo.commit()
    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    event({})
    monkeypatch.setenv("PRIVACY_DENYLIST", "Bluefinch")
    assert privacy.main(["--root", str(clone)]) == 1
    assert "fetch-depth: 0" in capsys.readouterr().err


def test_main_missing_denylist(repo: Repo, monkeypatch, event, capsys) -> None:
    repo.write("README.md", "# Demo\n")
    head = repo.commit()
    event({})
    assert run_main(repo, monkeypatch, None) == 1
    assert "PRIVACY_DENYLIST is empty" in capsys.readouterr().out

    assert run_main(repo, monkeypatch, "", "--require-denylist", "false") == 0

    event(pr_event(head, head, fork=True))
    assert run_main(repo, monkeypatch, None) == 0
    assert "not available to forks" in capsys.readouterr().out
