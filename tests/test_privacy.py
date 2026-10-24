"""Tests for the privacy check."""

from __future__ import annotations

import pytest

from ci_checks import privacy
from ci_checks._common import Commit, PullRequest, Reporter
from helpers import NOREPLY, Repo, pr_event

ALLOWED = privacy.DEFAULT_ALLOWED_DOMAINS


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
        ("mac 3c:22:fb:12:34:56", "mac"),
        ("mac 3C-22-FB-12-34-56", "mac"),
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
        "bot no-reply@service.io and noreply@vendor.io",
        "decorator @pytest.fixture and pkg@1.2.3",
        "docs https://www.home-assistant.io/integrations/ and https://github.com/x/y",
        "local http://homeassistant.local:8123 and http://localhost:8123",
        "test http://api.example.com/v1 and https://foo.test",
        "template http://{host}:{port}/ and http://$HOST/ and http://%s/",
        "literal http://[fe80::1]/ and http://127.0.0.1:8123/",
        "build 20240101 and +3 votes and timestamp +0100",
        "count 123456789",
        "runner /home/runner/work and /home/user/app and /Users/username/x",
        "placeholder aa:bb:cc:dd:ee:ff and 00:00:5e:00:53:01",
        "time 12:34:56",
        '"latitude": 32.87336, "longitude": -117.22743',
        "ratio lat: 1.5",
    ],
)
def test_generic_findings_ignore(text: str) -> None:
    assert privacy.generic_findings(text, ALLOWED) == []


def test_extra_allowed_domain() -> None:
    assert privacy.generic_findings("https://api.vendor.io/x", ("vendor.io",)) == []


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("noreply@github.com", True),
        ("41898282+github-actions[bot]@users.noreply.github.com", True),
        ("no-reply@vendor.io", True),
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
    denylist = privacy.Denylist("# comment\n\nBluefinch\nrue des Lilas\nzorb.example-corp.fr\n")
    assert denylist
    assert denylist.terms == ["Bluefinch", "rue des Lilas", "zorb.example-corp.fr"]
    assert denylist.matches("Hello BLUEFINCH!")
    assert denylist.matches("bluefínch with an accent")
    assert denylist.matches("lives at Rue  des\tlilas")
    assert denylist.matches("https://zorb.example-corp.fr/x")
    assert not denylist.matches("bluefinches are birds")
    assert not denylist.matches("superbluefinch")
    assert not privacy.Denylist("")
    assert not privacy.Denylist("").matches("anything")


def make_check(repo: Repo, denylist: str = "Bluefinch", exclude=()) -> privacy.PrivacyCheck:
    return privacy.PrivacyCheck(
        repo.root, privacy.Denylist(denylist), (), exclude, Reporter("Privacy")
    )


def test_check_files(repo: Repo, capsys) -> None:
    repo.write("ok.py", "x = 1\n")
    repo.write("leak.py", "a = 1\nowner = 'bluefinch'\nhost = '10.0.0.2'\n")
    repo.write("allowed.py", "host = '10.0.0.2'  # ci-allow: private-ip\n")
    repo.write("fixtures/data.txt", "host 10.0.0.2\n")
    repo.write("bluefinch.txt", "x\n")
    repo.write("image.bin", "\0\0")
    repo.commit()
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(["ok.py", "leak.py", "allowed.py", "fixtures/data.txt", "bluefinch.txt"])
    out = capsys.readouterr().out
    assert check.reporter.count == 3
    assert "file=leak.py,line=2::Line contains a denylisted term." in out
    assert "file=leak.py,line=3::Possible personal data (private-ip)" in out
    assert "file=bluefinch.txt::File path contains a denylisted term." in out
    assert "bluefinch" not in out.replace("file=bluefinch.txt", "")


def test_denylist_ignores_exclusions_and_pragmas(repo: Repo, capsys) -> None:
    repo.write("fixtures/data.txt", "Bluefinch  # ci-allow: private-ip\n")
    check = make_check(repo, exclude=("fixtures/*",))
    check.check_files(["fixtures/data.txt"])
    assert check.reporter.count == 1
    assert "denylisted term" in capsys.readouterr().out


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


def test_check_commits(capsys) -> None:
    check = privacy.PrivacyCheck(None, privacy.Denylist("Bluefinch"), (), (), Reporter("Privacy"))
    check.check_commits(
        [
            commit(),
            commit(author_name="Bluefinch"),
            commit(author_email="someone@vendor.io"),
            commit(message="fix: thanks bluefinch"),
            commit(message="docs: see https://nas.example-corp.fr"),
        ]
    )
    out = capsys.readouterr().out
    assert check.reporter.count == 4
    assert "author contains a denylisted term" in out
    assert "author e-mail is not a noreply address" in out
    assert "message contains a denylisted term" in out
    assert "message may contain personal data (url)" in out
    assert "vendor.io" not in out


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
    check = privacy.PrivacyCheck(None, privacy.Denylist("Bluefinch"), (), (), Reporter("P"))
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
    check = privacy.PrivacyCheck(None, privacy.Denylist("Bluefinch"), (), (), Reporter("P"))
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
    repo.commit()
    event({})
    assert run_main(repo, monkeypatch, "Bluefinch", "--allowed-domains", "vendor.io") == 0
    out = capsys.readouterr().out
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
    assert "file=notes.md,line=1::Line contains a denylisted term." in out
    assert "Pull request body may contain personal data (private-ip)." in out


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
