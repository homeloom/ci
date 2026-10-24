"""Tests for the language check."""

from __future__ import annotations

import pytest

from ci_checks import english
from ci_checks._common import Reporter
from helpers import Repo, pr_event


@pytest.mark.parametrize(
    "text",
    [
        "# Récupère la valeur du capteur",
        "Mise à jour du fichier",
        "Erreur",
        "Le capteur est hors ligne",
        "C\u2019est une tâche ménagère",
        "Il faut vérifier",
    ],
)
def test_french_detected(text: str) -> None:
    assert english.looks_french(text)


@pytest.mark.parametrize(
    "text",
    [
        "Fetch the sensor value",
        "A café in the entrée, a naïve résumé",
        "Les Paul guitar",
        "if x le y: return",
        "Run the tests on par with upstream",
        "",
        "1234 5678",
    ],
)
def test_english_accepted(text: str) -> None:
    assert not english.looks_french(text)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("custom_components/demo/translations/fr.json", True),
        ("custom_components/demo/translations/en.json", False),
        ("custom_components/demo/translations/en-GB.json", False),
        ("translations/de.json", True),
        ("app/locales/fr/messages.json", True),
        ("app/locales/en/messages.json", False),
        ("po/fr.po", True),
        ("README.fr.md", True),
        ("docs/guide.pt-BR.md", True),
        ("README.en.md", False),
        ("docs/setup.py.md", False),
        ("src/demo.py", False),
    ],
)
def test_is_translation(path: str, expected: bool) -> None:
    assert english.is_translation(path) is expected


def test_check_files(repo: Repo, capsys) -> None:
    repo.write("a.py", "# Fetch the value\n# Récupère la valeur\n")
    repo.write("b.py", "x = 'Récupère la valeur'  # ci-allow: french\n")
    repo.write("custom_components/demo/translations/fr.json", '{"title": "Le capteur"}\n')
    reporter = Reporter("English")
    english.check_files(
        repo.root, ["a.py", "b.py", "custom_components/demo/translations/fr.json"], reporter
    )
    assert reporter.count == 1
    assert "file=a.py,line=2::Line looks French." in capsys.readouterr().out


def test_check_messages(repo: Repo, capsys) -> None:
    base = repo.commit("chore: initial")
    repo.commit("fix: corrige le capteur")
    head = repo.commit("feat: add a sensor")
    reporter = Reporter("English")
    english.check_messages(
        repo.root,
        pr_event(base, head, title="feat: ajoute un capteur", body="Ajoute la valeur du capteur."),
        reporter,
    )
    out = capsys.readouterr().out
    assert reporter.count == 3
    assert "message looks French" in out
    assert "Pull request title looks French." in out
    assert "Pull request body looks French." in out


def test_bot_body_is_skipped(repo: Repo) -> None:
    head = repo.commit("chore: initial")
    reporter = Reporter("English")
    english.check_messages(
        repo.root, pr_event(head, head, body="Notes : la mise à jour", bot=True), reporter
    )
    assert reporter.count == 0


def test_main(repo: Repo, event, capsys) -> None:
    repo.write("a.py", "# Fetch the value\n")
    repo.write("vendor/b.py", "# Récupère la valeur\n")
    repo.commit("feat: add a")
    event({})
    assert english.main(["--root", str(repo.root), "--exclude", "vendor/*"]) == 0
    assert english.main(["--root", str(repo.root)]) == 1
    assert "English: 1 problem(s) found." in capsys.readouterr().out
