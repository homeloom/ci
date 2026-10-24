"""Tests for the language check."""

from __future__ import annotations

from pathlib import Path

import pytest

from ci_checks import english
from ci_checks._common import Reporter
from helpers import DEPENDABOT, EventWriter, Repo, pr_event

Capture = pytest.CaptureFixture[str]


@pytest.mark.parametrize(
    "text",
    [
        "# Récupère la valeur du capteur",
        "Mise à jour du fichier",
        "Erreur",
        "Le capteur est hors ligne",
        "C\u2019est une tâche ménagère",
        "Il faut vérifier",
        "Ce que les gens pour la plupart",
        "fix: correction du calcul de la temperature",
        "feat: gestion des volets roulants",
        "# Verifie si la connexion est active",
        "# Gerer les erreurs reseau",
        "la mise a jour des donnees",
        "Les valeurs par defaut",
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
        "Set la and le in the config",
        "Use des_valeur_2 or le_capteur_id as keys",
        "A modifier, a correction, a nouveau riche",
        "Supported languages: de, en, fr",
        "font-family: sans-serif",
        "The pendant light in the salon",
        "Smith et al. 2020",
        "It verifies the digests and modifies the temps",
    ],
)
def test_english_accepted(text: str) -> None:
    assert not english.looks_french(text)


def test_allowed_words() -> None:
    assert english.looks_french("Weather from Météo-France")
    assert not english.looks_french("Weather from Météo-France", frozenset({"météo"}))


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("custom_components/demo/translations/fr.json", True),
        ("custom_components/demo/translations/en.json", False),
        ("custom_components/demo/translations/en-GB.json", False),
        ("translations/de.json", True),
        ("demo/translations/fr.yaml", True),
        ("translations/fr.yml", True),
        ("demo/translations/en.yaml", False),
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


def test_check_files(repo: Repo, capsys: Capture) -> None:
    repo.write("a.py", "# Fetch the value\n# Récupère la valeur\n")
    repo.write("b.py", "x = 'Récupère la valeur'  # ci-allow: french\n")
    repo.write("custom_components/demo/translations/fr.json", '{"title": "Le capteur"}\n')
    reporter = Reporter("English")
    english.check_files(
        repo.root, ["a.py", "b.py", "custom_components/demo/translations/fr.json"], reporter
    )
    assert reporter.count == 1
    assert "file=a.py,line=2::Line looks French (or another language" in capsys.readouterr().out


def test_check_messages(repo: Repo, capsys: Capture) -> None:
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


def test_dependabot_commits_are_skipped(repo: Repo) -> None:
    base = repo.commit("chore: initial")
    head = repo.commit(
        "chore(deps): bump x\n\nNotes de version : la mise à jour",
        name="dependabot[bot]",
        email=DEPENDABOT,
    )
    reporter = Reporter("English")
    english.check_messages(repo.root, pr_event(base, head, login="dependabot[bot]"), reporter)
    assert reporter.count == 0
    # A bot address in a pull request that the bot did not open counts for nothing.
    english.check_messages(repo.root, pr_event(base, head), reporter)
    assert reporter.count == 1


def test_dependabot_body_is_skipped(repo: Repo) -> None:
    head = repo.commit("chore: initial")
    reporter = Reporter("English")
    body = "Notes : la mise à jour"
    english.check_messages(
        repo.root, pr_event(head, head, body=body, login="dependabot[bot]"), reporter
    )
    assert reporter.count == 0
    english.check_messages(repo.root, pr_event(head, head, body=body, login="other[bot]"), reporter)
    assert reporter.count == 1


def test_main(repo: Repo, event: EventWriter, capsys: Capture) -> None:
    repo.write("a.py", "# Fetch the value\n")
    repo.write("vendor/b.py", "# Récupère la valeur\n")
    repo.write("manifest.json", '{"name": "Météo-France"}\n')
    repo.commit("feat: add a")
    event({})
    root = ["--root", str(repo.root)]
    assert english.main([*root, "--exclude", "vendor/*", "--allowed-words", "Météo"]) == 0
    assert english.main(root) == 1
    assert "English: 2 problem(s) found." in capsys.readouterr().out


def test_main_rejects_shallow_clones(
    repo: Repo, event: EventWriter, tmp_path: Path, capsys: Capture
) -> None:
    repo.commit()
    repo.commit()
    clone = tmp_path / "shallow"
    repo.git("clone", "--quiet", "--depth=1", f"file://{repo.root}", str(clone))
    event({})
    assert english.main(["--root", str(clone)]) == 1
    assert "fetch-depth: 0" in capsys.readouterr().err
