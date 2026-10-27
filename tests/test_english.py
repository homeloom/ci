"""Tests for the language check."""

from __future__ import annotations

import unicodedata
from collections.abc import Callable
from pathlib import Path

import pytest

from ci_checks import english
from ci_checks._common import Reporter
from ci_checks.denylist import Denylist
from helpers import DEPENDABOT, EventWriter, Repo, pr_event

Capture = pytest.CaptureFixture[str]


def strip_accents(text: str) -> str:
    """Return text written without accents, as people often type French."""
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(char for char in decomposed if not unicodedata.combining(char))


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
        # Elisions are split, so that the elided word is checked too.
        "fix: gere l'erreur 401",
        "fix: l'utilisateur est deconnecte",
        "fix: unite incorrecte pour l'energie",
        "docs: precise qu'il faut redemarrer",
        "fix: entites desactivees par defaut",
        "feat: ajoutee aux options avancees",
        "fix: options nombreuses et dangereuses",
        "fix: l'API renvoie une liste vide",
        "Lorsqu'on relance, rien ne change",
        # A lowercase word with French accents is French.
        "fix: régression",
        "feat: thème sombre",
        "docs: légère reformulation",
        "# Conversion en degrés Celsius",
        '"name": "Prévisions météo"',
        '"name": "Énergie consommée"',
        # A capitalized accented word counts as one signal.
        "Réparé le bug",
        '"name": "Température de consigne"',
        # French words in capitals are signals.
        "fix: CORRIGE LE CAPTEUR DE TEMPERATURE",
        "# NE PAS SUPPRIMER CETTE LIGNE",
        "# ATTENTION : NE PAS MODIFIER CE FICHIER, IL EST GENERE AUTOMATIQUEMENT",
        '_LOGGER.error("ERREUR DE CONNEXION AU SERVEUR")',
    ],
)
def test_french_detected(text: str) -> None:
    assert english.looks_french(text)


@pytest.mark.parametrize(
    "text",
    [
        "Récupère l'état du thermostat",
        "fix: réponse vide de l'API",
        "feat: traduction des états",
    ],
)
def test_decomposed_accents_are_seen(text: str) -> None:
    assert english.looks_french(unicodedata.normalize("NFD", text))


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
        # Language tags and country codes.
        'DEFAULT_LANGUAGE = "de-DE"',
        '"de-de": "Germany",',
        "en-au",
        'SUPPORTED_REGIONS = ["AU", "DE", "FR"]',
        'REGIONS = ["us", "eu", "il", "au"]',
        # Words in capitals are codes and acronyms.
        "AUX ILS EST SI",
        '"aux": "AUX",',
        'self._source = self.send_command("SI?").removeprefix("SI")',
        "await asyncio.sleep(SECONDE)",
        "BLUEFINCH AVANCE GmbH",
        # English words that are also French.
        "# Build the PKCE code verifier",
        'raise InvalidAuth("Invalid code verifier")',
        "The user chose a device",
        "ONT ont",
        # An accent alone proves nothing: capitalized accented words are names.
        "Zürich",
        "Türkiye",
        "Réunion",
        "Data provided by Météo-France",
        "Côte d'Ivoire",
        '"CI": "Côte d\'Ivoire",',
        '"brand": "Bluéfinch",',
        "Weather data for Zürich, Genève and Réunion",
        # A single accented letter is not a word ("à la carte").
        '"é",',
        "# Matches '/*' and '/**', à la Javadoc",
        # Inside a sentence, a capitalized word is a name, and a word with
        # inner capitals is an identifier.
        '"title": "Waste collection Celle"',
        "Waste collection for Celle and nearby towns",
        "Tickets for the Notre Bluefinch museum",
        "The Ligne Bluefinch sofa sensor",
        "# The socket must be bound before we call ConnectEx().",
        "ov.ConnectEx(conn.fileno(), address)",
        "Serves hors d'oeuvres at 6 pm",
        # Prefixes, slugs, URLs and code are not sentences.
        "The relay must de-energize before the motor reverses.",
        "Models: nous-hermes2, nous-hermes2-mixtral",
        "See https://example.org/de/la/page-de-test for the details.",
        "value_fn=lambda le: le.date",
        "aux = aux[aux_sort]",
        "data = \"(S'V6' S'b'\"",
        "# d'oh, d'oh, the cache was stale",
        "A unique, oblique technique",
        "import xml.etree.ElementTree as ET",
        '"""Provides diagnostics for Aussie Broadband."""',
        '"name": "Horse riding"',
    ],
)
def test_english_accepted(text: str) -> None:
    assert not english.looks_french(text)


def test_allowed_words() -> None:
    # Brand names made of French words, written as the brand writes them.
    assert english.looks_french('"name": "Bien-Être Connect"')
    assert not english.looks_french('"name": "Bien-Être Connect"', frozenset({"bien-être"}))
    assert english.looks_french("Écran's dimmer is supported")
    assert not english.looks_french("Écran's dimmer is supported", frozenset({"écran"}))
    # Inside a sentence, a capitalized word is taken for a name anyway.
    assert not english.looks_french("fix: handle Écran's dimmer")
    # A brand written in lowercase with accents looks like a French word.
    assert english.looks_french("the bluéfinch hub")
    assert not english.looks_french("the bluéfinch hub", frozenset({"bluéfinch"}))


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
        ("po/en.po", False),
        ("README.fr.md", True),
        ("docs/guide.pt-BR.md", True),
        ("README.en.md", False),
        ("docs/setup.py.md", False),
        ("src/demo.py", False),
        ("custom_components/demo/frontend/src/localize/languages/fr.json", True),
        ("custom_components/demo/frontend/src/localize/languages/en.json", False),
        ("i18n/fr.json", True),
        ("locale/fr.json", True),
        ("locale/fr/LC_MESSAGES/messages.po", True),
        ("locale/messages.pot", True),
        ("lang/zh-Hant.json", True),
        ("lang/es-419.yaml", True),
        ("README_fr.md", True),
        ("README-fr.md", True),
        ("README-pt_BR.md", True),
        ("README_en.md", False),
        ("README.ca.md", True),
        ("README.cy.md", True),
        ("docs/fr/index.md", True),
        ("docs/fr/guide/setup.md", True),
        ("docs/de/guide/setup.md", True),
        ("docs/en/index.md", False),
        ("docs/api/index.md", False),
        ("docs/index.md", False),
        # Translation modules are named after their language or sit in its folder.
        ("locales/fr.js", True),
        ("src/locales/fr.ts", True),
        ("app/locales/fr/common.js", True),
        ("frontend/src/locales/fr.mjs", True),
        ("i18n/fr.toml", True),
        ("locales/fr.ini", True),
        ("locales/en.js", False),
        ("app/locales/en-GB/common.js", False),
        ("src/locales/loader.py", False),
        ("i18n/index.ts", False),
        ("docs/fr/conf.py", False),
        ("guide-fr.md", False),
        ("LICENSE", False),
        # Language codes are also folder and file names (Home Assistant OS):
        # a document only counts as a translation next to its English
        # original, and a page under docs/<language>/ only when docs/en/ has it.
        ("docs/os/installation.md", False),
        ("docs/ha/automations.md", False),
        ("docs/it/network.md", False),
        ("docs/fr/faq.md", False),
        ("notes.to.md", False),
        ("requirements.ha.txt", False),
        # Codes that file names more often use for something else, such as
        # ha for Home Assistant, never make a translation, even next to the
        # English original.
        ("README.ha.md", False),
        ("docs/installation.ha.md", False),
        ("README_OS.md", False),
        # A tag in capitals, and any name in capitals with a separator.
        ("README_FR.md", True),
        ("README.FR.md", True),
        ("DOCS_fr.md", True),
        ("DOCS-pt_BR.md", True),
        ("docs/installation_fr.md", False),
        ("Docs_fr.md", False),
    ],
)
def test_is_translation(path: str, expected: bool) -> None:
    assert english.is_translation(path, REPOSITORY_FILES | {path}) is expected


# The English documents that the documents above may translate.
REPOSITORY_FILES = frozenset(
    {
        "README.md",
        "DOCS.md",
        "Docs.md",
        "docs/guide.md",
        "docs/index.md",
        "docs/installation.md",
        "docs/en/index.md",
        "docs/en/guide/setup.md",
    }
)


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


def test_check_files_redacts_denylisted_paths(repo: Repo, capsys: Capture) -> None:
    repo.write("docs/Bluefinch/notes.md", "# Notes\n\nRécupère la valeur du capteur.\n")
    reporter = Reporter("English")
    english.check_files(
        repo.root, ["docs/Bluefinch/notes.md"], reporter, denylist=Denylist("Bluefinch")
    )
    out = capsys.readouterr().out
    assert reporter.count == 1
    assert "::error::docs/[redacted]/notes.md:3: Line looks French" in out
    assert "bluefinch" not in out.lower()


def test_english_ui_text_needs_no_pragma(repo: Repo) -> None:
    # JSON cannot hold a ci-allow comment, so English UI text must pass as it is.
    strings = """{
  "config": {
    "step": {"user": {"title": "Connect to the hub", "data": {"host": "Host"}}},
    "error": {"cannot_connect": "Failed to connect"}
  },
  "selector": {
    "source": {"options": {"aux": "AUX", "hdmi_1": "HDMI 1"}},
    "region": {
      "options": {
        "de-de": "Germany",
        "en-au": "Australia",
        "tr-tr": "Türkiye",
        "ci": "Côte d'Ivoire",
        "re": "Réunion",
        "zurich": "Zürich"
      }
    }
  }
}
"""
    paths = ["custom_components/demo/strings.json", "custom_components/demo/translations/en.json"]
    for path in paths:
        repo.write(path, strings)
    reporter = Reporter("English")
    english.check_files(repo.root, paths, reporter)
    assert reporter.count == 0


def test_french_ui_text_is_reported(repo: Repo, capsys: Capture) -> None:
    # Labels are short and start with a capital, often an accented one.
    repo.write(
        "custom_components/demo/strings.json",
        """{
  "entity": {
    "sensor": {
      "outdoor_temperature": {"name": "Température extérieure"},
      "setpoint": {"name": "Température de consigne"},
      "forecast": {"name": "Prévisions météo"},
      "energy": {"name": "Énergie consommée"},
      "pressure": {"name": "Pression atmosphérique"}
    }
  }
}
""",
    )
    reporter = Reporter("English")
    english.check_files(repo.root, ["custom_components/demo/strings.json"], reporter)
    out = capsys.readouterr().out
    assert reporter.count == 5
    assert [f"line={number}::" in out for number in range(4, 9)] == [True] * 5


def test_translations_need_their_english_original(repo: Repo, capsys: Capture) -> None:
    french = "Copiez le dossier puis redémarrez Home Assistant.\n"
    files = {
        "docs/en/setup.md": "Copy the folder, then restart Home Assistant.\n",
        "docs/fr/setup.md": french,
        "docs/os/install.md": french,
        "README.md": "Copy the folder, then restart Home Assistant.\n",
        "README.fr.md": french,
        "notes.fr.md": french,
        "src/locales/fr.js": 'export default { error: "Impossible de joindre le serveur" };\n',
    }
    for path, content in files.items():
        repo.write(path, content)
    reporter = Reporter("English")
    english.check_files(repo.root, list(files), reporter)
    out = capsys.readouterr().out
    assert reporter.count == 2
    assert "file=docs/os/install.md,line=1::" in out
    assert "file=notes.fr.md,line=1::" in out


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


def test_pragma_in_messages_and_body(repo: Repo) -> None:
    base = repo.commit("chore: initial")
    head = repo.commit("docs: quote the motto\n\nLa vie est belle  ci-allow: french")
    body = "Quotes a motto:\n\n> La vie est belle <!-- ci-allow: french -->"
    reporter = Reporter("English")
    english.check_messages(repo.root, pr_event(base, head, body=body), reporter)
    assert reporter.count == 0


def test_title_in_capitals(repo: Repo, capsys: Capture) -> None:
    # The title check accepts a first word in capitals, as in "fix: MQTT discovery".
    head = repo.commit("chore: initial")
    reporter = Reporter("English")
    title = "fix: CORRIGE LE CAPTEUR DE TEMPERATURE"
    english.check_messages(repo.root, pr_event(head, head, title=title), reporter)
    assert reporter.count == 1
    assert "Pull request title looks French." in capsys.readouterr().out


# Trailers that would look French if they were prose.
CO_AUTHOR = "Co-authored-by: Bluefinch de la Roche du Lac <2+bluefinch@users.noreply.github.com>"
SIGNER = "Signed-off-by: Bluefinch du Pré de la Brume <3+example@users.noreply.github.com>"


@pytest.mark.parametrize("trailer", [CO_AUTHOR, SIGNER])
def test_trailer_names_look_french(trailer: str) -> None:
    # Otherwise the tests of trailer skipping below would prove nothing.
    assert english.looks_french(trailer)


def test_trailers_naming_people_are_skipped(repo: Repo, capsys: Capture) -> None:
    base = repo.commit("chore: initial")
    # The message GitHub writes when it squashes the commits of several authors.
    head = repo.commit(
        "feat: add a humidity sensor (#12)\n\n"
        "* feat: add a humidity sensor\n\n"
        "---------\n\n"
        f"{CO_AUTHOR}\n"
        "Reviewed-by: Bluefinch\n du Lac des Bois <4+example@users.noreply.github.com>\n"
        f"{SIGNER}"
    )
    reporter = Reporter("English")
    english.check_messages(repo.root, pr_event(base, head), reporter)
    assert reporter.count == 0
    # Other trailers hold prose, and the same lines in the body are checked.
    breaking = repo.commit(
        "feat!: drop the cloud API\n\nBREAKING-CHANGE: le capteur ne fonctionne plus"
    )
    footer = repo.commit(
        f"feat!: drop the cloud API\n\nBREAKING CHANGE: le capteur ne fonctionne plus\n{CO_AUTHOR}"
    )
    in_body = repo.commit(
        "fix: add a sensor\n\nCo-authored-by: de la Roche du Lac\n\nThanks for the review."
    )
    english.check_messages(repo.root, pr_event(head, in_body), reporter)
    out = capsys.readouterr().out
    assert reporter.count == 3
    assert f"Commit {breaking[:12]}: message looks French." in out
    assert f"Commit {footer[:12]}: message looks French." in out
    assert f"Commit {in_body[:12]}: message looks French." in out


@pytest.mark.parametrize(
    "message",
    [
        # The line that `git cherry-pick -x` adds to the trailers.
        f"fix: handle timeouts\n\n{SIGNER}\n(cherry picked from commit {'0123abcd' * 5})",
        # The breaking change footer of Conventional Commits, with a space.
        "feat!: drop the cloud API (#7)\n\n"
        "* feat!: drop the cloud API\n\n"
        "---------\n\n"
        f"BREAKING CHANGE: the cloud option is gone\n{CO_AUTHOR}",
    ],
)
def test_trailer_blocks_as_git_reads_them(repo: Repo, message: str) -> None:
    base = repo.commit("chore: initial")
    head = repo.commit(message)
    reporter = Reporter("English")
    english.check_messages(repo.root, pr_event(base, head), reporter)
    assert reporter.count == 0


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
    repo.write("manifest.json", '{"name": "Bien-Être Connect"}\n')
    repo.commit("feat: add a")
    event({})
    root = ["--root", str(repo.root)]
    # Allowed words given with decomposed accents match the text all the same.
    allowed = unicodedata.normalize("NFD", "Bien-Être")
    assert english.main([*root, "--exclude", "vendor/*", "--allowed-words", allowed]) == 0
    assert english.main(root) == 1
    assert "English: 2 problem(s) found." in capsys.readouterr().out


def test_main_reads_the_denylist_secrets(
    repo: Repo, event: EventWriter, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    repo.write("Bluefinch.md", "Récupère la valeur du capteur.\n")
    repo.commit("docs: add notes")
    event({})
    monkeypatch.setenv("CI_SECRETS", '{"PRIVACY_DENYLIST_X": "Bluefinch"}')
    assert english.main(["--root", str(repo.root)]) == 1
    out = capsys.readouterr().out
    assert "[redacted]:1: Line looks French" in out
    assert "bluefinch" not in out.lower()
    monkeypatch.setenv("CI_SECRETS", "[]")
    assert english.main(["--root", str(repo.root)]) == 1
    assert "CI_SECRETS does not hold a JSON object." in capsys.readouterr().err


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


@pytest.mark.parametrize(
    "form",
    [
        pytest.param(lambda text: text, id="accents"),
        pytest.param(strip_accents, id="no-accents"),
        pytest.param(lambda text: unicodedata.normalize("NFD", text), id="decomposed"),
    ],
)
def test_french_corpus(form: Callable[[str], str]) -> None:
    lines = FRENCH_CORPUS.splitlines()
    missed = [form(line) for line in lines if not english.looks_french(form(line))]
    # Short lines written without accents can hold no French word at all.
    assert len(missed) <= len(lines) // 20, missed


def test_english_corpus() -> None:
    lines = [line for line in ENGLISH_CORPUS.splitlines() if line]
    assert [line for line in lines if english.looks_french(line)] == []


# Corpora written for these tests: commit messages, code, documentation and
# UI strings in the style of Home Assistant integrations.
FRENCH_CORPUS = '''\
fix: corrige le calcul de la consommation
feat: ajoute un capteur de luminosité
fix: gère l'expiration du jeton
docs: met à jour le guide d'installation
refactor: simplifie la gestion des erreurs
feat: prise en charge des thermostats connectés
fix: évite un plantage au démarrage
chore: supprime le code inutilisé
test: ajoute des tests pour le coordinateur
fix: la valeur du capteur reste à zéro
feat: nouvel écran de configuration
fix: l'intégration ne se recharge plus
docs: précise les prérequis
feat: option pour choisir l'intervalle de mise à jour
fix: mauvaise unité pour la température extérieure
ci: lance les tests sur chaque branche
fix: reconnexion automatique après une coupure réseau
feat: affiche le niveau de batterie
refactor: déplace les constantes dans un fichier dédié
fix: les volets ne s'ouvrent pas entièrement
feat: support du mode éco pour les radiateurs
fix: plantage quand la réponse est vide
docs: explique comment obtenir la clé d'API
style: renomme les variables mal nommées
perf: réduit le nombre de requêtes
fix: n'affiche plus d'avertissement inutile
feat: ajout d'un service pour redémarrer l'appareil
fix: traduction manquante pour l'erreur de connexion
chore: nettoyage des imports
fix: arrondi incorrect de la puissance
feat: détection de présence par pièce
test: vérifie le comportement hors ligne
fix: délai d'attente trop court
docs: corrige des fautes de frappe
feat: gestion des scènes
fix: entités désactivées par défaut
refactor: utilise le coordinateur partagé
fix: qu'il y ait ou non une connexion
feat: compteur d'énergie journalier
fix: icône incorrecte pour la fenêtre ouverte
build: met à jour les dépendances
fix: ignore les mesures aberrantes
feat: notifications lorsque la porte reste ouverte
fix: sauvegarde des réglages avant la mise à jour
docs: ajoute une capture de l'écran d'accueil
fix: chaîne de caractères non traduite
feat: choix de la langue des messages
fix: plusieurs appareils avec le même nom
chore: passe à la version suivante
fix: crash si l'hôte est injoignable
feat: historique des alarmes
fix: boucle infinie lors de la synchronisation
fix: le minuteur ne s'arrête jamais
feat: nouveau capteur pour la qualité de l'air
fix: mauvaise conversion des degrés
# Récupère l'état actuel de l'appareil
# On attend que la connexion soit établie
"""Retourne la liste des capteurs disponibles."""
_LOGGER.debug("Impossible de joindre le serveur")
raise UpdateFailed("Réponse invalide du serveur")
# TODO : gérer le cas où le jeton a expiré
Cette intégration permet de piloter les radiateurs depuis Home Assistant.
## Configuration avancée
Renseignez l'adresse de la passerelle puis validez.
# Valeur par défaut si le capteur ne répond pas
"description": "Choisissez la pièce de l'appareil"
# Convertit la puissance en kilowatts
- Ajout d'un capteur de qualité d'air
Les mises à jour sont récupérées toutes les cinq minutes.
# Ne pas appeler cette fonction dans la boucle d'événements
"""Classe de base pour les entités de l'intégration."""
_LOGGER.warning("Le délai est dépassé, nouvel essai dans %s secondes", delay)
# Si la valeur est absente, on garde l'ancienne
Pour installer l'intégration, copiez le dossier dans custom_components.
# Liste des modes supportés par le thermostat
msg = "Erreur lors de la lecture du fichier"
# Évite de remplir les journaux
* Correction de l'affichage de la température
Merci de décrire le problème rencontré.
Cette PR ajoute la prise en charge des volets roulants.
# Attendre un peu avant de réessayer
# Le serveur renvoie parfois une liste vide
"""Teste la configuration avec des identifiants erronés."""
# Il faut convertir en watts avant d'envoyer
# Les heures sont en temps universel
'''
ENGLISH_CORPUS = '''\
"""The Bluefinch integration."""
from __future__ import annotations
import logging
from datetime import timedelta
from typing import Any
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
_LOGGER = logging.getLogger(__name__)
DOMAIN = "bluefinch"
PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.CLIMATE, Platform.SENSOR]
SCAN_INTERVAL = timedelta(seconds=30)
DEFAULT_PORT = 8443
async def async_setup_entry(hass: HomeAssistant, entry: BluefinchConfigEntry) -> bool:
"""Set up Bluefinch from a config entry."""
coordinator = BluefinchCoordinator(hass, entry)
await coordinator.async_config_entry_first_refresh()
entry.runtime_data = coordinator
await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
return True
async def async_unload_entry(hass: HomeAssistant, entry: BluefinchConfigEntry) -> bool:
"""Unload a config entry."""
return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
class BluefinchCoordinator(DataUpdateCoordinator[dict[str, Any]]):
"""Fetch data from the Bluefinch hub."""
def __init__(self, hass: HomeAssistant, entry: BluefinchConfigEntry) -> None:
"""Initialize the coordinator."""
super().__init__(hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=SCAN_INTERVAL)
async def _async_update_data(self) -> dict[str, Any]:
"""Fetch the latest state of every device."""
except TimeoutError as err:
raise UpdateFailed("Timed out while fetching data from the hub") from err
except AuthenticationError as err:
raise ConfigEntryAuthFailed("The password was rejected") from err
except ConnectionError as err:
raise ConfigEntryNotReady(f"Cannot reach the hub at {host}") from err
_attr_has_entity_name = True
_attr_translation_key = "outdoor_temperature"
_attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
_attr_device_class = SensorDeviceClass.TEMPERATURE
_attr_state_class = SensorStateClass.MEASUREMENT
@property
def native_value(self) -> float | None:
"""Return the current temperature."""
return self.coordinator.data.get("temp")
# The hub reports the value in tenths of a degree.
# Older firmware omits the field, so fall back to None.
_LOGGER.debug("Received %s devices from the hub", len(devices))
_LOGGER.warning("Device %s did not answer, retrying in %s seconds", device_id, delay)
_LOGGER.error("Unexpected response from the hub: %s", response.status)
"""Handle the initial step."""
errors: dict[str, str] = {}
errors["base"] = "cannot_connect"
errors["base"] = "invalid_auth"
_LOGGER.exception("Unexpected exception")
errors["base"] = "unknown"
return self.async_show_form(step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors)
await self.async_set_unique_id(info["serial"])
self._abort_if_unique_id_configured()
return self.async_create_entry(title=info["name"], data=user_input)
LANGUAGES = ["de", "en", "es", "fr", "it", "nl", "pl"]
SUPPORTED_REGIONS = ["AU", "DE", "FR", "GB", "US"]
REGIONS = ["us", "eu", "il", "au"]
DEFAULT_LANGUAGE = "de-DE"
VOICES = {"de-DE": "voice_a", "en-AU": "voice_b", "fr-FR": "voice_c"}
SUPPORTED_LOCALES = ["de-de", "en-au", "en-gb", "fr-ca", "pt-br"]
# Build the PKCE code verifier and its challenge.
code_verifier = secrets.token_urlsafe(64)
"""Return the code verifier for the authorization request."""
raise InvalidAuth("Invalid code verifier")
CURRENCIES = ["AUD", "EUR", "ILS", "USD"]
# The user chose a device that is already configured.
"""Handle the step where the user chose the account."""
if source == "aux":
SOURCES = {"aux": "AUX", "hdmi1": "HDMI 1", "optical": "Optical"}
self._source = self.send_command("SI?").removeprefix("SI")
HVAC_MODES = [HVACMode.OFF, HVACMode.HEAT, HVACMode.AUTO]
# Fall back to the default if the hub does not support the option.
# Values above 100 are an error code, not a reading.
# Round to one decimal, as the display does.
return round(value * 9 / 5 + 32, 1)
if not self.coordinator.last_update_success:
return False
"""Representation of a Bluefinch light."""
await self.coordinator.async_request_refresh()
# Pendant lights report their state through the parent fixture.
# Debounce the button so that a long press is not reported twice.
# See RFC 6749, section 4.1.
# A tuple of (key, unit, device class) for each sensor.
elif unit == "%":
assert result["type"] is FlowResultType.CREATE_ENTRY
assert result["data"] == {CONF_HOST: "hub.example.com", CONF_PASSWORD: "test-password"}
mock_client.get_status.side_effect = TimeoutError
with patch("custom_components.bluefinch.config_flow.Client.login", return_value=True):
@pytest.fixture
def mock_setup_entry() -> Generator[AsyncMock]:
"""Override async_setup_entry."""
"""Test we get the form."""
"""Test we handle invalid auth."""
"""Test we handle cannot connect error."""
"""Test the sensor states match the snapshot."""
await hass.async_block_till_done()
assert hass.states.get("sensor.living_room_temperature").state == "21.5"
assert len(mock_setup_entry.mock_calls) == 1
freezer.tick(timedelta(minutes=5))
async_fire_time_changed(hass)
"""Fixtures for the Bluefinch tests."""
# Pour the descaler into the tank before starting the cleaning cycle.
CONF_ENTREE_LIGHT = "entree_light"
# Les Paul mode sets the equalizer of the speaker to a warm profile.
# Use the De Morgan form so that the condition reads better.
# The La Crosse protocol sends one packet per minute.
# Compute the dew point with the Magnus formula.
# Matches the model numbers of the Le Mans series.
# Vis-à-vis the old API, the new one returns ISO dates.
# Café mode keeps the water hot between two cups.
# A naïve datetime is interpreted as UTC.
# The fiancé chime is a joke name from the vendor's firmware.
# Use a façade so that tests can swap the client.
# Ugly, but the vendor's API offers nothing better.
# The temperature est. value is a forecast, not a reading.
# Convert SI units to the imperial system when needed.
# The ONT reports the optical power in dBm.
ONT_STATUS = "ont_status"
# Ad hoc mode is used when the hub has no network yet.
# De facto standard for these devices is Modbus TCP.
# Per se this is not an error, so only log a debug message.
# Et al. is how the datasheet credits the authors.
# The relay must de-energize before the motor reverses.
# Mark the entity as unavailable rather than raising.
# Entities are created once per device, not per channel.
@callback
def _handle_coordinator_update(self) -> None:
"""Handle updated data from the coordinator."""
self._attr_is_on = self.coordinator.data[self._device_id]["on"]
self.async_write_ha_state()
async def async_turn_on(self, **kwargs: Any) -> None:
"""Turn the light on."""
brightness = kwargs.get(ATTR_BRIGHTNESS, 255)
await self._client.set_level(self._device_id, round(brightness / 255 * 100))
async def async_turn_off(self, **kwargs: Any) -> None:
"""Turn the light off."""
device_info = DeviceInfo(identifiers={(DOMAIN, serial)}, manufacturer="Bluefinch", model=model)
"""Return diagnostics for a config entry."""
return async_redact_data(entry.data, TO_REDACT)
TO_REDACT = {CONF_PASSWORD, "serial", "token"}
"title": "Connect to the hub",
"description": "Enter the host name or IP address of your hub.",
"host": "Host",
"password": "Password",
"cannot_connect": "Failed to connect",
"invalid_auth": "Invalid authentication",
"unknown": "Unexpected error",
"already_configured": "Device is already configured",
"reauth_successful": "Re-authentication was successful",
"reconfigure_successful": "Re-configuration was successful",
"name": "Outdoor temperature"
"name": "Filter life remaining"
"name": "Water level"
"name": "Boost mode"
"auto": "Auto",
"eco": "Eco",
"boost": "Boost",
"aux": "AUX",
"hdmi_1": "HDMI 1",
"de-de": "Germany",
"en-au": "Australia",
"fr-fr": "France",
"tr-tr": "Türkiye",
"CI": "Côte d'Ivoire",
"RE": "Réunion",
"CH": "Switzerland",
"zurich": "Zürich",
"host": "The host name or IP address of your Bluefinch hub.",
"message": "The device {name} is unavailable."
"title": "The Bluefinch cloud API is deprecated",
"description": "Remove the entry and add it again to switch to the local API.",
"scan_interval": "Update interval (seconds)",
"mode": "Operating mode",
"chime": "Chime",
"quiet": "Quiet",
"standard": "Standard",
"turbo": "Turbo",
"description": "Choose the rooms that the robot cleans first.",
"title": "Bluefinch options",
"data_description": {
"name": "Café mode",
"name": "Entrée light",
"name": "Pendant light",
"name": "Salon speaker",
"name": "Bureau lamp"
"name": "PM2.5"
"brand": "Bluéfinch",
"title": "Data provided by Météo-France",
"en": "English",
"de": "German",
"fr": "French",
"la": "Latin",
"le": "Low energy",
"medium": "Medium",
"high": "High",
"off": "Off",
"on": "On",
"low": "Low",
"error": "Error",
"idle": "Idle",
"cleaning": "Cleaning",
"returning": "Returning to dock",
"paused": "Paused",
"docked": "Docked",
"set_mode": {
"name": "Set mode",
"description": "Sets the operating mode of the thermostat.",
"fields": {
"duration": "Duration",
"description": "How long the boost lasts, in minutes.",
"unit_of_measurement": "min",
"exceptions": {
"message": "Could not send the command to {device}: {error}"
"issues": {
# Bluefinch
Custom integration for Bluefinch smart thermostats.
## Installation
1. Install HACS if you have not already.
2. Search for "Bluefinch" and install it.
3. Restart Home Assistant.
## Configuration
Go to **Settings** > **Devices & services** and select **Add integration**.
The integration polls the hub every 30 seconds.
## Known limitations
- Only one hub per account is supported.
- The cloud API does not report the filter state.
- Schedules created in the vendor app are not shown.
## Supported devices
| Model | Supported | Notes |
| --- | --- | --- |
| BF-100 | Yes | Firmware 2.1 or later |
| BF-200 | Partly | No humidity sensor |
Data provided by Météo-France.
Supports the de-DE, en-AU, en-GB and fr-FR voices.
The pendant lamp in the salon dims to 30 percent at night.
## Removing the integration
This integration follows the standard integration removal process.
## Troubleshooting
If the hub does not appear, check that it is on the same network as Home Assistant.
Enable debug logging and attach the log to your issue.
## Contributing
Read CONTRIBUTING.md before opening a pull request.
## License
This project is released under the MIT License.
The coordinator fetches every device in one request, so the interval does not grow.
Options can be changed later from the integration page.
The thermostat entity exposes the heat, cool and auto modes.
Brightness is scaled from 0 to 255 in Home Assistant and from 0 to 100 on the device.
The energy sensor is a total, suitable for the energy dashboard.
Use the `bluefinch.set_mode` action to change the mode from an automation.
A reauthentication flow starts when the password changes.
The hub must run firmware 2.0 or later.
Only the local API is used; no cloud account is needed.
Requests time out after ten seconds.
### Example automation
action: bluefinch.set_mode
target:
entity_id: climate.living_room
data:
mode: eco
alias: Boost the heating in the morning
trigger: time
at: "06:30:00"
## Changelog
### Added
- Humidity sensor for the BF-200.
- Reconfigure flow to change the host.
### Fixed
- The boost switch no longer flips back after a refresh.
- Timeouts are reported as unavailable instead of an error.
### Changed
- The minimum Home Assistant version is now 2025.1.
### Removed
- The YAML configuration, deprecated since 1.2.
Thanks to the testers who reported the firmware 2.3 issue.
It works with the La Crosse and Bluefinch weather stations.
The device speaks the Le Mans protocol variant.
See the De Morgan rule for the reasoning.
The resume button continues the program where it stopped.
The rendezvous point of the robot is its dock.
The genre field is empty for podcasts.
The menu shows an entrée, a main course and a dessert.
Set la and le in the config to enable the experimental modes.
It verifies the digests and modifies the temps folder.
This is on par with the upstream library.
The ILS, EUR and USD currencies are supported.
The SI unit of power is the watt.
AUX, HDMI and optical inputs are listed as sources.
Weather data for Zürich, Genève and Réunion is available.
Côte d'Ivoire and Türkiye use their own region codes.
The Bluéfinch app must be closed while the integration runs.
feat: add a humidity sensor
fix: handle timeouts when the hub reboots
docs: explain how to find the API key
chore(deps): bump aiohttp from 3.11.11 to 3.11.12
refactor: move the constants into const.py
test: cover the reauthentication flow
fix(sensor): report None while the device is offline
ci: run the tests on Python 3.13
feat!: drop support for firmware 1.x
perf: reuse the shared aiohttp session
style: sort the imports
build: pin the hub library
fix: chose the wrong unit for the outdoor sensor
fix: store the PKCE code verifier between steps
feat: add the AUX input to the source list
fix: map the ILS currency code
feat: support the de-DE and en-AU locales
fix: keep the entrée light on after a restart
fix: round the power to one decimal
feat: add a reconfigure flow
fix: avoid blocking the event loop when reading the certificate
docs: describe the supported devices
chore: release 1.4.0
fix: ignore readings above the sensor range
feat: expose the filter life as a sensor
fix: do not log the token
refactor: split the client into its own package
test: add snapshot tests for the sensors
docs: fix typos in the README
fix: use the device serial as the unique ID
feat: add diagnostics
fix: retry once after a connection reset
ci: pin the actions by commit SHA
chore: update the issue templates
feat: support the BF-200 thermostat
fix: translate the error when the hub is busy
docs: document the boost action
fix: mark the entities unavailable when the hub is offline
feat: add a binary sensor for the window detection
Revert "feat: add a humidity sensor"
This reverts commit 4f2a9c1.
The humidity sensor reports wrong values on firmware 2.3.
Merge branch 'main' into feature/humidity
Merge pull request #12 from bluefinch/fix-timeouts
Signed-off-by: octocat <1+octocat@users.noreply.github.com>
Co-authored-by: hubot <2+hubot@users.noreply.github.com>
The hub closes idle connections after 60 seconds, so the client now reconnects on demand.
Older firmware sends the temperature as a string; parse both forms.
Fixes #42
Closes #17
## Description
Adds a humidity sensor to the hub device.
## Type of change
- [x] Bug fix
- [ ] New feature
- [ ] Breaking change
## Checklist
- [x] The code is formatted with ruff.
- [x] Tests cover the change.
- [ ] The documentation is updated.
## How was this tested
Ran the integration against a hub on firmware 2.3 for a week.
## Additional information
The vendor confirmed that the field is deprecated.
Screenshots are not needed for this change.
name: Bluefinch
version: "1.4.0"
slug: bluefinch
description: Local bridge for Bluefinch hubs
arch:
- aarch64
- amd64
init: false
options:
log_level: info
schema:
log_level: list(trace|debug|info|notice|warning|error|fatal)?
set_mode:
fields:
mode:
required: true
example: eco
selector:
select:
options:
- "eco"
- "comfort"
- "away"
"domain": "bluefinch",
"name": "Bluefinch",
"codeowners": ["@octocat"],
"config_flow": true,
"documentation": "https://example.com/bluefinch",
"integration_type": "hub",
"iot_class": "local_polling",
"requirements": ["bluefinch-client==2.3.1"],
"version": "1.4.0"
"homeassistant": "2025.1.0",
"render_readme": true
[tool.ruff]
line-length = 100
target-version = "py313"
pytest-homeassistant-custom-component==0.13.205
'''


# Short French labels, as user interfaces and translation keys write them.
FRENCH_LABELS = """
Paramètres Réglages Démarrer Arrêter Créer Désactiver Sélectionner Humidité
Qualité Sécurité Énergie Météo Prévisions Durée Délai Pièce Fenêtre Lumière
Allumée Éteinte Fermé Écran Élément Données Réinitialiser Supprimer
Températures Précédent Arrêt Activé Désactivé Intensité Luminosité Accès
Préférences Thème Système Vérifier
""".split()
# Accented names, which start English sentences too.
ACCENTED_NAMES = """
José André René Zoé Hélène Genève Jérôme Québec Céline Mégane Clémence
Montréal Bénédicte Valérie Amélie Frédéric Cécile Gérard Stéphane Thérèse
Noël Chloé Inès Léa Raphaël Héloïse Sébastien Jérémie Mélanie Aurélien Cédric
Pénélope Désirée Renée Agnès Clément Benoît Françoise Hervé Gaëlle Loïc Anaïs
Jérémy Rémi Thaïs Mérida Bogotá Zürich Pokémon Café
""".split()


def test_short_labels_are_found_and_names_are_not() -> None:
    found = [label for label in FRENCH_LABELS if english.looks_french(label)]
    assert len(found) >= 0.75 * len(FRENCH_LABELS), sorted(set(FRENCH_LABELS) - set(found))
    flagged = [
        name
        for name in ACCENTED_NAMES
        if english.looks_french(name) or english.looks_french(f"{name} added a sensor.")
    ]
    # Désirée ends as a past participle does.
    assert flagged == ["Désirée"]
    # In a sentence, a capital still says that a word may be a name.
    assert not english.looks_french("The Sécurité panel")
