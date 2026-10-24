"""Reject French text outside translation files.

A line is reported when it holds a word that only exists in French (or any
word with French accents, other than English loanwords such as "cafe"), or
at least three French function words such as "le", "des" or "pour".
Identifiers with digits or underscores are ignored. A line can opt out with
a `ci-allow: french` comment.

The same rule applies to the pull request title and body and to the messages
of the commits introduced by the event. Text written by bots is skipped.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path

from ci_checks._common import (
    CheckError,
    Reporter,
    allowed_by_pragma,
    commits,
    fail,
    iter_lines,
    load_event,
    matches_any,
    new_commit_range,
    pull_request,
    require_full_history,
    split_list,
    tracked_files,
)

CATEGORY = "french"
WEAK_THRESHOLD = 3

# Translation files: every language except English is allowed there.
TRANSLATION_GLOBS = (
    "*/translations/*.json",
    "*/translations/*.yaml",
    "*/translations/*.yml",
    "translations/*.json",
    "translations/*.yaml",
    "translations/*.yml",
    "*/locales/*",
    "locales/*",
    "*.po",
)
ENGLISH_TRANSLATION = re.compile(r"(^|/)(en|en[-_][A-Za-z]+)(\.[a-z]+|/.*)$")
LANGUAGE_CODES = (
    "bg cs da de el es et fi fr hr hu it ja ko lt lv nb nl pl pt ro ru sk sl sv tr uk zh"
).split()
LOCALIZED_DOC = re.compile(
    rf"\.(?:{'|'.join(LANGUAGE_CODES)})(?:[-_][A-Za-z]{{2,4}})?\.(?:md|rst|txt)$"
)

# Words that are French and not English. Words shared with English, even
# rare or British ones (correction, modifier, utilise, nouveau), stay out.
STRONG_WORDS = frozenset(
    """
    afficher ajout ajoute ajouter ajouts appareil appareils aucun aucune
    aujourd'hui aussi avec beaucoup c'est capteur capteurs cette chaque
    comme corrige corriger d'un d'une dans depuis donc doit entre erreur
    fichier fichiers heure heures j'ai jamais jour jours l'appareil lorsque
    maison mettre mieux modifie n'est n'y nettoie nettoyage nous nouvelle
    parce peut puis qu'il qu'on quand renomme renommer rien selon semaine
    sont supprime supprimer toujours tous trop utiliser valeur valeurs
    voici vous
    """.split()
)
WEAK_WORDS = frozenset(
    """
    au aux ce ces des du elle est et il ils la le les leur mais ou par pas
    pour que qui sur un une
    """.split()
)
# English words that are spelled with accents or look French.
ENGLISH_LOANWORDS = frozenset(
    """
    cafe café cliché déjà décor entrée façade fiancé fiancée naïve naïvety
    né née résumé rôle señor touché über
    """.split()
)
_TOKEN = re.compile(r"[\w']+")
_FRENCH_ACCENTS = frozenset("àâæçéèêëîïôœùûüÿ")


def french_words(text: str) -> tuple[int, int]:
    """Return the number of strong and weak French words in a piece of text.

    Identifiers (tokens with digits or underscores, such as the keys of a
    French API) are not words of the text and are ignored.
    """
    strong = weak = 0
    for token in _TOKEN.findall(text.lower().replace("\u2019", "'")):
        word = token.strip("'")
        if not word or "_" in word or any(char.isdigit() for char in word):
            continue
        if word in ENGLISH_LOANWORDS:
            continue
        if word in STRONG_WORDS or any(char in _FRENCH_ACCENTS for char in word):
            strong += 1
        elif word in WEAK_WORDS:
            weak += 1
    return strong, weak


def looks_french(text: str) -> bool:
    """Return whether text has a French word, or several French function words."""
    strong, weak = french_words(text)
    return strong > 0 or weak >= WEAK_THRESHOLD


def is_translation(path: str) -> bool:
    """Return whether a path holds a translation into a language other than English."""
    if LOCALIZED_DOC.search(path):
        return True
    if not matches_any(path, TRANSLATION_GLOBS):
        return False
    return not ENGLISH_TRANSLATION.search(path)


def check_files(root: Path, paths: Iterable[str], reporter: Reporter) -> None:
    """Report lines of non-translation files that look French."""
    selected = [path for path in paths if not is_translation(path)]
    for path, number, line in iter_lines(root, selected):
        if looks_french(line) and not allowed_by_pragma(line, CATEGORY):
            reporter.error(
                "Line looks French (or another language than English). Write it in "
                "English, move it to a translation file, or add `ci-allow: french` "
                "if it is English.",
                path,
                number,
            )


def check_messages(root: Path, event: dict, reporter: Reporter) -> None:
    """Report new commit messages and pull request text that look French.

    Text written by bots quotes upstream release notes and is skipped.
    """
    for commit in commits(root, new_commit_range(event, root)):
        if commit.is_bot:
            continue
        if any(looks_french(line) for line in commit.message.splitlines()):
            reporter.error(f"Commit {commit.short}: message looks French.")
    pr = pull_request(event)
    if pr is None:
        return
    if looks_french(pr.title):
        reporter.error("Pull request title looks French.")
    if not pr.author_is_bot and any(looks_french(line) for line in pr.body.splitlines()):
        reporter.error("Pull request body looks French.")


def main(argv: list[str] | None = None) -> int:
    """Run the language check from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--exclude", default="", help="globs of files to skip")
    args = parser.parse_args(argv)

    reporter = Reporter("English")
    try:
        require_full_history(args.root)
    except CheckError as err:
        return fail(str(err))
    exclude = split_list(args.exclude)
    paths = [path for path in tracked_files(args.root) if not matches_any(path, exclude)]
    check_files(args.root, paths, reporter)
    check_messages(args.root, load_event(), reporter)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
