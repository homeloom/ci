"""Reject French text outside translation files.

Each line gets a score: words that only exist in French count two points,
common French function words count one point, and a line scoring two or more
is reported. Common English loanwords spelled with accents do not count.
A line can opt out with a `ci-allow: french` comment.

The same rule applies to the pull request title and body and to the messages
of the commits introduced by the event.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path

from ci_checks._common import (
    Reporter,
    allowed_by_pragma,
    commits,
    iter_lines,
    load_event,
    matches_any,
    new_commit_range,
    pull_request,
    split_list,
    tracked_files,
)

CATEGORY = "french"
THRESHOLD = 2

# Translation files: every language except English is allowed there.
TRANSLATION_GLOBS = (
    "*/translations/*.json",
    "translations/*.json",
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

STRONG_WORDS = frozenset(
    """
    affiche afficher ajout ajoute ajouter ajouts appareil appareils aucun
    aucune aujourd'hui aussi avec beaucoup c'est capteur capteurs cette
    chaque chez comme corrige corriger correction d'un d'une dans depuis
    donc doit entre erreur fichier fichiers heure heures j'ai jamais
    jour jours l'appareil lorsque maison mettre mieux modifie modifier
    n'est n'y nettoie nettoyage nous nouveau nouvelle parce peut puis
    qu'il qu'on quand renomme renommer rien selon semaine sont
    supprime supprimer suppression toujours tous trop utilise utiliser
    valeur valeurs voici vous
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
_WORD = re.compile(r"[^\W\d_]+(?:'[^\W\d_]+)?")
_FRENCH_ACCENTS = frozenset("àâæçéèêëîïôœùûüÿ")


def french_score(text: str) -> int:
    """Return how French a piece of text looks."""
    score = 0
    for word in _WORD.findall(text.lower().replace("\u2019", "'")):
        if word in ENGLISH_LOANWORDS:
            continue
        if word in STRONG_WORDS or any(char in _FRENCH_ACCENTS for char in word):
            score += 2
        elif word in WEAK_WORDS:
            score += 1
    return score


def looks_french(text: str) -> bool:
    return french_score(text) >= THRESHOLD


def is_translation(path: str) -> bool:
    """Return whether a path holds a translation into a language other than English."""
    if LOCALIZED_DOC.search(path):
        return True
    if not matches_any(path, TRANSLATION_GLOBS):
        return False
    return not ENGLISH_TRANSLATION.search(path)


def check_files(root: Path, paths: Iterable[str], reporter: Reporter) -> None:
    selected = [path for path in paths if not is_translation(path)]
    for path, number, line in iter_lines(root, selected):
        if looks_french(line) and not allowed_by_pragma(line, CATEGORY):
            reporter.error(
                "Line looks French. Write it in English, move it to a translation "
                "file, or add `ci-allow: french` if it is not French.",
                path,
                number,
            )


def check_messages(root: Path, event: dict, reporter: Reporter) -> None:
    for commit in commits(root, new_commit_range(event)):
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--exclude", default="", help="globs of files to skip")
    args = parser.parse_args(argv)

    reporter = Reporter("English")
    exclude = split_list(args.exclude)
    paths = [path for path in tracked_files(args.root) if not matches_any(path, exclude)]
    check_files(args.root, paths, reporter)
    check_messages(args.root, load_event(), reporter)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
