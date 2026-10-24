"""Reject French text outside translation files.

A line is reported when it holds a word that only exists in French (or any
word with French accents, other than English loanwords such as "cafe"), at
least three French function words such as "le", "des" or "pour", or two of
them and no English function word. Identifiers with digits or underscores
are ignored. A line can opt out with a `ci-allow: french` comment, and a
repository can allow words such as the accented names of brands.

The same rule applies to the pull request title and body and to the messages
of the commits introduced by the event. Text written by dependency update
bots is skipped.
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
    dependency_bot_commits,
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

# Words that are French and not English, written without accents as people
# often do. Words shared with English, even rare or British ones (correction,
# modifier, nouveau, pendant, salon), stay out. Plurals in -s or -x count.
STRONG_WORDS = frozenset(
    """
    afficher ainsi ajout ajoute ajouter alors ancien ancienne annee
    appareil appel appeler apres aspirateur aucun aucune aujourd'hui aussi
    avec avez avoir avons beaucoup bien c'est calcul capteur chaine
    chambre chaque chauffage chien chose comme compte connexion corrige
    corriger courriel d'un d'une dans demarrage demarrer depuis dernier
    derniere doit doivent donc donnee donnees entre envoie envoyer erreur
    etait etat etes etre faire fais fait faut fenetre fichier fonction
    gerer gestion heure interrupteur j'ai jamais jour l'appareil lorsque
    lumiere maintenant maison matin methode mettre mieux mise modifie
    moins mois n'est n'y nettoie nettoyage nombre nouvelle nuit objet ont
    parce peut peuvent peux plusieurs porte pourquoi prenom prise puis
    qu'il qu'on quand quelque quoi recevoir recupere recuperer renomme
    renommer reponse requete reseau reveil rien roulant sauf selon semaine
    seulement sinon soir sommes sont souvent suis suivant suivante
    supprime supprimer toujours tous toute toutes tres trop trouve
    trouver utilisateur utiliser valeur veille verifie verifier veut voici
    volet vous vrai
    """.split()
)
# Short French words that also appear in English text, code or names, so
# that one of them alone proves nothing.
WEAK_WORDS = frozenset(
    """
    au aux ce ces de des du elle est et il ils la le les leur lui mais mes
    ou par pas pour que qui ses si sur un une vos
    """.split()
)
# English function words: a line with one of them is English unless it also
# has a French word or three French function words.
ENGLISH_WORDS = frozenset(
    """
    an and are as at be but by can do does for from has have if in into is
    it its not of or our should that the their them then there these they
    this to was we were when which while will with without you your
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


def _is_strong(word: str) -> bool:
    if word in STRONG_WORDS or any(char in _FRENCH_ACCENTS for char in word):
        return True
    # A plural, but not an English verb such as "verifies".
    return word[-1] in "sx" and not word.endswith("ies") and word[:-1] in STRONG_WORDS


def french_words(text: str, allowed: frozenset[str] = frozenset()) -> tuple[int, int, int]:
    """Return the number of French words, French function words and English function words.

    Identifiers (tokens with digits or underscores, such as the keys of a
    French API) are not words of the text and are ignored, and so are the
    words a repository allows.
    """
    strong = weak = english = 0
    for token in _TOKEN.findall(text.lower().replace("\u2019", "'")):
        word = token.strip("'")
        if not word or "_" in word or any(char.isdigit() for char in word):
            continue
        if word in ENGLISH_LOANWORDS or word in allowed:
            continue
        if _is_strong(word):
            strong += 1
        elif word in WEAK_WORDS:
            weak += 1
        elif word in ENGLISH_WORDS:
            english += 1
    return strong, weak, english


def looks_french(text: str, allowed: frozenset[str] = frozenset()) -> bool:
    """Return whether text has a French word, or French function words and no English ones."""
    strong, weak, english = french_words(text, allowed)
    return strong > 0 or weak >= WEAK_THRESHOLD or (weak >= 2 and english == 0)


def is_translation(path: str) -> bool:
    """Return whether a path holds a translation into a language other than English."""
    if LOCALIZED_DOC.search(path):
        return True
    if not matches_any(path, TRANSLATION_GLOBS):
        return False
    return not ENGLISH_TRANSLATION.search(path)


def check_files(
    root: Path, paths: Iterable[str], reporter: Reporter, allowed: frozenset[str] = frozenset()
) -> None:
    """Report lines of non-translation files that look French."""
    selected = [path for path in paths if not is_translation(path)]
    for path, number, line in iter_lines(root, selected):
        if looks_french(line, allowed) and not allowed_by_pragma(line, CATEGORY):
            reporter.error(
                "Line looks French (or another language than English). Write it in "
                "English, move it to a translation file, or add `ci-allow: french` "
                "if it is English.",
                path,
                number,
            )


def check_messages(
    root: Path, event: dict, reporter: Reporter, allowed: frozenset[str] = frozenset()
) -> None:
    """Report new commit messages and pull request text that look French.

    Text written by dependency update bots quotes upstream release notes and
    is skipped.
    """
    new = commits(root, new_commit_range(event, root))
    exempt = dependency_bot_commits(event, new)
    for commit in new:
        if commit.sha in exempt:
            continue
        if any(looks_french(line, allowed) for line in commit.message.splitlines()):
            reporter.error(f"Commit {commit.short}: message looks French.")
    pr = pull_request(event)
    if pr is None:
        return
    if looks_french(pr.title, allowed):
        reporter.error("Pull request title looks French.")
    body = pr.body.splitlines()
    if not pr.is_dependency_bot and any(looks_french(line, allowed) for line in body):
        reporter.error("Pull request body looks French.")


def main(argv: list[str] | None = None) -> int:
    """Run the language check from the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--exclude", default="", help="globs of files to skip")
    parser.add_argument(
        "--allowed-words", default="", help="words accepted as English, such as brand names"
    )
    args = parser.parse_args(argv)

    reporter = Reporter("English")
    try:
        require_full_history(args.root)
    except CheckError as err:
        return fail(str(err))
    exclude = split_list(args.exclude)
    paths = [path for path in tracked_files(args.root) if not matches_any(path, exclude)]
    allowed = frozenset(word.lower() for word in split_list(args.allowed_words))
    check_files(args.root, paths, reporter, allowed)
    check_messages(args.root, load_event(), reporter, allowed)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
