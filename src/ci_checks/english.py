"""Reject French text outside translation files.

A line is reported when it holds a word that only exists in French, at least
three French signals, or two of them and no English function word. French
signals are short French words that also appear in English text or code,
such as "le", "des" or "pour", lowercase words with French accents or
French endings ("-eux", "-ique"), and elisions such as "l'" or "qu'"; each
counts once. An accent alone proves nothing: capitalized accented words are
names (Zürich, Réunion) unless they are French words.

Words in capitals (codes and acronyms such as DE or AUX), identifiers with
digits or underscores and URLs are ignored. In a hyphenated compound or
alone in quotes, short French words are codes or prefixes ("de-DE", "au",
de-energize) and count for nothing. A line can opt out with a
`ci-allow: french` comment, and a repository can allow words such as brand
names, hyphenated or not.

The same rule applies to the pull request title and body and to the messages
of the commits introduced by the event, without the trailers that name
people, such as Co-authored-by; their lines can opt out with the same
comment. Text written by dependency update bots is skipped. File paths that
hold a denylisted term (see ci_checks.denylist) are redacted in the report.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Literal

from ci_checks._common import (
    CheckError,
    Reporter,
    allowed_by_pragma,
    commits,
    dependency_bot_commits,
    display_path,
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
from ci_checks.denylist import Denylist, denylist_sources, location

CATEGORY = "french"
SIGNAL_THRESHOLD = 3

# ISO 639-1 language codes.
LANGUAGE_CODES = frozenset(
    """
    aa ab ae af ak am an ar as av ay az ba be bg bi bm bn bo br bs ca ce ch
    co cr cs cu cv cy da de dv dz ee el en eo es et eu fa ff fi fj fo fr fy
    ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik io is it
    iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo
    lt lu lv mg mh mi mk ml mn mr ms mt my na nb nd ne ng nl nn no nr nv ny
    oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk sl
    sm sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw ty
    ug uk ur uz ve vi vo wa wo xh yi yo za zh zu
    """.split()
)
# Folders that hold translations, and the data and documentation files that
# count as translations in them: code that loads translations is checked.
TRANSLATION_FOLDERS = frozenset({"translations", "i18n", "locale", "locales", "lang", "languages"})
TRANSLATION_EXTENSIONS = frozenset(
    "arb ftl json md po pot properties rst strings txt xlf xliff yaml yml".split()
)
DOC_EXTENSIONS = frozenset({"md", "rst", "txt"})
# A language tag such as fr, fr-FR, pt_BR, zh-Hant or es-419.
_LANGUAGE_TAG = re.compile(r"([a-z]{2})(?:[-_](?:[A-Za-z]{2}|[A-Za-z]{4}|[0-9]{3}))*")
# A document named after its language: README.fr.md, guide.pt-BR.md, README_fr.md.
_LOCALIZED_DOC = re.compile(r"(?:.+\.|(?i:readme)[-_])(?P<tag>[^.]+)")

# Words that are French and not English, written without accents as people
# often do. Words shared with English, even rare or British ones (correction,
# modifier, nouveau, pendant, salon, utilise), or with brand names in other
# languages (Bonjour, Energie) stay out. Plurals and feminine past
# participles (ajoutee) count.
STRONG_WORDS = frozenset(
    """
    actuel actuelle actuellement affichage afficher afin ainsi ajout ajoute
    ajouter alarme alors amelioration ameliore ameliorer ancien ancienne
    annee annule annuler appareil appel appeler appelle apres arret arrete
    arreter aspirateur assez attendre attente aucun aucune aujourd'hui aussi
    automatiquement autre avait avance avec avertissement avez avoir avons
    beaucoup bien bloque bloquer boucle bouton c'est calcul capteur
    caractere ceci cela celle celui cette ceux chaine chambre changement
    chaque chargement chaudiere chauffage chien chiffre choisi choisir
    choisissez choix cinq comme comportement compte connecte consommation
    contre convertir convertit correcte correctif corrige corriger coupure
    courriel d'un d'une dans deconnecte deconnexion decrire decrit defaut
    defini definir delai demarrage demarre demarrer deplace deplacer depuis
    dernier derniere desactive desactiver deux deuxieme devoir devrait
    disponible doit doivent donc donnee donnees duree ecran ecrire ecrit
    ecriture elles enfin enleve enlever entier entiere entierement entite
    entre envoie envoyer erreur essai essaie essayer etage etaient etait
    etat etes etre evenement evite eviter explique expliquer exterieur faire
    fais fait faudrait faut faute fenetre ferme fermer fermeture fichier
    fonction fonctionnalite fonctionne fonctionnement gere gerer gestion
    heure horaire horloge hors humidite identifiant identite incorrecte
    indique indiquer indisponible injoignable interieur interrupteur
    intervalle inutile inutilise j'ai jamais jeton joindre jour journalier
    laquelle lequel ligne lors lorsque lumiere luminosite maintenant maison
    malgre manquant manquante manque matin mauvais mauvaise meilleur mesure
    methode mettre mieux minuteur mise modifie moins mois n'est n'y nettoie
    nettoyage nettoyer niveau nombre notre nous nouvel nouvelle nuit objet
    obtenir obtient ouvert ouverte ouverture ouvre ouvrir panne parametre
    parce parmi partage passerelle permet permettre peu peut peuvent peux
    plantage plusieurs porte pourquoi pourrait pouvoir prendre prenom
    prerequis prise puis puissance qu'il qu'on qualite quand quantite quatre
    quel quelle quelque quoi recevoir reconnecte reconnexion recupere
    recuperer redemarre redemarrer reduire reduit reessayer reglage remplace
    remplacer renomme renommer renvoie repondre reponse requete reseau
    retourne reveil rien roulant sauf sauvegarde sauvegarder seconde selon
    semaine serait seront serveur seuil seulement simplifie sinon soir soit
    sommes sont souvent suis suivant suivante supprime supprimer tache
    telecommande toujours tous toute toutes traduction traduire traduit tres
    trois trop trouve trouver utilisateur utiliser valeur valide valider
    veille verifie veut voici voiture volet votre vous vrai
    """.split()
)
# Endings of French words that English words do not have, except for words
# that end like the English words below. They only count on lowercase words,
# without a final "s": capitalized words with these endings are names
# (Martinique).
FRENCH_ENDINGS = ("aient", "ait", "aux", "eur", "euse", "eux", "ique", "bilite", "idite", "icite")
ENGLISH_ENDINGS = tuple(
    """
    adieux amateur antique applique auteur bait boutique bordeaux bureaux
    chanteuse chartreuse chateaux chauffeur clique communique connoisseur
    critique entrepreneur gait gateaux grandeur hauteur liqueur martinique
    masseur masseuse milieux monsieur mozambique mystique oblique physique
    plait plateaux poseur provocateur raconteur restaurateur saboteur
    tableaux technique trait trousseaux unique voyeur wait
    """.split()
)
# Short French words that also appear in English text, code or names, so
# that one of them alone proves nothing.
WEAK_WORDS = frozenset(
    """
    au aux ce ces cet chez chose connexion de des dont du elle est et il ils
    je la le les leur leurs lui mais mes ont ou par pas pour que qui sans
    ses si sous sur un une verifier vos
    """.split()
)
# English function words: a line with one of them is English unless it also
# has a French word or three French signals.
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
    cafe café cliché crème d'oh décor déjà entrée façade fiancé fiancée
    flambé matinée naïve naïvety né née passé protégé purée résumé rôle
    sauté señor soirée touché über
    """.split()
)
_TOKEN = re.compile(r"\w+(?:['-]\w+)*")
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S*", re.IGNORECASE)
_ELISION = re.compile(r"(?:jusqu|lorsqu|puisqu|qu|[cdjlmnst])'(?=\w)", re.IGNORECASE)
_CONTRACTION = re.compile(r"(?:'s|n't|'re|'ll|'ve|'d|'m)$", re.IGNORECASE)
_QUOTES = "\"'`"
_FRENCH_ACCENTS = frozenset("àâæçéèêëîïôœùûüÿ")
# The trailers that end a commit message, and those that name people.
_TRAILER = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*:\s")
_PERSON_TRAILER = re.compile(r"(?:[A-Za-z0-9-]+-by|cc):", re.IGNORECASE)

Kind = Literal["strong", "signal", "weak", "english"]


def normalize(text: str) -> str:
    """Return text with composed accents and straight apostrophes.

    Decomposed accents, as in macOS file names, would otherwise split words,
    because combining marks are not word characters.
    """
    return unicodedata.normalize("NFC", text).replace("\u2019", "'")


def _strip_accents(word: str) -> str:
    """Return a word without its accents and ligatures."""
    decomposed = unicodedata.normalize("NFD", word.replace("œ", "oe").replace("æ", "ae"))
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def _is_strong(word: str) -> bool:
    """Return whether a lowercase word without accents is French and not English."""
    if word in STRONG_WORDS:
        return True
    # A plural, but not an English verb such as "verifies".
    if word.endswith(("s", "x")) and not word.endswith("ies") and word[:-1] in STRONG_WORDS:
        return True
    # A feminine past participle (ajoutee), but not "etree".
    singular = word.removesuffix("s")
    return len(singular) > 5 and singular.endswith("ee") and singular[:-1] in STRONG_WORDS


def _has_french_ending(word: str) -> bool:
    """Return whether a lowercase word without accents has an ending only French has."""
    singular = word.removesuffix("s")
    return (
        len(singular) > 5
        and singular.endswith(FRENCH_ENDINGS)
        and not singular.endswith(ENGLISH_ENDINGS)
    )


def _word_kind(word: str, allowed: frozenset[str]) -> Kind | None:
    """Return what a word says about the language of its line, if anything."""
    lower = word.lower()
    if (
        "_" in word
        or any(char.isdigit() for char in word)
        or (len(word) > 1 and word.isupper())
        or lower in allowed
        or lower in ENGLISH_LOANWORDS
    ):
        return None
    bare = _strip_accents(lower)
    if _is_strong(bare):
        return "strong"
    if any(char in _FRENCH_ACCENTS for char in lower):
        # Capitalized, an accented word that is not French is a name (Zürich).
        return None if word[0].isupper() else "signal"
    if word.islower() and _has_french_ending(bare):
        return "signal"
    if lower in WEAK_WORDS:
        return "weak"
    return "english" if lower in ENGLISH_WORDS else None


def _part_kinds(part: str, allowed: frozenset[str]) -> Iterator[tuple[Kind, str]]:
    """Yield what a word, with its elision or English contraction, says, and the word."""
    lower = part.lower()
    if "'" in part and not part.isupper() and _strip_accents(lower) in STRONG_WORDS:
        yield "strong", lower  # c'est, aujourd'hui
        return
    if lower in ENGLISH_LOANWORDS:
        return
    if elision := _ELISION.match(part):
        part = part[elision.end() :]
        if part[0].isupper() and not part.isupper():
            return  # A name, as in Côte d'Ivoire.
        if len(part) > 1 and part.isalpha():
            yield "signal", elision.group().lower()
    if contraction := _CONTRACTION.search(part):
        part = part[: contraction.start()]
        yield "english", contraction.group().lower()
    if part and (kind := _word_kind(part, allowed)):
        yield kind, part.lower()


def _is_quoted(text: str, start: int, end: int) -> bool:
    """Return whether the text between start and end is all that a pair of quotes holds."""
    return start > 0 and end < len(text) and text[start - 1] == text[end] and text[end] in _QUOTES


def french_words(text: str, allowed: frozenset[str] = frozenset()) -> tuple[int, int, int]:
    """Return the number of French words, other French signals and English function words.

    Identifiers (tokens with digits or underscores, such as the keys of a
    French API) are not words of the text and are ignored, and so are the
    words a repository allows, with their English possessive. In a
    hyphenated compound, which is often a slug or a code, French words only
    count as signals. Each signal counts once, so that code such as `le=le`
    is not a sentence.
    """
    strong = english = 0
    signals: set[str] = set()
    text = _URL.sub(" ", normalize(text))
    for match in _TOKEN.finditer(text):
        token = match.group()
        if token.lower().removesuffix("'s") in allowed:
            continue
        parts = token.split("-")
        compound = len(parts) > 1
        codes = compound or _is_quoted(text, match.start(), match.end())
        for part in parts:
            for kind, word in _part_kinds(part, allowed):
                if kind == "strong" and not compound:
                    strong += 1
                elif kind in ("strong", "signal") or (kind == "weak" and not codes):
                    signals.add(word)
                elif kind == "english":
                    english += 1
    return strong, len(signals), english


def looks_french(text: str, allowed: frozenset[str] = frozenset()) -> bool:
    """Return whether text has a French word, or French signals and no English words."""
    strong, signals, english = french_words(text, allowed)
    return strong > 0 or signals >= SIGNAL_THRESHOLD or (signals >= 2 and english == 0)


def _language(tag: str) -> str | None:
    """Return the ISO 639-1 code of a language tag such as fr-FR, or None."""
    match = _LANGUAGE_TAG.fullmatch(tag)
    if match and match.group(1) in LANGUAGE_CODES:
        return match.group(1)
    return None


def is_translation(path: str) -> bool:
    """Return whether a path holds a translation into a language other than English.

    Translations are documents named after their language (README.fr.md,
    README_fr.md), data files in a translation folder (translations/fr.json,
    locales/fr/messages.json), documents under docs/<language>/, and
    gettext catalogs.
    """
    *folders, name = path.split("/")
    stem, dot, extension = name.rpartition(".")
    extension = extension.lower()
    if not dot or extension not in TRANSLATION_EXTENSIONS:
        return False
    localized = _LOCALIZED_DOC.fullmatch(stem)
    if localized and extension in DOC_EXTENSIONS and (language := _language(localized["tag"])):
        return language != "en"
    for index, folder in enumerate(folders):
        below = [*folders[index + 1 :], stem]
        if folder in TRANSLATION_FOLDERS or (
            folder == "docs" and len(below) > 1 and _language(below[0])
        ):
            return "en" not in map(_language, below)
    return extension == "po" and "en" not in map(_language, [*folders, stem])


def _prose_lines(message: str) -> list[str]:
    """Return the lines of a commit message without the trailers that name people.

    GitHub writes Co-authored-by trailers itself when it squashes the
    commits of several authors, and names are not prose. Other trailers,
    such as BREAKING-CHANGE, are kept.
    """
    lines = message.splitlines()
    blank = max((index for index, line in enumerate(lines) if not line.strip()), default=None)
    if blank is None:
        return lines
    block = lines[blank + 1 :]
    if not block or not all(
        _TRAILER.match(line) or (index > 0 and line[:1].isspace())
        for index, line in enumerate(block)
    ):
        return lines
    kept: list[str] = []
    person = False
    for line in block:
        if not line[:1].isspace():
            person = bool(_PERSON_TRAILER.match(line))
        if not person:
            kept.append(line)
    return lines[: blank + 1] + kept


def check_files(
    root: Path,
    paths: Iterable[str],
    reporter: Reporter,
    allowed: frozenset[str] = frozenset(),
    denylist: Denylist | None = None,
) -> None:
    """Report lines of non-translation files that look French."""
    denylist = denylist or Denylist("")
    selected = [path for path in paths if not is_translation(display_path(path))]
    for path, number, line in iter_lines(root, selected):
        if looks_french(line, allowed) and not allowed_by_pragma(line, CATEGORY):
            shown, annotated = location(denylist, display_path(path))
            reporter.error(
                ("" if annotated else f"{shown}:{number}: ")
                + "Line looks French (or another language than English). Write it in "
                "English, move it to a translation file, or add `ci-allow: french` "
                "if it is English.",
                annotated,
                number,
            )


def _french_lines(lines: Iterable[str], allowed: frozenset[str]) -> bool:
    return any(
        looks_french(line, allowed) and not allowed_by_pragma(line, CATEGORY) for line in lines
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
        if _french_lines(_prose_lines(commit.message), allowed):
            reporter.error(f"Commit {commit.short}: message looks French.")
    pr = pull_request(event)
    if pr is None:
        return
    if looks_french(pr.title, allowed):
        reporter.error("Pull request title looks French.")
    if not pr.is_dependency_bot and _french_lines(pr.body.splitlines(), allowed):
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
        denylist = Denylist("\n".join(denylist_sources(os.environ)))
        require_full_history(args.root)
    except CheckError as err:
        return fail(str(err))
    exclude = split_list(args.exclude)
    paths = [
        path for path in tracked_files(args.root) if not matches_any(display_path(path), exclude)
    ]
    allowed = frozenset(normalize(word).lower() for word in split_list(args.allowed_words))
    check_files(args.root, paths, reporter, allowed, denylist)
    check_messages(args.root, load_event(), reporter, allowed)
    return reporter.finish()


if __name__ == "__main__":
    sys.exit(main())
