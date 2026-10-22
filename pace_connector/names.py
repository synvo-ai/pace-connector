"""Rule-based person-name checks shared by masking and the egress check. No NER model.

Three signals:
- position: the name after a greeting ("Dear X,"), a sign-off ("Regards,\nX"), "my name is X",
  a "Name:" form field, or a title ("Ms X");
- shape: two or more capitalised words in a row where at least one is not an English word, is
  a common local surname that is also an English word (Tan, Lee, Ho), or the run starts with
  an initial. "Applied Data" or "Admissions Team" pass; "Mei Xuan Koh", "Émile Laurent",
  "Grace Ho" and "J. Doe" do not;
- the sender's and recipients' own display names from the email envelope.

Masking masks what these find; the egress check then requires that none of them is left.
"""

from __future__ import annotations

from email.utils import getaddresses
from functools import lru_cache
import gzip
from pathlib import Path
import re
from typing import Iterable

_HERE = Path(__file__).parent
_TOKEN = re.compile(r"[^\W\d_]+(?:['’\-/][^\W\d_]+)*", re.UNICODE)

TITLES = frozenset({"dr", "mr", "mrs", "ms", "mdm", "miss", "madam", "prof", "professor", "sir", "dame", "rev", "er", "ar"})
# Lower-case particles inside a name: "Nurul Huda binte Ismail", "Arjun s/o Krishnan", "Marta de Sousa".
_PARTICLES = frozenset({"bin", "binte", "bte", "binti", "s/o", "d/o", "a/l", "a/p", "de", "da", "del", "van", "von", "der", "la", "le", "al", "el", "dos"})
# Words that can sit next to a name without being part of it.
_EDGE = TITLES | frozenset({
    "dear", "hi", "hello", "hey", "greetings", "good", "morning", "afternoon", "evening", "thanks", "thank", "regards", "best",
    "kind", "warm", "warmest", "cheers", "sincerely", "yours", "faithfully", "truly", "please", "ask", "contact", "call", "email",
    "cc", "attn", "attention", "to", "from", "and", "or", "with", "by", "for", "of", "the", "a", "an", "my", "our", "your", "his",
    "her", "their", "i", "we", "you", "he", "she", "they", "this", "that", "re", "fw", "fwd", "also", "sorry", "hope", "welcome",
    "congratulations", "regarding", "name", "student", "applicant", "candidate", "colleague", "manager", "instructor", "lecturer",
    "trainer", "tutor", "officer", "staff", "team",
    # Closed-class words that start a sentence before a name: "Does Sunny teach", "Can Mei Ling".
    "do", "does", "did", "is", "are", "was", "were", "be", "been", "can", "could", "will", "would", "shall", "should", "may",
    "might", "must", "has", "have", "had", "when", "where", "what", "which", "who", "whom", "whose", "why", "how", "if", "so",
    "but", "then", "only", "just", "not", "no", "yes", "ok", "okay", "tell", "let", "said", "says", "told", "via", "at", "in",
    "on", "as", "about", "after", "before", "since", "because", "while", "both", "either", "neither", "all", "any", "each",
    "every", "some", "both", "him", "them", "us", "me", "it", "its", "is", "am", "also", "kindly", "pls", "per", "said",
})
_SALUTATION = frozenset({
    "dear", "hi", "hello", "hey", "greetings", "good", "morning", "afternoon", "evening", "thanks", "thank", "regards", "best",
    "kind", "warm", "warmest", "cheers", "sincerely", "yours", "faithfully", "truly", "rgds",
})
# Common Singapore surnames that are also English words, so the English-word test alone would
# pass "Will Tan" or "Grace Ho". Surnames that are not English words need no list. "Low", "Long"
# and "See" are left out: as words they start too many ordinary phrases ("Low Income").
_SURNAME_WORDS = frozenset({"tan", "lee", "ho", "sim", "foo", "yap", "wee", "pang", "chew", "chin", "yip", "ma"})
# Organisation suffixes: "Tan Tock Seng Hospital" names a place, not the sender.
_ORG_SUFFIX = frozenset({
    "hospital", "polytechnic", "university", "college", "institute", "school", "academy", "centre", "center", "corporation",
    "corp", "pte", "ltd", "limited", "inc", "llp", "bank", "group", "holdings", "ministry", "board", "council", "authority", "agency",
    "foundation", "association", "society", "clinic", "company", "consulting", "consultancy", "campus", "library", "office",
    "ave", "avenue", "road", "street", "crescent", "lane", "boulevard", "masterclass", "workshop",
})
# A greeting or a sign-off that addresses an office, not a person.
_GENERIC = frozenset({
    "sir", "madam", "sir/madam", "madam/sir", "all", "everyone", "there", "team", "pace", "ntu", "office", "admissions", "admission",
    "admin", "registry", "finance", "enquiries", "enquiry", "department", "staff", "committee", "colleagues", "customer", "service",
    "services", "support", "general", "hiring", "manager", "noreply", "no-reply", "donotreply", "unit", "desk", "programme",
    "program", "secretariat", "hr", "accounts", "helpdesk", "mailbox", "notification", "notifications", "weekly", "newsletter",
})
_FUNCTION_WORDS = frozenset({"sent", "from", "my", "the", "via", "on", "for", "and", "with", "get", "to", "of", "is", "in", "at", "this", "email"})
_CLOSING = re.compile(
    r"(?:(?:many\s+|with\s+)?thanks|thank\s+you|(?:thanks|thank\s+you)\s*(?:and|&)\s*(?:best\s+|kind\s+|warm\s+)?regards|"
    r"(?:best|kind|warm|warmest)\s+(?:regards|wishes)|regards|best|cheers|sincerely|yours\s+(?:sincerely|faithfully|truly)|"
    r"rgds|br|terima\s+kasih(?:\s+(?:and|&)\s+regards)?)",
    re.IGNORECASE,
)
_GREETING = re.compile(r"^[ \t]*(?:dear|hi|hello|hey|greetings)[ \t]+(?P<who>[^\n,!:;]{1,80}?)[ \t]*(?:[,!:;]|$)", re.IGNORECASE | re.MULTILINE)
_INTRO = re.compile(r"\b(?:my\s+name\s+is|this\s+is)[ \t]+(?P<who>[^\n,.;:!?()]{1,80})", re.IGNORECASE)
_HERE_INTRO = re.compile(r"^[ \t]*(?P<who>[^\W\d_][^\s,.!]*(?:[ \t]+[^\W\d_][^\s,.!]*)?)[ \t]+here[ \t]*[.,!]", re.MULTILINE)
_FIELD = re.compile(r"^[ \t]*(?:full\s+)?(?:name|student\s+name|applicant\s+name|contact\s+name|contact\s+person|sender)[ \t]*:[ \t]*(?P<who>[^\n]{1,80})$", re.IGNORECASE | re.MULTILINE)


@lru_cache(maxsize=1)
def _known_words() -> frozenset[str]:
    with gzip.open(_HERE / "english_words.txt.gz", "rt", encoding="utf-8") as handle:
        words = {line.strip() for line in handle if line.strip()}
    words.update(public_words())
    return frozenset(words)


@lru_cache(maxsize=1)
def public_words() -> frozenset[str]:
    words: set[str] = set()
    for line in (_HERE / "public_words.txt").read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            words.update(word.casefold() for word in line.split())
    return frozenset(words)


def is_name_cased(word: str) -> bool:
    """Title Case or ALL CAPS, per hyphen/apostrophe part ("Aisha-Rose", "O'Connor", "LIM")."""
    parts = [part for part in re.split(r"['’\-]", word) if part]
    if not parts or "/" in word:
        return False
    def cased(part: str) -> bool:
        letters = "".join(character for character in part if character.isalpha())
        return bool(letters) and (letters.isupper() or (letters[0].isupper() and (len(letters) == 1 or letters[1:].islower())))
    if all(cased(part) for part in parts):
        return True
    # "O'Connor", "McDonald": a name prefix glued to a capitalised part.
    return len(parts) == 1 and bool(re.fullmatch(r"(?:Mc|Mac|O)[A-Z][a-z]+", word))


def is_known_word(word: str) -> bool:
    """An ordinary English or public word. All-caps tokens of two or three letters count as
    acronyms (NTU, SMU); longer ones need to be a word or listed ("PACE", "GIRO", but not "JANE")."""
    letters = "".join(character for character in word if character.isalpha())
    if letters.isupper() and 2 <= len(letters) <= 3:
        return True
    folded = word.casefold().replace("’", "'")
    if folded.endswith("'s"):
        folded = folded[:-2]
    known = _known_words()
    return folded in known or all(part in known for part in re.split(r"['\-/]", folded) if part)


def _joins(text: str, previous: str, previous_end: int, start: int) -> bool:
    """Words on one line separated by spaces; a full stop only after an initial ("J. Chen")."""
    gap = text[previous_end:start]
    return bool(re.fullmatch(r"[ \t]+", gap) or (len(previous) == 1 and re.fullmatch(r"\.[ \t]+", gap)))


def _tokens(text: str) -> list[tuple[str, int, int]]:
    """Words, with a possessive cut off: "Haoran's" is the name "Haoran"."""
    tokens = []
    for match in _TOKEN.finditer(text):
        word, end = match.group(), match.end()
        if len(word) > 3 and word[-2] in "'’" and word[-1] in "sS":
            word, end = word[:-2], end - 2
        tokens.append((word, match.start(), end))
    return tokens


def _name_tokens(who: str, offset: int) -> list[tuple[int, int]] | None:
    """The spans of a name written in a name position, or None if it is not a name."""
    tokens = _tokens(who)
    if not tokens or len(tokens) > 6 or re.search(r"\d|@", who):
        return None
    if any(word.casefold() in _GENERIC for word, _start, _end in tokens):
        return None
    if any(word.casefold() in _FUNCTION_WORDS for word, _start, _end in tokens):
        return None
    while tokens and tokens[0][0].casefold().strip(".") in TITLES:
        tokens = tokens[1:]
    if not tokens or any(word.casefold() in _SALUTATION for word, _start, _end in tokens):
        return None
    lower = all(word.islower() for word, _start, _end in tokens)
    if not lower and not all(is_name_cased(word) or word.casefold() in _PARTICLES for word, _start, _end in tokens):
        return None
    if lower and all(is_known_word(word) for word, _start, _end in tokens):
        return None
    return [(offset + tokens[0][1], offset + tokens[-1][2])]


def position_spans(text: str) -> list[tuple[int, int]]:
    """Names in a greeting, a sign-off, a self-introduction or a "Name:" field."""
    spans: list[tuple[int, int]] = []
    for pattern in (_GREETING, _INTRO, _HERE_INTRO, _FIELD):
        for match in pattern.finditer(text):
            who = match.group("who")
            if pattern is _INTRO:
                # "this is Kevin from ...": stop at the first word that is not part of a name.
                words = _tokens(who)
                kept = []
                for word, start, end in words:
                    if not (is_name_cased(word) or (kept and word.casefold() in _PARTICLES)):
                        break
                    kept.append((word, start, end))
                if not kept:
                    continue
                who = who[:kept[-1][2]]
            spans.extend(_name_tokens(who, match.start("who")) or [])
    lines = text.split("\n")
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    for index, line in enumerate(lines):
        stripped = line.strip()
        same_line = re.fullmatch(rf"(?:{_CLOSING.pattern})[ \t]*[,!.]?[ \t]+(?P<who>[^\n,|]+?)[ \t]*[.!]?", stripped, re.IGNORECASE)
        if same_line:
            start = offsets[index] + line.index(stripped) + same_line.start("who")
            spans.extend(_name_tokens(same_line.group("who"), start) or [])
            continue
        if not re.fullmatch(rf"(?:{_CLOSING.pattern})[ \t]*[,!.]*", stripped, re.IGNORECASE):
            continue
        following = next((later for later in range(index + 1, min(index + 4, len(lines))) if lines[later].strip()), None)
        if following is None:
            continue
        signature = lines[following]
        # "Camellia Ong | Data Analyst | Brightpath": the name is the first segment.
        cut = re.split(r"\s*(?:\||,|\(|\s-\s|–|—)\s*", signature.strip(), maxsplit=1)[0]
        start = offsets[following] + signature.index(signature.strip())
        spans.extend(_name_tokens(cut, start) or [])
    # A body that ends with a short name line, with or without a closing ("...\n\nTony").
    filled = [index for index, line in enumerate(lines) if line.strip()]
    if len(filled) >= 2:
        last = lines[filled[-1]].strip()
        if len(_tokens(last)) <= 3 and re.fullmatch(r"[^\W\d_][\w'’\-/ \t.]*", last):
            start = offsets[filled[-1]] + lines[filled[-1]].index(last)
            spans.extend(_name_tokens(last.rstrip(". "), start) or [])
    return spans


def title_spans(text: str) -> list[tuple[int, int]]:
    """A title followed by a name: "Ms Wong", "Dr Lim Hui Min", "Prof David Ng", "Dr Marta de Sousa"."""
    tokens = _tokens(text)
    spans: list[tuple[int, int]] = []
    for index, (word, _start, end) in enumerate(tokens):
        if word.casefold() not in TITLES - {"sir", "madam"} or not is_name_cased(word):
            continue
        name: list[tuple[str, int, int]] = []
        previous, previous_end = word, end
        for following, start, stop in tokens[index + 1:index + 6]:
            if not (_joins(text, previous, previous_end, start) or (previous is word and re.fullmatch(r"\.[ \t]+", text[previous_end:start]))):
                break
            if is_name_cased(following) and following.casefold() not in _EDGE:
                name.append((following, start, stop))
            elif following.casefold() in _PARTICLES and name:
                name.append((following, start, stop))
            else:
                break
            previous, previous_end = following, stop
        while name and name[-1][0].casefold() in _PARTICLES:
            name.pop()
        if name:
            spans.append((name[0][1], name[-1][2]))
    return spans


def shape_spans(text: str) -> list[tuple[int, int]]:
    """Runs of two or more capitalised words on one line with at least one non-English word."""
    tokens = _tokens(text)
    spans: list[tuple[int, int]] = []
    run: list[tuple[str, int, int]] = []

    def flush() -> None:
        words = list(run)
        while words and (words[0][0].casefold() in _EDGE or words[0][0].casefold() in _PARTICLES):
            words.pop(0)
        while words and (words[-1][0].casefold() in _EDGE or words[-1][0].casefold() in _PARTICLES):
            words.pop()
        named = [word for word, _start, _end in words if word.casefold() not in _PARTICLES]
        initial = bool(named) and len(named[0]) == 1 and named[0] not in {"I", "A"}
        evidence = initial or any(not is_known_word(word) or word.casefold() in _SURNAME_WORDS for word in named)
        if len(named) >= 2 and words[-1][0].casefold() not in _ORG_SUFFIX and evidence:
            spans.append((words[0][1], words[-1][2]))
        run.clear()

    for word, start, end in tokens:
        joinable = is_name_cased(word) or (run and word.casefold() in _PARTICLES)
        if run and (not joinable or not _joins(text, run[-1][0], run[-1][2], start)):
            flush()
        if is_name_cased(word):
            run.append((word, start, end))
        elif joinable:
            run.append((word, start, end))
    flush()
    return spans


def extend_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Grow a detected name over capitalised neighbours on the same line ("Camellia" + "Ong Hui Shan").

    Leftwards any capitalised word that is not a greeting/title/function word joins; rightwards
    only a capitalised word that is not an English word, so "Ho said" or "Tan Hospital" do not.
    """
    while True:
        before = re.search(r"([^\W\d_]+(?:['’\-][^\W\d_]+)*)([ \t]+)$", text[:start])
        if not before or not is_name_cased(before.group(1)) or before.group(1).casefold() in _EDGE:
            break
        start = before.start(1)
    while True:
        after = re.match(r"[ \t]+([^\W\d_]+(?:['’\-][^\W\d_]+)*)", text[end:])
        if not after or not is_name_cased(after.group(1)) or after.group(1).casefold() in _EDGE or is_known_word(after.group(1)):
            break
        end += after.end(1)
    return start, end


def repeated_name_spans(text: str, spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Other mentions of a word from a detected multi-word name: "Sunny Goh ... Does Sunny teach".

    A word that is also English ("Sunny", "Will") is skipped at the start of a sentence.
    """
    words: set[str] = set()
    for start, end in spans:
        found = [word for word, _start, _end in _tokens(text[start:end]) if word.casefold() not in TITLES and word.casefold() not in _PARTICLES]
        if len(found) >= 2:
            words.update(word for word in found if is_name_cased(word) and len(word) >= 2)
    extra: list[tuple[int, int]] = []
    for word, start, end in _tokens(text):
        if word not in words or any(begin <= start < stop for begin, stop in spans):
            continue
        if is_known_word(word) and re.search(r"(?:^|[.!?:]\s+|\n\s*)$", text[:start]):
            continue
        extra.append((start, end))
    return extra


def is_public_phrase(value: str) -> bool:
    """Every word is a greeting/title word or a public word: "Madam", "Cheers", "Cloud Computing" stays."""
    words = [word.casefold() for word, _start, _end in _tokens(value)]
    return bool(words) and all(word in _EDGE or word in public_words() or word in _GENERIC for word in words)


def known_name_terms(addresses: Iterable[str | None]) -> tuple[str, ...]:
    """Display names from From/To/Cc, and those of their words that are not ordinary English words.

    "Mei Xuan Koh <meixuan@...>" gives "Mei Xuan Koh", "Mei", "Xuan", "Koh". "Grace Ho" gives only the
    full name, because "grace" and "ho" are English words. Office mailboxes give nothing.
    """
    terms: set[str] = set()
    for _name, _address in getaddresses([value for value in addresses if value]):
        name = re.sub(r"\([^)]*\)", " ", _name).strip().strip("\"'")  # "Jun Hao Lim (PaCE Enquiries)"
        words = [word for word, _start, _end in _tokens(name)]
        if not words or len(words) > 6 or re.search(r"\d|@", name):
            continue
        if any(word.casefold() in _GENERIC for word in words):
            continue
        if len(words) >= 2:
            terms.add(" ".join(words))
        terms.update(word for word in words if len(word) >= 2 and word.casefold() not in TITLES and word.casefold() not in _PARTICLES and not is_known_word(word))
    return tuple(sorted(terms, key=lambda term: (-len(term), term)))


def known_name_spans(text: str, terms: Iterable[str]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for term in terms:
        pattern = r"[ \t]+".join(re.escape(word) for word in term.split())
        # A possessive ends the name: "Wang Haoran's application".
        spans.extend((match.start(), match.end()) for match in re.finditer(rf"(?<![\w'’-]){pattern}(?=['’]s\b|[^\w'’-]|$)", text, re.IGNORECASE))
    return spans
