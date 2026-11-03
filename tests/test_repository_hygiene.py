"""What this repository must never carry, and the rules that stop it.

Written after it carried all of it. A generated election was committed by
a working copy that was not looked at -- 27 MB, ten thousand synthetic
citizens, every wallet seed, and `answer-keys/008-gen-261102_A.json`,
which is the citizen-to-ad-hoc-key mapping that *is* the answer to a
challenge of exactly the kind `docs/Challenge.md` publishes.

`service/generate.py` already said the rule in its own docstring: the
answer key is written beside the elections "and never inside one, so
publishing an election cannot publish its answer". The rule was right and
nothing enforced it, which is the shape of fault this suite exists for.

**Why `.gitignore` rather than the tracked state.** Knowing what git
tracks means running git, and `CLAUDE.md` is explicit that the suite
depends on what `pyproject.toml` declares and on nothing else -- a suite
that needs a command-line tool means something different on two machines.
So these read the ignore rules and check they would stop the paths that
matter, which is the rule rather than today's state; CI greps
`git ls-files` for the state, where git is a given.

A filesystem check is not an option either, and the reason is worth
keeping: `service/__main__.py` defaults `--data` to `election-data`, so a
developer who runs `python -m service` legitimately has elections sitting
there. Forbidding them on disk would fail the suite for doing the thing
the README tells you to do.
"""

from __future__ import annotations

import fnmatch
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Paths that must be ignored, and why each one is here.
MUST_BE_IGNORED = [
    ("election-data/answer-keys/022-gen-261103_A.json",
     "the answer to a published challenge"),
    ("election-data/009-gen-261105_X/election.store.json",
     "a generated electorate's wallet seeds"),
    ("election-data/009-gen-261105_X/closed/ledger.json",
     "a generated election's ledger, which is megabytes"),
    ("election-data/009-gen-261105_X/poll.state.json",
     "the office's openings and signed requests"),
    ("election-data/current",
     "rewritten by every mint, so a checkout that minted has a diff forever"),
    ("deploy/election-data/022-gen-261103_A/election.store.json",
     "the live volume, which is a deployment's and not a repository's"),
    ("deploy/.env", "a file whose whole genre is secrets"),
    ("ledger-demo-2026.json", "what a demo run wrote into the checkout"),
    ("releases-demo-2026.json", "the same"),
    ("output_ext_demo.txt", "the same"),
    ("Claude outputs/0085-something.patch", "a delivered patch file"),
    ("web/voter-app/static/bundle.js", "a build artefact"),
]

#: And paths that must *not* be, because the repository is meant to carry
#: them. Checked in both directions: an ignore rule wide enough to catch
#: the answer key is easily wide enough to drop the trust anchors, and
#: that failure is silent until an office comes up offering no route.
MUST_NOT_BE_IGNORED = [
    ("election-data/trust-anchors/manifest.json",
     "what this office is willing to believe, pinned"),
    ("election-data/election.store.json",
     "the one shipped election, clause X4"),
    ("election-data/vro_token_key.pem", "its token key, likewise"),
    ("election-data/README.md", "what that directory is"),
    ("tests/vectors/keys.json", "a private key published on the same reasoning"),
]


def rules() -> list[tuple[str, bool]]:
    """`.gitignore` as (pattern, is_negation), comments and blanks dropped."""
    lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        out.append((line.lstrip("!"), negated))
    return out


def ignored(path: str) -> bool:
    """Does `.gitignore` ignore this path?

    A deliberately small subset of git's matching: anchored patterns,
    directory patterns, and `*` within a segment. Last match wins, which
    is git's rule and the one the trust-anchors exception depends on.

    The part worth stating, because getting it wrong is how a first
    attempt at this file declared `election-data/README.md` ignored: a
    directory pattern matches a *prefix* of the path, so the path must
    have more segments than the pattern. `election-data/*/` catches
    `election-data/009-x/store.json` and leaves `election-data/README.md`
    alone, which is exactly the distinction the cleanup rests on.

    Not a reimplementation of gitignore and not trying to be. It covers
    the shapes this file uses, and a pattern it cannot read is a reason to
    simplify the pattern rather than to grow this.
    """
    verdict = False
    parts = path.split("/")

    for pattern, negated in rules():
        anchored = pattern.startswith("/") or "/" in pattern.strip("/")
        directory_only = pattern.endswith("/")
        segments = [p for p in pattern.strip("/").split("/") if p]

        if anchored:
            # Matched against the start of the path.
            hit = (len(parts) >= len(segments)
                   and all(fnmatch.fnmatch(a, b)
                           for a, b in zip(parts, segments)))
            # A directory pattern names a container, so the path has to
            # go on past it. Without this, `election-data/*/` would claim
            # `election-data/README.md`.
            if hit and (directory_only or len(segments) < len(parts)):
                hit = len(parts) > len(segments)
        else:
            # Unanchored: any single segment may match, and a directory
            # pattern may not match the last one.
            last = len(parts) - 1
            hit = any(fnmatch.fnmatch(part, segments[0])
                      for i, part in enumerate(parts)
                      if not (directory_only and i == last))

        if hit:
            verdict = not negated
    return verdict


@pytest.mark.parametrize("path, why", MUST_BE_IGNORED,
                         ids=[p for p, _ in MUST_BE_IGNORED])
def test_the_rules_would_keep_it_out(path, why):
    assert ignored(path), (
        f"{path} is not ignored, and it is {why}.\n\n"
        "This is how 27 MB of generated election and the answer to a "
        "challenge got committed: nothing stopped them, and a working "
        "copy nobody looked at did the rest.")


@pytest.mark.parametrize("path, why", MUST_NOT_BE_IGNORED,
                         ids=[p for p, _ in MUST_NOT_BE_IGNORED])
def test_the_rules_do_not_take_the_repository_with_them(path, why):
    assert not ignored(path), (
        f"{path} is ignored, and it is {why}. A rule wide enough to catch "
        "an answer key is easily wide enough to drop the trust anchors, "
        "and an office that comes up offering no qualified-signature "
        "route does not say it was a .gitignore that did it.")


def test_the_shipped_election_is_not_a_generated_one():
    """Clause X4 publishes one electorate on purpose. One, and chosen.

    X4's argument is that a reader should open the file and see exactly
    what the demonstration holds on each voter's behalf. It rests on the
    file being small enough to open and the electorate being the invented
    handful the README describes -- not on it being whatever the last
    local run left behind.
    """
    import json

    store = ROOT / "election-data" / "election.store.json"
    assert store.exists(), (
        "the repository ships no election, so a clone cannot be voted in "
        "at once -- which is what clause X4 and the README promise")
    body = json.loads(store.read_text(encoding="utf-8"))
    assert not body.get("generated"), (
        "the shipped election declares a generated electorate. Every "
        "signature in it is real, which is exactly why nothing downstream "
        "can tell -- and a clone would serve it believing it was a "
        "demonstration poll")
    assert len(body["electoral_register"]) < 100, (
        f"the shipped register holds {len(body['electoral_register'])} "
        "voters. X4 publishes every one of their wallet seeds in the "
        "clear, and that argument does not survive at scale")
