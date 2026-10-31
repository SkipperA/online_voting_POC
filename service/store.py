"""What survives a restart, and what does not.

The split is not arbitrary.  The durable half is everything the setup console
authors *before* the poll opens -- Phase A of the action table: the two key
pairs, the electoral register, the wallet personas, and the configuration
derived from them.  The volatile half is everything the poll itself produces:
the ballot box, the hash chain, the released-token register.

So restarting mid-demonstration loses the votes and keeps the election, which
is the right way round.  The alternative -- minting a fresh key at every
startup, as this service did until now -- silently voids every open page,
every saved token request and every token already issued, and makes the
pinning story on the voter's page aspirational rather than true: a
fingerprint that changes whenever the process restarts is not something
anybody could have pinned.

**The volatile half is a scope limit, not a design claim.** A real ballot box
does not lose its contents when its process stops. Clause: the demo's box and
release register are in memory.

**The store is committed, key material and all.** Every wallet seed in it is
in the clear, because one machine has to play a whole electorate and the
substitution should be visible rather than hinted at. A reader can open the
file and see exactly what the demo holds on each voter's behalf, which is
worth more here than the habit of hiding keys -- the voters are fictional,
the election is a demonstration, and `tests/vectors/keys.json` already
publishes a private key on the same reasoning. What must not happen is anyone
mistaking this for a deployment artefact, so the file says so about itself.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from ovpoc import keys, rsabssa
from ovpoc.messages import b64, unb64

STORE_VERSION = 5

# Earlier versions are still readable, and deliberately so. Each difference
# is a field whose absence means exactly what the older behaviour was:
# `tally_interval_seconds` (version 2) absent means no publication interval,
# so the close is the only publication point; `opens` and `closes` (version
# 3) absent means the pair the service used to hold as literals, which is
# what every store written before them was serving; `question` and `options`
# (version 4) absent means a ballot that names nothing and is numbered, which
# is what every election before them was; `minted_at` (version 5) absent
# means an election authored before anything recorded when, which no amount
# of reading the file can recover -- the selector prints a dash rather than
# the modification time, which moves on every enrolment and would be a
# plausible wrong answer. Refusing an election because its file predates a
# field that defaults to the old behaviour would lose the token key, the
# register and every persona for nothing. The next save writes the current
# version.
READABLE_STORE_VERSIONS = {1, 2, 3, 4, 5}

# What a store written before the schedule was authored was serving. Not a
# sensible default for a new election -- the console asks for one -- but the
# only honest reading of a file that predates the field.
LEGACY_OPENS = "2026-09-25T08:00:00Z"
LEGACY_CLOSES = "2026-09-25T20:00:00Z"


class NoElection(RuntimeError):
    """Raised when the runtime is asked to serve an election nobody created.

    Deliberately fatal rather than falling back to minting one. An election
    that appears because a process started is not an election.
    """


class NoElectionYet(NoElection):
    """Nothing has been authored here, which is not a misconfiguration.

    Separated from its parent because the two look alike on the way out and
    are answered differently. A pointer naming a directory that holds no
    election is an operator's mistake and has to stay loud: the service
    refuses to start and names the directories that do hold one. An empty
    data directory is the first start of a new deployment, and the answer to
    that is the setup console -- which cannot be the answer if the process
    exits before serving it.

    Catching the parent where this is meant would turn a wrong pointer into
    a silent fresh start, on top of an election still sitting on the disk.
    """


#: Names the folder under the parent that the service serves. A file rather
#: than a symlink: it survives a zip, a checkout on Windows and a diff, and
#: a reader can see which election is current by opening it.
POINTER = "current"


def _slug(election_id: str) -> str:
    """An ASCII directory name for an election named in any language.

    Flattened deliberately. A folder called `időközi-2027` is correct on
    every system this will ever run on and still a nuisance on some of
    them, and the identifier is kept verbatim in the store inside -- the
    directory name is a handle, not the record.
    """
    stripped = unicodedata.normalize("NFKD", election_id).encode("ascii", "ignore")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", stripped.decode()).strip("-.")
    return cleaned[:48] or "election"


def allocate(parent: Path, election_id: str) -> Path:
    """A new folder for a new election, beside whatever is already there.

    Numbered as well as named, and the number is what makes it safe: two
    elections may legitimately carry the same identifier -- the console
    will mint `demo-2026` over `demo-2026` without blinking -- and the
    second one's keys must not land on the first one's. The sequence is
    allocated from what exists rather than stored, so a folder deleted by
    hand leaves a gap instead of a collision.
    """
    parent.mkdir(parents=True, exist_ok=True)
    used = [int(m.group(1)) for d in parent.iterdir() if d.is_dir()
            if (m := re.match(r"(\d{3})-", d.name))]
    folder = parent / f"{max(used, default=0) + 1:03d}-{_slug(election_id)}"
    folder.mkdir()
    (parent / "README.md").write_text(
        "# election-data\n\n"
        "One directory per election, each holding the durable half that the\n"
        "setup console authored: the two key pairs, the electoral register and\n"
        "the wallet personas. `current` names the one the service serves.\n\n"
        "Minting from the console writes a **new** directory and moves the\n"
        "pointer. Nothing here is overwritten, so the keys of an election that\n"
        "has been superseded are still on disk and can be served again with\n"
        "`python -m service --election <directory>` -- which is what lets a\n"
        "ledger downloaded from a past election still be checked against the\n"
        "configuration it was published under.\n\n"
        "**Committed on purpose, key material included.** See the README inside\n"
        "each directory. The voters are fictional and these are not elections.\n",
        encoding="utf-8",
    )
    return folder


def current(parent: Path) -> Path:
    """The folder the service should serve, or the parent itself.

    The second case is the layout that came before this one, where a single
    election lived directly in `election-data/`. It is read where it lies
    rather than migrated: moving a committed directory out from under a
    checkout is not something a start-up should do on its own, and a save
    puts it back where it was found.
    """
    pointer = parent / POINTER
    if pointer.exists():
        named = parent / pointer.read_text(encoding="utf-8").strip()
        if (named / "election.store.json").exists():
            return named
        raise NoElection(
            f"{pointer} names {named.name}, which holds no election. Point it "
            f"at one of {', '.join(sorted(d.name for d in parent.iterdir() if d.is_dir())) or 'nothing'}."
        )
    if (parent / "election.store.json").exists():
        return parent                      # the single-election layout
    raise NoElectionYet(
        f"no election under {parent}. The setup console mints the first one, "
        f"and every other origin refuses until it has; `python -m service "
        f"--init` mints one before serving instead. The runtime does not mint "
        f"keys on its own: an election that appears because a process started "
        f"is not an election."
    )


def point_at(parent: Path, folder: Path) -> None:
    """Make `folder` the one a plain `python -m service` serves."""
    if folder == parent:
        return                             # the old layout points at itself
    (parent / POINTER).write_text(folder.name + "\n", encoding="utf-8")


def seed_of(pair: keys.SigningKeyPair) -> bytes:
    return pair.private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def pair_from(seed: bytes) -> keys.SigningKeyPair:
    return keys.SigningKeyPair(ed25519.Ed25519PrivateKey.from_private_bytes(seed))


def write(path: Path, *, token_private, statement_key, box_statement_key,
          register, personas,
          election_id: str, num_choices: int, opens: str, closes: str,
          tally_interval_seconds: int | None = None,
          question: str | None = None,
          options: Sequence[str] | None = None,
          minted_at: str | None = None) -> None:
    """Write the durable half. Called by the setup console, never at runtime."""
    path.mkdir(parents=True, exist_ok=True)
    (path / "README.md").write_text(
        "# one election\n\n"
        "The durable half of a demonstration election, written by the setup\n"
        "console and served when `../current` names this directory.\n\n"
        "**Committed on purpose, key material included.** `election.store.json`\n"
        "carries every wallet seed in the clear and `vro_token_key.pem` is the\n"
        "office's token signing key. Publishing them is the point: the demo\n"
        "substitutes a file for an eIDAS wallet and a directory for an HSM, and\n"
        "a reader should be able to see exactly what that substitution costs\n"
        "rather than take it on trust. The voters are fictional and this\n"
        "election is not one.\n\n"
        "What is **not** here is everything the poll produced: the ballot box,\n"
        "the hash chain and the released-token register are in memory and are\n"
        "lost when the process stops. A real ballot box does not forget its\n"
        "contents; this one does.\n",
        encoding="utf-8",
    )
    (path / "vro_token_key.pem").write_bytes(
        token_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (path / "election.store.json").write_text(
        json.dumps(
            {
                "store_version": STORE_VERSION,
                "warning": (
                    "DEMONSTRATION KEY MATERIAL, PUBLISHED DELIBERATELY. Every "
                    "wallet seed below is in the clear so that a reader can see "
                    "what this demo holds on each voter's behalf. The voters are "
                    "fictional and this election is not one. A deployment keeps "
                    "k_s^(v) in hardware it never leaves, and keeps k_s^(R) "
                    "nowhere a file can reach."
                ),
                "election_id": election_id,
                # When this election was authored, carried by the deployment
                # and written unchanged on every later save. Not the file's
                # own modification time, which moves whenever somebody is
                # enrolled, and not in `election.json`: a time in the pinned
                # configuration would move the digest for a fact about the
                # deployment rather than about the ballot, which is the
                # argument `service/build.py` makes for the revision.
                "minted_at": minted_at,
                "num_choices": num_choices,
                # Written whole rather than derived back from the published
                # configuration at load: this file is what an election *is*
                # between restarts, and a store that could not reproduce the
                # ballot would reproduce a different election under the same
                # keys.
                "question": question,
                "options": None if options is None else list(options),
                "tally_interval_seconds": tally_interval_seconds,
                "opens": opens,
                "closes": closes,
                "vro_statement_seed": b64(seed_of(statement_key)),
                "ebb_statement_seed": b64(seed_of(box_statement_key)),
                "electoral_register": sorted(register),
                # Wallet personas. A real wallet's key is in hardware and is
                # never written anywhere, least of all beside the election.
                # This file is the substitution, and it is why the store must
                # never be mistaken for a deployment artefact.
                "wallet_seeds": {v: b64(seed_of(p)) for v, p in sorted(personas.items())},
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def read(path: Path) -> dict:
    store = path / "election.store.json"
    pem = path / "vro_token_key.pem"
    if not store.exists() or not pem.exists():
        raise NoElection(
            f"{path} is not a complete election: it needs both "
            f"election.store.json and vro_token_key.pem."
        )
    body = json.loads(store.read_text(encoding="utf-8"))
    body.pop("warning", None)   # prose for the reader, not a field
    if body.get("store_version") not in READABLE_STORE_VERSIONS:
        raise NoElection(
            f"{store.name} declares store_version {body.get('store_version')!r}, "
            f"which this service does not understand (expected one of "
            f"{sorted(READABLE_STORE_VERSIONS)})."
        )
    private = serialization.load_pem_private_key(pem.read_bytes(), password=None)
    return {
        "election_id": body["election_id"],
        "minted_at": body.get("minted_at"),
        "num_choices": body["num_choices"],
        "question": body.get("question"),
        "options": body.get("options"),
        "tally_interval_seconds": body.get("tally_interval_seconds"),
        "opens": body.get("opens", LEGACY_OPENS),
        "closes": body.get("closes", LEGACY_CLOSES),
        "token_private": private,
        "token_public": private.public_key(),
        "statement_key": pair_from(unb64(body["vro_statement_seed"])),
        "box_statement_key": pair_from(unb64(body["ebb_statement_seed"]))
        if "ebb_statement_seed" in body else None,
        "electoral_register": set(body["electoral_register"]),
        "wallet_personas": {
            v: pair_from(unb64(s)) for v, s in body["wallet_seeds"].items()
        },
    }


def describe(folder: Path) -> dict | None:
    """One election as a row on a page, without loading it.

    Deliberately not `read`. That parses a PKCS#8 private key, which is the
    expensive half of reading an election, and a console listing nine of
    them has no business doing nine key loads to print nine names. Nothing
    here constructs anything: it is JSON, and whether a file exists.

    `None` for a directory that is not an election, so the anchors, a
    half-made folder and whatever else an operator leaves beside the
    elections are skipped rather than listed as broken ones.
    """
    if not (folder / "election.store.json").exists():
        return None
    if not (folder / "vro_token_key.pem").exists():
        return None
    try:
        body = json.loads((folder / "election.store.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    # The published record of a finished poll, written once at the close.
    # Its presence is what distinguishes an election that ran from one that
    # was minted and abandoned -- and the count is read from the office's
    # own dump rather than recomputed, because that file is what a verifier
    # was handed.
    closed = folder / "closed"
    released: int | None = None
    try:
        released = json.loads(
            (closed / "releases.json").read_text(encoding="utf-8"))["count"]
    except (OSError, ValueError, KeyError, TypeError):
        released = None

    return {
        "directory": folder.name,
        "election_id": body.get("election_id"),
        # Absent in a store written before anything recorded it. A dash on
        # the page, never the file's modification time: that moves whenever
        # somebody is enrolled, so it would be a plausible wrong answer,
        # which is worse than no answer.
        "minted_at": body.get("minted_at"),
        "num_choices": body.get("num_choices"),
        "question": body.get("question"),
        "closed": closed.is_dir(),
        "tokens_released": released,
    }


def listing(parent: Path) -> list[dict]:
    """Every election on disk, in directory order, saying which is served.

    Reading only. This is not an upload surface and does not create,
    migrate or repair anything: a directory that is not an election is left
    exactly where it is and left out of the list.
    """
    if not parent.is_dir():
        return []
    try:
        served: Path | None = current(parent)
    except NoElection:
        served = None                      # nothing pointed at, or nothing there

    folders = sorted((d for d in parent.iterdir() if d.is_dir()),
                     key=lambda d: d.name)
    if (parent / "election.store.json").exists():
        folders = [parent, *folders]       # the single-election layout
    out = []
    for folder in folders:
        described = describe(folder)
        if described is None:
            continue
        if folder == parent:
            described["directory"] = "."   # it points at itself
        described["served"] = served is not None and folder == served
        out.append(described)
    return out
