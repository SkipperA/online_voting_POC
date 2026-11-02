"""Build the challenge bundle from a closed generated election.

What this does and, more importantly, what it refuses to do.

It copies four files out of an election's `closed/` directory, writes the
statement beside them with that election's digests filled in, and writes a
manifest of SHA-256s. It never reads the answer key's *contents* -- only
its digest -- so a mistake here cannot put the answer in the bundle.

Run on the machine holding the data volume:

    python tools/publish_challenge.py \\
        deploy/election-data/election-0003 \\
        --answer-key deploy/election-data/answer-keys/election-0003.json \\
        --out /tmp/challenge-0003

Then attach the bundle to a release. It is deliberately not served by any
origin: the hosted deployment is a single-core VPS, a conference audience
downloading several megabytes from it at once is a self-inflicted outage,
and a dataset whose availability depends on the demonstration still running
is not a published dataset.

`tools/` may shell out and may assume things `tests/` may not; this one
assumes nothing beyond the standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: The four files, in the order the statement's table lists them. The first
#: three are what any citizen could download while the poll was open; the
#: fourth is the office's own register, which a real deployment keeps behind
#: its perimeter and a generated election publishes on purpose.
PUBLISHED = ("election.json", "ledger.json", "releases.json", "supervision.json")

STATEMENT = ROOT / "docs" / "Challenge.md"


def digest(path: Path) -> str:
    """SHA-256 of a file, read in chunks.

    Chunked because the ledger of a ten-thousand-voter election is not
    small and there is no reason for this to be the thing that cannot run
    on the server it is run on.
    """
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_election(closed: Path) -> dict:
    """The configuration, for the identity this bundle claims to be about."""
    return json.loads((closed / "election.json").read_text(encoding="utf-8"))


def build(election_dir: Path, answer_key: Path, out: Path) -> dict:
    """Write the bundle. Returns the manifest it wrote.

    Every refusal here is about publishing the wrong thing rather than
    about tidiness, so each one names what would have gone wrong.
    """
    closed = election_dir / "closed"
    if not closed.is_dir():
        raise SystemExit(
            f"{election_dir} has no closed/ directory. A challenge is "
            "published from a poll that finished: the record is written at "
            "the close and nowhere else.")

    missing = [name for name in PUBLISHED if not (closed / name).is_file()]
    if missing:
        extra = ""
        if "supervision.json" in missing:
            extra = (
                "\n\nsupervision.json is written at the close for a "
                "*generated* election only. Either this election was not "
                "generated -- in which case publishing its register would "
                "publish a real participation register, which is the one "
                "thing §3.7 keeps out of public view -- or it closed before "
                "the box produced a verifiable closing statement.")
        raise SystemExit(f"{closed} is missing: {', '.join(missing)}{extra}")

    config = read_election(closed)
    if not config.get("generated"):
        raise SystemExit(
            f"{closed / 'election.json'} does not declare `generated`. This "
            "tool publishes a synthetic electorate and an office register "
            "together; doing that to a real poll would publish who voted.")

    if not answer_key.is_file():
        raise SystemExit(
            f"{answer_key} does not exist. The challenge is a claim without "
            "it: its digest is what lets a submitted solution be scored "
            "against an answer nobody could have moved afterwards.")

    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in PUBLISHED:
        shutil.copyfile(closed / name, out / name)
        files[name] = digest(out / name)

    # The answer key is *hashed*, never copied and never parsed. Keeping it
    # out of this function's reach is cheaper than remembering not to write
    # it: there is no code path here that holds its contents.
    answer_digest = digest(answer_key)

    manifest = {
        "format": "ovpoc-challenge/1",
        "election_id": config["election_id"],
        "configuration_digest": files["election.json"],
        "files": files,
        "withheld": {
            "answer_key": {
                "filename": answer_key.name,
                "sha256": answer_digest,
                "note": (
                    "The true mapping from citizen to ad-hoc public key. Not "
                    "in this bundle. This digest is the commitment: it is "
                    "published now so that a claim submitted later is scored "
                    "against an answer that cannot have been changed."),
            }
        },
    }
    (out / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8")

    statement = STATEMENT.read_text(encoding="utf-8")
    header = "\n".join([
        "<!-- Written by tools/publish_challenge.py. This copy is the one"
        " that binds. -->",
        "",
        f"> **Election** `{config['election_id']}`  ",
        f"> **Configuration digest** `{files['election.json']}`  ",
        f"> **Answer key SHA-256** `{answer_digest}`  ",
        "> The answer key is withheld. Its digest above is published now, with"
        " the dataset.",
        "",
        "---",
        "",
    ])
    (out / "CHALLENGE.md").write_text(header + statement, encoding="utf-8")

    # A plain sha256sum file beside the JSON one, because the first thing
    # anybody does with a downloaded dataset is check it with the tool they
    # already have rather than with ours.
    (out / "SHA256SUMS").write_text(
        "".join(f"{value}  {name}\n" for name, value in sorted(files.items())),
        encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("election", type=Path,
                        help="an election directory holding closed/")
    parser.add_argument("--answer-key", type=Path, required=True,
                        help="the withheld mapping; hashed, never copied")
    parser.add_argument("--out", type=Path, required=True,
                        help="directory to write the bundle into")
    args = parser.parse_args(argv)

    manifest = build(args.election.resolve(), args.answer_key.resolve(),
                     args.out.resolve())
    print(f"bundle written to {args.out}")
    print(f"  election      {manifest['election_id']}")
    for name, value in sorted(manifest["files"].items()):
        print(f"  {name:<20} {value}")
    print(f"  answer key    {manifest['withheld']['answer_key']['sha256']}"
          "  (withheld)")
    print()
    print("Publish the digest above with the dataset, before the challenge "
          "opens.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
