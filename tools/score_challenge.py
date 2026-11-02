"""Score a submitted claim against the withheld answer key.

A challenge whose scoring rule is described but not implemented is a rule
that gets argued about after somebody claims a win. This is the rule.

    python tools/score_challenge.py answer-key.json claim.json \\
        --expect-digest <the SHA-256 published with the dataset>

A claim is one JSON object mapping citizen identifier to base64url ad-hoc
public key, spelled as `ledger.json` spells them. It may name as many or as
few citizens as the claimant likes.

The verdict is a p-value, not an opinion. Under the null hypothesis -- the
record leaks nothing, so a claim is guessing -- each named citizen is right
with probability 1/N independently, where N is the number of citizens in the
answer key. The probability of getting *at least* the observed number of
hits by chance is computed exactly from the binomial distribution, with no
normal approximation: the counts are small, the tail is what matters, and an
approximation in the tail is exactly where it is worst.

Nothing here depends on anything outside the standard library, and that is
deliberate for a tool somebody else is meant to be able to run against our
answer without taking our word for the arithmetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

#: Below this the claim is treated as a win: the record leaked. One in a
#: thousand rather than the customary one in twenty, because this is a
#: public claim about a cryptographic property and somebody will submit
#: many claims. A threshold that a handful of attempts can cross by luck is
#: a threshold that will be crossed by luck.
ALPHA = 1e-3


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def at_least(hits: int, claimed: int, n: int) -> float:
    """P(at least `hits` correct) for `claimed` independent guesses of 1/n.

    Exact, summed from the far tail inward so the smallest terms are added
    first. `math.comb` and floats are enough here: the numbers a claim
    produces are small, and summing from the top avoids losing the tail to
    a partial sum that is already of order one.
    """
    if n <= 0 or claimed <= 0:
        return 1.0
    hits = max(0, min(hits, claimed))
    if hits == 0:
        return 1.0
    p = 1.0 / n
    total = 0.0
    for k in range(claimed, hits - 1, -1):
        total += math.comb(claimed, k) * (p ** k) * ((1.0 - p) ** (claimed - k))
    return min(1.0, total)


def score(answer: dict, claim: dict) -> dict:
    """Hits, the population guessed from, and how surprising that is.

    Citizens named in the claim that the answer key has never heard of are
    counted and reported rather than ignored. They are not hits, and a
    claim padded with invented identifiers must not look better than one
    that was honest about its scope -- but silently dropping them would
    also hide a claimant who was working from a different election.
    """
    truth = answer["citizen_to_adhoc_key"]
    n = len(truth)

    unknown = sorted(set(claim) - set(truth))
    named = [voter for voter in claim if voter in truth]
    hits = sorted(voter for voter in named if claim[voter] == truth[voter])

    claimed = len(claim)          # the claimant's own stated scope
    p = at_least(len(hits), claimed, n)
    return {
        "election_id": answer.get("election_id"),
        "citizens": n,
        "claimed": claimed,
        "recognised": len(named),
        "unknown": unknown,
        "hits": len(hits),
        "correct": hits,
        "expected_by_chance": claimed / n if n else 0.0,
        "p_value": p,
        "leaked": p < ALPHA,
    }


def report(result: dict) -> str:
    lines = [
        f"election            {result['election_id']}",
        f"citizens            {result['citizens']}",
        f"claimed             {result['claimed']}",
        f"recognised          {result['recognised']}",
        f"hits                {result['hits']}",
        f"expected by chance  {result['expected_by_chance']:.4f}",
        f"p-value             {result['p_value']:.3e}",
    ]
    if result["unknown"]:
        shown = ", ".join(result["unknown"][:5])
        more = "" if len(result["unknown"]) <= 5 else f" (+{len(result['unknown']) - 5} more)"
        lines.append(f"not in this election {shown}{more}")
    lines.append("")
    if result["leaked"]:
        lines.append(
            f"CLAIM UPHELD. {result['hits']} correct out of "
            f"{result['claimed']} is not chance (p < {ALPHA:g}). The record "
            "links citizens to ballots and the design's privacy claim is "
            "wrong, or this dataset leaks something a real poll would not. "
            "Either is a finding; publish the method.")
    else:
        lines.append(
            f"CLAIM NOT UPHELD. {result['hits']} correct out of "
            f"{result['claimed']} is consistent with guessing "
            f"(p = {result['p_value']:.3e}, threshold {ALPHA:g}).")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("answer_key", type=Path)
    parser.add_argument("claim", type=Path)
    parser.add_argument(
        "--expect-digest",
        help="the answer key's SHA-256 as published with the dataset; the "
             "scorer refuses to run if it does not match")
    args = parser.parse_args(argv)

    if args.expect_digest:
        # The half of the commitment that protects the *claimant*. Without
        # it they are taking our word that the file they are scored against
        # is the one we committed to.
        actual = digest(args.answer_key)
        if actual != args.expect_digest.strip().lower():
            print(f"answer key does not match the published digest\n"
                  f"  published {args.expect_digest}\n"
                  f"  this file {actual}", file=sys.stderr)
            return 2

    answer = json.loads(args.answer_key.read_text(encoding="utf-8"))
    claim = json.loads(args.claim.read_text(encoding="utf-8"))
    if not isinstance(claim, dict):
        print("a claim is one JSON object: citizen identifier to base64url "
              "ad-hoc public key", file=sys.stderr)
        return 2

    result = score(answer, claim)
    print(report(result))
    return 1 if result["leaked"] else 0


if __name__ == "__main__":
    sys.exit(main())
