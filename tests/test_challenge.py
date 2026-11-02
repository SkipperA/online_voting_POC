"""The challenge: what is published, what is withheld, and how a claim is scored.

A generated election is published whole -- including the office's own
register, which a real poll keeps behind its supervision perimeter -- with
an invitation to link a citizen to their ballot. `docs/Challenge.md` is the
statement; these are the parts of it that can be made to fail.

Three properties, and they are different in kind:

  * the dataset is the *real* record, not a second rendering of it made for
    the occasion. A challenge about a file this project wrote specially is
    a challenge about nothing;
  * the answer never leaves. The bundle carries its digest, which is what
    lets a claim submitted later be scored against an answer that cannot
    have moved;
  * the scoring rule exists as code. A rule described but not implemented
    is a rule that gets argued about after somebody claims a win.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from ovpoc.messages import canonical_bytes
from service import api, generate
from service.generate import ANSWER_KEYS, Distribution
from service.state import Deployment

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import publish_challenge  # noqa: E402
import score_challenge  # noqa: E402
import verify_election  # noqa: E402

TEST_BITS = 2048

#: Small. Nothing here is about scale -- the generator's own tests cover
#: that -- and every ballot is a blind signature.
PLAN = Distribution(per_option={1: 5, 2: 4, 3: 3},
                    protest={-1: 2}, abstentions=3, revotes=2)


def _made(root, *, generated: bool) -> Deployment:
    made = Deployment.create(
        bits=TEST_BITS, election_id="challenge-2026", num_choices=3,
        question="Ki legyen a képviselő?", options=["Egy", "Kettő", "Három"],
        generated=generated, document_root=root / "config", trust_anchors=None)
    made.data_dir = root / "elections"
    made.save(made.data_dir)
    return made


@pytest.fixture(scope="module")
def published(tmp_path_factory):
    """One filled, closed, archived generated election."""
    made = _made(tmp_path_factory.mktemp("challenge"), generated=True)
    generate.populate(made, PLAN)
    api.archive_at_close(made)
    return made


@pytest.fixture(scope="module")
def answer_key(published) -> Path:
    return published.data_dir / ANSWER_KEYS / f"{published.data_folder.name}.json"


@pytest.fixture(scope="module")
def bundle(tmp_path_factory, published, answer_key) -> Path:
    out = tmp_path_factory.mktemp("bundle")
    publish_challenge.build(published.data_folder, answer_key, out)
    return out


# -- the office's register is archived, and only when nobody is exposed ----

def test_the_archive_carries_the_office_register_for_a_generated_election(published):
    """The fourth file, and the one that makes this a challenge.

    The first three are what any citizen could download while the poll ran.
    This one names every citizen who was issued a token and carries the
    blinded value they asked the office to sign -- so an attacker gets the
    identifiers and the blinded values *together*, which is strictly more
    than any observer of a real poll ever holds. Handing it over is the
    whole demonstration: the claim is that it still does not help.
    """
    assert (published.data_folder / "closed" / "supervision.json").is_file()


def test_the_archived_register_is_what_the_origin_serves(published):
    """One renderer, or the challenge is about a file we wrote for it.

    `supervision_register` was a closure inside the supervision app until
    the archive needed it. A second rendering here would be a second
    object, differing in whatever a later edit touched on one side -- and
    the difference would show up as an attacker's recount of a published
    dataset disagreeing with a supervisor's, with no way to say which was
    the register.
    """
    archived = json.loads(
        (published.data_folder / "closed" / "supervision.json").read_text(
            encoding="utf-8"))
    again = api.supervision_register(published)

    assert set(archived) == set(again), (
        "the archive and the origin disagree about what a register has in it")

    # Everything but the counter, which must differ: `supervisor_downloads`
    # is published so that the office cannot hand the register out quietly,
    # and both the archive and this second call are the office handing it
    # out. The archived file therefore records its own release -- it says
    # 1, not 0 -- which is the accurate thing for a file somebody is
    # holding to say.
    assert archived["supervisor_downloads"] >= 1
    assert again["supervisor_downloads"] > archived["supervisor_downloads"]
    archived.pop("supervisor_downloads")
    again.pop("supervisor_downloads")
    assert canonical_bytes(archived) == canonical_bytes(again)


def test_a_real_poll_archives_no_register(tmp_path):
    """§3.7 in a directory rather than in a warning.

    Absence from the release register is conclusive proof of non-voting,
    which is what a coercer demanding turnout needs. On a real poll that
    register stays behind the perimeter, and `closed/` is the *public*
    record -- the one somebody zips and sends on. The flag is read from
    the configuration, so an election cannot acquire the behaviour by
    being reloaded.
    """
    real = _made(tmp_path, generated=False)
    for voter in ("Nagy Béla", "Kiss Anna"):
        real.vro.enrol(voter)
    real.ebb.open()
    real.ebb.close()
    api.archive_at_close(real)

    closed = real.data_folder / "closed"
    assert (closed / "ledger.json").is_file(), "the public record is still written"
    assert not (closed / "supervision.json").exists(), (
        "a real poll's participation register was archived into the public "
        "record")


# -- the bundle ------------------------------------------------------------

def test_the_bundle_carries_the_four_files_and_their_digests(bundle):
    import hashlib

    manifest = json.loads((bundle / "MANIFEST.json").read_text(encoding="utf-8"))
    assert set(manifest["files"]) == set(publish_challenge.PUBLISHED)
    for name, stated in manifest["files"].items():
        actual = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        assert actual == stated, f"{name} does not hash to what the manifest says"

    # And the plain file, because the first thing anybody does with a
    # downloaded dataset is check it with the tool they already have.
    sums = (bundle / "SHA256SUMS").read_text(encoding="utf-8")
    for name, stated in manifest["files"].items():
        assert f"{stated}  {name}" in sums


def test_the_answer_is_not_in_the_bundle(bundle, answer_key):
    """The one mistake that would end the challenge quietly.

    Not a file-name check: the test reads every byte published and looks
    for an ad-hoc key beside the citizen it belongs to. A bundle that
    carried the answer under another name, or inside another file, would
    pass a listing and fail this.
    """
    answer = json.loads(answer_key.read_text(encoding="utf-8"))
    mapping = answer["citizen_to_adhoc_key"]
    assert mapping, "the fixture produced no answer at all"

    for path in sorted(bundle.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for citizen, key in mapping.items():
            assert not (citizen in text and key in text), (
                f"{path.name} names {citizen} beside their ad-hoc key")


def test_the_bundle_commits_to_the_answer_it_withheld(bundle, answer_key):
    import hashlib

    manifest = json.loads((bundle / "MANIFEST.json").read_text(encoding="utf-8"))
    stated = manifest["withheld"]["answer_key"]["sha256"]
    assert stated == hashlib.sha256(answer_key.read_bytes()).hexdigest()
    # And the statement a reader is handed says the same thing, since that
    # is the copy that binds.
    assert stated in (bundle / "CHALLENGE.md").read_text(encoding="utf-8")


def test_the_statement_names_every_file_the_tool_publishes():
    """The table and the tool, kept in step.

    A statement that promised a file the bundle does not carry would be
    read as the dataset being incomplete; one that omitted a file the
    bundle does carry would understate what an attacker was given, which
    is worse -- it makes the claim look stronger than it is.
    """
    statement = (Path(__file__).resolve().parents[1]
                 / "docs" / "Challenge.md").read_text(encoding="utf-8")
    for name in publish_challenge.PUBLISHED:
        assert f"`{name}`" in statement, (
            f"docs/Challenge.md does not name {name}, which the bundle "
            "publishes")


def test_publishing_a_real_poll_is_refused(tmp_path, answer_key):
    """The tool's own §3.7 check, after the archive's.

    Two refusals for one mistake, deliberately: the archive declines to
    *write* the register for a real poll, and this declines to publish a
    directory whose configuration does not declare a synthetic electorate.
    Either alone is a single point of failure for the one error that
    cannot be taken back.
    """
    real = _made(tmp_path, generated=False)
    real.vro.enrol("Nagy Béla")
    real.ebb.open()
    real.ebb.close()
    api.archive_at_close(real)
    # Hand it the register it refuses to write, so the test is about the
    # configuration check rather than about a missing file.
    (real.data_folder / "closed" / "supervision.json").write_bytes(b"{}")

    with pytest.raises(SystemExit) as refused:
        publish_challenge.build(real.data_folder, answer_key, tmp_path / "out")
    assert "generated" in str(refused.value)


def test_publishing_without_the_answer_is_refused(tmp_path, published):
    """A challenge nobody can settle is a claim."""
    with pytest.raises(SystemExit) as refused:
        publish_challenge.build(published.data_folder,
                                tmp_path / "nothing-here.json", tmp_path / "out")
    assert "answer" in str(refused.value).lower()


# -- scoring ---------------------------------------------------------------

def _answer(n: int) -> dict:
    return {"election_id": "challenge-2026",
            "citizen_to_adhoc_key": {f"GEN-{i:06d}": f"key-{i}" for i in range(n)}}


def test_a_perfect_claim_is_upheld():
    answer = _answer(500)
    result = score_challenge.score(answer, dict(answer["citizen_to_adhoc_key"]))
    assert result["hits"] == 500
    assert result["leaked"] is True


def test_guessing_is_not_upheld():
    """The null hypothesis, exercised rather than asserted.

    One hit out of ten over five hundred citizens is what luck looks like,
    and a scorer that called it a win would hand the challenge to the first
    person who submitted ten guesses.
    """
    answer = _answer(500)
    claim = {f"GEN-{i:06d}": f"key-{i + 1}" for i in range(10)}
    claim["GEN-000000"] = "key-0"          # one lucky hit
    result = score_challenge.score(answer, claim)
    assert result["hits"] == 1
    assert result["leaked"] is False


def test_a_small_claim_can_still_win():
    """Scope is the claimant's to choose, and a narrow claim is not a weak one.

    Somebody who can link five citizens out of five hundred and says so has
    broken the property exactly as thoroughly as somebody who links all of
    them. The threshold is about the chance of being right, never about
    how much was attempted.
    """
    answer = _answer(500)
    claim = {f"GEN-{i:06d}": f"key-{i}" for i in range(5)}
    result = score_challenge.score(answer, claim)
    assert result["hits"] == 5
    assert result["leaked"] is True


def test_a_claim_padded_with_strangers_does_not_look_better():
    """Named and unrecognised, counted and reported.

    A claim scored only over the identifiers it got right would make
    padding free. Counting every identifier the claimant named keeps the
    denominator honest; reporting the unknown ones keeps a claimant who
    was working from a different election from being told, silently, that
    they guessed badly.
    """
    answer = _answer(500)
    claim = {"GEN-000000": "key-0"}
    claim.update({f"NOBODY-{i}": "x" for i in range(200)})
    result = score_challenge.score(answer, claim)
    assert result["hits"] == 1
    assert result["recognised"] == 1
    assert len(result["unknown"]) == 200
    assert result["claimed"] == 201
    assert result["leaked"] is False


def test_an_empty_claim_claims_nothing():
    result = score_challenge.score(_answer(500), {})
    assert result["hits"] == 0 and result["p_value"] == 1.0
    assert result["leaked"] is False


@pytest.mark.parametrize("hits, claimed, n", [
    (0, 10, 100), (1, 1, 2), (3, 7, 50), (10, 10, 1000), (5, 1000, 3),
])
def test_the_tail_is_a_probability(hits, claimed, n):
    assert 0.0 <= score_challenge.at_least(hits, claimed, n) <= 1.0


def test_more_hits_are_never_more_likely():
    """Monotone, which is the property the threshold rests on.

    If the tail were not monotone in `hits`, a claim could be made to look
    luckier by getting *more* of it right, and the verdict would be
    nonsense in a way nobody would notice until somebody argued it.
    """
    tail = [score_challenge.at_least(k, 40, 500) for k in range(41)]
    assert tail == sorted(tail, reverse=True)


def test_the_scorer_refuses_an_answer_that_does_not_match_the_commitment(
        tmp_path, answer_key, capsys):
    """The half of the commitment that protects the claimant.

    Without it they are taking our word that the file they are scored
    against is the one we published a digest of. With it, a swapped answer
    key is an exit code rather than an argument.
    """
    claim = tmp_path / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    code = score_challenge.main([str(answer_key), str(claim),
                                 "--expect-digest", "00" * 32])
    assert code == 2
    assert "does not match" in capsys.readouterr().err


def test_the_scorer_runs_against_the_real_answer(tmp_path, answer_key, capsys):
    import hashlib

    claim = tmp_path / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    code = score_challenge.main([
        str(answer_key), str(claim),
        "--expect-digest", hashlib.sha256(answer_key.read_bytes()).hexdigest()])
    assert code == 0
    assert "NOT UPHELD" in capsys.readouterr().out


# -- the verifier says so --------------------------------------------------

def test_the_verifier_reports_a_generated_electorate(bundle, capsys):
    """A generated election passes every check, which is why it is said.

    The checker's verdict is about the record and the record is perfect.
    Nothing in it is about who chose the selections, and a reader handed a
    page of green ticks will not infer the question. So the line comes
    after the verdict rather than before it: it is what they should carry
    away from a report that said yes to everything.
    """
    code = verify_election.verify(bundle / "election.json",
                                  bundle / "ledger.json",
                                  bundle / "releases.json")
    out = capsys.readouterr().out
    assert code == 0, out
    assert "Every check passed" in out
    assert "NOBODY CHOSE THESE VOTES" in out
    assert "S8" in out


def test_the_verifier_says_nothing_of_the_sort_about_a_real_poll():
    """The other direction, which a test written one way round would miss."""
    report = verify_election.Report()
    assert report.generated is False
    assert report.as_dict()["generated"] is False
