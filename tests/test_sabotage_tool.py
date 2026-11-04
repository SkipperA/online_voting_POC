"""The sabotage runner reads its own evidence through one parser.

`tools/sabotage.py` is the project's argument that a passing negative test
actually constrains the check it names, and everything it concludes is read
out of pytest's short summary by `parse_report`. A parser that quietly
stopped recognising a line would under-report in the direction that looks
like success: no failures parsed means "not caught", and no skips parsed
means "the suite you ran is the suite CI runs".

The second of those went wrong the first time an optional extra appeared.
Three mutations in `driver/qualified_signature.py` came back NOT CAUGHT on a
machine whose virtual environment predated the `pades` extra, because the
only tests that defend them are skipped without it. The report was true and
about the environment; `docs/sabotage.md` is committed and CI diffs it, so a
report written in that state claims a defence is undefended when CI will say
the opposite.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import sabotage  # noqa: E402
from sabotage import MUTATIONS, PYTEST_ARGS, parse_report  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_the_runner_asks_pytest_for_both_summaries(tmp_path):
    """Run pytest for real, with the tool's own arguments, and read it back.

    The tests below feed `parse_report` strings written by hand, which is
    worth having and was not enough: it pins what the parser does with a
    line and says nothing about whether pytest emits one. Those are
    different questions and the second is where this went wrong.

    `-rf -rs` looks like it asks for failures and skips. A second `-r`
    *replaces* the first, so it asks for skips alone and the failure
    summary disappears -- and a tool that detects a mutation by its
    failures then detects nothing at all. The only integration check run
    before that shipped had no failing tests in it, so the half that broke
    was the half not exercised.

    This runs a suite with one of each, through `PYTEST_ARGS`, so the
    arguments under test are the arguments the tool uses.
    """
    (tmp_path / "test_sample.py").write_text(
        "import pytest\n"
        "def test_fails(): assert False\n"
        "@pytest.mark.skip(reason='an optional extra is not installed')\n"
        "def test_skips(): pass\n"
        "def test_passes(): pass\n"
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *PYTEST_ARGS, "test_sample.py"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    failures, skips = parse_report(result.stdout)
    assert failures == ["test_fails"], (
        "the runner cannot see failures, so it can detect no mutation at all"
    )
    assert len(skips) == 1 and "optional extra" in skips[0]


def test_failures_are_read_out_of_the_short_summary():
    failures, skips = parse_report(
        "....F..\n"
        "=== short test summary info ===\n"
        "FAILED tests/test_attacks.py::test_forged_token_is_rejected - assert\n"
        "1 failed, 6 passed\n"
    )
    assert failures == ["test_forged_token_is_rejected"]
    assert skips == []


def test_a_collection_error_counts_as_a_failure():
    failures, _skips = parse_report("ERROR tests/test_x.py\n")
    assert failures == ["ERROR tests/test_x.py"]


def test_skips_are_read_with_their_reasons():
    """The line the runner has to notice, in the shape pytest writes it."""
    _failures, skips = parse_report(
        "=== short test summary info ===\n"
        "SKIPPED [1] tests/test_qualified_signature.py:36: "
        "the pades extra is not installed\n"
    )
    assert skips == [
        "tests/test_qualified_signature.py:36: the pades extra is not installed"
    ]


def test_a_skip_line_without_a_count_is_still_reported():
    """Belt and braces: an unrecognised shape is kept, not dropped.

    Dropping it would be the failure this test exists to prevent, arriving
    through a change in pytest's output rather than a change here.
    """
    _failures, skips = parse_report("SKIPPED some other shape\n")
    assert skips == ["SKIPPED some other shape"]


def test_failures_are_deduplicated_and_ordered_but_skips_are_not():
    failures, skips = parse_report(
        "FAILED tests/b.py::test_two - x\n"
        "FAILED tests/a.py::test_one - x\n"
        "FAILED tests/c.py::test_one - x\n"
        "SKIPPED [1] a: r\n"
        "SKIPPED [1] a: r\n"
    )
    # Names, not paths: two tests of the same name in different files are
    # one entry, which is how the report has always counted them.
    assert failures == ["test_one", "test_two"]
    assert len(skips) == 2


def test_every_mutation_names_a_file_that_exists():
    """A mutation against a deleted file is a mutation that tests nothing.

    The runner already refuses one whose pattern has drifted; this catches
    the cheaper mistake of the path itself going stale, without having to
    run the suite thirty-odd times to find out.
    """
    for mutation in MUTATIONS:
        assert (ROOT / mutation.path).exists(), mutation.name


def test_every_mutation_still_matches_its_target_exactly_once():
    """The same check the runner makes, run in a second and not in minutes.

    `docs/sabotage.md` takes several minutes to regenerate, so drift
    between the mutations and the code is otherwise found either by
    spending that time or by pushing and waiting for CI.
    """
    for mutation in MUTATIONS:
        source = (ROOT / mutation.path).read_text()
        assert source.count(mutation.find) == 1, (
            f"{mutation.name}: its pattern matches "
            f"{source.count(mutation.find)} times in {mutation.path}, not once"
        )


def test_mutation_names_are_unique():
    names = [m.name for m in MUTATIONS]
    assert len(names) == len(set(names))


def test_a_worker_tree_carries_everything_the_run_needs(tmp_path):
    """`--jobs` sabotages copies, so the copy has to be complete.

    Each worker gets its own tree because a mutation is applied to a file
    and the suite is then run against it; two workers sharing one checkout
    would overwrite each other's mutations and report nonsense. What makes
    the copy cheap is leaving things out -- `.git`, the caches,
    `node_modules` -- and that is exactly where it can go wrong.

    A mutation whose target is excluded fails with *pattern not found --
    source has drifted*, which reads as the source having moved rather
    than as the copy being incomplete, and is reported as a mutation that
    could not be applied rather than as a bug in this tool.

    The files listed beside the mutation targets are ones the suite reads
    that nothing else here would notice the loss of: `.gitignore` is read
    by `test_repository_hygiene`, the trust anchors by `conftest`, and
    `tests/fixtures/` by the Swift tests' Python half.
    """
    from sabotage import worker_tree

    tree = worker_tree(tmp_path / "w")

    missing = sorted({m.path for m in MUTATIONS}
                     - {str(p.relative_to(tree)) for p in tree.rglob("*")})
    assert not missing, (
        "a worker tree is missing files mutations target, so those "
        f"mutations would report as drifted source: {missing}")

    for needed in (".gitignore", "pyproject.toml",
                   "election-data/trust-anchors",
                   "tests/fixtures/published-election.json"):
        assert (tree / needed).exists(), (
            f"{needed} is not in a worker tree, and the suite reads it")


def test_a_worker_tree_leaves_the_weight_behind(tmp_path):
    """The copy is per worker, so its size is multiplied by the core count.

    Not a performance test: `.git` carries every version of the 27 MB
    generated election that was once committed, and copying it eight times
    would be slower than the run it is meant to speed up.
    """
    from sabotage import worker_tree

    tree = worker_tree(tmp_path / "w")
    assert not (tree / ".git").exists()
    size = sum(f.stat().st_size for f in tree.rglob("*") if f.is_file())
    assert size < 32 * 1024 * 1024, f"a worker tree is {size / 1e6:.0f} MB"


def test_no_test_pins_a_port_offset():
    """Two deployments alive at once must not agree on a block by hand.

    `tests/service_process.py` probes for a free block, and that only
    works if everything probes. One test kept a hardcoded `offset=340`
    beside the fixture's old hardcoded 320 -- safe while both were
    constants, and a flake in about one run in twenty the moment the
    first one started probing, because a probe landing in 331..349
    overlapped the block the constant had claimed.

    The failure was in a test about tally privacy, which is the problem:
    nothing in the symptom points at a port, so it reads as flakiness in
    the thing being tested.
    """
    import re

    offenders = {}
    for path in sorted(ROOT.glob("tests/*.py")):
        found = re.findall(r"Deployment\(\s*offset\s*=", path.read_text(encoding="utf-8"))
        if found:
            offenders[path.name] = len(found)
    assert not offenders, (
        "these pin a port offset instead of probing for a free block: "
        + ", ".join(f"{n} ({c})" for n, c in offenders.items())
        + ". Two deployments that agree on a block by hand collide the "
        "day either one starts choosing.")


def _stub_the_suite(monkeypatch, chosen, finished):
    """Everything `main` calls that costs a suite run or a tree copy.

    `worker_tree` returns the path it was given without copying: the run
    below never reaches a tree, because `run_one` is stubbed too. What is
    left unstubbed is the part this is about -- the argument parsing, the
    drift check against the real checkout, the pool, and the pairing of
    results with mutations.
    """
    monkeypatch.setattr(sabotage, "MUTATIONS", chosen)
    monkeypatch.setattr(sabotage, "worker_tree", lambda into: into)
    monkeypatch.setattr(sabotage, "failing_tests", lambda tree, skipped=None: [])

    def out_of_order(mutation, trees):
        # Later mutations finish first, so a run that reported in
        # completion order would report these backwards.
        time.sleep(0.02 * (len(chosen) - chosen.index(mutation)))
        return [f"test_{mutation.name}"]

    monkeypatch.setattr(sabotage, "run_one", out_of_order)
    monkeypatch.setattr(sabotage, "write_report", finished.append)


def test_the_runner_pairs_each_result_with_the_mutation_it_came_from(monkeypatch):
    """Drive `main` with the suite stubbed out, which nothing did.

    Every piece below `main` had a test -- `parse_report` above, the
    worker tree below, `run_one` exercised by hand -- and `main` is where
    they are joined. So the first real parallel run printed `Baseline
    green.` and raised `TypeError: cannot use 'Mutation' as a dict key`,
    after fourteen tree copies and a full baseline suite: results were
    collected into a dict keyed by the mutation, and a plain `@dataclass`
    defines `__eq__`, which sets `__hash__` to None.

    No unit test of a part can see that. The general form is the one this
    project keeps meeting from different directions: when each half is
    covered in isolation, the thing nobody covers is the join -- it was
    the validator and the event loop, and here it is the mutation list
    and the pool.
    """
    chosen = MUTATIONS[:4]
    finished = []
    _stub_the_suite(monkeypatch, chosen, finished)

    assert sabotage.main(["-j", "4"]) == 0

    assert [m.name for m, _ in finished[0]] == [m.name for m in chosen]
    assert all(caught == [f"test_{m.name}"] for m, caught in finished[0]), (
        "a result was reported against a mutation it did not come from")


def test_the_report_does_not_depend_on_how_many_jobs_wrote_it(monkeypatch):
    """`--jobs` is a speed dial and nothing else.

    `docs/sabotage.md` is committed and CI diffs it, so a report whose
    rows moved with the scheduler would show a diff on every run and mean
    nothing -- and nobody reading one can tell which `-j` produced it.
    """
    chosen = MUTATIONS[:4]
    serial, parallel = [], []
    _stub_the_suite(monkeypatch, chosen, serial)
    assert sabotage.main(["-j", "1"]) == 0
    _stub_the_suite(monkeypatch, chosen, parallel)
    assert sabotage.main(["-j", "4"]) == 0

    assert serial[0] == parallel[0]
