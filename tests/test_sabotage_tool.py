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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

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
