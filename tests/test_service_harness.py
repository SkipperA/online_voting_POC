"""The live-deployment harness, where a flake becomes a false report.

`tests/service_process.py` is the only thing in the suite that competes
for a resource outside the process, and `tools/sabotage.py` runs one
whole suite per core. That combination has a failure mode the other
tests do not: a deployment that loses a port fails the test that needed
it, the sabotage runner reads a failing test as a mutation caught, and
`docs/sabotage.md` -- which CI diffs -- records a defence as held by a
test that never ran against it.

It happened. Two consecutive runs of `tools/sabotage.py` on an unchanged
checkout disagreed about nineteen of fifty-nine mutations, and sixteen
of those disagreements were one test:
`test_the_tally_is_refused_while_open_when_no_running_tally_is_configured`,
which starts a second deployment while the module's own is still up.

Both checks below are about that, and neither binds a port: one is
arithmetic on the offsets, the other is a string the service writes when
it loses. Tests that needed real deployments to state this would be
subject to the thing they are stating.
"""

from __future__ import annotations

import pathlib
import re

from service_process import (BLOCK, OFFSET_RANGE, PORTS, lost_the_port,
                             offsets_for_this_process)

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_no_two_offsets_name_the_same_port():
    """Offsets a block apart, so drawing differently is drawing apart.

    A block is every port in `PORTS` at one offset, so two offsets closer
    together than the span of that table overlap: at 300 and 305 the two
    deployments share five ports, each probe sees a block that is partly
    free, and both can accept. The range used to run `range(300, 700)` --
    four hundred offsets, about forty of which could be held at once.
    """
    assert OFFSET_RANGE.step >= BLOCK, (
        f"offsets {OFFSET_RANGE.step} apart cannot carry blocks {BLOCK} "
        "wide without overlapping")
    assert BLOCK == max(PORTS) - min(PORTS) + 1

    claimed = [port + offset for offset in OFFSET_RANGE for port in PORTS]
    assert len(claimed) == len(set(claimed)), (
        "two offsets in the range claim a port in common, so two probes "
        "can each see a block that is partly free and both accept")


def test_a_lost_race_is_recognised_in_the_service_s_own_words():
    """The platform numbers the error; only the words are portable.

    `start` retries on this and reports anything else, so a message it
    stopped recognising would go back into the report as a mutation
    caught -- and one it recognised too eagerly would retry a service
    that is failing for a reason worth seeing.
    """
    for said in ("[Errno 48] Address already in use",
                 "[Errno 98] error while attempting to bind on address "
                 "('127.0.0.1', 8304): address already in use"):
        assert lost_the_port(said), said

    for said in ("Traceback (most recent call last):\n  ImportError: ovpoc",
                 "ValueError: the electoral register is empty",
                 ""):
        assert not lost_the_port(said), said


def test_each_worker_draws_from_a_share_no_other_worker_has(monkeypatch):
    """The runner divides the ports, because the runner divides the work.

    A probe answers "free *now*", and two processes asking together can
    both be told yes. Losing that race is not a flake in the ordinary
    sense: the module that lost runs against the winner's deployment,
    fails nearly every test it has, and `tools/sabotage.py` reads all of
    them as the mutation being caught. It happened once and put
    thirty-nine tests from `test_service_flow.py` into one row of
    `docs/sabotage.md`.

    Shares make it impossible rather than unlikely, so what is checked
    here is that they partition: no offset in two shares, none dropped,
    and none of them empty.
    """
    workers = 14
    shares = []
    for worker in range(workers):
        monkeypatch.setenv("OVPOC_PORT_WORKER", str(worker))
        monkeypatch.setenv("OVPOC_PORT_WORKERS", str(workers))
        shares.append(offsets_for_this_process())

    drawn = [offset for share in shares for offset in share]
    assert len(drawn) == len(set(drawn)), "two workers may draw one block"
    assert sorted(drawn) == sorted(OFFSET_RANGE), "offsets went missing"
    assert all(shares), "a worker with no offsets cannot start anything"


def test_a_suite_run_by_hand_draws_from_the_whole_range(monkeypatch):
    """Nobody to share with, and the same for an answer that makes no sense.

    Falling back to the whole range is right when the names are absent,
    and it is also the safe reading of a share that cannot be parsed: a
    worker that drew from nothing would fail every test needing a
    deployment, which is the outcome this is all here to avoid.
    """
    monkeypatch.delenv("OVPOC_PORT_WORKER", raising=False)
    monkeypatch.delenv("OVPOC_PORT_WORKERS", raising=False)
    assert offsets_for_this_process() == list(OFFSET_RANGE)

    for worker, workers in (("nonsense", "14"), ("14", "14"), ("-1", "14")):
        monkeypatch.setenv("OVPOC_PORT_WORKER", worker)
        monkeypatch.setenv("OVPOC_PORT_WORKERS", workers)
        assert offsets_for_this_process() == list(OFFSET_RANGE), (worker, workers)


def test_the_runner_and_the_harness_agree_on_the_names():
    """Two files joined by a string, where a rename is silent.

    `tools/sabotage.py` writes the share into the environment and this
    module reads it. Spelled differently on one side, every worker draws
    from the whole range again and the collision comes back -- with no
    error anywhere, because an absent name is exactly how a suite run by
    hand announces that it has nobody to share with.
    """
    runner = (ROOT / "tools" / "sabotage.py").read_text(encoding="utf-8")
    for name in ("OVPOC_PORT_WORKER", "OVPOC_PORT_WORKERS"):
        assert re.search(rf'{name}"', runner), (
            f"{name} is read by service_process and set by nobody")
