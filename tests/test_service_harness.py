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

from service_process import BLOCK, OFFSET_RANGE, PORTS, lost_the_port


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
