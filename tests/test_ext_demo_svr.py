"""The adversarial demo, run against a real deployment, in CI.

`ext_demo_svr.py` needs a listening service and two terminals, so it would
otherwise be exercised only by hand -- and a demonstration nobody runs is a
document, not evidence. The script reports its own failures and exits
non-zero, so the assertion here is simply that it passed.
"""

from __future__ import annotations

import os
import subprocess
import sys

from service_process import ROOT, Deployment

OFFSET = 520


def test_the_adversarial_scenarios_all_hold():
    deployment = Deployment(offset=OFFSET).start()
    try:
        result = subprocess.run(
            [sys.executable, "ext_demo_svr.py"],
            cwd=ROOT,
            env=dict(
                os.environ,
                OVPOC_PORT_OFFSET=str(OFFSET),
                PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
            ),
            capture_output=True, text=True, timeout=300,
        )
    finally:
        deployment.stop()

    assert result.returncode == 0, result.stdout[-4000:]
    assert "checks failed                      0" in result.stdout
