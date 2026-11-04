"""Start a real deployment in a subprocess, on ports of its own.

`TestClient` binds no port, so an origin that calls another origin over HTTP
cannot work under it.  Since the wallet now transmits to the office across
the wire -- which is what §5.3 requires and what stage 2 will split -- the
tests have to drive a deployment that is actually listening.

The cost is honest: slower than `TestClient`, and dependent on free ports.
The offset is **probed** rather than fixed, which matters for two reasons.

A development server on the same machine no longer breaks the suite with
failures that look like bugs -- the docstring used to admit the dependency
and then hardcode 320 anyway.

And several suites can run at once, which `tools/sabotage.py --jobs` needs:
it puts one whole suite per core, each in its own copy of the tree. With a
fixed offset every worker but one would fail to bind, and the failures would
land in exactly the tests that need a live service -- so a mutation would be
recorded as caught by `test_the_ledger_downloads_as_one_canonical_file` and
the report would be confidently wrong about which defence holds.
"""

from __future__ import annotations

import os
import pathlib
import random
import socket
import subprocess
import sys
import time

import httpx

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from service import origins as _origins          # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOT_TIMEOUT = 60.0

#: Read from `service/origins.py` rather than listed here. A second copy of
#: the port table would drift, and the way it would drift is an origin added
#: later whose port the probe never checks -- which is a collision that
#: appears only under load and only on one origin.
PORTS = tuple(sorted(origin.port for origin in _origins.ALL))

#: The width of one deployment's block: every port in `PORTS` is claimed
#: at the same offset, so the block spans the whole table.
BLOCK = max(PORTS) - min(PORTS) + 1

#: Offsets to draw from. Clear of 8000-8009, where a development server
#: lives, and **stepped by a whole block** rather than by one.
#:
#: The step matters more than the width of the range. Two offsets less
#: than `BLOCK` apart overlap -- 300 and 305 share half their ports --
#: so a range of four hundred drawn one apart was not four hundred
#: places to stand. It was about forty, and four hundred ways for two
#: probes to agree on part of a block and lose the race below. Stepped,
#: every offset in the range names ports no other offset in it can
#: touch, and the only way to collide is to draw the same number.
OFFSET_RANGE = range(300, 8000, BLOCK)


def free_offset() -> int:
    """An offset at which every origin's port is free, right now.

    All of them are held open together and released at the last moment, so
    an offset is accepted only if the whole block is available -- checking
    them one at a time would accept a block whose last port went away while
    the first was being tested.

    Drawn in random order so that two probes running at the same instant
    are unlikely to agree. The window between releasing and the service
    binding is not zero and cannot be closed without passing the service
    an inherited socket, which is a larger change than this is worth.

    This used to say that what closes it in practice is `start`
    reporting a service that exited, so that a lost race is a loud
    failure rather than a flake that looks like a mutation being caught.
    The first half is true and the second does not follow. Under
    `tools/sabotage.py` a loud failure *is* a failing test, and a failing
    test is exactly how that tool records a mutation as caught -- so the
    loudness is indistinguishable from the thing it was supposed to be
    distinguished from, and the report said a defence held because a
    worker had lost a port. `start` re-probes instead.
    """
    for offset in random.sample(OFFSET_RANGE, k=len(OFFSET_RANGE)):
        held: list[socket.socket] = []
        try:
            for port in PORTS:
                sock = socket.socket()
                # As uvicorn will. Without it a port left in TIME_WAIT by a
                # previous run reads as busy, and the probe walks away from
                # an offset the service could have used.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", port + offset))
                held.append(sock)
        except OSError:
            continue
        finally:
            for sock in held:
                sock.close()
        return offset
    raise RuntimeError(
        f"no free block of {len(PORTS)} ports in {OFFSET_RANGE}. Something "
        "is listening across the whole range, or a previous run left "
        "services behind.")


#: What losing the race looks like in the service's own words, whatever
#: number the platform puts on the error.
_LOST_THE_PORT = "address already in use"

#: How many times a probed block is worth drawing again. More than one
#: because the second draw can lose as well; few, because a machine where
#: it keeps happening has something to find out about rather than retry.
START_ATTEMPTS = 3


class PortRaceLost(RuntimeError):
    """Free when the block was probed, taken before it could be bound."""


def lost_the_port(output: str) -> bool:
    """Whether a service that exited did so because its block went away.

    Kept apart from `start` so it can be tested without binding anything,
    for the reason `tools/sabotage.py` keeps `parse_report` apart from
    the subprocess that feeds it: what this returns decides whether a
    failure is retried or reported, and a check that quietly stopped
    recognising the message would put every lost race back into
    `docs/sabotage.md` as a defence held by whichever worker lost.
    """
    return _LOST_THE_PORT in output.lower()


class Deployment:
    def __init__(self, offset: int | None = None):
        #: Whether `start` may draw again. An offset given by hand is a
        #: caller naming the ports to use, and quietly moving off it
        #: would answer a different question than the one asked. Nothing
        #: passes one today and `test_no_test_pins_a_port_offset` is
        #: there to keep it that way, so this is the argument's promise
        #: rather than a branch the suite exercises.
        self.probed = offset is None
        self.offset = free_offset() if offset is None else offset
        self.http = httpx.Client(timeout=30.0)
        self.proc: subprocess.Popen | None = None

    def url(self, port: int) -> str:
        return f"http://127.0.0.1:{port + self.offset}"

    @property
    def config(self) -> str: return self.url(8000)
    @property
    def wallet(self) -> str: return self.url(8002)
    @property
    def vro(self) -> str: return self.url(8003)
    @property
    def ebb(self) -> str: return self.url(8004)

    @property
    def checker(self) -> str: return self.url(8005)
    @property
    def setup(self) -> str: return self.url(8009)

    def start(self) -> "Deployment":
        """Bring the deployment up, drawing again if its block was taken.

        A lost race is not a failure of anything under test. It says that
        something else was starting at the same moment, and nothing else.
        Raised, it becomes a failing test; and under `tools/sabotage.py` a
        failing test is how a mutation is recorded as caught, so a race
        lost in `w7` is published in `docs/sabotage.md` as a defence that
        `w7` happened to be disabling at the time. That report is diffed
        by CI, which is where it stops being a flake and starts being a
        job that cannot be made to pass twice running.
        """
        lost: PortRaceLost | None = None
        for _ in range(START_ATTEMPTS):
            try:
                return self._start_once()
            except PortRaceLost as exc:
                # The service exited on its own; there is nothing to reap.
                lost, self.proc = exc, None
                self.offset = free_offset()
        raise RuntimeError(
            f"lost the race for a free block of ports {START_ATTEMPTS} times "
            f"running, which is not luck. The last service to exit said:\n"
            f"{lost}")

    def _start_once(self) -> "Deployment":
        # PYTHONPATH pinned to *this* checkout, ahead of anything installed.
        # Without it the subprocess imports whichever `ovpoc` happens to be on
        # the editable-install path, which may be a different copy of the
        # source entirely -- and then `tools/sabotage.py` patches one tree
        # while the service runs another, and every mutation these tests
        # should catch passes silently.
        env = dict(
            os.environ,
            OVPOC_PORT_OFFSET=str(self.offset),
            PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
        )
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "service", "--bits", "2048", "--choices", "3",
             "--ephemeral"],
            cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                said = self.proc.stdout.read()[-2000:]
                if self.probed and lost_the_port(said):
                    raise PortRaceLost(said)
                raise RuntimeError(f"service exited: {said}")
            try:
                self.http.get(f"{self.config}/health", timeout=1.0)
                # A9. The deployment no longer opens its own box, so the
                # harness performs the act a demonstrator would: almost
                # every test below is about a poll that is running.
                self.http.post(f"{self.ebb}/open", timeout=2.0)
                return self
            except httpx.TransportError:
                time.sleep(0.2)
        self.stop()
        raise RuntimeError("service did not come up")

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:      # pragma: no cover
                self.proc.kill()
        self.http.close()
