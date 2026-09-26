"""Start a real deployment in a subprocess, on ports of its own.

`TestClient` binds no port, so an origin that calls another origin over HTTP
cannot work under it.  Since the wallet now transmits to the office across
the wire -- which is what §5.3 requires and what stage 2 will split -- the
tests have to drive a deployment that is actually listening.

The cost is honest: slower than `TestClient`, and dependent on free ports.
The port offset keeps it clear of a development server on 8000-8009.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time

import httpx

OFFSET = 320
ROOT = pathlib.Path(__file__).resolve().parents[1]
BOOT_TIMEOUT = 60.0


class Deployment:
    def __init__(self, offset: int = OFFSET):
        self.offset = offset
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
    def setup(self) -> str: return self.url(8009)

    def start(self) -> "Deployment":
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
            [sys.executable, "-m", "service", "--bits", "2048", "--choices", "3"],
            cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"service exited: {self.proc.stdout.read()[-2000:]}")
            try:
                self.http.get(f"{self.config}/health", timeout=1.0)
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
