"""Which build this is -- and what that claim is worth.

Every check we have for "is the deployment running the code I think it is"
has been a proxy: grep a page for a string only one patch introduced, or
`exec` into the container and read a file. Each works and each has to be
invented again for the next patch. The container knows, and said nothing.

So it says it now, on `/health` for every origin and on the configuration
index for a reader. One `curl` replaces the proxies.

**This is not evidence and must not be presented as any.** The revision is
a string the builder passed in; nothing verifies that the running code is
that commit, and anyone building an image can put anything here. It
belongs with clause S4 -- the configuration is published with a digest and
no signature, so tampering is demonstrable rather than attributable -- and
it is weaker than that, since there is no digest either. It answers "which
code did the operator mean to deploy", which is an operations question,
and not "which code is this", which would need a reproducible build and a
signature over the result.

It is also deliberately *not* in `election.json`. The configuration
digest covers the election, and a build identifier is not part of the
election: an image rebuilt with no source change must not move the digest
every voter pinned, and a reader must not be able to mistake a software
version for something the digest attests. Two sections on the index page,
for that reason.

Unset, this reports `unknown` rather than guessing. An image built without
the argument is a real thing that happens -- `docker compose up -d
--build` without the variable does it -- and "unknown" is the honest
answer to it. A wrong-but-plausible revision would be worse than no
revision, because it would be believed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _from_git() -> str | None:
    """The working tree's revision, for a laptop run.

    The container has no `.git` and takes the environment variable
    instead; this is for `python -m service` in a checkout, where
    requiring an argument would mean everyone sees `unknown` and stops
    reading the field.

    `-dirty` when the tree has uncommitted changes, which is the whole
    point of consulting git rather than printing a tag: a revision that
    ignores local edits is a revision that lies on exactly the machine
    where someone is editing.
    """
    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(
                ["git", "-C", str(_ROOT), *args],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    revision = git("rev-parse", "--short", "HEAD")
    if not revision:
        return None
    return f"{revision}-dirty" if git("status", "--porcelain") else revision


def _resolve() -> str:
    """The environment first, then git, then `unknown`.

    The environment wins because it is the container's explicit claim
    about what was built, and a `.git` that happened to be present in an
    image would otherwise override it with whatever the build context
    carried.
    """
    declared = os.environ.get("OVPOC_REVISION", "").strip()
    if declared:
        return declared
    return _from_git() or "unknown"


#: Read once, at import. A build identifier that changed per request would
#: be describing something other than the build.
REVISION = _resolve()
