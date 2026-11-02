# the closed poll

The three files `tools/verify_election.py` takes, in its order:

    python tools/verify_election.py election.json ledger.json releases.json

`election.json` is the configuration as it was published, byte for byte --
the dumps name its digest, and a configuration re-rendered later would not
match it. Written once, at the close, and not rewritten afterwards.

This is the published record, not a durable ballot box: the live registry
is in memory and a restart during a poll still loses it.
