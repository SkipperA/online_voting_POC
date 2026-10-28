# election-data

One directory per election, each holding the durable half that the
setup console authored: the two key pairs, the electoral register and
the wallet personas. `current` names the one the service serves.

Minting from the console writes a **new** directory and moves the
pointer. Nothing here is overwritten, so the keys of an election that
has been superseded are still on disk and can be served again with
`python -m service --election <directory>` -- which is what lets a
ledger downloaded from a past election still be checked against the
configuration it was published under.

**Committed on purpose, key material included.** See the README inside
each directory. The voters are fictional and these are not elections.

## This is not a server's election directory

Everything here is a fixture, committed so that a clone has something to
run and so that a past election can be served again. A hosted deployment
does not use it at all: `deploy/compose.yaml` mounts `deploy/election-data`
as the container's `/data`, so a server's own elections, its register and
its pinned trust anchors are there, and arrive in a checkout by nothing but
`git pull` putting *these* in front of you.

The symptom is an operator looking at the wrong seven directories and
concluding that minting did not save, or that the trust anchors they pinned
have no effect. Both have happened. On a server, read

    deploy/election-data/

and nothing in here.
