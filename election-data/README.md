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
