# election-data

The durable half of a demonstration election, written by the setup
console (`python -m service --init`) and reloaded at every start.

**Committed on purpose, key material included.** `election.store.json`
carries every wallet seed in the clear and `vro_token_key.pem` is the
office's token signing key. Publishing them is the point: the demo
substitutes a file for an eIDAS wallet and a directory for an HSM, and
a reader should be able to see exactly what that substitution costs
rather than take it on trust. The voters are fictional and this
election is not one.

What is **not** here is everything the poll produced: the ballot box,
the hash chain and the released-token register are in memory and are
lost when the process stops. A real ballot box does not forget its
contents; this one does.
