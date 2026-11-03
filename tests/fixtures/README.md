# fixtures

Files a test reads that are **not** conformance vectors.

`tests/vectors/` has a contract of its own: every file there declares a
schema version the suites agree on, and `tests/test_vectors.py` refuses
any that does not. It is pinned interop evidence between three
implementations, and adding something to it that is merely *useful to a
test* breaks that meaning.

This directory is for the rest.

## `published-election.json`

A configuration the setup console minted, copied out of `election-data/`
byte for byte. `ios/OVPOCKit/Tests/OVPOCKitTests/ElectionTests.swift`
parses it, so that the field set the Swift client understands is the
field set the service actually writes, rather than a fixture written by
hand that would agree with whatever it assumed.

**It used to live at the repository root as `election.json`**, where it
was indistinguishable from what `python -m service` leaves in a checkout
— and a cleanup deleted it as spill. `swift test` broke on a Mac;
`python -m pytest` stayed green, because nothing in the Python suite
compiles Swift. `test_the_swift_tests_fixtures_are_all_here` closes that
gap, and this directory and this paragraph are the other half: a file
whose purpose is invisible from its location is a file somebody will
eventually remove.
