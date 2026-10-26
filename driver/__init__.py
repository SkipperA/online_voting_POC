"""Infrastructure the proposal *depends on*, rather than proposes.

Nothing in this package is part of the system under design.  It stands in for
services that exist in law and are operated by somebody else -- and it lives
outside `src/ovpoc/` for exactly that reason.  §3.2 of the article draws the
boundary explicitly: what the design builds is kept distinct from what it
assumes, so that a reader can see which guarantees rest on the construction
and which rest on infrastructure already established elsewhere.

If a lookup table for identity ever appears inside `src/ovpoc/`, the code has
started contradicting the paper.
"""

from .population_register import Certificate, PopulationRegister

# Not imported here. `qualified_signature` needs the `pades` extra, and a
# package that cannot be imported without it would make a dependency of the
# second route into a dependency of the first.
__all__ = ["Certificate", "PopulationRegister"]
