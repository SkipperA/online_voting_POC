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

__all__ = ["Certificate", "PopulationRegister"]
