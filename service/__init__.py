"""The stage 1 HTTP layer.

Deliberately outside `src/ovpoc`, as `driver/` is.  This package imports
`ovpoc`; `ovpoc` never imports this one.  The dependency runs one way so that
a protocol decision cannot drift into the transport without the import graph
showing it.
"""
