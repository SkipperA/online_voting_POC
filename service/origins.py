"""The eight origins of stage 1, in one table.

Separate ports rather than paths, because a browser origin is scheme, host
*and* port.  Paths under one origin would share a JavaScript context, a CSP
and a fetch policy, and the isolation the design claims would be a diagram
rather than a fact.  See `docs/Stage1_Surface_and_Boundary_Map.md` §1.

Six of the eight are trust domains.  `config` is inert and `setup` is
build-time -- the poll must run with 8009 stopped, which is a test rather
than an intention.

Hosted, the ports become hostnames and nothing else changes.  Set
``OVPOC_DOMAIN=diw.hu`` and every origin addresses its neighbours as
``https://checker.diw.hu`` instead of ``http://127.0.0.1:8005``; the
processes still listen on the same loopback ports, with a reverse proxy
in front mapping one hostname to each.  Separate hostnames rather than
paths for exactly the reason stage 1 used separate ports: an origin is
scheme, host *and* port, and paths under one host would share a
JavaScript context whatever the diagram said.

A hosted deployment must be HTTPS, and not only for the padlock.  The
checker and the supervisor verify Ed25519 statements in the browser
through ``crypto.subtle``, which exists only in a secure context, so over
plain HTTP to a remote host the independent checks do not merely warn --
they are unavailable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

#: What the processes bind. Loopback by default, so a laptop exposes
#: nothing. In a container it must be the container's own interface --
#: `127.0.0.1` there is reachable only from inside the container, and the
#: proxy would find nothing listening. `OVPOC_BIND=0.0.0.0` is safe when,
#: and only when, the container publishes no ports of its own and the
#: proxy reaches it over a private network.
HOST = os.environ.get("OVPOC_BIND", "127.0.0.1")

#: Set to a registered domain to address the origins by hostname instead of
#: by port. Empty means stage 1 as it has always been, so a laptop needs no
#: configuration and the default path stays the tested one.
DOMAIN = os.environ.get("OVPOC_DOMAIN", "").strip().lower()

# Added to every port. Lets a test deployment run beside a development one
# instead of fighting it for 8000-8009, without any origin learning that it
# has moved: everything derives its neighbours' addresses from this table.
OFFSET = int(os.environ.get("OVPOC_PORT_OFFSET", "0"))


@dataclass(frozen=True)
class Origin:
    name: str
    base_port: int
    trust_domain: bool
    serves: str
    #: (light, dark) band colour identifying this trust domain, or None.
    #:
    #: Hue carries trust-domain identity and nothing else -- never a verdict,
    #: never decoration.  The six domains group into three families of two:
    #: voter side (teal), authority side (orange-brown), oversight (violet),
    #: with a lightness step between the two members of each family.  The
    #: families, rather than six independent hues, because an audience holds
    #: three mappings and not six, and because the three are distinctions the
    #: papers already argue about.
    #:
    #: Teal, orange-brown and violet rather than anything nearer the
    #: primaries: that leaves red and green free to go on meaning danger and
    #: verified *inside* the pages.  Were the supervisor's band crimson, the
    #: crimson that means "this page names citizens" would stop being a
    #: warning and become the page's own colour.
    #:
    #: `None` for the two origins that are not trust domains, so that "not a
    #: domain" reads as the absence of colour rather than as a seventh one.
    hue: tuple[str, str] | None = None
    #: What to call this surface in the band every page carries.  Not the
    #: page's own `<h1>`, which says what the page does; this says which
    #: trust domain the reader is standing in.
    title: str = ""
    #: Which of the three families the hue belongs to, or None for the two
    #: origins that are not trust domains.  Named on screen because a colour
    #: grouping nobody explains teaches nothing.
    family: str | None = None
    #: The label this origin takes under a hosted domain.  Defaults to the
    #: origin's name; given explicitly only where the name is not what one
    #: would type, as with `voter-app`, which an audience reads and says
    #: aloud as `voter`.
    label: str = ""

    @property
    def port(self) -> int:
        return self.base_port + OFFSET

    @property
    def hostname(self) -> str | None:
        """This origin's name under a hosted domain, or None on a laptop."""
        return f"{self.label or self.name}.{DOMAIN}" if DOMAIN else None

    @property
    def url(self) -> str:
        """How every other origin addresses this one.

        The one place the two deployments differ. Everything downstream --
        the cross-origin allowances, the addresses the pages are handed,
        the startup banner -- derives from here, so a hosted deployment is
        a single environment variable rather than a second set of
        addresses to keep in step with the first.
        """
        if DOMAIN:
            return f"https://{self.hostname}"
        return f"http://{HOST}:{self.port}"

    def matches(self, sent: str | None) -> bool:
        """Is this surface, reached by whatever name the caller used?

        A page opened at localhost:8005 and one at 127.0.0.1:8005 are
        different browser origins and the same surface. Naming one of them
        in an allowance means the other is refused -- which is how the
        checker's recount came to fail in the browser for anyone who typed
        `localhost`, while every test passed, because the tests send the
        canonical name.

        The port is what identifies the surface on a laptop: each runs on
        its own, which is the whole of the separation in stage 1. Under a
        hosted domain the hostname identifies it instead, and the port is
        no longer distinguishing -- every origin arrives from the proxy on
        443, so matching by port there would make all eight the same
        surface and the allowances meaningless.
        """
        if not sent:
            return False
        if DOMAIN:
            host = sent.rsplit("://", 1)[-1].rsplit(":", 1)[0].lower()
            return host == self.hostname
        return sent.rsplit(":", 1)[-1] == str(self.port)


CONFIG = Origin("config", 8000, False, "election.json and its digest, as static files",
                title="Election configuration")
VOTER_APP = Origin("voter-app", 8001, True, "Voter App – the voting client; never reads id",
                   hue=("#115e59", "#5eead4"),
                   title="Voter application", family="voter side", label="voter")
WALLET = Origin("wallet", 8002, True, "Identity Wallet – consent page and signing daemon",
                hue=("#0f766e", "#2dd4bf"),
                title="Identity Wallet", family="voter side")
VRO = Origin("vro", 8003, True, "VRO: token endpoints, release query, back office",
             hue=("#7c2d12", "#fdba74"),
             title="Voter Registration Office", family="authority side")
EBB = Origin("ebb", 8004, True, "EBB: submission, receipts, published view",
             hue=("#9a3412", "#fb923c"),
             title="Electronic Ballot Box", family="authority side")
CHECKER = Origin("checker", 8005, True, "Checker: the three independent checks of §3.7",
                 hue=("#4c1d95", "#c4b5fd"),
                 title="Independent checker", family="oversight")
SUPERVISOR = Origin("supervisor", 8006, True,
                    "Supervisor of VRO – the release register with identifiers; perimeter-protected",
                    hue=("#5b21b6", "#a78bfa"),
                    title="Supervision of the office", family="oversight")
SETUP = Origin("setup", 8009, False, "build-time authoring of election.json",
               title="Setup console")

ALL = (CONFIG, VOTER_APP, WALLET, VRO, EBB, CHECKER, SUPERVISOR, SETUP)
RUNTIME = tuple(o for o in ALL if o is not SETUP)
TRUST_DOMAINS = tuple(o for o in ALL if o.trust_domain)

BY_NAME = {o.name: o for o in ALL}
