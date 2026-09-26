"""One FastAPI application per origin.

The service layer decides nothing about the protocol.  These applications
parse requests, call into `ovpoc`, serialise the answers, and enforce the
boundaries the surface map names.  Every acceptance, rejection, ordering and
disclosure rule stays in `src/ovpoc`, where the sabotage suite can reach it --
if a mutation stops being detected because a check moved in here, this layer
has taken a decision that does not belong to it.

The endpoints themselves are in `api.py`; this module owns the shared
middleware and the assembly.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import origins
from .api import ebb_app, setup_app, vro_app, wallet_app
from .state import Deployment

VOTER_APP_STATIC = Path(__file__).resolve().parents[1] / "web" / "voter-app" / "static"


def _base(origin: origins.Origin) -> FastAPI:
    """An application with the boundary rules already applied.

    No cookies anywhere.  Cookies ignore the port component of an origin, so
    one set on 127.0.0.1:8001 is readable on 127.0.0.1:8002 and the isolation
    above becomes a fiction.  The voter application has no login by
    construction and nothing else in the demo needs one, so the cheapest
    enforcement is to assert their absence rather than to configure them.
    """
    app = FastAPI(title=f"ovpoc {origin.name}", docs_url=None, redoc_url=None)
    app.state.origin = origin

    @app.middleware("http")
    async def no_cookies(request, call_next):
        response: Response = await call_next(request)
        response.headers["X-OVPOC-Origin"] = origin.name
        # Belt and braces: nothing in this process sets a cookie, and if
        # something ever does, this is where it is caught rather than in a
        # reviewer's memory.
        if "set-cookie" in response.headers:
            del response.headers["set-cookie"]
        return response

    @app.get("/health")
    async def health() -> dict:
        return {
            "origin": origin.name,
            "port": origin.port,
            "trust_domain": origin.trust_domain,
            "serves": origin.serves,
        }

    return app


def config_app(deployment: Deployment) -> FastAPI:
    """8000 — inert. Static bytes written before the poll opened.

    Nothing here is computed at request time. The digest is meaningful only
    because the artefact it covers was fixed in advance.
    """
    app = _base(origins.CONFIG)

    @app.middleware("http")
    async def readable_by_the_voter_app(request, call_next):
        """The configuration is public by design, so it is readable cross-origin.

        Everything here is published to anyone before the poll opens; there
        is nothing to protect with a same-origin rule, and the voter
        application is on a different origin precisely so that it holds no
        privilege this one could leak to it.
        """
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    payload = (deployment.document_root / "election.json").read_bytes()
    digest_line = (deployment.document_root / "election.json.sha256").read_text()

    @app.get("/election.json")
    async def election() -> Response:
        return Response(content=payload, media_type="application/json")

    @app.get("/election.json.sha256")
    async def election_digest() -> PlainTextResponse:
        return PlainTextResponse(digest_line)

    return app


def voter_app(deployment: Deployment) -> FastAPI:
    """8001 — the voter's application.

    Static files only. Every cryptographic operation runs in the browser:
    the ad-hoc key pair, the blinding, the unblinding, and the verification
    of the token against the pinned key. This origin computes nothing and,
    crucially, holds nothing -- there is no session, no cookie and no state
    here for an identifier to be stored in even if one arrived.

    The config origin's address is injected into the page rather than
    hard-coded, so the port offset used by the tests reaches the browser.
    """
    app = _base(origins.VOTER_APP)
    index = VOTER_APP_STATIC / "index.html"

    @app.get("/", response_class=HTMLResponse)
    async def page() -> HTMLResponse:
        if not index.exists():
            return HTMLResponse(
                "<h1>The voter application has not been built.</h1>"
                "<p>Run <code>npm install &amp;&amp; npm run build</code> in "
                "<code>web/voter-app</code>.</p>",
                status_code=503,
            )
        html = index.read_text(encoding="utf-8").replace(
            'data-config-origin=""', f'data-config-origin="{origins.CONFIG.url}"'
        )
        return HTMLResponse(html)

    if VOTER_APP_STATIC.exists():
        app.mount("/", StaticFiles(directory=VOTER_APP_STATIC), name="static")
    return app


def stub_app(origin: origins.Origin) -> FastAPI:
    """An origin that is bound and reachable but implements nothing yet.

    Present so the boundary tests are written against the real port map from
    the first commit, rather than retrofitted once the endpoints exist.
    """
    app = _base(origin)

    @app.get("/")
    async def root() -> JSONResponse:
        return JSONResponse(
            {
                "origin": origin.name,
                "status": "not implemented in this step",
                "serves": origin.serves,
            },
            status_code=501,
        )

    return app


def build_all(deployment: Deployment) -> dict[origins.Origin, FastAPI]:
    apps = {
        origins.CONFIG: config_app(deployment),
        origins.VOTER_APP: voter_app(deployment),
        origins.WALLET: wallet_app(deployment, _base),
        origins.VRO: vro_app(deployment, _base),
        origins.EBB: ebb_app(deployment, _base),
        origins.SETUP: setup_app(deployment, _base),
    }
    for origin in origins.ALL:
        if origin not in apps:
            apps[origin] = stub_app(origin)
    return apps
