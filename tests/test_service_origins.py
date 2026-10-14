"""The boundary invariants, written before the UI so they constrain it.

These are not tests of FastAPI.  They are the claims the surface map makes
about the shape of the deployment, in a form that fails when the shape
changes: that the origins are genuinely separate, that nothing sets a cookie,
that the config origin is inert, that the poll survives the setup console
being stopped, and -- the one worth writing first -- that `id` never appears
on the voter application's origin.

`id` is the invariant that is easy to break by accident and hard to notice.
The voting application already knows `k_p^a`; if it also learned `id`, one
component on the voter's own device would hold both halves of the association
the blind signature exists to sever, together with the office's signature over
it (§5.3). The blinding would still stop the VRO linking voter to ballot, but
the linkage would survive intact where it could be recorded, exported, or
produced under compulsion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from service import origins
from service.apps import build_all
from service.state import Deployment

TEST_VOTER_IDS = ["HU-1970-0442", "Kovács Ágnes"]


@pytest.fixture(scope="module")
def deployment(tmp_path_factory) -> Deployment:
    # 2048 rather than 3072: this suite tests plumbing, not cryptography, and
    # the golden vectors already pin a full-size key.
    return Deployment.create(
        bits=2048, document_root=tmp_path_factory.mktemp("config-root")
    )


@pytest.fixture(scope="module")
def clients(deployment) -> dict[str, TestClient]:
    return {o.name: TestClient(app) for o, app in build_all(deployment).items()}


# -- the port map ----------------------------------------------------------

def test_every_origin_has_its_own_port():
    ports = [o.port for o in origins.ALL]
    assert len(ports) == len(set(ports)), "two origins share a port and so share an origin"


def test_six_trust_domains_and_two_that_are_not():
    assert len(origins.TRUST_DOMAINS) == 6
    assert {o.name for o in origins.ALL} - {o.name for o in origins.TRUST_DOMAINS} == {
        "config",
        "setup",
    }


def test_every_origin_answers_health(clients):
    for name, client in clients.items():
        body = client.get("/health").json()
        assert body["origin"] == name
        assert body["port"] == origins.BY_NAME[name].port


# -- the invariant that had to be written first ----------------------------

def test_the_voter_app_origin_never_returns_id(clients, deployment):
    """No response from 8001 may contain a voter identifier.

    Exhaustive over the routes that exist rather than over routes imagined,
    so it keeps biting as endpoints are added.
    """
    client = clients["voter-app"]
    for voter_id in TEST_VOTER_IDS:
        deployment.vro.enrol(voter_id)

    for route in client.app.routes:
        path = getattr(route, "path", "")
        if not path or "{" in path:
            continue
        response = client.get(path)
        body = response.text
        for voter_id in TEST_VOTER_IDS:
            assert voter_id not in body, f"{path} disclosed {voter_id!r}"


def test_the_voter_app_serves_no_route_named_for_identity(clients):
    paths = [getattr(r, "path", "") for r in clients["voter-app"].app.routes]
    for path in paths:
        assert "voter_id" not in path and "/id" not in path, path


# -- cookies ---------------------------------------------------------------

def test_no_origin_sets_a_cookie(clients):
    """Cookies ignore the port, so one cookie would collapse the isolation.

    A cookie set on 127.0.0.1:8001 is readable on 127.0.0.1:8002. The
    separation of origins is the whole mechanism here, so the rule is absence
    rather than configuration.
    """
    for name, client in clients.items():
        for path in ("/health", "/"):
            response = client.get(path)
            assert "set-cookie" not in {k.lower() for k in response.headers}, name
            assert not response.cookies, name


# -- the config origin is inert -------------------------------------------

def test_config_serves_the_artefact_and_its_digest(clients, deployment):
    client = clients["config"]
    body = client.get("/election.json").content
    assert body == deployment.config.to_bytes()

    line = client.get("/election.json.sha256").text
    assert line.split()[0] == deployment.config.digest_hex()


def test_config_is_byte_stable_across_requests(clients):
    """Inert means inert: nothing computed at request time.

    If the artefact were rebuilt per request, the published digest would cover
    something that no longer exists, and the tamper demonstration would be
    meaningless.
    """
    client = clients["config"]
    first = client.get("/election.json").content
    for _ in range(3):
        assert client.get("/election.json").content == first


def test_the_configuration_carries_both_keys(clients):
    body = json.loads(clients["config"].get("/election.json").text)
    assert body["vro_token_key_spki"], "k_p^(R) missing"
    assert body["vro_statement_key"], "k_p^(O) missing"
    assert body["vro_token_key_fingerprint"], "nothing for the voter to pin"


def test_the_configuration_says_it_is_unsigned(clients):
    """Clause S4. The demo must say what it cannot demonstrate."""
    body = json.loads(clients["config"].get("/election.json").text)
    assert "signature" in body["scope_limits"]


def test_the_digest_detects_a_single_changed_byte(deployment):
    """The failure the demo is meant to show, as a test."""
    original = deployment.config.to_bytes()
    tampered = original.replace(b'"num_choices": 4', b'"num_choices": 5')
    assert tampered != original

    import hashlib

    assert hashlib.sha256(tampered).hexdigest() != deployment.config.digest_hex()


# -- the setup console is build-time --------------------------------------

def test_the_poll_runs_with_the_setup_console_stopped(deployment):
    """A test, not an intention (surface map §1).

    Nothing at runtime may depend on 8009. Building the runtime origins
    without it must succeed, and the configuration must still be servable,
    because it was written to disk before the poll opened.
    """
    apps = build_all(deployment)
    runtime = {o.name: a for o, a in apps.items() if o is not origins.SETUP}
    assert "setup" not in runtime

    with TestClient(runtime["config"]) as client:
        assert client.get("/election.json").status_code == 200


# -- the voter application is static and holds nothing --------------------

def test_the_voter_app_serves_the_page_with_the_config_origin_injected(clients):
    """Injected, not hard-coded, so a shifted port map still reaches 8000."""
    response = clients["voter-app"].get("/")
    assert response.status_code in (200, 503)
    if response.status_code == 503:
        return  # the bundle has not been built in this checkout
    assert f'data-config-origin="{origins.CONFIG.url}"' in response.text
    assert 'src="bundle.js"' in response.text


def test_the_voter_app_bundle_contains_no_identifier_handling(clients):
    """A weak check, deliberately: the strong one is that no route returns an id.

    What this adds is that the shipped JavaScript has no notion of a voter
    identifier at all -- no field, no parameter, no fetch to the wallet. The
    blinding runs here; identity does not.
    """
    response = clients["voter-app"].get("/bundle.js")
    if response.status_code == 404:
        return  # not built
    source = response.text
    assert "voter_id" not in source
    assert "release-query-credentials" not in source


def test_an_unbuilt_voter_app_says_so_rather_than_rendering_blank(deployment, tmp_path):
    """The failure that actually happened: page fine, script absent, no error.

    Guarding on index.html was useless — it is committed. The artefact that
    can be missing is the bundle, and a page that renders perfectly while
    doing nothing is worse than one that fails visibly.
    """
    import service.apps as apps_module

    original = apps_module.VOTER_APP_STATIC
    apps_module.VOTER_APP_STATIC = tmp_path / "never-built"
    try:
        client = TestClient(apps_module.voter_app(deployment))
        response = client.get("/")
        assert response.status_code == 503
        assert "npm run build" in response.text
    finally:
        apps_module.VOTER_APP_STATIC = original


def test_the_config_origin_serves_an_index_of_the_whole_deployment(clients):
    """One page a newcomer can open. Still inert: it describes, it holds nothing.

    The origin table is injected from `service/origins.py` rather than typed
    into the HTML, so a port that moves in code moves on the page too. The
    surface map's prose table has no such link and can drift.
    """
    response = clients["config"].get("/")
    assert response.status_code == 200
    for origin in origins.ALL:
        assert origin.url in response.text, origin.name
    assert "demonstration, not an election" in response.text
    assert "Demo_Scope_Limits" in response.text


# -- the shared look, and the separation it must not blur ------------------

def test_every_page_carries_the_tokens_and_its_own_band(clients):
    """One stylesheet and one band, eight copies, each origin for itself.

    The pages were eight hand-written `<style>` blocks that had drifted
    apart, and the drift was invisible to this suite: it reads page source
    and had nothing to say about what the source declared.

    The band is the separation made visible. Eight surfaces that look alike
    turn a security property into a claim in a document, so every page says
    which trust domain it is, which family that domain belongs to, and at
    what address -- in that domain's own colour. It is served rather than
    written into the pages, so a surface added later cannot be added
    without one, and this says so.
    """
    for origin in origins.ALL:
        if origin is origins.VOTER_APP:
            continue  # its page is a 503 until someone runs the build
        page = clients[origin.name].get("/").text

        assert "--ink-dim" in page, f"{origin.name}: no shared tokens"
        assert 'name="viewport"' in page, origin.name

        # the whole palette, so the config origin can draw the legend
        for other in origins.ALL:
            if other.hue is None:
                assert f"--hue-{other.name}:" not in page, (
                    f"{other.name} is not a trust domain and has no hue")
                continue
            light, dark = other.hue
            assert f"--hue-{other.name}:{light}" in page, origin.name
            assert f"--hue-{other.name}:{dark}" in page, f"{origin.name}: no dark value"

        assert origin.title in page and origin.url in page, origin.name
        if origin.hue is None:
            assert '<header class="origin origin--plain">' in page, (
                f"{origin.name} is not a trust domain and must carry no colour")
            assert "--domain:var(" not in page, origin.name
            assert "infrastructure" in page, origin.name
        else:
            assert '<header class="origin">' in page, f"{origin.name}: no band"
            assert f"--domain:var(--hue-{origin.name})" in page, (
                f"{origin.name} serves a band that is not its own")
            assert origin.family in page, origin.name


def test_no_page_declares_a_colour_of_its_own():
    """Where the drift came back last time, it came back as a literal.

    Every colour has a light value and a dark value, and both live in
    `web/shared/tokens.css`. A hex code typed into a page is a colour with
    one value, which in practice means a colour that fails in one of the
    two themes -- which is how the secret-red came to sit at 2.90:1 against
    the dark canvas while the page declared `color-scheme: light dark`.
    """
    import re

    root = Path(__file__).resolve().parents[1] / "web"
    for page in sorted(root.glob("*/static/index.html")):
        literals = set(re.findall(r"(?:color|background|border[\w-]*)\s*:\s*[^;\"}]*?(#[0-9a-fA-F]{3,8})", page.read_text()))
        assert not literals, f"{page.parent.parent.name}: {sorted(literals)}"


def test_nothing_sets_a_size_of_its_own():
    """The floor is in the tokens, and only in the tokens.

    These pages are read projected and from the back of a room. The scale
    starts at 13px equivalent and is expressed in `rem`, so that a reader
    who raises their browser's font size raises all of it -- the pages
    previously mixed `px` and `rem` in the same rule sets, which moved half
    the type and left the rest.

    The scripts are scanned too, not just the pages: the caption on every
    payload in the voter application was a 12px literal in `main.ts`,
    below the floor and invisible to a check that only read HTML.
    """
    import re

    root = Path(__file__).resolve().parents[1] / "web"
    sources = sorted(root.glob("*/static/index.html"))
    sources += sorted(root.glob("*/static/*.js"))
    sources += sorted(root.glob("voter-app/src/*.ts"))
    for source in sources:
        literals = re.findall(r"font-size\s*:\s*([\d.]+(?:px|pt|em))", source.read_text())
        assert not literals, f"{source.name}: {sorted(set(literals))}"


def test_every_scope_note_names_a_kind_and_a_real_clause():
    """`Demo_Scope_Limits.md` is the single list the screen derives from.

    Its opening sentence says the labels shown in the UI and the clauses
    spoken during a demonstration are written once so that the screen and
    the presenter cannot drift apart. Nothing enforced that: the pages
    carried one amber box saying four different sorts of thing, and A8 --
    every wallet key in the repository, published on purpose -- reached no
    surface at all.

    So: every aside declares one of the four kinds, every clause it cites
    exists in the list, and the kind it declares is the section that clause
    actually sits under. A clause moved between sections and not relabelled
    on screen is exactly the conflation the document exists to prevent.
    """
    import re

    root = Path(__file__).resolve().parents[1]
    doc = (root / "docs" / "Demo_Scope_Limits.md").read_text()

    section_of = {"Substituted": "substituted", "Absent": "absent",
                  "Out of scope": "scope", "Exposed": "exposed"}
    kind_of_clause, section = {}, None
    for line in doc.splitlines():
        head = re.match(r"## (.+)$", line)
        if head and head.group(1) in section_of:
            section = section_of[head.group(1)]
        clause = re.match(r"### ([SAOX]\d+) — ", line)
        if clause and section:
            kind_of_clause[clause.group(1)] = section
    assert len(kind_of_clause) > 10, "the clause list did not parse"

    for page in sorted((root / "web").glob("*/static/index.html")):
        name = page.parent.parent.name
        html = page.read_text()
        for note in re.finditer(r'class="note note--(\w+)"(.*?)(?:</div>|</p>)', html, re.S):
            kind, body = note.group(1), note.group(2)
            assert kind in section_of.values(), f"{name}: unknown kind {kind!r}"
            cited = re.findall(r"<code>([SAOX]\d+)</code>", body)
            assert cited, f"{name}: a {kind} note citing no clause"
            for clause in cited:
                assert clause in kind_of_clause, (
                    f"{name} cites {clause}, which is not in Demo_Scope_Limits.md")
                assert kind_of_clause[clause] == kind, (
                    f"{name} shows {clause} as {kind!r}, but the list files it "
                    f"under {kind_of_clause[clause]!r}")


def test_the_index_does_not_disclose_an_identifier(clients, deployment):
    """It is served by an origin that holds no identifiers, and must stay so."""
    for voter_id in TEST_VOTER_IDS:
        deployment.vro.enrol(voter_id)
    body = clients["config"].get("/").text
    for voter_id in TEST_VOTER_IDS:
        assert voter_id not in body


# -- what a page fetches, and what it is allowed to fetch ------------------

def test_every_origin_the_checker_fetches_will_answer_it(clients):
    """The page and the allowance are written in different files.

    Nothing had connected them: the suite checked the recount arithmetic in
    Python and never asked what a page is permitted to fetch. This reads
    the script and tries each request the way the browser would, under a
    hostname the allowance does not name -- which is how the recount came
    to fail for anyone who typed `localhost`.
    """
    import re
    from pathlib import Path

    script = (Path(__file__).resolve().parents[1]
              / "web" / "checker" / "static" / "checker.js").read_text()

    wanted = {
        "EBB": (origins.EBB, set(re.findall(r"\$\{EBB\}(/[\w-]+)", script))),
        "VRO": (origins.VRO, set(re.findall(r"\$\{VRO\}(/[\w-]+)", script))),
    }
    assert wanted["EBB"][1], "the script should be fetching something from the box"

    # Deliberately not the canonical spelling: the same surface by another
    # name is the same surface, and the browser is unforgiving about it.
    as_the_browser_sends_it = f"http://localhost:{origins.CHECKER.port}"

    for name, (origin, paths) in wanted.items():
        for path in paths:
            response = clients[origin.name].get(
                path, headers={"origin": as_the_browser_sends_it})
            allowed = response.headers.get("access-control-allow-origin")
            assert allowed in ("*", as_the_browser_sends_it), (
                f"the checker fetches {name}{path} and would be refused: "
                f"allow-origin was {allowed!r}")
