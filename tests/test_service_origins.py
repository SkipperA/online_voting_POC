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


def test_every_origin_reports_which_build_it_is(clients):
    """One `curl` instead of a fresh proxy per patch.

    Every check for "is the deployment running the code I think it is" was
    a proxy: grep a page for a string only one patch introduced, or `exec`
    into the container and read a file. Each works, and each has to be
    invented again next time. The process knows.

    On every origin rather than one, because stage 2 splits the process and
    at that point they can differ -- a single reported version would then
    be a guess about seven other containers.
    """
    from service import build

    for origin in origins.ALL:
        body = clients[origin.name].get("/health").json()
        assert body["revision"] == build.REVISION, origin.name
        assert body["revision"], f"{origin.name}: an empty revision says nothing"


def test_the_revision_is_not_part_of_the_election(clients):
    """It is a claim about software, not a field the digest covers.

    An image rebuilt with no change to the election must not move the
    digest every voter pinned, and a reader must not be able to mistake a
    software version for something the configuration attests. So the
    revision reaches the index page through the served markup and never
    through `election.json`.
    """
    from service import build

    served = clients["config"].get("/election.json").json()
    for key, value in served.items():
        assert build.REVISION not in str(value), (
            f"the revision has leaked into election.json under {key!r}")
    assert not any("revision" in k for k in served), served.keys()

    page = clients["config"].get("/").text
    assert f'data-revision="{build.REVISION}"' in page
    assert "This build" in page


def test_an_unset_revision_is_reported_rather_than_guessed(monkeypatch):
    """`unknown`, and not something plausible.

    An image built without the argument is a real thing that happens --
    `up -d --build` with the variable unexported does it. A revision that
    looked right and was wrong would be believed, which is worse than a
    field that admits it has nothing.
    """
    import importlib

    from service import build

    monkeypatch.setenv("OVPOC_REVISION", "")
    monkeypatch.setattr(build, "_from_git", lambda: None)
    assert build._resolve() == "unknown"

    # And the environment wins over a `.git` that happens to be present:
    # the container's explicit claim about what was built must not be
    # overridden by whatever the build context carried in.
    monkeypatch.setenv("OVPOC_REVISION", "deadbee")
    monkeypatch.setattr(build, "_from_git", lambda: "0000000")
    assert build._resolve() == "deadbee"
    importlib.reload(build)


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


def test_every_runtime_page_watches_the_configuration_it_pinned(clients):
    """A page cannot be served without the guard that notices a new election.

    Every surface pins the published configuration when it loads, and the
    setup console can mint a new election over the running one at any
    moment -- replacing all three key pairs. Until this guard existed
    nothing told the open pages, so they went on checking a new election's
    artefacts against an old election's keys and said, accurately, that
    nothing verified. Those messages name defences doing their job and
    read, in a room, as the system being broken.

    Served rather than written into the pages, like the band and the
    tokens, so a surface added later cannot be added without one. And
    injected rather than linked: a `<script src>` at 8000 would let the
    config origin run code on six trust domains, which is a different and
    worse dependency than sharing a stylesheet.
    """
    import re

    body = (Path(__file__).resolve().parents[1]
            / "web" / "shared" / "config-watch.js").read_text()
    # A line from the file itself rather than a name it happens to define:
    # a page carrying this is carrying the file, not something that looks
    # like it.
    fingerprint = "election.json.sha256"

    for origin in origins.ALL:
        if origin is origins.VOTER_APP:
            continue  # its page is a 503 until someone runs the build
        page = clients[origin.name].get("/").text

        if origin is origins.SETUP:
            # The console is the author of the change. A page reporting an
            # operator's own mint back to them as news is noise, and noise
            # in the one place a reader has been taught to read carefully.
            assert fingerprint not in page, (
                "the setup console must not warn about its own act")
            continue

        assert fingerprint in page, f"{origin.name}: no staleness watch"
        assert f'window.OVPOC_CONFIG_ORIGIN="{origins.CONFIG.url}"' in page, (
            f"{origin.name}: the watch has no config origin to read")
        assert body.strip() in page, f"{origin.name}: the watch is not this file"
        # A page's own scripts are same-origin and relative. Anything with a
        # scheme in it is another origin running code here.
        assert not re.findall(r'<script[^>]+src="[^"]*//', page), (
            f"{origin.name}: a page that executes another origin's code "
            "has handed that origin the page")


def test_the_supervisor_reports_its_two_checks_separately(clients):
    """One verdict for two checks could only name the weaker finding.

    The page recomputes each commitment from the office's own
    `[id, opening]` pair, and separately chains the published commitments
    from the genesis hash to the head the office signed. These fail for
    unrelated reasons and have unrelated remedies: a commitment that does
    not recompute puts an identifier in doubt, while a chain that does not
    reach the head can happen with every commitment recomputing perfectly
    -- an entry inserted, dropped or reordered leaves each one correct and
    the sequence wrong.

    They were collapsed into a single line reading "THE REGISTER DOES NOT
    REBUILD", which told a supervisor that something was wrong and not
    which half. So: two rows, and each verdict a function of its own
    check alone.
    """
    import re

    root = Path(__file__).resolve().parents[1] / "web" / "supervisor" / "static"
    html = (root / "index.html").read_text()
    script = (root / "supervisor.js").read_text()

    page = clients[origins.SUPERVISOR.name].get("/").text
    for slot in ("commitments", "chain"):
        assert f'id="{slot}"' in html, f"no row for {slot}"
        assert f"show('{slot}'," in script, f"nothing fills {slot}"
        assert f'id="{slot}"' in page, f"{slot} is not served"

    labels = re.findall(r'<span class="label">([^<]+)</span>\s*'
                        r'<span class="value" id="(commitments|chain)"', html)
    assert len(labels) == 2 and labels[0][0] != labels[1][0], (
        "two checks reported under one name is the collapse coming back")

    # Each verdict a function of its own check. The commitment line must
    # not consult the head, and the chain line must not consult whether
    # the commitments recomputed -- which is exactly what the single line
    # did, and why a chain failure could be reported as a commitment one.
    def call(slot: str) -> str:
        at = script.index(f"show('{slot}',")
        depth, out = 0, []
        for ch in script[at:]:
            out.append(ch)
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
        return "".join(out)

    commitments, chain = call("commitments"), call("chain")
    assert "data.head" not in commitments, (
        "the commitment verdict must not depend on the chain")
    for borrowed in ("rebuilt", "wrong"):
        assert borrowed not in chain, (
            f"the chain verdict must not depend on {borrowed}")


def test_the_watch_reports_and_never_navigates():
    """It says reload. It does not reload.

    On the voter application a reload costs the voter the ad-hoc key, and
    with it the entitlement to re-vote -- which is the design's own answer
    to coercion, so a stale configuration must not be allowed to spend it.
    The only navigation in the file is on a click the reader performed,
    where the page's own `beforeunload` guard stands in the way.

    And the bar collapses rather than closes: the condition is permanent
    until the page is reloaded, so a notice that could be dismissed
    outright would leave a stale page looking exactly like a current one.
    """
    import re

    body = (Path(__file__).resolve().parents[1]
            / "web" / "shared" / "config-watch.js").read_text()

    navigations = re.findall(r"(?:location\.reload\(\)|location\s*=|location\."
                             r"(?:href|assign|replace))", body)
    assert len(navigations) == 1, f"more than one way out: {navigations}"
    assert "reload.onclick = () => window.location.reload();" in body, (
        "the one navigation must hang off a click the reader made")

    assert "classList.add('stale--slim')" in body, "the bar must collapse"
    for gone in (".remove()", "display = 'none'", "removeChild"):
        assert gone not in body, f"the bar must not be closable ({gone})"


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

    # The scripts build markup too, and the step highlight in `main.ts` was
    # a hard-coded teal that outlived the sweep because nothing read the
    # TypeScript. It reads the band's own colour now; this keeps it that way.
    scripts = (sorted(root.glob("*/static/*.js"))
               + sorted(root.glob("shared/*.js"))
               + sorted(root.glob("voter-app/src/*.ts")))
    for script in scripts:
        literals = set(re.findall(r"#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3}(?:[0-9a-fA-F]{2})?)?\b",
                                  script.read_text()))
        assert not literals, f"{script.name}: {sorted(literals)}"


def test_nothing_sticky_is_transparent():
    """A sticky element with nothing behind it is a rendering fault.

    The origin band sticks to the top so that "which trust domain is this"
    can be asked halfway down a page of base64. The two origins that are
    not trust domains carry the band without a hue -- and carried it
    without a background too, so on 8000 and 8009 the page scrolled
    straight through it and the band's own text sat on top of whatever had
    just gone under it.

    "No colour" has to mean the canvas, not nothing. This is the one layout
    property the suite can check: it cannot see the overlap, but it can see
    the declaration that causes it.
    """
    import re

    css = (Path(__file__).resolve().parents[1]
           / "web" / "shared" / "tokens.css").read_text()
    for rule in re.finditer(r"([.#][\w-]+(?:[^{};]*?))\{([^}]*)\}", css):
        selector, body = rule.group(1).strip(), rule.group(2)
        if "position: sticky" not in body and "position:sticky" not in body:
            continue
        assert re.search(r"background:\s*(?!transparent|none)\S", body), (
            f"{selector} is sticky with no opaque background")

    plain = re.search(r"\.origin--plain\s*\{([^}]*)\}", css)
    assert plain, "the uncoloured band variant is gone"
    assert "transparent" not in plain.group(1), (
        "the uncoloured band shares the sticky container and must stay opaque")


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
    sources += sorted(root.glob("shared/*.js"))
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


def test_every_clause_reaches_a_surface_or_is_named_as_not_doing_so():
    """A clause nobody is shown is a clause nobody applies.

    `docs/Demo_Scope_Limits.md` exists so that the labels on screen and
    the clauses spoken during a demonstration are written once. The
    companion test checks that every aside cites a real clause; this
    checks the other direction, which is the one that rots quietly --
    A8 reached no surface at all until somebody noticed, and the first
    draft of A10 would have been a clause about the browser client that
    the browser client never mentioned.

    Some clauses legitimately reach no page: they are about the suite,
    the repository or an operator's machine rather than about anything a
    reader is standing on. Those are listed, and the list is checked for
    staleness so it stays a place to explain a clause rather than hide
    one.
    """
    import re

    root = Path(__file__).resolve().parents[1]
    doc = (root / "docs" / "Demo_Scope_Limits.md").read_text()
    clauses = set(re.findall(r"^### ([SAOX]\d+) — ", doc, re.M))

    #: Clauses about the repository, the suite or an operator's machine,
    #: with no surface a reader could be standing on.
    OFF_SCREEN = {
        "A7",   # a restart loses a poll: an operator's fact
        "A9",   # the iOS blinding factor, stated in the app's own prose
        "X4",   # key material committed to the repository
        "O2",   # the voter's check runs on the device that cast
    }

    #: **Debt, not exemption.** These are about something a reader is
    #: standing on and are shown to them nowhere. The list is here so it
    #: can only shrink by work and grow by a visible edit; every entry is
    #: a page that should carry a note and does not.
    NOT_YET_SHOWN = {
        "A1",   # one office issues every token — belongs on the office page
        "A3",   # browser-delivered code — belongs on every browser surface
        "A5",   # the schedule is recorded, not enforced — the setup console
        "A6",   # the box's close is an operator's act
        "A8",   # the handover is a file and a discipline — the voter app
        "O3",   # one operator holds several roles
        "S2",   # the certificate lookup is a fixture — the office page
        "S3",   # the register is a handful of invented identifiers
    }

    shown = ""
    for page in sorted((root / "web").rglob("*.html")):
        shown += page.read_text(encoding="utf-8")
    for page in sorted((root / "web").rglob("*.js")):
        shown += page.read_text(encoding="utf-8")
    for page in sorted((root / "web" / "voter-app" / "src").rglob("*.ts")):
        shown += page.read_text(encoding="utf-8")

    cited = {c for c in clauses if f"<code>{c}</code>" in shown or f"'{c}'" in shown}
    missing = sorted(clauses - cited - OFF_SCREEN - NOT_YET_SHOWN)
    assert not missing, (
        "these clauses reach no surface: " + ", ".join(missing)
        + " — show them where a reader would wonder, or add them to "
        "NOT_YET_SHOWN, which is debt and is meant to shrink")

    # The debt list must not outlive the debt. A clause shown on a page
    # and still listed here reads as unfinished work that is finished.
    paid = sorted(NOT_YET_SHOWN & cited)
    assert not paid, (
        "these are shown now and still listed as debt: " + ", ".join(paid))

    stale = sorted((OFF_SCREEN | NOT_YET_SHOWN) - clauses)
    assert not stale, f"these lists name clauses that do not exist: {stale}"
