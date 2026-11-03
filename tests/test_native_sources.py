"""A syntax smoke test for the Swift the package's own tests cannot reach.

`swift test` covers `ios/OVPOCKit`. It does not cover `ios/VoterApp` and
`ios/WalletApp`, which are app targets built by Xcode and have no test
target of their own -- so the only thing standing between a malformed
source file and somebody's build is somebody's build.

This is not a parser and does not pretend to be. It balances delimiters,
which catches the one failure that has actually happened: a closing brace
dropped while editing a file programmatically, leaving
`WalletApp/ContentView.swift` with a `struct` that never closed. Xcode
found it; this suite, which runs on every change, had nothing to say.

What it deliberately does *not* do is check anything semantic. A Swift
file that balances is not a Swift file that compiles, and a green run
here means only that the cheapest class of mistake is absent.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
NATIVE = ROOT / "ios"

PAIRS = {"{": "}", "[": "]", "(": ")"}
CLOSERS = {v: k for k, v in PAIRS.items()}


def swift_sources() -> list[pathlib.Path]:
    return sorted(NATIVE.rglob("*.swift"))


def strip(source: str) -> str:
    """Remove comments and string literals, leaving the code's skeleton.

    Written out rather than regexed, because the regex version got this
    wrong in the obvious way: stripping `//` comments first truncates
    `"https://host"` mid-literal, after which every quote is misaligned
    and the delimiter count is nonsense. The order matters, so the states
    are explicit.
    """
    out: list[str] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":
            i = source.find("\n", i)
            if i == -1:
                break
            continue
        if c == "/" and nxt == "*":
            # Swift nests block comments, unlike C.
            depth, i = 1, i + 2
            while i < n and depth:
                if source.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif source.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            continue
        if source.startswith('"""', i):
            end = source.find('"""', i + 3)
            i = n if end == -1 else end + 3
            continue
        if c == '"':
            i += 1
            while i < n:
                if source[i] == "\\":
                    # An interpolation can carry delimiters of its own,
                    # but it is balanced within the literal, so skipping
                    # the escape and continuing is enough for a count.
                    i += 2
                    continue
                if source[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        out.append(c)
        i += 1
    return "".join(out)


def test_there_are_native_sources_to_check():
    """A glob that silently matches nothing is a test that always passes."""
    assert len(swift_sources()) > 15, "the Swift sources have moved"


@pytest.mark.parametrize(
    "path", swift_sources(), ids=lambda p: str(p.relative_to(NATIVE))
)
def test_delimiters_balance(path: pathlib.Path):
    stack: list[tuple[str, int]] = []
    skeleton = strip(path.read_text(encoding="utf-8"))

    line = 1
    for ch in skeleton:
        if ch == "\n":
            line += 1
        elif ch in PAIRS:
            stack.append((ch, line))
        elif ch in CLOSERS:
            assert stack, f"{path.name}: stray {ch!r} at line {line}"
            opener, opened = stack.pop()
            assert opener == CLOSERS[ch], (
                f"{path.name}: {ch!r} at line {line} closes {opener!r} "
                f"opened at line {opened}")

    assert not stack, (
        f"{path.name}: {len(stack)} unclosed "
        + ", ".join(f"{o!r} at line {ln}" for o, ln in stack))


# --------------------------------------------------------------------------
# Two renderers, one document
# --------------------------------------------------------------------------

def _swift_literals(source: str) -> str:
    """The Swift with its string concatenations joined up.

    Swift splits a long literal across lines with `+`; Python does it by
    writing them adjacent and letting the parser join them. The two break
    in different places, so comparing them literally would report a
    difference in line wrapping as a difference in the document. Closing
    the joins on this side makes the comparison about the text.
    """
    import re

    return re.sub(r'"\s*\+\s*"', "", source)


def _rendered_prose() -> list[str]:
    """Every fixed string `pdfrequest._lines` puts on the page.

    Read out of the Python with `ast` rather than listed here, so that a
    sentence added to the renderer is a sentence this test starts
    requiring -- a list in a test file would have to be remembered.
    """
    import ast

    tree = ast.parse((ROOT / "src" / "ovpoc" / "pdfrequest.py").read_text())
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == "_lines"):
            continue
        # The docstring is a string constant too, and it is prose about the
        # page rather than prose on it. Both files carry an explanation and
        # they are allowed to word it differently.
        docstrings = {
            id(n.value) for n in ast.walk(node)
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
        }
        return [
            n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and len(n.value) >= 12 and id(n) not in docstrings
        ]
    raise AssertionError("pdfrequest._lines has moved or been renamed")


def test_the_swift_renderer_says_what_the_python_renderer_says():
    """The office rebuilds the document; the phone writes it. One text.

    `tests/vectors/pdf-request.json` pins the bytes, and pins them only on
    a machine running `swift test`. CI has no Mac, so an edit to one
    renderer's prose and not the other's would reach a demonstration
    before it reached anybody's attention -- as a document the office
    refuses, reported to the citizen as "not as rendered", which is a
    message about their request and really a message about this.

    Not a compiler and not a substitute for the vector. It compares the
    words, which is the part that gets edited.
    """
    swift = _swift_literals(
        (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit" / "PDFRequest.swift")
        .read_text())
    missing = [line for line in _rendered_prose() if line not in swift]
    assert not missing, (
        "the Swift renderer does not carry these lines from pdfrequest._lines:\n  "
        + "\n  ".join(repr(m) for m in missing))


def test_the_two_renderers_agree_on_the_constants_that_are_not_prose():
    """The values that decide the bytes rather than the reading.

    Each is a thing somebody could reasonably change on one side: the
    marker a reader greps for, the name inside the embedded file, the
    fixed date that keeps the renderer a function of its payload, the
    three standard-14 faces, and the page size.
    """
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from ovpoc import pdfrequest

    swift = _swift_literals(
        (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit" / "PDFRequest.swift")
        .read_text())
    expected = [
        pdfrequest.MARKER.decode("ascii"),
        pdfrequest.EMBEDDED_NAME,
        pdfrequest._INFO_DATE,
        "Helvetica", "Courier", "Helvetica-Bold",
        str(pdfrequest.PAGE_W), str(pdfrequest.PAGE_H),
        *pdfrequest.FIELDS,
    ]
    missing = [value for value in expected if value not in swift]
    assert not missing, f"the Swift renderer is missing: {missing}"


# --------------------------------------------------------------------------
# One compile error the Python suite can see
# --------------------------------------------------------------------------

AUTOCLOSURE_ASSERTIONS = ("XCTUnwrap", "XCTAssertEqual", "XCTAssertTrue",
                          "XCTAssertFalse", "XCTAssertNil", "XCTAssertNotNil",
                          "XCTAssertGreaterThan", "XCTAssertLessThan")


def _awaits_inside_an_assertion(source: str) -> list[str]:
    """Calls whose own argument list contains `await`.

    The argument of these is an `@autoclosure`, and an autoclosure is not
    async, so `try await` inside one does not compile. An `await` *outside*
    the parentheses is ordinary and common -- `try await load(try
    XCTUnwrap(x))` is fine -- so this balances from the call's own opening
    parenthesis rather than reading the line.
    """
    found = []
    for name in AUTOCLOSURE_ASSERTIONS:
        start = 0
        while (at := source.find(name + "(", start)) != -1:
            i, depth = at + len(name), 0
            while i < len(source):
                if source[i] == "(":
                    depth += 1
                elif source[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            argument = source[at:i]
            if "await " in argument:
                line = source.count("\n", 0, at) + 1
                found.append(f"line {line}: {name}")
            start = at + 1
    return found


def test_no_swift_test_awaits_inside_an_assertion():
    """A compile error the balancer cannot see and CI cannot compile.

    `swift test` runs on a Mac and nowhere else, so a Swift file that does
    not compile reaches whoever next opens the package -- which here meant
    a build failure arriving in the same run as a new renderer, where it
    read as the renderer's fault and was not.

    Narrow on purpose. This is not a parser and knows one mistake: that
    `XCTUnwrap` and its neighbours take an `@autoclosure`, which cannot
    carry an `await`. It is in the suite because it already happened.
    """
    problems = {}
    for path in swift_sources():
        if "Tests" not in path.parts:
            continue
        found = _awaits_inside_an_assertion(path.read_text(encoding="utf-8"))
        if found:
            problems[path.name] = found
    assert not problems, (
        "an `await` inside an assertion's autoclosure will not compile:\n  "
        + "\n  ".join(f"{name}: {', '.join(where)}"
                      for name, where in problems.items()))


# --------------------------------------------------------------------------
# The one shortcut clause A8 names
# --------------------------------------------------------------------------

#: The endpoint that receives a signed document. Only the office and the
#: page the office serves have any business naming it.
SIGNED_DOCUMENT_TRACES = ("signed-token-requests",)

#: How a signed document would get back *in*.
#:
#: Sharper than a URL, and the thing that was actually missing: an Upload
#: button needs a file picker, and nothing else in this application has any
#: use for one. The app may *name* the office's page — it does, through
#: `Origins.handIn`, handed to `Link` so the browser opens it — because
#: telling a person where to go is not handling what they take there.
DOCUMENT_IMPORT_APIS = ("fileImporter", "UIDocumentPicker", "NSOpenPanel",
                        "onDrop", "importsItemProviders")


def test_the_voting_application_has_no_way_to_hand_a_document_in():
    """The property the qualified-signature route was arranged to keep.

    This application holds `k_p^a` and `r`, so it is the component that
    must not learn `id`. On that route `id` is in the signing certificate,
    which means it is in the *signed* document -- so the application
    writes the unsigned one, the voter carries it, and the voter hands the
    signed one to the office themselves on a page the office serves.

    The convenience somebody will propose is an Upload button here. It
    would be one screen, it would save a step, and it would put the signed
    document inside the one component that must not see it.

    What this watches is the *inbound* direction: the endpoint that
    receives a signed document, and the system APIs that would let one be
    chosen. Naming the office's page is not watched, because the
    application does name it -- the handover screen offers a `Link` the
    browser opens -- and a voter who is told to hand the document in
    themselves and not told where is being set up to look for a button.

    A grep is not a mechanism and clause A8 says as much about the sandbox
    itself: "what is here is the discipline, the file, and this clause --
    not a mechanism that makes the shortcut impossible". This makes taking
    the shortcut a visible edit rather than a quiet one, which is all a
    tripwire ever does.
    """
    offenders = {}
    for path in sorted((NATIVE / "VoterApp").rglob("*.swift")):
        source = path.read_text(encoding="utf-8")
        found = [t for t in SIGNED_DOCUMENT_TRACES + DOCUMENT_IMPORT_APIS
                 if t in source]
        if found:
            offenders[path.name] = found
    assert not offenders, (
        "the voting application posts to the office's upload endpoint, or "
        "offers a way to choose a file -- either of which only a component "
        "handling the signed document would need:\n  "
        + "\n  ".join(f"{name}: {', '.join(found)}" for name, found in offenders.items())
        + "\n(clause A8; the signed document must not pass through this app)")

    # And nothing native posts to that endpoint at all -- not the voting
    # application, not the package it links, not the wallet. The page the
    # office serves is the only client it has.
    for path in sorted(NATIVE.rglob("*.swift")):
        assert "signed-token-requests" not in path.read_text(encoding="utf-8"), (
            f"{path.name} names the office's upload endpoint")

    # Calibration. The wallet must choose a file -- that is its whole job --
    # so the same patterns fire there. A tripwire that matches nothing
    # anywhere is one nobody can tell apart from a typo.
    wallet = "\n".join(p.read_text(encoding="utf-8")
                       for p in (NATIVE / "WalletApp").rglob("*.swift"))
    assert any(api in wallet for api in DOCUMENT_IMPORT_APIS), (
        "no wallet source opens a file picker any more: either the wallet "
        "changed or these patterns have stopped matching anything, and a "
        "tripwire that matches nothing is not protecting the voter app")


def test_the_native_client_reads_the_ballot_s_wording():
    """The phone's half of `tests/test_ballot_wording.py`.

    The names live in `election.json`, which the native client already
    fetches and whose digest it already pins -- so showing them is reading
    two more fields rather than trusting a new source. A client that did
    not read them would show `1…4` where the browser shows candidates,
    which is the kind of divergence nobody notices until a demonstration.
    """
    election = (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit"
                / "Election.swift").read_text(encoding="utf-8")
    assert '"question"' in election and '"options"' in election
    assert "func optionName(" in election

    app = (NATIVE / "VoterApp" / "VoterApp").glob("*.swift")
    shown = "".join(path.read_text(encoding="utf-8") for path in app)
    assert "optionName(" in shown or "selectionLabel" in shown, (
        "the voting application reads the wording and shows none of it")


def test_the_document_renderer_still_names_no_option():
    """`ő` and `ű` are outside WinAnsiEncoding, and the office rebuilds.

    `pdfrequest.py` renders ASCII with standard-14 fonts and no embedded
    font deliberately, and the Swift renderer has to agree byte for byte
    or the office refuses a citizen's own request as "not as rendered".
    The wording must therefore reach the document by no route at all --
    the request names the election by identifier and digest.
    """
    renderer = (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit"
                / "PDFRequest.swift").read_text(encoding="utf-8")
    for forbidden in ("optionName", "election.question", "election.options"):
        assert forbidden not in renderer, (
            f"{forbidden} reaches the token-request document")


# --------------------------------------------------------------------------
# The hand-off between the two applications
# --------------------------------------------------------------------------

def test_the_two_applications_agree_on_the_hand_off():
    """Three places have to say the same two words, and one is generated.

    `Info.plist` is produced by Xcode and excluded from the repository, so
    the registration that makes a URL scheme work lives in `ios/README.md`
    as an instruction to a human. The code that *opens* those schemes is
    in `HandOff.swift`. Nothing connects the two, and the failure when
    they disagree is the worst kind: the hand-off does nothing at all, no
    error is raised anywhere, and the demonstration looks like a wallet
    that was never installed.

    So this reads the scheme names out of the package and requires the
    README to name both. It is not a mechanism either -- nothing here can
    check what an operator typed into Xcode -- but it makes a rename a
    visible edit in three files rather than a quiet one in two.
    """
    handoff = (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit"
               / "HandOff.swift").read_text(encoding="utf-8")

    schemes = dict(re.findall(
        r'static let (walletScheme|voterScheme)\s*=\s*"([^"]+)"', handoff))
    assert set(schemes) == {"walletScheme", "voterScheme"}, (
        "HandOff.swift no longer declares both scheme names where this "
        f"test can read them: found {sorted(schemes)}")
    assert schemes["walletScheme"] != schemes["voterScheme"], (
        "both applications would register the same URL scheme, and which "
        "one the system opens is then undefined")

    readme = (NATIVE / "README.md").read_text(encoding="utf-8")
    for role, scheme in schemes.items():
        assert scheme in readme, (
            f"{scheme} ({role}) is opened by the code and registered by "
            "nobody: ios/README.md is where an Xcode URL Type is written "
            "down, because Info.plist is not in this repository")


def test_the_hand_off_carries_no_identifier():
    """What crosses is the request file's bytes, and nothing beside them.

    The voting application does not hold `id` and cannot put one here.
    The risk is the opposite direction: a later edit adding a field to
    make the wallet's screen friendlier -- the voter's name, say, read
    from somewhere -- would put the one thing §5.3 keeps apart into a URL
    that any application on the device can be handed.

    `HandOffTests.testTheHandOffNamesTheElectionAndNobodyElse` asserts the
    payload's three keys from the Swift side. This asserts the source
    names nothing of the sort, which is the cheaper half and the one that
    runs on every machine.
    """
    handoff = (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit"
               / "HandOff.swift").read_text(encoding="utf-8")
    for forbidden in ("voterID", "voter_id", '"id"', "identifier:"):
        assert forbidden not in handoff, (
            f"{forbidden} appears in the hand-off, which the voting "
            "application can build and anything on the device can read")


def test_only_the_wallet_transmits_and_only_the_voter_app_is_returned_to():
    """The direction of each scheme, asserted where it is used.

    Opening a URL is the one thing these applications can do to each
    other, so which one opens which is the whole of the arrangement. The
    voting application opens the wallet with a request; the wallet opens
    the voting application with an outcome. A wallet that built a request
    URL, or a voting application that built an outcome, would be a sign
    that the two halves had been copied into each other.
    """
    voter = "".join(p.read_text(encoding="utf-8")
                    for p in sorted((NATIVE / "VoterApp").rglob("*.swift")))
    wallet = "".join(p.read_text(encoding="utf-8")
                     for p in sorted((NATIVE / "WalletApp").rglob("*.swift")))

    assert "HandOff.outcome(" in voter, (
        "the voting application does not read the wallet's outcome")
    assert "HandOff.backToVoter(" not in voter, (
        "the voting application builds its own return URL, which would "
        "let it report an outcome the office never gave")

    assert "HandOff.request(" in wallet, (
        "the wallet does not read a handed-over request")
    assert "HandOff.toWallet(" not in wallet, (
        "the wallet builds a request hand-off, which only the voting "
        "application has any business doing")

    # And the file route stays. A phone with no wallet installed, and a
    # request somebody carried in, both end up at this picker.
    assert "fileImporter" in wallet, (
        "the wallet can no longer open a request file: the browser's "
        "arrangement is what the phone's is a trade against, and clause "
        "A8 needs both to exist")


def test_a_hand_off_nothing_accepts_is_reported_rather_than_silent():
    """The failure mode of a URL scheme is doing nothing at all.

    `Info.plist` is generated by Xcode and not in this repository, so
    whether the wallet registered the scheme is a step a human performs
    and humans skip steps. `openURL`'s completion says whether anything
    on the device claimed it, and reports to nobody by default -- so
    without this the voter is looking at a screen that says the wallet
    should have opened, and a wallet that never did.

    "An outcome that is deliberately uninformative to a stranger must be
    *more* informative to the operator, not less" is already in
    `CLAUDE.md` about the office's refusals. This is the same rule on the
    other side of the glass, and it is why the voting application keeps
    a way to hand the request over as a file: the fallback has to exist
    before the diagnosis is worth printing.
    """
    app = "".join(p.read_text(encoding="utf-8")
                  for p in sorted((NATIVE / "VoterApp").rglob("*.swift")))

    assert "handOffWasAccepted" in app and "handOffAccepted" in app, (
        "the voting application opens the wallet and never learns whether "
        "anything accepted -- use openURL's completion")
    assert "completion" in app or "{ accepted in" in app, (
        "openURL is called without its completion handler, which is the "
        "only thing that reports an unregistered scheme")
    assert "ShareLink" in app, (
        "there is no way to hand the request over when the hand-off is "
        "refused: a diagnosis with no fallback is just bad news")


def test_the_wallet_does_not_re_ask_who_it_belongs_to_on_every_launch():
    """Clause S1 substitutes a picker; it does not substitute two things.

    A real wallet belongs to one citizen and its key is hardware-bound to
    them, so it opens on the question being asked and not on *who are
    you*. The picker is the demonstration's substitution for the
    ownership. Re-running it on every launch substitutes the one-question
    flow as well, which the clause does not cover and the phone
    demonstration exists to show -- a cold launch from a hand-off would
    otherwise always cost a tap that no deployment has.

    The identifier is kept and the key is not: adoption fetches it again
    from the endpoint whose own docstring says no real wallet exposes it.
    """
    wallet = "".join(p.read_text(encoding="utf-8")
                     for p in sorted((NATIVE / "WalletApp").rglob("*.swift")))

    assert "restoreRememberedPersona" in wallet, (
        "the wallet forgets whose it is between launches")
    assert "UserDefaults" in wallet, (
        "nothing persists the adopted citizen")
    # The picker stays. It is how a demonstration plays several citizens
    # from one device, which is the reason it exists at all.
    assert "func adopt(" in wallet and "loadPersonas" in wallet, (
        "the persona picker has gone, and with it the ability to "
        "demonstrate more than one citizen from one phone")


# --------------------------------------------------------------------------
# What each application declares to the operating system
# --------------------------------------------------------------------------

def _info_plist(target: str) -> dict:
    """The target's committed `Info.plist`, parsed.

    `plistlib` is in the standard library, which is the whole reason this
    check can exist: the suite depends on what `pyproject.toml` declares
    and on nothing else, and a plist parser installed on one machine
    would make this test mean something different on two.
    """
    import plistlib

    path = NATIVE / target / "Info.plist"
    assert path.exists(), (
        f"{target} has no committed Info.plist. The URL type that makes "
        "the hand-off work lives there, and a generated one leaves it as "
        "an instruction nobody can check")
    return plistlib.loads(path.read_bytes())


def _schemes(plist: dict) -> set[str]:
    return {scheme
            for entry in plist.get("CFBundleURLTypes", [])
            for scheme in entry.get("CFBundleURLSchemes", [])}


def test_each_application_registers_the_scheme_the_other_opens_it_with():
    """The check `ios/README.md` could only ask a human to perform.

    A scheme nobody registered fails by doing *nothing at all*: `openURL`
    reports the refusal to the caller and to no one else, and the symptom
    on the device is a wallet that never appears. That is how this
    shipped, and the reason the plists are now in the repository rather
    than typed into a generated file Xcode owns.

    What this asserts is the join: the scheme the code opens is the
    scheme the other application claims. It is still not a mechanism --
    nothing here can check what is installed on a phone -- but the half
    that can be checked now is.
    """
    handoff = (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit"
               / "HandOff.swift").read_text(encoding="utf-8")
    declared = dict(re.findall(
        r'static let (walletScheme|voterScheme)\s*=\s*"([^"]+)"', handoff))

    assert declared["walletScheme"] in _schemes(_info_plist("WalletApp")), (
        "the voting application opens a scheme the wallet does not claim")
    assert declared["voterScheme"] in _schemes(_info_plist("VoterApp")), (
        "the wallet opens a scheme the voting application does not claim")

    # And neither claims the other's, which would have an application
    # opening itself and the voter never seeing the office answer.
    assert declared["voterScheme"] not in _schemes(_info_plist("WalletApp"))
    assert declared["walletScheme"] not in _schemes(_info_plist("VoterApp"))


def test_the_wallet_can_be_handed_the_request_as_a_file():
    """The fallback has to be reachable, or the diagnosis is just bad news.

    When the hand-off finds nobody the voting application offers to share
    the request, and a share sheet only offers applications that declare
    they can open that kind of file. The request is `blinded-key.json` on
    both demonstrations -- deliberately the same artefact -- so the
    wallet declares `public.json`.

    The cost is that it offers itself for any JSON on the device. That is
    honest: what it does with one is read it and refuse it by name, which
    is the consent screen's entire purpose.
    """
    from pathlib import PurePosixPath

    flow = (NATIVE / "OVPOCKit" / "Sources" / "OVPOCKit"
            / "VoterFlow.swift").read_text(encoding="utf-8")
    name = re.search(r'walletRequestFileName\s*=\s*"([^"]+)"', flow)
    assert name, "the wallet route's request file is no longer named here"
    suffix = PurePosixPath(name.group(1)).suffix

    types = {uti
             for entry in _info_plist("WalletApp").get("CFBundleDocumentTypes", [])
             for uti in entry.get("LSItemContentTypes", [])}
    expected = {".json": "public.json", ".pdf": "com.adobe.pdf"}.get(suffix)
    assert expected and expected in types, (
        f"the request is a {suffix} file and the wallet declares {types or 'nothing'}: "
        "a share sheet will not offer the wallet, so the fallback the "
        "voting application points at does not exist")


def test_the_voting_application_declares_no_document_type():
    """The inbound tripwire's other half, and the half with no picker.

    `test_the_voting_application_has_no_way_to_hand_a_document_in`
    watches the Swift for a file picker, because an Upload button needs
    one. A `CFBundleDocumentTypes` entry needs none: it puts this
    application in the share sheet and in *Open with* for the signed
    document, and the voter does the rest. Same shortcut, no code.

    This application holds `k_p^a` and `r` and must never learn `id`,
    which is in the signing certificate and therefore in the signed
    document. Clause A8.
    """
    plist = _info_plist("VoterApp")
    assert not plist.get("CFBundleDocumentTypes"), (
        "the voting application declares a document type, which offers it "
        "in the share sheet for the signed document -- the one file it "
        "must never receive (clause A8)")


def test_the_info_plists_are_not_inside_the_synchronized_sources():
    """Beside the project, never among the sources, and the build says why.

    From Xcode 16 a new project uses a file-system-synchronized folder:
    every file under `<Target>/<Target>/` belongs to the target without
    anybody adding it. An `Info.plist` there is therefore also copied as
    a *resource*, so the bundle's own `Info.plist` is produced twice and
    the build fails with `Multiple commands produce ... Info.plist`.

    One level up is outside that folder and still inside `SRCROOT`, so
    `INFOPLIST_FILE` is the bare name. This is the kind of arrangement
    that gets quietly undone by somebody tidying files toward the code
    they describe, and the failure is a build error with no obvious
    connection to the move.
    """
    for target in ("VoterApp", "WalletApp"):
        stray = NATIVE / target / target / "Info.plist"
        assert not stray.exists(), (
            f"{target}'s Info.plist is inside the synchronized source "
            "folder, where Xcode will also copy it as a resource: the "
            "build fails with 'Multiple commands produce'. It belongs "
            f"at ios/{target}/Info.plist, beside the project")
        assert (NATIVE / target / "Info.plist").exists(), (
            f"ios/{target}/Info.plist is missing")


def test_each_application_says_which_schemes_its_own_build_registers():
    """The one fault nothing else in this suite can see.

    Every other check here reads the repository: that the committed
    plists agree with `HandOff`, that the two applications open each
    other's schemes and not their own. None of them can see a *build
    setting*, and an `INFOPLIST_FILE` nobody set produces a binary that
    registers nothing at all -- whose symptom is identical to a scheme
    spelled wrong, to a wallet that is not installed, and to a hand-off
    that was never attempted: nothing happens, on two screens, with no
    error on either.

    So each application reads its own bundle and says what it answers
    to. It is the argument `service/build.py` makes for printing the
    revision, one layer down: a thing that cannot say what it is gets
    checked by proxies invented on the spot, and this one cost an hour
    before it existed.
    """
    for target, scheme in (("VoterApp", "voterScheme"),
                           ("WalletApp", "walletScheme")):
        source = "".join(p.read_text(encoding="utf-8")
                         for p in sorted((NATIVE / target).rglob("*.swift")))
        assert "HandOff.schemesRegistered(" in source, (
            f"{target} never reads its own CFBundleURLTypes, so a build "
            "that registered nothing looks exactly like one that worked")
        assert f"HandOff.{scheme}" in source, (
            f"{target} does not check its own registration against the "
            "scheme the other application opens it with")


def test_the_swift_tests_fixtures_are_all_here():
    """Nothing in this suite compiles Swift, so nothing notices a deletion.

    `ElectionTests` reads a published configuration from `tests/vectors/`
    and checks that the field set the Swift parses is the field set the
    service writes. That file used to sit at the repository root as
    `election.json`, where it was indistinguishable from what
    `python -m service` leaves in a checkout -- and a cleanup removed it
    as spill. `swift test` broke; `python -m pytest` stayed green, because
    the gap between the two suites is exactly this.

    The general rule, which this project keeps meeting from new
    directions: **a file one suite depends on and another cannot see needs
    the second suite to name it.** `test_native_sources.py` is where the
    Python half watches the Swift half, so it is where the naming goes.

    It reads literal suite names, which is all a grep can do: a file
    loaded through a variable is invisible here. That is a limit rather
    than a hole -- `tests/vectors/` has `tests/test_vectors.py` watching
    it, and what this adds is cover for the fixtures that belong to no
    such directory, which is the kind that went missing.
    """
    import json
    import re

    swift = (NATIVE / "OVPOCKit" / "Tests" / "OVPOCKitTests").rglob("*.swift")
    wanted = set()
    for path in swift:
        source = path.read_text(encoding="utf-8")
        # Vectors.directory / Vectors.fixtures, then a file name.
        for kind, name in re.findall(
                r'Vectors\.(directory|fixtures)\s*\n?\s*'
                r'\.appendingPathComponent\("([^"]+)"\)', source):
            wanted.add(("vectors" if kind == "directory" else "fixtures", name))
        # Vectors.load("suite") -> tests/vectors/suite.json
        wanted |= {("vectors", f"{name}.json")
                   for name in re.findall(r'Vectors\.load\("([^"]+)"\)', source)}

    assert wanted, (
        "no Swift test names a file in tests/vectors/, which means this "
        "test is reading the sources wrongly rather than that the fixtures "
        "have gone")

    missing = sorted(f"tests/{where}/{name}" for where, name in wanted
                     if not (ROOT / "tests" / where / name).is_file())
    assert not missing, (
        "`swift test` reads these and they are not here: "
        + ", ".join(missing)
        + "\nNothing in the Python suite compiles Swift, so a deletion "
        "shows up on a Mac and nowhere else.")

    # And they parse, because a fixture that is present and malformed
    # fails in the same place with a worse message.
    for where, name in sorted(wanted):
        json.loads((ROOT / "tests" / where / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# The package's public surface
# --------------------------------------------------------------------------

#: Public API that nothing calls, with the argument for keeping it.
#:
#: Empty is the goal. An entry here is a claim that a symbol earns its
#: place without a caller, and the claim has to be written down -- which
#: is the whole mechanism: it makes keeping dead API a visible edit
#: rather than the default outcome of nobody looking.
DELIBERATELY_UNCALLED: dict[str, str] = {
    # `Origins.checker` is an address to hand somebody, not one these
    # applications fetch: its own docstring says "not called by these
    # apps; here because an audience asks where the independent checks
    # live, and the answer is a URL they can open themselves."
    #
    # Written down honestly: no surface shows it yet, so the argument is
    # for a thing that has not been built. It is kept rather than deleted
    # because the address is correct and the reason is good, and it is
    # listed here rather than left silent because an entry that overstates
    # itself is worse than no list. Showing it on the voting
    # application's screen would retire this entry.
    "checker": "an address for a person to open; no surface shows it yet",
}


def test_the_package_exposes_nothing_nobody_calls():
    """`OVPOCKit` has one consumer, and it is in this repository.

    A library's public surface is normally a promise to strangers, so
    "unused" means little. This package has exactly two consumers --
    `VoterApp` and `WalletApp`, both here -- and `CLAUDE.md` is explicit
    about why the surface is narrow: the seams are "the §3.6 boundary
    expressed in types", so that a voting application wanting to transmit
    `[id, c, s]` would have to grow a dependency visible in its
    initialiser. A boundary expressed in types is only as good as the
    types, and every unused public member is a hole somebody can reach
    through without a decision being made.

    Two were found by writing this. `WalletKey.demoSeed` returned the
    wallet's raw private key -- out of the type that stands for hardware
    the key never leaves -- so a persona could survive a reinstall, which
    is not how the wallet ended up remembering anybody. `Receipt
    .exportable` built a dictionary for a receipt screen that does not
    exist. Neither had a caller; both read as supported API.

    Narrow on purpose: `public var/let/func`, because those are the
    members a caller reaches through. Types, initialisers and enum cases
    are not checked -- a `public struct` with no mention would be a
    different and louder kind of dead, and protocol conformances make
    naive matching wrong.
    """
    sources = sorted((NATIVE / "OVPOCKit" / "Sources").rglob("*.swift"))
    assert sources, "no package sources found; this test is reading nothing"

    declared: dict[str, pathlib.Path] = {}
    for path in sources:
        for name in re.findall(r"^\s*public\s+(?:var|let|func)\s+([A-Za-z_]\w*)",
                               strip(path.read_text(encoding="utf-8")), re.M):
            declared.setdefault(name, path)

    # Every Swift file in ios/, which is every consumer there is -- with
    # comments and string literals removed, which is not a detail. The
    # first version of this counted them, and so a symbol was "used" by
    # the paragraph explaining that it had been deleted. `strip` is the
    # same one the delimiter test uses, and it exists because a naive
    # version of it got this class of thing wrong before.
    everything = "".join(strip(p.read_text(encoding="utf-8"))
                         for p in sorted(NATIVE.rglob("*.swift"))
                         if ".build" not in p.parts)

    orphans = {}
    for name, where in declared.items():
        mentions = len(re.findall(rf"\b{re.escape(name)}\b", everything))
        declarations = len(re.findall(
            rf"^\s*public\s+(?:var|let|func)\s+{re.escape(name)}\b",
            everything, re.M))
        if mentions <= declarations and name not in DELIBERATELY_UNCALLED:
            orphans[name] = where.name

    assert not orphans, (
        "public API nothing calls:\n  "
        + "\n  ".join(f"{name}  ({where})" for name, where in sorted(orphans.items()))
        + "\n\nRemove it, or add it to DELIBERATELY_UNCALLED with the "
        "argument for keeping it. An unused public member is a hole "
        "somebody can reach through without a decision being made, which "
        "is what the narrow surface exists to prevent.")

    stale = sorted(set(DELIBERATELY_UNCALLED) - set(declared))
    assert not stale, (
        f"DELIBERATELY_UNCALLED names symbols that no longer exist: {stale}")
