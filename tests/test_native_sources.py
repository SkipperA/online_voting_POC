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
