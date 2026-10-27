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

#: Things only a component handling the *signed* document would mention.
#: The upload endpoint and the page that posts to it, by name.
SIGNED_DOCUMENT_TRACES = ("signed-token-requests", "/upload")


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

    A grep is not a mechanism and clause A8 says as much about the sandbox
    itself: "what is here is the discipline, the file, and this clause --
    not a mechanism that makes the shortcut impossible". This makes taking
    the shortcut a visible edit rather than a quiet one, which is all a
    tripwire ever does.
    """
    offenders = {}
    for path in sorted((NATIVE / "VoterApp").rglob("*.swift")):
        source = path.read_text(encoding="utf-8")
        found = [t for t in SIGNED_DOCUMENT_TRACES if t in source]
        if found:
            offenders[path.name] = found
    assert not offenders, (
        "the voting application names the office's upload path, which only a "
        "component handling the signed document would need:\n  "
        + "\n  ".join(f"{name}: {', '.join(found)}" for name, found in offenders.items())
        + "\n(clause A8; the signed document must not pass through this app)")
