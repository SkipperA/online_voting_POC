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
