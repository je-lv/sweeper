"""Parsing for the operator's --ports selection.

Separate from stages/naabu.py, and shaped like resolvers.py, because the
same string is validated in three places that must agree: app.py (the
--ports argument), ui/menu.py (the prompt), and the stage that builds the
command. Three copies of a port-range parser would eventually disagree, and
the failure mode of disagreement here is scanning a range the operator did
not authorise.

Two syntaxes, because the levels themselves use both forms:

    top-100          ->  -top-ports 100
    80,443,8443      ->  -p 80,443,8443
    1-1024           ->  -p 1-1024

Validation is deliberately strict rather than permissive. The dangerous
value is not the one naabu rejects -- that surfaces loudly as a preflight
ARG_ERROR -- but the one it ACCEPTS under a meaning the operator did not
intend. `80;443` is a single odd port to a parser that splits on commas.
"""
from __future__ import annotations

import re

MIN_PORT = 1
MAX_PORT = 65535

_TOP_N = re.compile(r"top-(\d+)\Z")
_PORT = re.compile(r"\d+\Z")
_RANGE = re.compile(r"(\d+)-(\d+)\Z")


class PortSpecError(ValueError):
    """A --ports value that cannot be used as written."""


def _port(text: str) -> int:
    if not _PORT.fullmatch(text):
        raise PortSpecError(
            f"{text!r} is not a port number; expected a number, a lo-hi "
            "range, or the top-N shorthand"
        )
    value = int(text)
    if not MIN_PORT <= value <= MAX_PORT:
        raise PortSpecError(
            f"port {value} is outside {MIN_PORT}-{MAX_PORT}"
        )
    return value


def parse(value: str) -> str:
    """Return the canonical spec, or raise PortSpecError.

    The return value is the string itself once validated -- callers that
    want naabu flags use flag_args(). Kept separate so a caller can validate
    without depending on how the flags happen to be spelled.
    """
    value = (value or "").strip()
    if not value:
        # An empty --ports is not "use the level default": that is what
        # omitting the flag means. An operator who typed it meant to
        # restrict something, and silently scanning all 65535 ports while
        # they believe otherwise is the exact failure this module exists to
        # prevent.
        raise PortSpecError(
            "no port selection given; omit --ports to use the level's own "
            "range"
        )
    top = _TOP_N.fullmatch(value)
    if top:
        count = int(top.group(1))
        if not MIN_PORT <= count <= MAX_PORT:
            raise PortSpecError(
                f"top-{count} is outside top-{MIN_PORT}..top-{MAX_PORT}"
            )
        return value
    if value.lower().startswith("top"):
        # "top100" and "top_100" reach the element loop below and fail there
        # with a message about port numbers, which names the wrong mistake.
        raise PortSpecError(
            f"{value!r} looks like the top-N shorthand but is not; write it "
            "as top-100"
        )
    for element in value.split(","):
        element = element.strip()
        if not element:
            raise PortSpecError(
                f"{value!r} has an empty entry; check for a stray comma"
            )
        rng = _RANGE.fullmatch(element)
        if rng:
            lo, hi = _port(rng.group(1)), _port(rng.group(2))
            if lo > hi:
                raise PortSpecError(
                    f"range {element!r} runs backwards; write it as {hi}-{lo}"
                )
            continue
        _port(element)
    return value


def flag_args(value: str) -> list[str]:
    """The naabu flags for a validated selection.

    Callers pass a value that has already been through parse() at argument
    time; this re-validates rather than trusting it, because the value can
    also arrive from a saved profile or a resumed run's manifest, neither of
    which came through the CLI.
    """
    spec = parse(value)
    top = _TOP_N.fullmatch(spec)
    if top:
        return ["-top-ports", top.group(1)]
    return ["-p", spec]


def nmap_flag_args(value: str) -> list[str]:
    """Nmap spelling for the same validated selection grammar."""
    spec = parse(value)
    top = _TOP_N.fullmatch(spec)
    if top:
        return ["--top-ports", top.group(1)]
    return ["-p", spec]


#: The flags a level may use to select ports. build_command strips whichever
#: of these the level supplied before appending the operator's, so that a
#: narrowed command can never carry both.
PORT_FLAGS = ("-p", "-top-ports")
