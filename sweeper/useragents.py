"""Browser User-Agent shortlist.

Scanners that announce themselves (curl, python-requests, nuclei, ffuf,
feroxbuster) are trivially blocked by WAFs and CDN bot rules, which turns a
scan into a measurement of the WAF rather than the application. Every
HTTP-issuing stage therefore sends a realistic desktop-browser UA drawn from
this shortlist.

Deliberately narrow: Windows and Ubuntu, Chrome/Firefox/Edge only. Exotic or
stale UAs are themselves a bot signal, so a small pool of current, ordinary
strings blends better than a large varied one.

NOTE for engagement records: a browser UA makes scan traffic HARDER for a
client's blue team to attribute. Where the rules of engagement require
attributable traffic, override with a fixed identifying UA instead.
"""
from __future__ import annotations

import random

USER_AGENTS = (
    # Windows 11 / Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    # Windows 11 / Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
    # Windows 11 / Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
    "Gecko/20100101 Firefox/133.0",
    # Windows 10 / Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Ubuntu / Firefox
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) "
    "Gecko/20100101 Firefox/133.0",
    # Ubuntu / Chrome
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)


def random_agent(rng: random.Random | None = None) -> str:
    """One UA from the shortlist. Pass an rng seeded for reproducible runs."""
    return (rng or random).choice(USER_AGENTS)


def header_args(rng: random.Random | None = None) -> list[str]:
    """Rendered as -H arguments, the form every tool here accepts.

    Prefer header_args_for(ctx.user_agent) inside a stage: a fresh random
    draw per call makes build_command non-deterministic, so preflight
    validates a different argv than the runner executes and the command
    recorded in run.json cannot be replayed.
    """
    return ["-H", f"User-Agent: {random_agent(rng)}"]


def header_args_for(user_agent: str) -> list[str]:
    """Rendered -H arguments for an already-chosen UA."""
    return ["-H", f"User-Agent: {user_agent}"]
