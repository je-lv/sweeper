"""Shared rate-limit argument helpers.

``RunConfig.rate_override`` is an engagement-wide safety control.  Every
active stage with a native throughput flag must replace its level default,
not append a second copy and depend on tool-specific duplicate-flag rules.
"""
from __future__ import annotations

import math


def replace_value_flag(
    flags: list[str], aliases: tuple[str, ...], canonical: str, value: int,
) -> list[str]:
    """Replace a value-taking flag and return one canonical occurrence."""
    if value <= 0:
        return list(flags)
    out: list[str] = []
    skip = False
    for item in flags:
        if skip:
            skip = False
            continue
        if item in aliases:
            skip = True
            continue
        out.append(item)
    return [*out, canonical, str(value)]


def interval(rate: int) -> str:
    """A conservative per-operation delay for tools without a rate flag."""
    if rate <= 0:
        raise ValueError("rate must be positive")
    milliseconds = max(1, math.ceil(1000 / rate))
    return f"{milliseconds}ms"


def pause_seconds(rate: int, default: float = 0.0) -> float:
    """Sequential-request pause that never exceeds ``rate`` operations/s."""
    if rate <= 0:
        return default
    return max(default, 1.0 / rate)
