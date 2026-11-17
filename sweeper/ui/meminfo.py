"""How much memory the MACHINE has left, for the progress gauge.

Memory, not time, is what actually bounds a large scan: `--time-limit`
bounds how long a stage runs and nothing bounds its resident set. katana has
reached 9.3 GB in 124 seconds and been killed by the kernel OOM killer, and
nuclei's headless browsers have exhausted a 15 GB machine outright and taken
a whole run with them. In both cases the UI showed a stage running and a
number going up, which is no warning at all.

SYSTEM-WIDE ON PURPOSE. The instinct is to measure sweeper's own process
tree, which is fairer -- but the OOM killer fires on GLOBAL pressure
whatever caused it, and on the day it fired the machine was filled by katana
plus Docker plus a browser. A per-process number would have shown sweeper
looking innocent right up until the kernel killed it, which is precisely
when the operator needed to know.

MemAvailable, not MemFree. MemFree excludes reclaimable page cache and reads
alarmingly low on a perfectly healthy machine; a gauge that cries wolf every
run means nothing on the run that matters. MemAvailable is the kernel's own
estimate of what a new allocation could actually get.
"""
from __future__ import annotations

from pathlib import Path

#: The two fields that answer "how much headroom is left". Both are required:
#: a total with no available figure cannot answer it, and reporting one
#: alone would be a number the operator could not act on.
_FIELDS = ("MemAvailable", "MemTotal")

PROC_MEMINFO = Path("/proc/meminfo")


def read(path: "str | Path | None" = None) -> "tuple[int, int] | None":
    """`(available_bytes, total_bytes)`, or None if it cannot be known.

    None is the honest answer on a non-Linux host, in a container without
    /proc, or against a kernel that stopped publishing these fields. It is
    never a zero and never an estimate: the gauge exists to be trusted
    enough to act on, and a fabricated headroom figure is worse than no
    gauge at all -- it would say "plenty of room" as the machine died.

    Never raises. A progress display that can throw would take down the run
    it is describing.
    """
    try:
        text = Path(path or PROC_MEMINFO).read_text(encoding="utf-8")
    except OSError:
        return None

    found: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key not in _FIELDS:
            continue
        try:
            # "MemAvailable:    3141592 kB" -- kB in /proc means KiB.
            found[key] = int(rest.split()[0]) * 1024
        except (ValueError, IndexError):
            return None

    if len(found) != len(_FIELDS):
        return None
    available, total = found["MemAvailable"], found["MemTotal"]
    if total <= 0:
        return None
    return available, total


def pressure(reading: "tuple[int, int] | None") -> "float | None":
    """Fraction of memory IN USE, 0.0-1.0, or None.

    In-use rather than available because that is the direction of danger,
    and a gauge that fills as things get worse is read correctly at a
    glance by someone who is not really looking at it.
    """
    if not reading:
        return None
    available, total = reading
    if total <= 0:
        return None
    return 1.0 - (available / total)
