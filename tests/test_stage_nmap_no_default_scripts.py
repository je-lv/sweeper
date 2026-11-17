"""-sC is not requested: it crashes nmap 7.98 and nothing parses its output.

REPRODUCED against the lab, with the exact argv this stage builds:

    nmap: nse_nsock.cc:381: void callback(nsock_pool, nsock_event, void*):
    Assertion `lua_status(L) == LUA_YIELD' failed.

an NSE assertion failure that aborts with SIGABRT. The stage was recorded
`partial -- exit -6`, produced nothing, and service detection was lost for
the entire run at both high and full. The same command without -sC finishes
cleanly.

The second reason stands on its own even where nmap is patched: parse() in
this module reads <host>, <address>, <hostname>, <port>, <state> and
<service>. There is no handling for <script> elements anywhere, so -sC spent
scan time against the client producing a section nothing reads -- the same
objection stages/dnsx.py records for not requesting flags its parser
ignores.
"""
import pytest

from sweeper.stages.base import LEVELS
from sweeper.stages.nmap import NmapStage


@pytest.mark.parametrize("level", LEVELS)
def test_default_scripts_are_never_requested(level):
    assert "-sC" not in NmapStage().levels[level], (
        f"{level} requests -sC, which aborts nmap 7.98 and whose output "
        "parse() does not read"
    )


@pytest.mark.parametrize("level", LEVELS)
def test_no_script_flag_in_any_form(level):
    """--script=default is the same thing spelled differently."""
    args = " ".join(NmapStage().levels[level])
    assert "--script" not in args, level


def test_version_detection_is_still_requested_where_it_was():
    """Dropping -sC must not quietly drop -sV with it: service/product/
    version is what parse() actually reads and what the OUTDATED findings
    match against."""
    levels = NmapStage().levels
    for level in ("mid", "high", "full"):
        assert "-sV" in levels[level], level
