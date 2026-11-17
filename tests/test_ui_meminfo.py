"""Machine memory headroom, for the gauge that would have warned us.

katana reached 9.3 GB on a 15 GB box and was killed by the kernel OOM
killer; nuclei's headless browsers later took the machine down and lost a
whole run. Neither was visible while it happened -- the UI showed a stage
running and a number going up.

SYSTEM-WIDE, deliberately, not sweeper's own process tree. The OOM killer
fires on GLOBAL pressure whatever caused it, and on the day it fired the
machine was filled by katana plus Docker plus a browser. A per-process
number would have shown sweeper looking innocent right up to the kill.

MemAvailable, not MemFree: MemFree excludes reclaimable page cache and reads
alarmingly low on a healthy machine, which would make the gauge cry wolf on
every run and therefore mean nothing on the one that mattered.

Returns None rather than guessing. This is Linux-only by construction, and a
fabricated headroom number is worse than no gauge -- the whole point is that
an operator can trust it enough to act on it.
"""

from sweeper.ui import meminfo


def _write(tmp_path, text):
    p = tmp_path / "meminfo"
    p.write_text(text, encoding="utf-8")
    return p


REAL_SHAPE = """\
MemTotal:       16106127 kB
MemFree:          521048 kB
MemAvailable:    3141592 kB
Buffers:          102400 kB
Cached:          8388608 kB
"""


def test_reads_available_and_total(tmp_path):
    got = meminfo.read(_write(tmp_path, REAL_SHAPE))
    assert got == (3141592 * 1024, 16106127 * 1024)


def test_a_missing_file_is_not_a_zero(tmp_path):
    """Non-Linux, or a container without /proc. No gauge beats a wrong one."""
    assert meminfo.read(tmp_path / "does-not-exist") is None


def test_a_file_without_the_fields_is_not_a_guess(tmp_path):
    assert meminfo.read(_write(tmp_path, "Nonsense: 1 kB\n")) is None


def test_partial_data_is_refused(tmp_path):
    """MemTotal alone cannot answer "how much headroom is left"."""
    assert meminfo.read(_write(tmp_path, "MemTotal: 16106127 kB\n")) is None


def test_malformed_values_do_not_raise(tmp_path):
    assert meminfo.read(_write(tmp_path,
                               "MemTotal: banana kB\nMemAvailable: 12 kB\n")) is None


def test_a_zero_total_is_refused_rather_than_divided_by(tmp_path):
    assert meminfo.read(_write(tmp_path,
                               "MemTotal: 0 kB\nMemAvailable: 0 kB\n")) is None


def test_pressure_is_the_fraction_in_use():
    assert meminfo.pressure((2 * 1024**3, 10 * 1024**3)) == 0.8


def test_pressure_of_nothing_is_nothing():
    assert meminfo.pressure(None) is None


def test_the_real_machine_answers(tmp_path):
    """Against the actual /proc on this box, so a kernel that renames or
    drops the field is caught here rather than by a blank gauge."""
    import sys
    got = meminfo.read()
    if not sys.platform.startswith("linux"):
        assert got is None
        return
    assert got is not None, "/proc/meminfo did not yield MemAvailable/MemTotal"
    available, total = got
    assert 0 < available <= total
    assert total > 512 * 1024**2, "implausible total; parsed the wrong units?"
