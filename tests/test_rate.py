import pytest

from sweeper.rate import interval, pause_seconds, replace_value_flag


def test_replace_value_flag_removes_alias_and_value():
    assert replace_value_flag(
        ["-c", "10", "-rate-limit", "150", "-headless"],
        ("-rate-limit", "-rl"), "-rate-limit", 7,
    ) == ["-c", "10", "-headless", "-rate-limit", "7"]


def test_zero_rate_keeps_level_default_unchanged():
    flags = ["-rl", "15"]
    assert replace_value_flag(flags, ("-rl",), "-rl", 0) == flags


@pytest.mark.parametrize(("rate", "expected"), [
    (1, "1000ms"), (3, "334ms"), (100, "10ms"), (5000, "1ms"),
])
def test_interval_rounds_up_so_the_cap_is_not_exceeded(rate, expected):
    assert interval(rate) == expected


def test_pause_uses_stricter_of_default_and_override():
    assert pause_seconds(10, 0.2) == 0.2
    assert pause_seconds(2, 0.2) == 0.5
