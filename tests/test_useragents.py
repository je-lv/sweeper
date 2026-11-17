import random
from sweeper.useragents import (
    USER_AGENTS, header_args, header_args_for, random_agent,
)


def test_every_agent_is_a_desktop_browser():
    for ua in USER_AGENTS:
        assert ua.startswith("Mozilla/5.0")
        assert ("Windows NT" in ua) or ("X11" in ua and "Linux" in ua)
        assert any(b in ua for b in ("Chrome/", "Firefox/", "Edg/"))


def test_no_tool_signatures_leak_into_the_shortlist():
    banned = ("curl", "python-requests", "nuclei", "ffuf",
              "httpx", "feroxbuster", "Go-http-client", "libwww", "Wget")
    for ua in USER_AGENTS:
        for token in banned:
            assert token.lower() not in ua.lower()


def test_random_agent_returns_a_listed_agent():
    assert random_agent() in USER_AGENTS


def test_random_agent_is_reproducible_with_a_seeded_rng():
    a = random_agent(random.Random(7))
    b = random_agent(random.Random(7))
    assert a == b


def test_random_agent_varies_across_seeds():
    seen = {random_agent(random.Random(i)) for i in range(50)}
    assert len(seen) > 1, "selection is not actually random"


def test_header_args_render_as_a_dash_h_pair():
    args = header_args(random.Random(1))
    assert args[0] == "-H"
    assert args[1].startswith("User-Agent: Mozilla/5.0")


def test_header_args_for_renders_the_given_agent():
    ua = USER_AGENTS[0]
    assert header_args_for(ua) == ["-H", f"User-Agent: {ua}"]


def test_header_args_for_is_deterministic():
    """The point of the function: same input, same argv, every time."""
    ua = USER_AGENTS[2]
    assert {tuple(header_args_for(ua)) for _ in range(20)} == {
        ("-H", f"User-Agent: {ua}")
    }
