import pytest

from sweeper import resolvers
from sweeper.resolvers import ResolverError


def test_empty_value_means_tool_defaults():
    assert resolvers.parse("") == []
    assert resolvers.parse("   ") == []


def test_bare_v4_gets_an_explicit_port():
    assert resolvers.parse("127.0.0.1") == ["127.0.0.1:53"]


def test_explicit_port_is_kept():
    assert resolvers.parse("127.0.0.1:15353") == ["127.0.0.1:15353"]


def test_comma_separated_list_keeps_order():
    assert resolvers.parse("1.1.1.1, 8.8.8.8:5353") == [
        "1.1.1.1:53", "8.8.8.8:5353",
    ]


def test_duplicates_collapse():
    assert resolvers.parse("1.1.1.1,1.1.1.1:53") == ["1.1.1.1:53"]


def test_trailing_comma_does_not_produce_an_empty_argv_element():
    assert resolvers.parse("1.1.1.1,") == ["1.1.1.1:53"]


def test_bare_ipv6_needs_no_brackets():
    assert resolvers.parse("::1") == ["[::1]:53"]


def test_bracketed_ipv6_with_port():
    assert resolvers.parse("[::1]:5353") == ["[::1]:5353"]


def test_ipv6_is_compressed_so_two_spellings_are_one_resolver():
    assert resolvers.parse("[2001:0db8:0000::1]:53,[2001:db8::1]:53") == [
        "[2001:db8::1]:53",
    ]


def test_hostname_is_refused():
    """The whole point of --resolver is not to depend on ambient DNS.

    Accepting a hostname would make the setting resolve through exactly the
    configuration it exists to replace.
    """
    with pytest.raises(ResolverError) as exc:
        resolvers.parse("ns1.example.test")
    assert "IP" in str(exc.value)


def test_a_flag_shaped_entry_is_refused():
    """`-r "-silent"` is accepted by every Go tool here and changes the run.

    This is the argv-injection case the strict parse exists to close.
    """
    with pytest.raises(ResolverError):
        resolvers.parse("-silent")


def test_port_must_be_numeric_and_in_range():
    with pytest.raises(ResolverError):
        resolvers.parse("127.0.0.1:http")
    with pytest.raises(ResolverError):
        resolvers.parse("127.0.0.1:0")
    with pytest.raises(ResolverError):
        resolvers.parse("127.0.0.1:70000")


def test_unbalanced_bracket_is_refused():
    with pytest.raises(ResolverError):
        resolvers.parse("[::1:53")


def test_resolver_error_is_a_valueerror():
    """app.main turns ValueError into a friendly exit 2, which is right here."""
    assert issubclass(ResolverError, ValueError)


def test_as_ips_drops_the_port():
    entries = resolvers.parse("127.0.0.1:15353,[::1]:5353")
    assert resolvers.as_ips(entries) == ["127.0.0.1", "::1"]


def test_non_standard_ports_flags_only_the_off_port_entries():
    entries = resolvers.parse("1.1.1.1,127.0.0.1:15353")
    assert resolvers.non_standard_ports(entries) == ["127.0.0.1:15353"]


def test_non_standard_ports_empty_when_all_are_53():
    entries = resolvers.parse("1.1.1.1,8.8.8.8:53")
    assert resolvers.non_standard_ports(entries) == []
