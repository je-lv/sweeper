# tests/test_scope.py
import ipaddress

import pytest
from sweeper.scope import ScopeGuard, multi_host_error, normalize


def test_exact_host_allowed():
    g = ScopeGuard({"acc.example"})
    assert g.allows("acc.example") is True


def test_unlisted_host_refused():
    g = ScopeGuard({"acc.example"})
    assert g.allows("evil.test") is False


def test_subdomain_not_implicitly_allowed():
    g = ScopeGuard({"acc.example"})
    assert g.allows("admin.acc.example") is False


def test_wildcard_entry_allows_subdomains_and_apex():
    g = ScopeGuard({"*.acc.example"})
    assert g.allows("admin.acc.example") is True
    assert g.allows("a.b.acc.example") is True
    assert g.allows("acc.example") is True
    assert g.allows("acc.example.evil.test") is False


# --- O1: the wildcard's two boundaries -------------------------------------
#
# A "*." entry has a boundary on each side of its base and neither was
# pinned. The RIGHT one was ("acc.example.evil.test", above). The LEFT one
# was not: mutating _is_permitted's `host.endswith("." + base)` to
# `host.endswith(base)` left the whole suite green while admitting
# "evil-acc.example" for an allowlist of "*.acc.example" -- a domain an
# attacker registers, in scope, scanned, reported to the client as theirs.
#
# Written as a property over every character that can stand where the
# boundary dot must be, rather than as a list of the two or three near-misses
# that happen to come to mind. The dot is the ONLY separator; enumerating
# what is not a dot is the same as asserting that.
_LABEL_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_"


@pytest.mark.parametrize("joiner", [""] + list(_LABEL_CHARS))
def test_wildcard_requires_a_dot_at_the_left_label_boundary(joiner):
    """Only a "." separates the prefix from the base. Anything else -- a
    hyphen, another letter, or nothing at all -- makes it a DIFFERENT
    registrable domain that merely ends in the same characters.
    """
    g = ScopeGuard({"*.acc.example"})
    host = f"evil{joiner}acc.example"
    assert g.allows(host) is False
    assert g.permits_discovery(host) is False


@pytest.mark.parametrize("host", [
    "a.acc.example",
    "b.a.acc.example",
    "deep.er.still.acc.example",
    "acc.example",              # the apex; see the module docstring
])
def test_wildcard_matches_the_apex_and_any_depth_of_subdomain(host):
    """The other side of the boundary property: a real dot-separated prefix
    of any depth is in scope. Without this, refusing everything would pass
    the test above.
    """
    g = ScopeGuard({"*.acc.example"})
    assert g.allows(host) is True
    assert g.permits_discovery(host) is True


def test_wildcard_entry_is_not_itself_a_host():
    """"*.acc.example" ends with ".acc.example", so the entry matched itself
    and app.prepare() seeded the allowlist LINE as a HOST artifact: a junk
    query from every HOST-consuming stage, targets_permitted inflated by one,
    and "*.acc.example" printed in the client's asset inventory as a host
    that was scanned.

    It is refused but NOT recorded in refusals: that list is what the report
    prints under "Out-of-scope targets refused — worth checking against the
    rules of engagement", and the operator's own DNS-scope grant appearing
    there is a false RoE alarm in a deliverable.
    """
    g = ScopeGuard({"*.acc.example"})
    assert g.allows("*.acc.example") is False
    assert g.permits_discovery("*.acc.example") is False
    assert g.refusals == []


def test_wildcard_line_is_not_seeded_as_a_target_alongside_real_ones():
    """filter()'s permitted list is exactly what app.prepare() turns into
    HOST artifacts, so this is the store-level consequence stated where it
    can be checked without a run.
    """
    g = ScopeGuard({"*.acc.example", "acc.example"})
    permitted, refused = g.filter(["*.acc.example", "acc.example",
                                   "shop.acc.example"])
    assert permitted == ["acc.example", "shop.acc.example"]
    assert refused == ["*.acc.example"]
    assert g.refusals == []


def test_a_star_is_not_a_wildcard_prefix_on_someone_elses_domain():
    """The entry-matches-itself fix is a property of the prefix, not a
    special case for the literal marker: no "*"-bearing host is a subdomain.
    """
    g = ScopeGuard({"*.acc.example"})
    for host in ("*.b.acc.example", "**.acc.example", "a.*.acc.example",
                 # Anchored at BOTH ends: a prefix whose first label is
                 # label-shaped but which then stops being one must still be
                 # refused, or "a" matching at position 0 carries the rest.
                 "a*b.acc.example", "a..acc.example", ".acc.example"):
        assert g.permits_discovery(host) is False


def test_suffix_confusion_is_refused():
    g = ScopeGuard({"acc.example"})
    assert g.allows("notacc.example") is False
    assert g.allows("acc.example.evil.test") is False


def test_url_and_port_forms_are_normalized():
    g = ScopeGuard({"acc.example"})
    assert g.allows("https://acc.example/path?q=1") is True
    assert g.allows("acc.example:8443") is True
    assert g.allows("ACC.EXAMPLE") is True


def test_filter_splits_and_records_refusals():
    g = ScopeGuard({"acc.example"})
    ok, refused = g.filter(["acc.example", "evil.test"])
    assert ok == ["acc.example"]
    assert refused == ["evil.test"]
    assert g.refusals[0]["target"] == "evil.test"


def test_extend_requires_reason_and_is_recorded():
    g = ScopeGuard({"acc.example"})
    g.extend(["new.acc.example"], reason="operator-confirmed subfinder output")
    assert g.allows("new.acc.example") is True
    assert g.extensions[0]["reason"].startswith("operator-confirmed")


def test_empty_allowlist_refuses_everything():
    g = ScopeGuard(set())
    assert g.allows("anything.example") is False


def test_userinfo_bypass_is_refused():
    """The authority before the last "@" is userinfo, not the host.

    "acc.example:80@evil.test" addresses evil.test. A hand-rolled split on
    the first colon reduces it to "acc.example" and admits it, while the
    unmodified string is what reaches the subprocess.
    """
    g = ScopeGuard({"acc.example"})
    assert g.allows("acc.example:80@evil.test") is False
    assert g.allows("acc.example:1@attacker.tld") is False
    assert g.allows("https://acc.example@evil.test/") is False


def test_userinfo_bypass_does_not_leak_into_permitted_list():
    g = ScopeGuard({"acc.example"})
    ok, refused = g.filter(["acc.example:80@evil.test"])
    assert ok == []
    assert refused == ["acc.example:80@evil.test"]


def test_allows_alone_records_refusal():
    g = ScopeGuard({"acc.example"})
    assert g.allows("evil.test") is False
    assert len(g.refusals) == 1
    assert g.refusals[0]["target"] == "evil.test"
    assert g.refusals[0]["normalized"] == "evil.test"


def test_repeated_refusals_are_deduped():
    g = ScopeGuard({"acc.example"})
    g.allows("evil.test")
    g.allows("evil.test")
    g.filter(["evil.test", "evil.test"])
    assert len(g.refusals) == 1


def test_bracketed_ipv6_normalizes_and_is_refused():
    assert normalize("[::1]:8080") == "::1"
    g = ScopeGuard({"acc.example"})
    assert g.allows("[::1]:8080") is False


# --- C1: __init__ must normalize exactly as allows()/extend() do -----------
# ScopeGuard stored allowlist entries verbatim ("127.0.0.1:8080" stayed
# "127.0.0.1:8080") while allows() compared fully normalized hostnames
# ("127.0.0.1"). A targets file written the two most ordinary ways --
# host:port, or a URL -- refused every one of its own entries: every target
# refused, no stage ran, degraded:false, exit 0.


def test_targets_file_entries_permit_themselves(tmp_path):
    """A targets file of host:port and URL forms must permit both entries.

    ScopeGuard is built directly from a targets file's raw lines
    (RunContext.create). If __init__ does not normalize those lines the
    same way allows() normalizes what it is asked about, the file refuses
    itself.
    """
    targets = ["127.0.0.1:8080", "http://127.0.0.1/app"]
    g = ScopeGuard(set(targets))
    ok, refused = g.filter(targets)
    assert refused == []
    assert set(ok) == set(targets)


def test_init_and_extend_normalize_identically():
    """The two writers of self.allowed must agree.

    extend() already routes hosts through normalize(); __init__ used a bare
    .strip().lower().rstrip(".") that does not understand host:port or
    scheme-prefixed forms. Both paths must produce the same stored form for
    the same input.
    """
    g1 = ScopeGuard({"ACC.example:8443"})
    g2 = ScopeGuard(set())
    g2.extend(["ACC.example:8443"], reason="test")
    assert g1.allowed == g2.allowed == {"acc.example"}


def test_wildcard_allowlist_entry_is_normalized_too():
    """The "*." marker must survive normalization of the base it prefixes."""
    g = ScopeGuard({"*.ACC.EXAMPLE:9090"})
    assert g.allows("sub.acc.example") is True
    assert g.allows("acc.example") is True


# Named test_filter_dedupes_case_varied_repeated_refusals rather than the
# task brief's test_repeated_refusals_are_deduped: that name is already
# taken above (line 90) by a test covering the same invariant through a
# different call pattern. Reusing it would silently shadow the existing
# test instead of adding coverage.
def test_filter_dedupes_case_varied_repeated_refusals():
    g = ScopeGuard({"acc.example"})
    g.filter(["evil.test"])
    g.filter(["evil.test"])
    g.filter(["EVIL.TEST"])
    assert len(g.refusals) == 1


def test_refusal_records_first_seen_form():
    g = ScopeGuard({"acc.example"})
    g.filter(["https://evil.test/x"])
    assert g.refusals[0]["normalized"] == "evil.test"


# --- permits_discovery()/record_discovery_refusal(): separate accounting ---
# runner.py's admission choke point uses this pair instead of allows(), so a
# discovery-heavy stage (subfinder finding hundreds of subdomains) does not
# flood scope.refusals -- the list the report titles "out-of-scope targets
# refused", meaning "the operator supplied a target outside scope".


def test_permits_discovery_agrees_with_allows_on_membership():
    g = ScopeGuard({"acc.example"})
    assert g.permits_discovery("acc.example") is True
    assert g.permits_discovery("evil.test") is False


def test_permits_discovery_does_not_touch_refusals():
    g = ScopeGuard({"acc.example"})
    assert g.permits_discovery("evil.test") is False
    assert g.refusals == []


def test_record_discovery_refusal_is_separate_from_refusals():
    g = ScopeGuard({"acc.example"})
    g.record_discovery_refusal(stage="subfinder", kind="HOST",
                               value="evil.test", host="evil.test")
    assert g.refusals == []
    assert g.discoveries_refused == [
        {"stage": "subfinder", "kind": "HOST", "value": "evil.test",
         "host": "evil.test"}
    ]


def test_record_discovery_refusal_dedupes_by_host():
    g = ScopeGuard({"acc.example"})
    g.record_discovery_refusal(stage="subfinder", kind="HOST",
                               value="evil.test", host="evil.test")
    g.record_discovery_refusal(stage="dnsx", kind="HOST",
                               value="evil.test", host="evil.test")
    assert len(g.discoveries_refused) == 1


def test_extend_makes_a_previously_refused_discovery_admitted():
    g = ScopeGuard({"acc.example"})
    assert g.permits_discovery("new.acc.example") is False
    g.extend(["new.acc.example"], reason="operator-confirmed subfinder output")
    assert g.permits_discovery("new.acc.example") is True


# --- B3: a line that expands to more hosts than its allowlist entry --------
# normalize("127.0.0.0/30") is "127.0.0.0", so a targets file naming that
# network allowlisted ONE host, matched its own line, seeded the raw "/30"
# as a HOST artifact, and handed it to naabu -- which scans all four. The
# other three came back through admission control, were refused, and landed
# in discoveries_refused, the one bucket that never marks a run degraded.
# Three unauthorised hosts scanned, their findings discarded, and a report
# reading "1 requested, 1 in scope. No findings." with degraded:false.


# Each line paired with hosts it genuinely reaches that are NOT the single
# hostname normalize() salvages from it -- i.e. the addresses that used to be
# scanned from outside the allowlist. Both IP families, plus the two
# non-CIDR multi-host syntaxes the scanners accept.
MULTI_HOST_LINES = {
    "127.0.0.0/30": ["127.0.0.1", "127.0.0.2", "127.0.0.3"],
    "10.0.0.0/24": ["10.0.0.1", "10.0.0.99", "10.0.0.254"],
    "10.0.0.1/24": ["10.0.0.2", "10.0.0.7"],          # host bits set
    "2001:db8::/126": ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
    "10.0.0.1-5": ["10.0.0.2", "10.0.0.5"],           # nmap/naabu octet range
    "10.0.0.1-5:80": ["10.0.0.2", "10.0.0.5"],        # ... with a port
    "10.0.0.*": ["10.0.0.1", "10.0.0.200"],
    "acc.example,evil.test": ["evil.test"],
}


@pytest.mark.parametrize("line,also_reaches", sorted(MULTI_HOST_LINES.items()))
def test_every_host_a_targets_line_reaches_is_in_scope_or_the_line_is_refused(
        line, also_reaches):
    """The invariant, stated over the guard the run actually uses.

    Deliberately NOT "a CIDR is rejected": either resolution is acceptable
    (allowlist the whole range, or refuse the line), and asserting the
    rejection alone would pass just as well for a fix that refused the line
    while still letting it into the store. What must never hold is the state
    that shipped -- the line permitted, and so scanned, while hosts inside it
    are not permitted, and so their results are thrown away.
    """
    guard = ScopeGuard({line})
    if guard.allows(line):
        assert all(guard.permits_discovery(h) for h in also_reaches), (
            f"{line!r} is in scope and will be scanned in full, but "
            f"{[h for h in also_reaches if not guard.permits_discovery(h)]} "
            "inside it are not in scope: those hosts get scanned and their "
            "findings discarded"
        )
    else:
        # Refused: nothing in the range may be admitted by the back door
        # either, or admission control would let the discoveries through
        # from a scan that was never authorised to happen.
        assert not any(guard.permits_discovery(h) for h in also_reaches)


@pytest.mark.parametrize("line", sorted(MULTI_HOST_LINES))
def test_a_multi_host_line_never_becomes_a_single_host_allowlist_entry(line):
    """The entry, not just the verdict.

    Storing the salvaged hostname is what made the line match itself. An
    allowlist that cannot represent the line faithfully must not represent
    it at all.
    """
    assert ScopeGuard({line}).allowed == set()
    assert multi_host_error(line) != ""


def test_cidr_hosts_are_refused_rather_than_silently_narrowed():
    guard = ScopeGuard({"127.0.0.0/30"})
    for addr in ipaddress.ip_network("127.0.0.0/30"):
        assert guard.allows(str(addr)) is False
    assert guard.allows("127.0.0.0/30") is False


def test_a_range_is_refused_even_when_its_own_address_is_allowlisted():
    """Dropping the entry is not sufficient on its own.

    An operator who lists both the network's first address and the network
    -- an entirely reasonable-looking targets file -- gets an allowlist of
    {"127.0.0.0"} from the first line, and the second line normalizes to
    exactly that. Without a check on the LINE, it matches, app.prepare()
    seeds the raw "/30" as a HOST artifact verbatim, and naabu sweeps all
    four addresses: the original defect, reconstructed. The line has to be
    refused for what it reaches, not for what its entry happens to be.
    """
    guard = ScopeGuard({"127.0.0.0", "127.0.0.0/30"})
    assert guard.allowed == {"127.0.0.0"}
    assert guard._is_permitted(normalize("127.0.0.0/30")) is True
    assert guard.allows("127.0.0.0/30") is False
    ok, refused = guard.filter(["127.0.0.0", "127.0.0.0/30"])
    assert ok == ["127.0.0.0"]
    assert refused == ["127.0.0.0/30"]


def test_a_refused_multi_host_line_is_recorded_as_an_operator_refusal():
    """It belongs in `refusals` ("the operator supplied an out-of-scope
    target"), not in `discoveries_refused`, which never marks a run degraded.
    """
    guard = ScopeGuard({"acc.example"})
    guard.filter(["acc.example", "10.0.0.0/24"])
    assert [r["target"] for r in guard.refusals] == ["10.0.0.0/24"]
    assert guard.discoveries_refused == []


def test_extend_will_not_widen_scope_to_a_range():
    """extend() is the audited widening path; a CIDR recorded there would
    read as one host in run.json and authorise none of the others.
    """
    guard = ScopeGuard({"acc.example"})
    guard.extend(["10.0.0.0/24"], reason="test")
    assert guard.allowed == {"acc.example"}
    assert guard.extensions == []
    assert guard.permits_discovery("10.0.0.7") is False


# --- ... without refusing the single-host and wildcard forms ---------------
# A check that fires on ordinary targets is a check the next operator works
# around. These are the forms a real targets file is written in.


@pytest.mark.parametrize("line", [
    "acc.example",
    "ACC.EXAMPLE",
    "acc.example.",
    "acc.example:8443",
    "http://127.0.0.1/app",
    "https://acc.example/path?q=1",
    "127.0.0.1",
    "127.0.0.1:8080",
    "10.0.0.1/32",            # a /32 IS one host
    "2001:db8::1/128",        # ... as is a /128
    "[::1]:8080",
    "host-1.acc.example",     # hyphen in a NAME is not an octet range
    "acc.example/app",        # schemeless with a path, not a network
    # A URL's authority is unambiguous and everything after it is a path, so
    # host-set syntax cannot hide there. These are ordinary URLs whose PATHS
    # contain the very characters that mean "many hosts" in a bare line.
    "http://10.0.0.0/24",
    "https://acc.example/a,b",
    "https://acc.example/assets/*",
    "https://acc.example/2010-2020/report",
])
def test_single_host_forms_are_not_treated_as_ranges(line):
    assert multi_host_error(line) == ""


def test_a_targets_file_of_ordinary_forms_still_permits_itself():
    targets = ["acc.example", "acc.example:8443", "http://127.0.0.1/app",
               "10.0.0.1/32"]
    guard = ScopeGuard(set(targets))
    ok, refused = guard.filter(targets)
    assert refused == []
    assert set(ok) == set(targets)


def test_wildcard_entry_is_exempt_because_the_entry_covers_what_it_admits():
    """"*.acc.example" also denotes many hosts -- and is the sanctioned way
    to say so, because unlike a CIDR the ENTRY matches every host it admits.
    Refusing it would break the documented DNS-scope form.
    """
    assert multi_host_error("*.acc.example") == ""
    guard = ScopeGuard({"*.acc.example"})
    assert guard.allowed == {"*.acc.example"}
    # The line is EXEMPT from the multi-host refusal (it is not dropped from
    # the allowlist the way a CIDR is) but it is still not a target: see
    # test_wildcard_entry_is_not_itself_a_host. Exemption is about what the
    # entry authorises, not about scanning the entry.
    assert guard.allows("*.acc.example") is False
    for host in ("acc.example", "admin.acc.example", "a.b.acc.example"):
        assert guard.permits_discovery(host) is True
