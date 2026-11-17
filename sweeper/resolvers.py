"""Operator-supplied DNS resolvers, parsed once and shared by every stage.

WHY THIS EXISTS. Sweeper had no way to say "resolve names against THIS
nameserver". That is not a lab-only convenience: on an internal engagement
the client's names very often exist only in their own split-horizon DNS, and
resolving them against whatever the scanning box inherited returns NXDOMAIN
for the entire scope. The failure mode is the one this project keeps finding
— every stage runs, every stage exits 0, every stage reports nothing, and the
report says "All selected stages completed."

WHY IP LITERALS ONLY. A resolver named by hostname has to be resolved by some
OTHER resolver before it can be used, so the setting would silently depend on
exactly the DNS configuration it exists to replace. On a split-horizon
engagement that fallback is the thing that is broken. An IP literal is the
only form with no such dependency, so a hostname is refused rather than
quietly resolved through a path the operator was trying to avoid.

WHY THE PARSE IS STRICT. These values are interpolated into an argv. A bare
`-foo` entry would be read by the tool as another FLAG rather than as a
resolver — `-r "-silent"` is accepted by every Go tool here and changes what
the command does. Rejecting anything that is not an IP (optionally with a
port) closes that without needing a per-tool escape rule, which is why
validation lives here and not in each stage.
"""
from __future__ import annotations

import ipaddress

#: Every resolver entry is an IP with an optional port. Bare IPv6 needs no
#: brackets; IPv6-with-port does, because the colons are otherwise ambiguous.
DEFAULT_DNS_PORT = 53

#: Public resolvers tried, IN ORDER, only when the system resolver cannot
#: resolve the scope AND the operator named no resolver of their own.
#:
#: This is a confidentiality decision as much as a connectivity one: whichever
#: of these answers SEES THE CLIENT'S HOSTNAMES. That is why nothing here is
#: consulted unless the system resolver has already failed, why an explicit
#: --resolver is never replaced by one of these (see preflight), and why
#: every use is recorded as a run warning and in the manifest. An operator
#: whose engagement forbids third-party DNS passes --no-resolver-fallback.
#:
#: Three, from three separate operators, because the failure being worked
#: around is "the one nameserver this box knows about has stopped answering",
#: and a list from a single provider does not survive that class of problem.
FALLBACKS = ("1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53")


class ResolverError(ValueError):
    """An operator-supplied --resolver value that cannot be used.

    A ValueError subclass so app.main's existing `except ValueError` turns it
    into the same friendly exit-2 an unknown --stages name gets: this is an
    operator typo, not a broken stage module.
    """


def _split_host_port(entry: str) -> tuple[str, int | None]:
    """Split one entry into (ip_text, port or None) without resolving anything.

    Bracketed IPv6 (`[::1]:53`) is handled explicitly because splitting on the
    last colon is wrong for a bare IPv6 literal, where every separator is a
    colon and none of them is a port.
    """
    if entry.startswith("["):
        host, sep, rest = entry[1:].partition("]")
        if not sep:
            raise ResolverError(f"unbalanced '[' in resolver {entry!r}")
        if rest == "":
            return host, None
        if not rest.startswith(":"):
            raise ResolverError(
                f"expected ':port' after ']' in resolver {entry!r}"
            )
        return host, _port(rest[1:], entry)
    # A bare IPv6 literal contains two or more colons and carries no port; a
    # v4 address with a port contains exactly one. Anything else is an error
    # the ip_address() call below will report.
    if entry.count(":") == 1:
        host, _, port_text = entry.partition(":")
        return host, _port(port_text, entry)
    return entry, None


def _port(text: str, entry: str) -> int:
    if not text.isdigit():
        raise ResolverError(f"non-numeric port in resolver {entry!r}")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ResolverError(f"port out of range in resolver {entry!r}")
    return port


def parse(value: str) -> list[str]:
    """Normalise a comma-separated --resolver value into `ip:port` entries.

    Returns [] for an empty value, which every caller reads as "use the
    tool's own default resolvers" — the pre-flag behaviour.

    The port is made EXPLICIT on every entry even when the operator omitted
    it. Two of the tools involved take a file of resolvers rather than a flag
    value, and a bare IP in that file means port 53 to some parsers and is a
    parse error in others; writing `:53` ourselves removes the ambiguity from
    the evidence trail as well as from the argv.
    """
    entries: list[str] = []
    seen: set[str] = set()
    for chunk in value.split(","):
        entry = chunk.strip()
        if not entry:
            # A trailing comma is a typo, not a request for a blank resolver.
            # Skipping it silently would hand the tool an empty argv element.
            continue
        host_text, port = _split_host_port(entry)
        try:
            ip = ipaddress.ip_address(host_text)
        except ValueError:
            raise ResolverError(
                f"resolver {entry!r} is not an IP address. Resolvers must be "
                "IP literals: a hostname would have to be resolved by the "
                "very DNS configuration --resolver exists to replace."
            ) from None
        port = DEFAULT_DNS_PORT if port is None else port
        normalised = (f"[{ip.compressed}]:{port}" if ip.version == 6
                      else f"{ip.compressed}:{port}")
        if normalised in seen:
            continue
        seen.add(normalised)
        entries.append(normalised)
    return entries


def as_ips(entries: list[str]) -> list[str]:
    """The IP halves of `entries`, dropping the port.

    For nmap, whose --dns-servers takes addresses only and always queries
    port 53. See non_standard_ports() — a caller must check that first, or it
    will send queries to a port the operator did not choose.
    """
    ips = []
    for entry in entries:
        host, _ = _split_host_port(entry)
        ips.append(host)
    return ips


def for_run(ctx) -> list[str]:
    """This run's normalised resolver entries, or [] if none was given.

    Parsed on every call rather than cached on ctx: build_command() must be
    deterministic (preflight validates the same argv the runner executes),
    and parse() is pure, so recomputing is both cheap and safer than a
    mutable cache that a resume could reload out of step with the config.
    """
    return parse(getattr(ctx.config, "resolver", "") or "")


def flag_args(ctx, flag: str = "-r") -> list[str]:
    """`[flag, "ip:port,ip:port"]` for tools taking a comma-separated list.

    Empty list when no resolver is configured, so a stage can append this
    unconditionally and get exactly its previous argv.
    """
    entries = for_run(ctx)
    if not entries:
        return []
    return [flag, ",".join(entries)]


def file_args(ctx, flag: str = "-r", filename: str = "resolvers.txt") -> list[str]:
    """`[flag, path]` for tools that take a FILE of resolvers (nuclei).

    The file is written under the run's raw/ directory so the resolvers a
    finding was produced against are part of the evidence, not just of the
    operator's shell history. Written on every build_command call, which is
    idempotent: same content, same path.
    """
    entries = for_run(ctx)
    if not entries:
        return []
    path = ctx.run_dir / "raw" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return [flag, str(path)]


def non_standard_ports(entries: list[str]) -> list[str]:
    """Entries whose port is not 53.

    A tool that cannot express a port (nmap) must not be handed these: it
    would query port 53 of the right ADDRESS, which on a lab or a
    port-forwarded resolver is a different service or nothing at all, and the
    stage would report no DNS data while appearing to honour the setting.
    """
    return [e for e in entries if _split_host_port(e)[1] != DEFAULT_DNS_PORT]
