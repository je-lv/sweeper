"""Saved run profiles.

Profiles may reference target files and auth material, so .gitignore
excludes *.profile. Nothing sensitive is stored inline here — only paths.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import yaml

from .context import RunConfig
from .stages.base import LEVELS

AUTH_MODES = ("unauth", "auth")


class ProfileError(Exception):
    """Any failure to load a profile, regardless of cause.

    A malformed profile can fail in more ways than any enumeration of
    exception types will ever cover: broken YAML syntax
    (yaml.parser.ParserError / yaml.scanner.ScannerError), a scalar or
    list-valued document instead of a mapping (AttributeError / TypeError),
    a missing required key (KeyError), an out-of-range field (a deliberate
    ValueError raised below). A caller enumerating types it expects will
    always miss one — that is exactly how a YAML syntax error used to kill
    the menu REPL despite it already catching ValueError/KeyError/OSError.
    load_profile catches everything and re-raises it as this single type,
    because the caller only needs to know one thing: the profile did not
    load, and here is why.
    """


def save_profile(config: RunConfig, path: Path) -> Path:
    """Write a RunConfig to a YAML profile.

    The field list below is written out by hand, and that is a known weak
    point: a field added to RunConfig but not added here is dropped on
    reload, and the reloaded run differs from the saved one with no error.
    preflight_timeout was missed exactly this way. The guard is
    test_every_runconfig_field_survives_a_round_trip, which enumerates
    dataclasses.fields(RunConfig) rather than a second hand-written list,
    so field eleven fails the suite instead of vanishing quietly.
    """
    # Resolve to absolute before writing. A relative targets_file/outdir
    # reloads relative to the CWD at LOAD time, not the CWD at save time —
    # outdir defaults to the relative Path("recon/sweeper"), so a profile
    # saved in one directory and loaded from another silently writes
    # somewhere else. Cross-machine portability is not a use case here; a
    # profile whose meaning depends on the launch directory is a scan-output
    # integrity problem, not a convenience trade-off.
    data = {
        "targets_file": str(Path(config.targets_file).resolve()),
        "outdir": str(Path(config.outdir).resolve()),
        "level": config.level,
        "auth_mode": config.auth_mode,
        "stages": list(config.stages),
        "proxy": config.proxy,
        "user_agent": config.user_agent,
        "rate_override": config.rate_override,
        # Dropping this would reload a deliberately narrowed scan as an
        # all-ports one -- the precise failure --ports exists to prevent,
        # and silent, because a wider scan looks like a more thorough run
        # rather than an unauthorised one. See RunConfig.ports.
        "ports": config.ports,
        "udp_ports": config.udp_ports,
        # Whether a public-DNS fallback is permitted. A reloaded profile that
        # silently re-enabled it could disclose a scope the operator had
        # deliberately kept off third-party resolvers.
        "resolver_fallback": config.resolver_fallback,
        "time_limit": config.time_limit,
        "subdomain_enum": config.subdomain_enum,
        "preflight_timeout": config.preflight_timeout,
        "verify_secrets": config.verify_secrets,
        "custom_templates": config.custom_templates,
        # None (the field's default -- "use the default triage path", see
        # RunConfig.triage_file) is written as YAML null, not skipped: an
        # omitted key and an explicit "no override" must round-trip the
        # same way, and yaml.safe_dump already renders None as `null`.
        "triage_file": str(Path(config.triage_file).resolve())
                       if config.triage_file else None,
        # See RunConfig.resolver. Stored as the raw operator string, so a
        # reloaded profile scans against the same nameservers as the run it
        # was saved from. Dropping it would silently move a split-horizon
        # scan back onto the scanning box's own DNS, where the entire scope
        # is NXDOMAIN -- a reloaded profile that finds nothing and reports
        # no error.
        "resolver": config.resolver,
        "content_wordlists": config.content_wordlists,
        "content_wordlists_only": config.content_wordlists_only,
    }
    # The completeness guard for the hand-written dict above. The docstring
    # calls that list a known weak point, and it has now dropped a field
    # TWICE (preflight_timeout, then resolver). The round-trip test catches
    # it in CI; this catches it here, at the moment of writing, so a field
    # added without one can never reach a saved profile as a silent absence.
    missing = [f.name for f in dataclasses.fields(config) if f.name not in data]
    if missing:
        raise ProfileError(
            f"save_profile does not persist RunConfig field(s) {missing}. Add "
            "them to the dict above and to load_profile, or a reloaded run "
            "will silently differ from the one that was saved."
        )
    path = Path(path)
    path.write_text(yaml.safe_dump(data, sort_keys=True), encoding="utf-8")
    return path


def load_profile(path: Path) -> RunConfig:
    """Load a profile, or raise ProfileError.

    Everything here is wrapped: the deliberate validation raises below
    (bad level, bad auth_mode) construct ProfileError directly, so they
    pass through the `except ProfileError: raise` unchanged. Everything
    else -- a YAML syntax error, a scalar or list-valued document, a
    missing key -- is caught by the broad `except Exception` and converted,
    with the original exception preserved as __cause__ so a traceback still
    shows what actually went wrong underneath.
    """
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        level = data.get("level", "mid")
        if level not in LEVELS:
            raise ProfileError(f"invalid level {level!r}; must be one of {LEVELS}")
        auth_mode = data.get("auth_mode", "unauth")
        if auth_mode not in AUTH_MODES:
            raise ProfileError(
                f"invalid auth_mode {auth_mode!r}; must be one of {AUTH_MODES}"
            )
        return RunConfig(
            targets_file=Path(data["targets_file"]),
            outdir=Path(data.get("outdir", "recon/sweeper")),
            level=level,
            auth_mode=auth_mode,
            stages=list(data.get("stages") or []),
            proxy=data.get("proxy", ""),
            user_agent=str(data.get("user_agent", "")),
            rate_override=int(data.get("rate_override", 0)),
            # .get() with a default, as with every field here: a profile
            # saved before --ports existed loads as "use the level's own
            # range", which is what those runs did.
            ports=str(data.get("ports", "")),
            udp_ports=str(data.get("udp_ports", "")),
            resolver_fallback=bool(data.get("resolver_fallback", True)),
            time_limit=data.get("time_limit", ""),
            subdomain_enum=bool(data.get("subdomain_enum", False)),
            preflight_timeout=float(data.get("preflight_timeout", 3.0)),
            verify_secrets=bool(data.get("verify_secrets", False)),
            # .get() with a default, same as every other field here: an
            # older profile saved before this field existed must still
            # load, silently defaulting to "no custom templates" rather
            # than raising ProfileError over a key that simply predates it.
            custom_templates=str(data.get("custom_templates", "")),
            # .get() with a default of None, same reasoning as
            # custom_templates above: an older profile saved before this
            # field existed must still load, silently defaulting to "use
            # the default triage path" rather than raising over a key that
            # predates it.
            triage_file=Path(data["triage_file"]) if data.get("triage_file") else None,
            # .get() with a default, same reasoning as the two fields above:
            # a profile saved before --resolver existed must still load,
            # meaning "each tool's own default resolvers".
            resolver=str(data.get("resolver", "")),
            content_wordlists=str(data.get("content_wordlists", "")),
            content_wordlists_only=bool(
                data.get("content_wordlists_only", False)),
        )
    except ProfileError:
        raise
    except Exception as exc:
        raise ProfileError(
            f"could not load profile {path}: {type(exc).__name__}: {exc}"
        ) from exc


def list_profiles(directory: Path) -> list[Path]:
    return sorted(Path(directory).glob("*.profile"))
