"""content stage — paths that are not linked from anywhere.

WHY THIS EXISTS. Every other discovery stage here follows a reference:
katana follows links, jsrecon follows script tags and chunk maps, dnsx
follows records. None of them can reach a path that nothing points at, and
unlinked paths are where a lot of the worst exposures live -- a forgotten
`/backup.zip`, a `.git` directory, a debug endpoint someone added and never
removed.

Measured against a lab whose crawl was otherwise thorough (17744 katana
artifacts): `/api/debug/config` returns 200 and dumps the entire application
config with third-party credentials, and nothing in the pipeline found it,
because no page links to it. Same for `/.git/config` and `/backup.zip`.

WHAT IT WILL NOT FIND, stated plainly so an empty result is not misread as
coverage. This guesses from a wordlist, so it finds paths someone has seen
before. A bespoke path (`/api/debug/config` is one -- it is in none of the
SecLists files checked) is found only if the operator supplies a wordlist
containing it. Absence of a finding here is not evidence of absence.

WORDLISTS ARE COMBINED, and that is a measured decision rather than a
preference. No single SecLists file covers the ordinary cases:

    quickhits.txt   .git/config  .env  backup.zip  backup.sql   (no server-status)
    common.txt      .git/config  .env  server-status            (no backups)

so a level's lists are merged and deduped into one file under raw/, which
also makes the exact wordlist used part of the run's evidence rather than a
path that may have changed on disk since.

ONE ffuf INVOCATION, not one per host. ffuf takes several wordlists with
their own keywords and combines them (`-mode clusterbomb`), so origins and
paths are two wordlists and the whole matrix runs as a single command --
which keeps this inside the one-command-per-stage contract the runner is
built around.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

from .. import useragents
from ..artifacts import Artifact, ArtifactKind, Finding

_SL = "/usr/share/seclists/Discovery/Web-Content/"

#: CUMULATIVE by level: each one is the previous list plus more. The
#: escalation is in the WORDLIST, which is what actually decides what this
#: stage can find -- flags only decide how fast it looks.
#:
#: The sizes matter more than they look, because the request count is
#: ORIGINS x WORDS, and a crawl routinely turns up ten origins on one
#: engagement:
#:
#:     low    ~2.6k words   x10 origins ~   26k requests   ~12 min at -rate 40
#:     mid    ~7.3k words   x10 origins ~   73k requests   ~30 min
#:     high  ~27.8k words   x10 origins ~  278k requests   ~1.9 h
#:     full  ~70.8k words   x10 origins ~  708k requests   ~4.9 h
#:
#: So `full` is a genuine commitment, not a bigger `high`, and --time-limit
#: is how it gets bounded. build_command logs the estimate BEFORE the
#: requests are made -- see the ctx.log call there -- because an operator
#: has to be able to decide against it in time.
#:
#: `low` gets the small high-signal list rather than nothing: it is
#: read-only, rate-limited GETs, and the exposures it catches (.env, .git,
#: backups) are the ones worth catching on a first pass.
WORDLISTS = {
    "low":  (_SL + "quickhits.txt",),
    "mid":  (_SL + "quickhits.txt", _SL + "common.txt"),
    "high": (_SL + "quickhits.txt", _SL + "common.txt", _SL + "big.txt"),
    "full": (_SL + "quickhits.txt", _SL + "common.txt", _SL + "big.txt",
             _SL + "raft-small-words.txt"),
}

#: Paths whose mere existence is a finding, with the severity it warrants.
#: Matched on the discovered path's tail, longest first, so `.git/config`
#: wins over a bare `config`. Everything else discovered is emitted as an
#: HTTP_SERVICE artifact for the rest of the pipeline and left unflagged --
#: "this path exists" is not by itself a finding, and a stage that reports
#: every 200 as one is noise a reader learns to skip.
SENSITIVE = (
    (".env", "critical", "Environment file exposed",
     "Environment files carry database URLs, secret keys and third-party "
     "credentials in plaintext."),
    (".git/config", "high", "Git repository exposed",
     "A readable .git directory discloses remotes, branch history and often "
     "credentials committed in error; the full source can be reconstructed."),
    (".git/HEAD", "high", "Git repository exposed", ""),
    (".svn/entries", "high", "Subversion metadata exposed", ""),
    ("backup.sql", "high", "Database backup exposed",
     "A database dump reachable without authentication."),
    ("backup.zip", "high", "Backup archive exposed", ""),
    ("dump.sql", "high", "Database backup exposed", ""),
    ("db.sql", "high", "Database backup exposed", ""),
    ("id_rsa", "critical", "Private key exposed", ""),
    (".htpasswd", "high", "Password file exposed", ""),
    ("phpinfo.php", "medium", "phpinfo() exposed",
     "Discloses the full PHP configuration, paths and loaded modules."),
    ("server-status", "medium", "Server status page exposed",
     "Apache/nginx status pages disclose internal hosts, request URLs and "
     "traffic patterns."),
    ("server-info", "medium", "Server info page exposed", ""),
    (".DS_Store", "low", "Directory index metadata exposed",
     "Discloses filenames in the directory, including ones not linked."),
    ("wp-config.php", "critical", "WordPress configuration exposed", ""),
    (".aws/credentials", "critical", "AWS credentials file exposed", ""),
    ("docker-compose.yml", "medium", "Compose file exposed", ""),
)


#: An origin returning more than this fraction of the WHOLE wordlist is
#: answering arbitrary paths, not exposing that many files.
#:
#: Measured, and the margin is not close:
#:
#:     real origins            25 hits   0.4% of a 7134-word list
#:     a catch-all origin    7134 hits   100%
#:
#: The catch-all in that measurement was the operator's own Burp Suite on
#: 127.0.0.1:8080, which ECHOES THE REQUESTED PATH in its error page -- so
#: every response is a slightly different length and ffuf's calibration,
#: which filters on size, cannot see it. -ac and -ach are both on and
#: neither helps; no ffuf flag does. It has to be caught here.
#:
#: Without this the stage reported id_rsa, .htpasswd, .svn/entries,
#: phpinfo.php, docker-compose.yml and a dozen more as exposed on that
#: origin. False positives in a client deliverable are worse than finding
#: nothing: they cost the client's time and they cost the report its
#: credibility.
CATCHALL_HIT_RATE = 0.25


def origins(artifacts, permitted: list[str]) -> list[str]:
    """One `scheme://host:port` per distinct origin, sorted.

    Fuzzing a wordlist against `https://host/a/b` would test `/a/b/<word>`,
    which is a different and much narrower question than "what exists at the
    root". Every artifact is therefore reduced to its origin and deduped:
    the crawl feeds this stage thousands of URLs across a handful of
    origins, and each duplicate would re-run the ENTIRE wordlist.

    Sorted, because build_command must be deterministic -- preflight
    validates the same argv the runner executes.
    """
    allowed = set(permitted)
    seen: set[str] = set()
    for art in artifacts:
        url = getattr(art, "value", "")
        if url not in allowed:
            continue
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            continue
        seen.add(urlunsplit((parts.scheme, parts.netloc, "", "", "")))
    return sorted(seen)


def sources_for(level: str, extra=(), only: bool = False) -> tuple[str, ...]:
    """The wordlist files for `level`, plus whatever the operator supplied.

    `only` replaces the built-in lists rather than adding to them, which is
    what an operator with a curated list for a specific target wants -- a
    bespoke path like `/api/debug/config` appears in none of the SecLists
    files, so their list is the only thing that will find it, and making
    them pay for 70k generic guesses alongside it is not a service.
    """
    extra = tuple(e for e in extra if e)
    if only:
        return extra
    return tuple(WORDLISTS.get(level, ())) + extra


def build_wordlist(level: str, dest: Path, extra=(), only: bool = False) -> int:
    """Merge the level's lists into `dest`, deduped. Returns the entry count.

    Written into the run directory rather than passed through as several
    paths so that the exact list used is part of the evidence: a SecLists
    package upgrade changes those files, and a finding that cannot be
    reproduced from the run's own artifacts is a weaker finding.
    """
    seen: dict[str, None] = {}
    for source in sources_for(level, extra, only):
        path = Path(source)
        if not path.is_file():
            continue
        for line in path.read_text(errors="ignore").splitlines():
            word = line.strip().lstrip("/")
            if not word or word.startswith("#"):
                continue
            seen.setdefault(word, None)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(seen) + "\n", encoding="utf-8")
    return len(seen)


def classify(path: str) -> tuple[str, str, str] | None:
    """(severity, title, description) if this path is sensitive, else None."""
    tail = path.lstrip("/").lower()
    best = None
    for needle, severity, title, description in SENSITIVE:
        n = needle.lower()
        if tail == n or tail.endswith("/" + n):
            if best is None or len(n) > len(best[0]):
                best = (n, severity, title, description)
    return (best[1], best[2], best[3]) if best else None


class ContentStage:
    name = "content"
    #: ffuf has no resolver option; it resolves through the system resolver.
    honors_resolver = False
    resolver_note = ("ffuf has no resolver option; it resolves through the "
                     "system resolver.")
    requires = ["ffuf"]
    consumes = ArtifactKind.HTTP_SERVICE
    produces = {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}
    #: Discoveries carry a path and a content type, so the stages that READ
    #: what an artifact points at -- arjun's parameter discovery, jsrecon's
    #: JS fetching -- are ordered after this one and see what it finds. That
    #: is the whole point: an unlinked /api/debug/config is worth far more
    #: once arjun has fuzzed parameters against it.
    provides_facets = frozenset({"url_path", "content_type"})
    optional = True
    raw_suffix = "json"       # ffuf -o ... -of json
    writes_own_raw = True
    #: -ac (auto-calibrate) is not optional. A target that answers 200 with a
    #: "not found" page for every path -- a soft 404, which single-page apps
    #: and many frameworks do by default -- otherwise reports the ENTIRE
    #: wordlist as discovered. ffuf measures a few random paths first and
    #: filters by what they return.
    #:
    #: -ach (PER HOST) is what makes that work here, and it was missing from
    #: the first draft. This stage fuzzes several origins in one clusterbomb
    #: run, and plain -ac calibrates ONCE: a well-behaved first host sets the
    #: filter, and a catch-all origin later in the list sails through it.
    #:
    #: Caught against the lab, where 127.0.0.1:8080 happened to be the
    #: operator's own Burp Suite answering 200 to every path. The stage
    #: reported id_rsa, .htpasswd, .svn/entries, phpinfo.php,
    #: docker-compose.yml and a dozen more as exposed on that origin -- every
    #: one a false positive, in a client deliverable, which is worse than
    #: finding nothing.
    #:
    #: -t bounds concurrency, -rate bounds throughput; they are not
    #: substitutes, same reasoning as stages/vhost.py. The numbers escalate
    #: with level and stay well under naabu's because every request here is a
    #: full HTTP round trip against one host.
    levels = {
        "low":  ["-ac", "-ach", "-t", "15", "-rate", "15"],
        "mid":  ["-ac", "-ach", "-t", "20", "-rate", "20"],
        "high": ["-ac", "-ach", "-t", "30", "-rate", "30"],
        "full": ["-ac", "-ach", "-t", "40", "-rate", "40"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        level = ctx.config.level
        extra = [w.strip() for w
                 in (getattr(ctx.config, "content_wordlists", "") or "").split(",")
                 if w.strip()]
        only = bool(getattr(ctx.config, "content_wordlists_only", False))
        if not sources_for(level, extra, only):
            # Nothing to fuzz with. No command at all, which the runner
            # records as NO_INPUT -- honest, where a command that fuzzes
            # nothing would report "complete" and look like coverage.
            return []

        artifacts = ctx.store.get(ArtifactKind.HTTP_SERVICE)
        permitted, _ = ctx.scope.filter([a.value for a in artifacts])
        hosts = origins(artifacts, permitted)

        raw_dir = ctx.run_dir / "raw"
        words_file = raw_dir / "content-words.txt"
        count = build_wordlist(level, words_file, extra, only)
        if not count:
            # The wordlists are missing from this machine. Refusing is the
            # only honest answer: running ffuf against an empty list finds
            # nothing and is indistinguishable from a target with nothing to
            # find.
            return []

        hosts_file = raw_dir / "content-hosts.txt"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        # Written even when empty: preflight calls build_command before httpx
        # has produced any HTTP_SERVICE, and the probe needs the file to
        # exist for the flags to validate.
        hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        # The request count is ORIGINS x WORDS and it grows fast: `full`
        # against ten origins is roughly 700k requests. Logged BEFORE the
        # first request so an operator can still decide against it -- the
        # same decide-and-inform stance ctx.warnings takes elsewhere. A
        # number an operator only sees afterwards is a bill, not a choice.
        if hosts:
            ctx.log(f"content: {len(hosts)} origin(s) x {count} words = "
                    f"~{len(hosts) * count} requests at level {level}")

        flags = list(self.levels[level])
        if ctx.config.rate_override:
            # REPLACE the level's -rate, never append a second one. This is
            # the client's no-DoS rules-of-engagement term, and this stage is
            # the heaviest request generator in the tool -- an override that
            # silently did not apply here would be the one place it mattered
            # most. Built correctly rather than relying on which occurrence a
            # parser happens to take; same reasoning as stages/naabu.py.
            out, skip = [], False
            for flag in flags:
                if skip:
                    skip = False
                    continue
                if flag == "-rate":
                    skip = True
                    continue
                out.append(flag)
            flags = out + ["-rate", str(ctx.config.rate_override)]

        outfile = ctx.raw_path(self.name, self.raw_suffix)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        cmd = [str(binaries.resolve("ffuf")),
                "-w", f"{hosts_file}:HFUZZ",
                "-w", f"{words_file}:WFUZZ",
                "-u", "HFUZZ/WFUZZ",
                "-mode", "clusterbomb",
                *useragents.header_args_for(ctx.user_agent),
                "-o", str(outfile), "-of", "json", "-s",
                *flags]
        if ctx.config.proxy:
            cmd += ["-x", ctx.config.proxy]
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        path = Path(raw_path)
        if not path.exists() or not path.read_text(encoding="utf-8").strip():
            return
        try:
            doc = json.loads(path.read_text(encoding="utf-8")) or {}
        except json.JSONDecodeError:
            return
        raw_ref = f"raw/{self.name}.{self.raw_suffix}"

        # How many words were actually fuzzed, read from the sidecar this
        # stage wrote next to the raw output -- the same idiom cdncheck uses
        # to know what it QUERIED rather than only what came back. Without a
        # denominator there is no way to tell "this origin exposes six files"
        # from "this origin answers everything".
        words_file = path.parent / "content-words.txt"
        total_words = 0
        if words_file.exists():
            total_words = sum(1 for line in
                              words_file.read_text(errors="ignore").splitlines()
                              if line.strip())

        rows = [r for r in (doc.get("results") or []) if r.get("url")]
        per_origin: dict[str, int] = {}
        for row in rows:
            parts = urlsplit(row["url"])
            per_origin[f"{parts.scheme}://{parts.netloc}"] = (
                per_origin.get(f"{parts.scheme}://{parts.netloc}", 0) + 1)

        catchall = set()
        if total_words:
            catchall = {origin for origin, hits in per_origin.items()
                        if hits / total_words > CATCHALL_HIT_RATE}

        for origin in sorted(catchall):
            # ONE finding for the origin, instead of one per wordlist entry.
            # Still reported rather than silently dropped: an origin that
            # answers everything is itself worth knowing about, and the
            # operator needs to know this stage could tell them nothing here.
            yield Finding(
                stage=self.name, severity="info",
                title="Origin answers arbitrary paths (content discovery unreliable)",
                target=origin, template_id="content-catchall", matcher=origin,
                evidence=f"{origin} returned {per_origin[origin]} of "
                         f"{total_words} guessed paths "
                         f"({100 * per_origin[origin] / total_words:.0f}%)",
                raw_ref=raw_ref,
                description="This origin returns a success response for paths "
                            "that do not exist, so content discovery cannot "
                            "distinguish a real file from a guess here. Its "
                            "individual results have been suppressed.",
                remediation="Confirm whether this is a proxy, a catch-all "
                            "route or a single-page app fallback; probe it by "
                            "hand if the paths matter.",
            )

        seen: set[str] = set()
        for row in rows:
            url = row["url"]
            if url in seen:
                continue
            parts = urlsplit(url)
            if f"{parts.scheme}://{parts.netloc}" in catchall:
                # Suppressed: emitting these as HTTP_SERVICE would also push
                # thousands of imaginary endpoints into nuclei and arjun.
                continue
            seen.add(url)
            host = parts.hostname or ""
            yield Artifact(
                ArtifactKind.HTTP_SERVICE, url,
                # meta["host"] is what runner.py's admission check reads --
                # see stages/katana.py's parse() for the longer explanation.
                meta={"host": host, "src": self.name,
                      "status_code": row.get("status"),
                      "content_type": row.get("content-type", ""),
                      "content_length": row.get("length")},
            )

            verdict = classify(parts.path)
            if verdict is None:
                continue
            severity, title, description = verdict
            yield Finding(
                stage=self.name, severity=severity, title=title,
                target=url, template_id=f"content-{title.lower().replace(' ', '-')}",
                # matcher=url: one origin can expose several sensitive paths,
                # and two of them must not collapse onto one finding id. The
                # URL is intrinsic to the discovery and identical on a rerun.
                matcher=url,
                evidence=f"{url} -> status={row.get('status')} "
                         f"length={row.get('length')}",
                raw_ref=raw_ref,
                description=description or
                    "This path is reachable and is not linked from anywhere "
                    "in the application.",
                remediation="Remove the file from the web root, or restrict "
                            "access to it at the edge.",
            )
