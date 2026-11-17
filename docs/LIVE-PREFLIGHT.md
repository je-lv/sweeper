# Running `high` against live infrastructure

A runbook for using Sweeper on authorized infrastructure. The automated test
suite uses synthetic fixtures and loopback services; those checks do not prove
that every external tool or production network will behave the same way.

Work top to bottom. Steps 1–4 happen before the first packet.

## 1. The targets file

One entry per line. Default-deny: **a bare entry matches only itself.**
Subdomains require an explicit wildcard.

```
acc.example             # this host and nothing else
*.acc.example           # the apex AND every subdomain
shop.acc.example
```

`*.acc.example` deliberately includes the apex, because that is what the
notation means in a rules-of-engagement document. See the module docstring in
`sweeper/scope.py` for why, and for what would have to change together if that
reading is ever narrowed.

Comments (`#`) and blank lines are fine. `targets*.txt` is gitignored —
hostnames are engagement-sensitive — so put the file anywhere convenient and
do not commit it.

Every discovered host is filtered against this list before any stage touches
it, and anything refused is recorded in the report's *Discovered, not scanned*
section rather than silently dropped.

## 2. Decide the TCP and UDP ranges — this is the one that bites

**Scope is enforced per HOST. Services are host:PORT.**

An all-ports scan of an authorised *name* reaches every service bound to that
name's IP. On shared hosting, behind a reverse proxy, on a CDN origin or a jump
box, that can include services the client does not own — and because no
off-scope *hostname* is ever resolved, the scope guard has nothing to refuse.
It will not appear in the report as a refusal, because from the guard's point
of view nothing went wrong.

This is inherent to port-scanning a name. The mitigations are `--ports` for
TCP and `--udp-ports` for UDP.

Resolve each target and look at what else lives there:

```sh
for h in $(grep -v '^#' <scope>.txt | tr -d '*.' | sort -u); do
  printf '%-40s %s\n' "$h" "$(dig +short "$h" | tr '\n' ' ')"
done
```

Then pick:

| Situation | Choice |
|---|---|
| Client confirmed the IPs are dedicated to them | omit both options — `high` scans all 65,535 TCP ports and the top 1,000 UDP ports |
| Shared hosting, or ownership unconfirmed | `--ports top-1000 --udp-ports top-100` |
| CDN-fronted, or a tight web-only engagement | `--ports 80,443,8080,8443,8000,8888,3000,5000,9443,10443 --udp-ports 53,123,161,500,4500` |

Both options accept forms such as `top-100`, `80,443,8443`, or `1-1024`.
Each option **replaces** its protocol's level default, and a bad value is
refused at argument time rather than becoming a mid-run tool error.

Restricting ports narrows the *whole run*, not just discovery: later stages
consume the TCP and UDP endpoints the discovery stages produced. Both
restrictions are stated in the report's Coverage section, so a narrowed scan
cannot be read as exhaustive later. UDP `open|filtered` results remain
candidates: silence cannot distinguish an open service from a filtered port,
and the raw Nmap XML remains the source evidence.

## 3. Bound the runtime — not optional

`--time-limit` is required in practice. nuclei ran **90+ minutes against a
five-host lab**; unbounded against a real estate it does not finish. A bounded
stage reports `stopped at the <limit> time limit`, which is a distinct outcome
from a stage that failed — so a shortened scan cannot read as a complete one.

`--rate` is the client's no-DoS engagement term. Set it to whatever the RoE
says.

Content discovery is the stage that scales worst: requests = **origins ×
wordlist size**, and `high` is ~27.8k words per origin. Ten origins is ~278k
requests. The estimate is logged before the first request — read it, and if it
is wrong for the engagement, bound it with `--rate` and `--time-limit` or drop
the stage.

## 4. Confirm authorisation covers what you are about to do

- `high` is a full TCP and top-1,000 UDP sweep of every host in scope.
  Rate-limited, but a sweep; UDP can be materially slower than TCP.
- `full` additionally **mutates application state** — it places orders, applies
  coupons and fuzzes parameters against live data. That is what the explicit
  `--ack` gate exists for. Do not run it against
  production unless that is in the RoE in writing.

## 5. The run

```sh
python sweeper.py \
  --targets <scope>.txt \
  --no-menu --level high --yes \
  --ports top-1000 \
  --udp-ports top-100 \
  --time-limit 20m \
  --rate <client's cap> \
  --resolver <their DNS, if split-horizon> \
  --outdir runs/
```

Drop `--resolver` unless the scope resolves only in the client's own DNS. If it
does and you omit it, every name is NXDOMAIN on the scanning box and every
stage completes successfully having found nothing — which looks exactly like a
clean result. `run.json`'s `resolver` block records which stages honoured it;
`ffuf`, `arjun` and jsrecon cannot take one and stay on system DNS.

For an authenticated pass, add `--auth-request ./session.req` (a raw Burp
request). Credentials are read from the file and never appear in argv.
Credential-containment tests use synthetic sessions and loopback services to
verify that credential values do not follow refused redirects.

### Fixed 2026-08-04: stage tools inherited sweeper's stdin

Worth knowing because it would have bitten the first automated run. Naabu
appeared to hang and self-abort at 180s in ~25% of runs. The cause was
sweeper: every ProjectDiscovery tool reads its target list from stdin when
stdin is a pipe (that is how `cat hosts.txt | httpx` works), and the runner
let stage tools inherit sweeper's stdin. Run sweeper from cron, CI or any
wrapper that hands it a pipe — **the `--no-menu` path you will be using** —
and the tool blocks on a pipe nothing writes to until its internal deadline.

naabu produces the PORT artifacts every later stage consumes, so the result
was an empty run that looked like a flaky tool. Fixed with
`stdin=subprocess.DEVNULL` on every child sweeper spawns. Verified: 46.7s
blocked before, 5.2s after, under an identical pipe.

If you see a stage die at exactly 180s with no output, that is this shape of
bug — check how the process was launched.

### Retry on a stage that produced nothing

**Since 2026-08-04:** the runner retries a stage **once** when the
tool exits non-zero having written *nothing at all*. Never on partial output
(the tool did work; re-running duplicates it), never on a `--time-limit` stop
(that bound is yours, often an engagement term, and a retry spends it twice),
and never on `ARG_ERROR`. One extra attempt, never a loop.

`run.json` records `attempts` per stage. **`attempts: 2` means the target was
scanned twice** — check it before handing a report to a client with a
rate-limit clause, and read it as "this tool is flaky here" when an otherwise
clean result carries it.

Note what the retry is not: it does not cure a *persistent* cause. When the
stdin bug above was still present, both attempts blocked and the stage simply
took 360s to fail instead of 180s. A retry buys you a second roll against a
genuinely transient failure, nothing more.

**If both attempts fail:** the stage reports `failed` / `TRANSPORT`, the run is
marked `degraded: true`, and the Coverage section lists it. It cannot be
mistaken for a clean scan — that was verified. Recover with
`python sweeper.py --resume runs/<run-dir>`, which re-runs only the failed
stage and restores the run's config, `--ports` included.

Check the port stage completed before walking away from a live run.

### While it runs

- Do not kill sweeper with SIGKILL. It writes `run.json` on exit; killed hard,
  the whole run is lost. SIGTERM lets it finish writing.
- If it dies anyway: `python sweeper.py --resume runs/<run-dir>` re-runs only
  the incomplete stages, leaves `complete` ones alone, and restores the run's
  config — including `--ports`, so a resumed narrow scan stays narrow.

## 6. Reading the result — Coverage first, findings second

Open the report's **Coverage** section before the findings list. It is the
only place that tells you what the findings list is silent about:

1. **Ports** — if `--ports` or `--udp-ports` was set, what was excluded.
2. **Stages that did not complete** — with the failure class and reason.
   `stopped at the 20m time limit` means that stage was cut short, not that it
   found everything there was to find.
3. **Discovered, not scanned** — hosts found in-run and correctly refused as
   out of scope. A discovery-heavy run producing many of these is a
   *successful* run, not a degraded one, but it is also the list a scope
   extension conversation happens over.
4. **Targets requested vs in scope vs refused** — if anything you supplied was
   refused, check it against the RoE before assuming the tool is wrong.

`degraded: true` in `run.json` means at least one requested stage did not
produce what it should have. Exit code 0 alone does not prove complete
coverage; review every stage status and its reason.

## What has and has not been proven

| Property | State |
|---|---|
| Scope enforcement | Covered by unit and loopback integration tests, including redirects and discovered-host admission. |
| Credential containment | Covered by synthetic-session and loopback redirect tests. |
| `low` / `mid`, unauthenticated | Covered by automated stage and pipeline tests. |
| `high` | Command construction and parsing are covered; operators must still validate installed external-tool versions. |
| `full` | Mutates state and requires explicit acknowledgement; use only where the rules of engagement allow it. |
| A real scope | Environment-specific. Begin with a controlled authorized target and review `run.json` before broadening scope. |
| Memory headroom | **Weakest.** `--time-limit` bounds stage runtime, not resident memory. Run in a resource-constrained container when guaranteed limits are required. |
