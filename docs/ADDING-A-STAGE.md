# Adding a stage

A stage wraps one external tool. The architecture holds: `maildns` — the
most recent — was 282 lines in its own file, one `BinarySpec`, and two lines
in `app.py`. Nothing in the runner, the registry, or the reports.

This is the checklist for the parts that are NOT obvious. Every sharp edge
listed here was hit while adding a real stage.

---

## 1. The tool

Confirm the flags against the installed binary before writing any code, and
put the version you checked in a comment. Three stages have carried a flag
that did not exist, and an unknown flag is an argument error that aborts the
whole run rather than one stage:

```sh
checkdmarc --help          # not the docs, not memory — the binary you have
```

Answer these before continuing, because each one changes the stage's shape:

| Question | Why it matters |
|---|---|
| Does it accept a **file** of targets? | Keeps argv bounded on a large scope; use the `<stage>-input.txt` sidecar idiom |
| Does it emit **JSON**? one object or one per line? | Sets `raw_suffix` and how `parse()` reads it. ffuf writes ONE object with a `results` array, not JSONL |
| Does it take a **resolver**, with a port? | See §4 — this one has a contract test |
| Does it have a **silent** flag? | Required. A chatty banner can bury a genuine argument error |
| Does it make connections you did not ask for? | `checkdmarc` opens SMTP to the target's MX unless `--skip-tls`. Pass the opt-out unconditionally |

## 2. `binaries.py`

```python
"checkdmarc": BinarySpec(
    "checkdmarc", [USR / "checkdmarc", LOCAL / "checkdmarc"],
    "--version", r"^\d+\.\d+",
    "pipx install checkdmarc",
    bare_version=True,
),
```

- **Absolute paths, never `PATH`.** On Kali, `httpx` on `PATH` is the Python
  HTTP client, not ProjectDiscovery's.
- **`identity_pattern` must reject an impostor.** Match the tool's own name
  where it prints one; `PD_IDENTITY` is for ProjectDiscovery tools only.
- **`bare_version=True`** if the tool prints only a number (`5.17.4`). The
  default requires the word "version" on the line — a rule that exists
  because matching numbers anywhere once recorded nmap as running liblua's
  version. Without the flag the version silently reaches `run.json` empty,
  and `run.json` is what says which tool version produced which finding.
- `LOCAL` is `~/.local/bin`, where pipx and `pip --user` land console
  scripts.

## 3. The stage file

```python
class MaildnsStage:
    name = "maildns"
    requires = ["checkdmarc"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.FINDING}
    optional = True
    raw_suffix = "json"
    honors_resolver = False
    resolver_note = "..."
    levels = {"low": [], "mid": [], "high": ["--skip-tls"], "full": ["--skip-tls"]}

    def build_command(self, ctx) -> list[str]: ...
    def parse(self, raw_path) -> Iterator[Artifact | Finding]: ...
```

- **Ordering is derived, not declared.** `consumes`/`produces` decide where
  the stage runs. You never edit a pipeline order anywhere.
- **An empty `levels` list means the stage does not run at that level.**
- **Scope-filter the input**, even though admission control also checks the
  output: `ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))`. Filtering
  the input is what stops a packet; admission control stops the artifact.
- **`parse()` must never raise on garbage.** A missing, empty, truncated or
  non-JSON raw file yields nothing. A tool that did not run must not become
  "this target is clean" — that is this project's recurring defect.
- **In-process stages** (no subprocess: `jsrecon`, `dnssec`) set
  `in_process = True`, `writes_own_raw = True`, and return the raw `Path`
  from `run_in_process(ctx)`. Read `jsrecon` before writing one.

## 4. The contracts you will otherwise learn by breaking

Four cross-cutting tests run against **every** stage automatically. They are
the reason a new stage is safe, and they will fail before you think to ask:

- **`honors_resolver` must match what `build_command` actually emits.**
  Declaring `True` and then dropping a resolver on a non-standard port is
  worse than declaring `False` — the manifest vouches for something the argv
  did not do. If the tool cannot express a port, declare `False` and write a
  `resolver_note` saying why (see `nmap`, `maildns`).
- **`registry.validate()`** — `produces` is a set of `ArtifactKind`,
  `levels` has all four keys.
- **Argument validation at preflight** drives the real binary with the real
  flags. It is `@pytest.mark.slow` and deliberately still in the default run.
- **`test_every_stage_is_registered`** hardcodes the stage-name set. Update it.

## 5. Registration

Two lines in `sweeper/app.py`:

```python
from .stages.maildns import MaildnsStage      # import
ALL_STAGES = (..., DnssecStage, MaildnsStage, CdncheckStage, ...)
```

Position in that tuple is cosmetic — real ordering comes from
`consumes`/`produces`.

## 6. Tests

Write these before the stage (see the existing `tests/test_stage_*.py`):

- `registry.validate(YourStage()) == []`
- the levels it runs at
- `parse()` on a real captured sample of the tool's output — not a
  hand-written approximation of it
- `parse()` on empty, malformed and truncated input, yielding nothing
- **`build_command()`'s `argv[0]` is a real file.** `binaries.resolve()`
  returns `None` for an unregistered tool and `str(None)` is `"None"`, which
  produces a command that runs nothing while every flag assertion still
  passes.
- any traffic-suppressing flag is present unconditionally

## 7. Before you call it done

```sh
python -m pytest                       # the whole suite, not just your file
python sweeper.py --targets <scope> --no-menu --yes --level high \
       --stages <yourstage> --resolver 1.1.1.1:53
```

Then read `run.json`: your stage should be `complete`, `attempts: 1`, with a
recorded tool **version**. And check `sweep.log` for what it actually said.

**A stage that exits 0 and reports `complete` has not proven anything.**
Nine of this project's defects had exactly that shape — a stage that ran and
was structurally incapable of doing its job. Point it at something you KNOW
has the condition and confirm the finding appears.
