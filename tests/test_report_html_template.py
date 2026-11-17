"""Tests for the self-contained HTML report template.

Three properties here are security properties, not cosmetics:

1. **Escaping.** Findings carry attacker-influenced strings -- scanner
   template output, response snippets, header values, crawled URLs. This
   file is opened in the operator's browser and may be handed to a client.
   Unescaped interpolation is stored XSS in our own deliverable. Note that
   `jinja2.select_autoescape()` -- the idiomatic way to build the
   environment -- returns **False** for a filename ending `.html.j2`
   (it matches on the LAST extension). So the template must not depend on
   the environment getting it right: it carries its own
   `{% autoescape true %}` block, and every escaping test below is
   parametrised over an environment with autoescape OFF.

2. **No network.** The report is read from a `file://` URL on a machine
   that may be air-gapped, and a report that phones out on open leaks
   which engagement is being read, and when. Nothing may be fetched --
   including via a `url()` smuggled through a `style` attribute.

3. **Severity is never colour alone.** Five ordered severities on a dark
   surface, printed and read by colour-blind operators. The palette is
   re-validated here (CVD simulation + WCAG contrast) rather than eyeballed,
   and the redundant text-label channel is asserted structurally.

A fourth property is a correctness one that has bitten this kind of report
before: the client-side filters must key off the attributes the renderer
actually emits. `test_filters_read_only_attributes_the_renderer_emits`
compares the two directly instead of trusting that they were written
together.
"""
from __future__ import annotations

import math
import re
from html.parser import HTMLParser
from pathlib import Path

import jinja2
import jinja2.meta
import pytest

REPO = Path(__file__).resolve().parents[1]
TPL = REPO / "sweeper" / "templates" / "report.html.j2"

SURFACE = "#0e0e14"
ORDER = ("critical", "high", "medium", "low", "info")
PALETTE = {
    "critical": "#e0484f",
    "high": "#d9663a",
    "medium": "#c98500",
    "low": "#3987e5",
    "info": "#898781",
}

# The context contract with Task 5 (which builds this environment and this
# mapping). A name the template reads that is not in here is a name Task 5
# has no reason to pass -- see test_template_reads_no_undeclared_variable.
CONTEXT_KEYS = {
    "run_name", "level", "auth_mode", "started", "degraded", "aborted_reason",
    "warnings", "finding_collisions", "counts",
    "findings", "assets", "coverage", "refusals", "discoveries_refused",
    "tool_versions", "targets_requested", "targets_permitted",
    # The operator's --ports restriction, "" when the level's own range was
    # used. Part of the coverage story, not a cosmetic: a narrowed run and an
    # exhaustive one are otherwise the same document.
    "ports", "udp_ports", "proxy",
}

# Hostile strings. Each one breaks a different context.
XSS = "<script>alert('pwn')</script>"
ATTR_BREAK = 'x" onmouseover="alert(1)'
CSS_BREAK = "red);background-image:url(http://evil.example/beacon.png"
PAYLOADS = (XSS, ATTR_BREAK, CSS_BREAK)

AUTOESCAPE_MODES = (False, True, jinja2.select_autoescape())


def text() -> str:
    return TPL.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

def finding(**over):
    f = dict(severity="high", title="Exposed .git directory",
             target="acc.example", stage="nuclei", template_id="git-config",
             triage="new", evidence="HTTP/1.1 200 OK",
             description="d", remediation="r", matched_at="https://acc.example/.git/config",
             raw_ref="raw/nuclei.jsonl", triage_note="n")
    f.update(over)
    return f


def asset(*values, total=None):
    """One `assets` entry in the shape the renderer builds.

    `total` is the number found, which is NOT `len(shown)` once the
    inventory cap bites -- keeping them separate is the whole point of the
    shape, so the helper lets a test set them independently.
    """
    return {"total": len(values) if total is None else total,
            "shown": list(values),
            "truncated": 0 if total is None else max(0, total - len(values))}


def base_context(**over):
    ctx = dict(
        run_name="acc-2026-07-31",
        level="full",
        auth_mode="auth",
        started="2026-07-31T04:00:00Z",
        degraded=True,
        aborted_reason="",
        warnings=[],
        finding_collisions=[],
        counts={"critical": 1, "high": 2, "medium": 0, "low": 1, "info": 3},
        findings=[
            finding(severity="critical", title="Default credentials accepted",
                    target="admin.acc.example", stage="nuclei"),
            finding(severity="high"),
            finding(severity="high", stage="jsrecon", target="cdn.acc.example",
                    template_id="js-secret"),
            finding(severity="low", stage="tlsx", target="acc.example",
                    template_id="tls-weak-cipher"),
            finding(severity="info", stage="httpx", target="acc.example",
                    template_id="http-title"),
        ],
        assets={"Hosts": asset("acc.example", "admin.acc.example"),
                "HTTP services": asset("https://acc.example/")},
        coverage=[{"stage": "naabu", "status": "skipped",
                   "failure": "MISSING_BINARY", "reason": "binary not found"}],
        refusals=[{"target": "evil.test"}],
        discoveries_refused=[{"host": "cdn.thirdparty.example", "stage": "katana"},
                             {"host": "mail.acc-partner.example", "stage": "subfinder"}],
        tool_versions={"nuclei": "3.2.0", "httpx": "1.6.0"},
        targets_requested=3,
        targets_permitted=2,
        ports="top-1000",
        udp_ports="top-100",
        proxy="http://127.0.0.1:8080",
    )
    ctx.update(over)
    return ctx


def render(context=None, autoescape=False, undefined=jinja2.Undefined) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TPL.parent)),
        autoescape=autoescape,
        undefined=undefined,
    )
    return env.get_template(TPL.name).render(base_context() if context is None
                                             else context)


def hostile_context():
    """Every operator-visible string replaced with something hostile."""
    return base_context(
        run_name=XSS,
        level=ATTR_BREAK,
        auth_mode=XSS,
        started=XSS,
        # The three signals B9 added. A stage failure reason reaches
        # aborted_reason verbatim (app.py stringifies the exception), a
        # warning is assembled from tool and config names, and a collision
        # row carries a stage/target/template_id straight off a scanner --
        # all three are attacker-influenced and all three are new attack
        # surface on this page.
        aborted_reason=XSS,
        warnings=[XSS, ATTR_BREAK, CSS_BREAK],
        finding_collisions=[
            {"stage": XSS, "target": ATTR_BREAK, "template_id": XSS,
             "differing_fields": [XSS, CSS_BREAK]},
        ],
        findings=[
            finding(title=XSS, target=ATTR_BREAK, evidence=XSS,
                    template_id=XSS, description=XSS, remediation=XSS,
                    matched_at=XSS, raw_ref=XSS, triage_note=XSS,
                    stage=ATTR_BREAK, triage=XSS),
            finding(severity=CSS_BREAK, title=XSS),
        ],
        assets={XSS: asset(XSS, ATTR_BREAK, total=900)},
        coverage=[{"stage": XSS, "status": XSS, "failure": XSS, "reason": XSS}],
        refusals=[{"target": XSS}],
        # A discovered host is crawl and DNS output -- the value an attacker
        # controls most directly on this page, since putting a name in a
        # crawled page or a DNS zone is all it takes to get it rendered here.
        discoveries_refused=[{"host": XSS, "stage": ATTR_BREAK},
                             {"host": CSS_BREAK, "stage": XSS}],
        tool_versions={XSS: ATTR_BREAK},
    )


# --------------------------------------------------------------------------
# a small HTML model, so the structural tests read the DOM rather than grep
# --------------------------------------------------------------------------

VOID = {"meta", "link", "br", "img", "input", "hr", "source", "col"}


class Element:
    __slots__ = ("tag", "attrs", "parent", "text")

    def __init__(self, tag, attrs, parent):
        self.tag = tag
        self.attrs = attrs
        self.parent = parent
        self.text = []

    def classes(self):
        return set((self.attrs.get("class") or "").split())

    def own_text(self):
        return "".join(self.text)

    def ancestors(self, limit=None):
        node, out = self.parent, []
        while node is not None and (limit is None or len(out) < limit):
            out.append(node)
            node = node.parent
        return out


class Doc(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self._stack = []
        self.script_text = []
        self._in_script = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        el = Element(tag, dict(attrs), self._stack[-1] if self._stack else None)
        self.elements.append(el)
        if tag == "script":
            self._in_script = True
        if tag not in VOID:
            self._stack.append(el)

    def handle_startendtag(self, tag, attrs):
        self.elements.append(
            Element(tag, dict(attrs), self._stack[-1] if self._stack else None))

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i].tag == tag:
                del self._stack[i:]
                return

    def handle_data(self, data):
        if self._in_script:
            self.script_text.append(data)
        for el in self._stack:
            el.text.append(data)

    def find(self, tag=None, cls=None, attr=None):
        out = []
        for el in self.elements:
            if tag and el.tag != tag:
                continue
            if cls and cls not in el.classes():
                continue
            if attr and attr not in el.attrs:
                continue
            out.append(el)
        return out

    def by_id(self, ident):
        for el in self.elements:
            if el.attrs.get("id") == ident:
                return el
        return None


# --------------------------------------------------------------------------
# colour maths -- CVD simulation and WCAG contrast, so the palette claim is
# computed rather than asserted. Machado, Oliveira & Fernandes (2009)
# transforms at severity 1.0, CIE76 delta-E in CIELAB (D65).
# --------------------------------------------------------------------------

MACHADO = {
    "protan": [[0.152286, 1.052583, -0.204868],
               [0.114503, 0.786281, 0.099216],
               [-0.003882, -0.048116, 1.051998]],
    "deutan": [[0.367322, 0.860646, -0.227968],
               [0.280085, 0.672501, 0.047413],
               [-0.011820, 0.042940, 0.968881]],
    "tritan": [[1.255528, -0.076749, -0.178779],
               [-0.078411, 0.930809, 0.147602],
               [0.004733, 0.691367, 0.303900]],
}
CVD_TARGET = 12.0       # delta-E at which two marks read as different colours
CONTRAST_MIN = 3.0      # WCAG non-text contrast, vs the report surface
CHROMA_FLOOR = 0.10     # OKLCH C below which a hue reads as grey


def _lin(hex_value):
    h = hex_value.lstrip("#")
    out = []
    for i in (0, 2, 4):
        c = int(h[i:i + 2], 16) / 255
        out.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    return tuple(out)


def _luminance(hex_value):
    r, g, b = _lin(hex_value)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def chroma(hex_value):
    r, g, b = _lin(hex_value)
    l = (0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b) ** (1 / 3)
    m = (0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b) ** (1 / 3)
    s = (0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b) ** (1 / 3)
    return math.hypot(1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
                      0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s)


def _lab(rgb):
    r, g, b = rgb
    xyz = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b,
           0.2126729 * r + 0.7151522 * g + 0.0721750 * b,
           0.0193339 * r + 0.1191920 * g + 0.9503041 * b)
    ref = (0.95047, 1.0, 1.08883)
    f = [(t / n) ** (1 / 3) if t / n > 0.008856 else 7.787 * (t / n) + 16 / 116
         for t, n in zip(xyz, ref)]
    return (116 * f[1] - 16, 500 * (f[0] - f[1]), 200 * (f[1] - f[2]))


def _simulate(hex_value, kind):
    r, g, b = _lin(hex_value)
    m = MACHADO[kind]
    return tuple(max(0.0, min(1.0, row[0] * r + row[1] * g + row[2] * b))
                 for row in m)


def delta_e(a, b, kind=None):
    return math.dist(_lab(_simulate(a, kind) if kind else _lin(a)),
                     _lab(_simulate(b, kind) if kind else _lin(b)))


# ==========================================================================
# 1. the template exists and is self-contained
# ==========================================================================

def test_template_exists():
    assert TPL.exists()


def test_no_external_stylesheets_or_scripts():
    bad = re.findall(r'(?:src|href)\s*=\s*["\']https?://', text())
    assert bad == [], f"external references found: {bad}"


def test_no_css_import_of_remote_font():
    assert "@import" not in text()
    assert "fonts.googleapis" not in text()


def test_no_external_reference_in_rendered_output():
    """Hostile findings must not be able to plant one either.

    Greps the RENDERED document, not the source: a finding whose target is
    an attacker-chosen URL must land in a text node, never in a fetching
    position. Protocol-relative `//host` counts -- from a file:// URL it
    resolves to file://host, but from anywhere else it is a live request.
    """
    doc = Doc(render(hostile_context(), autoescape=False))
    fetching = ("src", "href", "srcset", "action", "formaction", "poster",
                "data", "background", "cite")
    for el in doc.elements:
        for name in fetching:
            value = el.attrs.get(name)
            assert not (value and re.match(r"\s*(?:https?:)?//", value)), (
                f"<{el.tag} {name}={value!r}> would fetch from the network")
    css = "".join(s.own_text() for s in doc.find(tag="style"))
    css += " ".join(el.attrs.get("style", "") for el in doc.elements)
    assert "url(" not in css, "CSS fetches something"
    assert "@import" not in css


def test_script_is_inline_and_has_no_fetch():
    body = text()
    assert "<script>" in body
    assert "fetch(" not in body
    assert "XMLHttpRequest" not in body


def test_script_block_makes_no_network_call_of_any_kind():
    out = render()
    script = "".join(Doc(out).script_text)
    for sink in ("fetch(", "XMLHttpRequest", "import(", "navigator.sendBeacon",
                 "EventSource", "WebSocket", "new Image", "location.href ="):
        assert sink not in script, f"network sink in inline script: {sink}"


# ==========================================================================
# 2. escaping -- the security property
# ==========================================================================

def test_select_autoescape_does_not_cover_this_extension():
    """Documents WHY the template carries its own autoescape block.

    If this ever starts returning True the belt-and-braces block is still
    correct, but the reason for it has changed and the comment above it
    should be revisited.
    """
    assert jinja2.select_autoescape()(TPL.name) is False


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
def test_script_tag_in_a_finding_title_renders_inert(autoescape):
    out = render(base_context(findings=[finding(title=XSS)]), autoescape=autoescape)
    assert XSS not in out
    assert "alert(&#39;pwn&#39;)" in out or "&lt;script&gt;" in out
    # the only <script> in the document is our own inline one
    assert len(Doc(out).find(tag="script")) == 1


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
def test_every_interpolated_field_is_escaped(autoescape):
    """Not just the title: run name, target, evidence, asset labels, coverage
    reasons, refused targets and tool versions are all attacker-influenced."""
    out = render(hostile_context(), autoescape=autoescape)
    assert XSS not in out
    assert "<script>alert" not in out
    # the quote in ATTR_BREAK must have been neutralised, not passed through
    assert "&#34;" in out or "&quot;" in out


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
def test_attacker_string_cannot_break_out_of_an_attribute(autoescape):
    out = render(hostile_context(), autoescape=autoescape)
    doc = Doc(out)
    for el in doc.elements:
        for name in el.attrs:
            assert not name.startswith("on"), (
                f"event-handler attribute {name!r} materialised on <{el.tag}>")


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
def test_attacker_string_never_reaches_the_script_block(autoescape):
    """No finding-derived value is interpolated into JS at all.

    HTML-escaping is the wrong escaping for a script context, so the
    template's defence is that nothing attacker-influenced goes there --
    the only interpolation inside <script> is the fixed severity order.
    """
    script = "".join(Doc(render(hostile_context(), autoescape=autoescape)).script_text)
    for payload in PAYLOADS:
        assert payload not in script
    for fragment in ("alert", "evil.example", "onmouseover"):
        assert fragment not in script


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
def test_no_style_attribute_carries_a_url_or_an_injected_declaration(autoescape):
    """A severity that is not one of the five may not reach a CSS context.

    `style="background:var(--sev-{{ severity }})"` with an unconstrained
    severity is a CSS injection -- and `url(http://...)` inside it is a
    live network request from the operator's browser, defeating the
    no-network property that attribute escaping alone does not protect.
    """
    doc = Doc(render(hostile_context(), autoescape=autoescape))
    for el in doc.elements:
        style = el.attrs.get("style", "")
        assert "url(" not in style, f"url() in style attribute: {style!r}"
        assert "http" not in style, f"scheme in style attribute: {style!r}"
        for var in re.findall(r"var\(--sev-([^)]*)\)", style):
            assert var in ORDER or var == "unknown", (
                f"unconstrained severity reached a CSS variable: {var!r}")


# ==========================================================================
# 3. severity is never colour alone
# ==========================================================================

def test_validated_severity_colors_present():
    for hex_value in ("#e0484f", "#d9663a", "#c98500", "#3987e5", "#898781"):
        assert hex_value in text(), f"{hex_value} missing from palette"


def test_dark_surface_matches_validated_surface():
    assert "#0e0e14" in text()


def test_severity_chip_includes_text_label():
    # the chip must print the severity word, not just tint a box
    assert "{{ f.severity" in text() or "{{ f['severity']" in text()


def test_severity_is_never_identified_by_colour_alone():
    """Every element tinted with a severity colour carries the word too.

    Checked on the rendered document within two levels of ancestry, so a
    dot inside a labelled chip passes and a bare tinted box does not. This
    is the test that fails if someone drops `{{ f.severity }}` from the
    chip and leaves the coloured dot behind.
    """
    doc = Doc(render())
    tinted = [el for el in doc.elements
              if "var(--sev-" in (el.attrs.get("style") or "")]
    assert tinted, "no severity-tinted elements found -- fixture or template broken"
    for el in tinted:
        sev = re.search(r"var\(--sev-([a-z]+)\)", el.attrs["style"]).group(1)
        scope = " ".join([el.own_text()] + [a.own_text() for a in el.ancestors(2)])
        assert sev in scope.lower(), (
            f"<{el.tag}> is tinted --sev-{sev} but neither it nor its two "
            f"nearest ancestors print the word: {scope!r}")


def test_severity_colours_survive_colour_blind_simulation():
    """Any two severity chips can end up side by side (adjacent table rows),
    so ALL pairs are checked, not just neighbours in the ordering."""
    worst = None
    for kind in ("protan", "deutan", "tritan"):
        for i, a in enumerate(ORDER):
            for b in ORDER[i + 1:]:
                d = delta_e(PALETTE[a], PALETTE[b], kind)
                if worst is None or d < worst[0]:
                    worst = (d, kind, a, b)
    assert worst[0] >= CVD_TARGET, (
        f"{worst[2]}/{worst[3]} collapse under {worst[1]}: delta-E {worst[0]:.1f} "
        f"< {CVD_TARGET}")


def test_severity_colours_clear_three_to_one_against_the_surface():
    for sev, hex_value in PALETTE.items():
        ratio = contrast(hex_value, SURFACE)
        assert ratio >= CONTRAST_MIN, f"{sev} {hex_value} only {ratio:.2f}:1 on {SURFACE}"


def test_info_is_achromatic_which_is_why_the_label_channel_is_load_bearing():
    """`info` is deliberately below the chroma floor -- it reads as grey ink
    so the lowest severity recedes. That is a deliberate exception to the
    palette rules and it only holds because every severity also prints its
    word; if that ever stops being true this test's docstring is the record
    of what was traded away."""
    assert chroma(PALETTE["info"]) < CHROMA_FLOOR
    for sev in ("critical", "high", "medium", "low"):
        assert chroma(PALETTE[sev]) >= CHROMA_FLOOR, f"{sev} reads as grey"


# ==========================================================================
# 4. the filters key off what the renderer emits
# ==========================================================================

def test_filter_controls_present():
    body = text()
    for control in ("filter-severity", "filter-stage", "filter-search", "filter-host"):
        assert control in body, f"missing filter control: {control}"


def test_filters_read_only_attributes_the_renderer_emits():
    """The defect this exists for: JS reading `dataset.severity` while the
    renderer writes `data-sev`. Compares the two sides directly."""
    out = render()
    doc = Doc(out)
    script = "".join(doc.script_text)

    read = set(re.findall(r"dataset\.([A-Za-z0-9_]+)", script))
    read |= {m.replace("-", "_")
             for m in re.findall(r"""getAttribute\(['"]data-([\w-]+)""", script)}
    assert read, "no dataset reads found -- the filter script is not doing anything"

    emitted = set()
    for el in doc.elements:
        for name in el.attrs:
            if name.startswith("data-"):
                emitted.add(name[5:].replace("-", "_"))

    missing = sorted(k for k in read
                     if re.sub(r"([A-Z])", r"_\1", k).lower() not in emitted)
    assert not missing, (
        f"script reads data attributes the renderer never emits: {missing} "
        f"(emitted: {sorted(emitted)})")


def test_ids_the_script_looks_up_are_all_rendered():
    out = render()
    doc = Doc(out)
    script = "".join(doc.script_text)
    for ident in re.findall(r"""getElementById\(['"]([\w-]+)['"]\)""", script):
        assert doc.by_id(ident) is not None, f"script looks up missing #{ident}"


def test_filter_option_values_match_the_row_values_they_filter_on():
    doc = Doc(render())
    rows = doc.find(tag="tr", cls="finding")
    assert rows
    for select_id, data_key in (("filter-stage", "data-stage"),
                                ("filter-host", "data-host")):
        select = doc.by_id(select_id)
        assert select is not None, f"missing #{select_id}"
        options = {o.attrs.get("value", "") for o in doc.find(tag="option")
                   if o.parent is select} - {""}
        values = {r.attrs.get(data_key) for r in rows}
        assert options == values, (
            f"#{select_id} offers {sorted(options)} but rows carry "
            f"{sorted(values)} in {data_key}")


def test_every_severity_present_in_the_table_has_a_toggle():
    ctx = base_context()
    ctx["findings"].append(finding(severity="not-a-severity", title="odd"))
    doc = Doc(render(ctx))
    toggles = {b.attrs.get("data-sev")
               for b in doc.find(tag="button", cls="sevtoggle")}
    rows = {r.attrs.get("data-sev") for r in doc.find(tag="tr", cls="finding")}
    assert rows <= toggles, (
        f"rows carry severities with no toggle: {sorted(rows - toggles)}")


def test_client_side_sort_order_matches_the_rendered_severity_order():
    """One source of truth for the ordering: the script's sort map is
    generated from the same list the chips are, so a client-side sort can
    never disagree with the order the report presents."""
    doc = Doc(render())
    script = "".join(doc.script_text)
    block = re.search(r"var\s+order\s*=\s*\{([^}]*)\}", script)
    assert block, "no severity sort map in the inline script"
    js_order = re.findall(r"([a-z-]+)\s*:\s*\d+", block.group(1))
    chips = [b.own_text().strip() for b in doc.find(tag="button", cls="sevtoggle")]
    assert js_order[:len(ORDER)] == list(ORDER)
    assert chips[:len(ORDER)] == list(ORDER)


# ==========================================================================
# 5. layout: wide content scrolls in its own container
# ==========================================================================

def test_table_is_horizontally_scrollable():
    assert "overflow-x" in text()


def test_every_table_lives_inside_a_horizontal_scroll_container():
    doc = Doc(render())
    tables = doc.find(tag="table")
    assert tables
    for t in tables:
        assert any("tablewrap" in a.classes() for a in t.ancestors()), (
            "a <table> is not inside a .tablewrap -- it will widen the page")
    assert re.search(r"\.tablewrap\s*\{[^}]*overflow-x\s*:\s*auto", text())


def test_long_unbreakable_strings_wrap_instead_of_widening_the_page():
    """Evidence blocks and asset lists carry URLs with no break opportunity;
    without this they push the page wider than the viewport."""
    body = text()
    for selector in (r"pre\s*\{", r"li\s*\{"):
        block = re.search(selector + r"([^}]*)\}", body)
        assert block and ("break-all" in block.group(1)
                          or "anywhere" in block.group(1)), (
            f"rule matching {selector} does not break long tokens")


# ==========================================================================
# 6. the contract with Task 5, and rendering robustness
# ==========================================================================

def test_template_reads_no_undeclared_variable():
    """Every top-level name the template reads must be one Task 5 passes.

    A template referencing `bar_width(...)` or `severity_order` renders
    blank or raises depending on the undefined policy -- and neither is in
    the agreed context. Anything derived is derived with {% set %}.
    """
    source = text()
    env = jinja2.Environment()
    used = jinja2.meta.find_undeclared_variables(env.parse(source))
    assert used <= CONTEXT_KEYS, f"undeclared context names: {sorted(used - CONTEXT_KEYS)}"


def test_all_contract_keys_are_actually_used():
    source = text()
    for key in CONTEXT_KEYS:
        assert re.search(r"\b" + key + r"\b", source), f"context key unused: {key}"


def test_renders_with_strict_undefined_and_minimal_findings():
    """Only `severity` and `title` are required on a finding dict; every
    other key is optional. Rendered under StrictUndefined so a missing
    optional key raises here rather than blanking a cell in a deliverable."""
    ctx = base_context(findings=[{"severity": "medium", "title": "only the basics"}])
    out = render(ctx, autoescape=True, undefined=jinja2.StrictUndefined)
    assert "only the basics" in out


def test_renders_an_empty_run():
    ctx = base_context(findings=[], counts=dict.fromkeys(ORDER, 0), assets={},
                       coverage=[], refusals=[], discoveries_refused=[],
                       tool_versions={},
                       targets_requested=0, targets_permitted=0, degraded=False)
    out = render(ctx, autoescape=True, undefined=jinja2.StrictUndefined)
    assert "No findings" in out
    assert "DEGRADED" not in out


def test_degraded_banner_appears_only_when_degraded():
    assert "DEGRADED" in render(base_context(degraded=True))
    assert "DEGRADED" not in render(base_context(degraded=False))


# ==========================================================================
# 6b. the three signals the Markdown report leads with (B9)
# ==========================================================================

def test_aborted_run_names_its_reason_rather_than_only_being_degraded():
    """A Ctrl-C'd run used to render an unexplained DEGRADED banner: the
    operator saw that something went wrong and nothing about what."""
    out = render(base_context(degraded=True,
                              aborted_reason="interrupted by operator (SIGINT)"))
    assert "RUN ABORTED" in out
    assert "interrupted by operator (SIGINT)" in out


def test_abort_replaces_the_degraded_banner_rather_than_stacking_with_it():
    """The Markdown report is an if/elif; two banners saying the same thing
    with different force is not two facts."""
    out = render(base_context(degraded=True, aborted_reason="boom"))
    assert "DEGRADED RUN" not in out


def test_aborted_run_does_not_also_claim_all_stages_completed():
    """Where the interrupt lands during the last stage every RECORDED result
    is complete, so the coverage table is empty and its empty state used to
    read 'All selected stages completed.' two inches under the banner."""
    out = render(base_context(degraded=True, aborted_reason="boom", coverage=[]))
    assert "All selected stages completed." not in out
    assert "aborted before finishing" in out


def test_clean_run_still_says_all_selected_stages_completed():
    """Mutation guard for the test above: the honest empty state must not
    have been replaced everywhere, only where it would be a lie."""
    out = render(base_context(degraded=False, aborted_reason="", coverage=[]))
    assert "All selected stages completed." in out


def test_run_warnings_reach_the_page():
    """The arjun `ps` case: live credentials were visible in the process
    list on the scanning host and the HTML deliverable said nothing."""
    out = render(base_context(warnings=[
        "arjun exposes credentials via `ps` on this host",
        "second notice",
    ]))
    assert "2 RUN WARNINGS" in out
    assert "arjun exposes credentials" in out
    assert "second notice" in out


def test_a_single_warning_is_not_pluralised():
    assert "1 RUN WARNING" in render(base_context(warnings=["only one"]))
    assert "1 RUN WARNINGS" not in render(base_context(warnings=["only one"]))


def test_no_warning_banner_when_there_are_no_warnings():
    assert "RUN WARNING" not in render(base_context(warnings=[]))


def test_finding_collisions_caveat_the_counts_and_are_itemised():
    out = render(base_context(finding_collisions=[
        {"stage": "nuclei", "target": "acc.example", "template_id": "git-config",
         "differing_fields": ["evidence", "title"]},
    ]))
    assert "1 FINDING ID COLLISION DETECTED" in out
    assert "UNDERCOUNT" in out
    # identity, itemised -- not just a number
    assert "git-config" in out
    assert "evidence, title" in out


def test_no_collision_banner_when_there_are_none():
    out = render(base_context(finding_collisions=[]))
    assert "COLLISION" not in out.upper()


def test_asset_heading_counts_what_was_found_not_what_was_shown():
    """The `_assets` half of B9: the truncation notice used to be appended
    to the value list the template counts, so 500 ports rendered as
    'Ports (201)' here and 'Ports (500)' in the Markdown report."""
    out = render(base_context(
        assets={"Ports": asset(*[f"acc.example:{i}" for i in range(200)],
                               total=500)}))
    assert "Ports (500)" in out
    assert "Ports (201)" not in out
    assert "300 more ports" in out


def test_untruncated_inventory_shows_no_truncation_notice():
    out = render(base_context(assets={"Hosts": asset("a.example", "b.example")}))
    assert "Hosts (2)" in out
    assert "truncated" not in out


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
@pytest.mark.parametrize("field,value", [
    ("aborted_reason", XSS),
    ("warnings", [XSS]),
    ("finding_collisions", [{"stage": XSS, "target": XSS, "template_id": XSS,
                             "differing_fields": [XSS]}]),
    ("discoveries_refused", [{"host": XSS, "stage": XSS}]),
])
def test_each_new_signal_field_renders_inert(field, value, autoescape):
    """Each field on its own, so a single unescaped one cannot hide behind
    the others being escaped in the combined hostile context."""
    out = render(base_context(**{field: value}), autoescape=autoescape)
    assert XSS not in out
    assert "&lt;script&gt;" in out or "alert(&#39;pwn&#39;)" in out
    assert len(Doc(out).find(tag="script")) == 1


# A reported number must be read out of the sentence that reports it, in the
# role it is reported in -- never as a bare substring of the document. This
# page carries a hex palette (#3987e5), percentage bar widths, an ISO
# timestamp and CSS lengths, so `"9" in out` is true of a document that never
# printed a nine, and stays true when the template hardcodes the wrong number.
# Both tests below were written that way, and both survived hardcoding
# `99 in scope` into the coverage line.
TARGET_LINE = re.compile(
    r"(\d+)\s+requested,\s*(\d+)\s+in scope(?:,\s*(\d+)\s+refused)?\.")


@pytest.mark.parametrize("requested,permitted", [
    (5, 2), (1, 1), (3, 0), (12, 7), (100, 99),
])
def test_coverage_reports_requested_permitted_and_refused(requested, permitted):
    """Each number in its own role, over several pairs: a template that prints
    a constant, or swaps requested for permitted, or recomputes the refused
    count wrongly, fails on at least one pair."""
    out = render(base_context(targets_requested=requested,
                              targets_permitted=permitted))
    m = TARGET_LINE.search(out)
    assert m, "the coverage line did not render in the expected shape"
    assert int(m.group(1)) == requested
    assert int(m.group(2)) == permitted
    refused = requested - permitted
    if refused:
        assert m.group(3) is not None and int(m.group(3)) == refused
    else:
        assert m.group(3) is None, "nothing was refused; do not say '0 refused'"


def test_coverage_line_is_absent_when_no_targets_were_requested():
    """The complement, so the test above cannot be satisfied by a template
    that prints the line unconditionally with fabricated numbers."""
    out = render(base_context(targets_requested=0, targets_permitted=0))
    assert TARGET_LINE.search(out) is None


# --------------------------------------------------------------------------
# discovered, not scanned (out of scope) -- O2
# --------------------------------------------------------------------------
# These hosts are the basis of a scope-extension conversation with the
# client ("we found these, we did not touch them, do you want them in
# scope?"), and this file is the deliverable that conversation happens over.
# They reached report.md and run.json; this page omitted them entirely, so
# the reader of the client-facing file could not have that conversation.

def test_discovered_hosts_are_named_with_the_stage_that_found_them():
    out = render(base_context(discoveries_refused=[
        {"host": "cdn.thirdparty.example", "stage": "katana"}]))
    assert "cdn.thirdparty.example" in out
    assert "katana" in out


def test_discovered_section_states_how_many_were_found():
    out = render(base_context(discoveries_refused=[
        {"host": f"h{i}.thirdparty.example", "stage": "subfinder"}
        for i in range(37)]))
    assert "Discovered, not scanned (out of scope) (37)" in out


def test_every_discovered_host_is_listed_not_only_counted():
    """Uncapped, matching the Markdown twin: a silently short list of the
    hosts a scope extension would cover is the recurring defect in a
    smaller box."""
    hosts = [f"h{i:03d}.thirdparty.example" for i in range(250)]
    out = render(base_context(discoveries_refused=[
        {"host": h, "stage": "subfinder"} for h in hosts]))
    missing = [h for h in hosts if h not in out]
    assert not missing, f"{len(missing)} discovered hosts never rendered"


def test_no_discovered_section_when_nothing_was_discovered():
    out = render(base_context(discoveries_refused=[]))
    assert "Discovered, not scanned" not in out


def test_discovered_hosts_do_not_claim_the_run_is_degraded():
    """A discovery-heavy run finding many out-of-scope hosts is a
    SUCCESSFUL run. 200 discoveries and nothing else wrong raises no
    banner at all, and none of them leaks into one."""
    clean = dict(degraded=False, aborted_reason="", warnings=[],
                 finding_collisions=[])
    hosts = [{"host": f"h{i}.thirdparty.example", "stage": "katana"}
             for i in range(200)]
    doc = Doc(render(base_context(discoveries_refused=hosts, **clean)))
    assert "h0.thirdparty.example" in doc.find(tag="body")[0].own_text(), \
        "test is vacuous: the discoveries never rendered"
    assert doc.find(cls="banner") == []

    # and with a banner legitimately present, it still says nothing about them
    doc = Doc(render(base_context(discoveries_refused=hosts,
                                  **{**clean, "degraded": True})))
    banners = doc.find(cls="banner")
    assert banners, "test is vacuous: no banner to check against"
    for banner in banners:
        assert "thirdparty" not in banner.own_text()
        assert "Discovered" not in banner.own_text()


@pytest.mark.parametrize("autoescape", AUTOESCAPE_MODES)
def test_script_tag_in_a_discovered_hostname_renders_inert(autoescape):
    """A discovered hostname comes from crawl output and DNS: getting a name
    into a crawled page is all it takes to get it rendered in the operator's
    browser. The page has its own legitimate <script>, so assert on the
    count as well as on the payload."""
    out = render(base_context(discoveries_refused=[
        {"host": XSS, "stage": XSS}]), autoescape=autoescape)
    assert XSS not in out
    assert "&lt;script&gt;" in out or "alert(&#39;pwn&#39;)" in out
    assert len(Doc(out).find(tag="script")) == 1


def test_zero_count_severity_draws_no_bar():
    """A minimum-width bar on a zero count reads as 'a few, but small'."""
    doc = Doc(render(base_context(counts={"critical": 0, "high": 0, "medium": 0,
                                          "low": 0, "info": 4})))
    rows = doc.find(cls="row")
    assert len(rows) == len(ORDER)
    for row in rows:
        words = row.own_text().split()
        count = words[-1]
        bars = [e for e in doc.elements
                if "bar" in e.classes() and row in e.ancestors()]
        assert bool(bars) == (count != "0"), (
            f"row {words} has {len(bars)} bar(s) for a count of {count}")


RECONCILE_LINE = re.compile(
    r"Distribution totals\s+(\d+)\s+across all severities;\s*(\d+)\s+listed")


@pytest.mark.parametrize("critical,n_findings", [
    (9, 5), (2, 5), (7, 1), (40, 3),
])
def test_distribution_total_and_row_count_are_both_visible_when_they_differ(
        critical, n_findings):
    """Finding-count reconciliation, at the last mile: no single number in
    this report may stand in for a different one. If the severity
    distribution totals more than the table lists (triage filtering, for
    instance), both numbers are printed -- and each is read back out of the
    role it was printed in, over several pairs, so neither can be a constant
    and the two cannot be swapped for one another.
    """
    counts = {"critical": critical, "high": 0, "medium": 0, "low": 0, "info": 0}
    out = render(base_context(
        counts=counts,
        findings=[finding(title=f"f{i}") for i in range(n_findings)]))
    m = RECONCILE_LINE.search(out)
    assert m, "the reconciliation line did not render in the expected shape"
    assert int(m.group(1)) == sum(counts.values())
    assert int(m.group(2)) == n_findings


def test_no_reconciliation_line_when_the_two_counts_agree():
    """The complement: the line is a caveat, and a caveat printed when there
    is nothing to caveat trains the reader to skip it."""
    out = render(base_context(
        counts={"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 0},
        findings=[finding(title="a"), finding(title="b")]))
    assert RECONCILE_LINE.search(out) is None
