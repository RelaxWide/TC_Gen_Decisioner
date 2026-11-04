"""Small HTML-building helpers. Every piece of raw log/dmesg text MUST go
through `esc()` before being interpolated — QST excerpts contain literal
`<MAIN  >` tokens that would otherwise corrupt the page markup.
"""
import html

_BADGE_STYLE = {
    "firmware_defect": ("var(--status-critical)", "#ffffff", "defect"),
    "test_env_issue": ("var(--status-good)", "#ffffff", "env issue"),
    "needs_engineer_review": ("var(--status-warning)", "#0b0b0b", "needs review"),
}


def esc(text) -> str:
    return html.escape(str(text if text is not None else ""))


def stat_tile(label: str, value: str, sublabel: str = "") -> str:
    sub = f'<div class="stat-sub">{esc(sublabel)}</div>' if sublabel else ""
    return (
        f'<div class="stat-tile"><div class="stat-label">{esc(label)}</div>'
        f'<div class="stat-value">{esc(value)}</div>{sub}</div>'
    )


def progress_bar(pct: float, label: str) -> str:
    pct_clamped = max(0.0, min(100.0, pct))
    return (
        f'<div class="meter-row"><div class="meter-label">{esc(label)}</div>'
        f'<div class="meter-track"><div class="meter-fill" style="width:{pct_clamped:.1f}%"></div></div>'
        f'<div class="meter-pct">{pct:.1f}%</div></div>'
    )


def badge(classification: str) -> str:
    bg, fg, text = _BADGE_STYLE.get(classification, ("var(--text-muted)", "#ffffff", classification))
    return f'<span class="badge" style="background:{bg};color:{fg}">&#9679; {esc(text)}</span>'


def table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<table class="data-table"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def details_block(summary_html: str, body_html: str) -> str:
    return f"<details><summary>{summary_html}</summary><div class='details-body'>{body_html}</div></details>"


STYLE = """
<style>
:root {
  color-scheme: light;
  --surface-1: #fcfcfb; --surface-2: #f9f9f7;
  --text-primary: #0b0b0b; --text-secondary: #52514e; --text-muted: #898781;
  --series-blue: #2a78d6; --series-blue-track: #b7d3f6;
  --status-good: #0ca30c; --status-warning: #fab219; --status-serious: #ec835a; --status-critical: #d03b3b;
  --gridline: #e1e0d9; --border: rgba(11,11,11,0.10);
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --surface-1: #1a1a19; --surface-2: #0d0d0d;
    --text-primary: #f0efec; --text-secondary: #c3c2b7; --text-muted: #898781;
    --series-blue: #3987e5; --series-blue-track: #104281;
    --status-good: #0ca30c; --status-warning: #fab219; --status-serious: #ec835a; --status-critical: #e66767;
    --gridline: #2c2c2a; --border: rgba(255,255,255,0.10);
  }
}
* { box-sizing: border-box; }
body {
  background: var(--surface-2); color: var(--text-primary);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  margin: 0; padding: 24px;
}
h1, h2 { font-weight: 600; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 12px; border-bottom: 1px solid var(--gridline); padding-bottom: 8px; }
.subtitle { color: var(--text-secondary); font-size: 13px; margin-bottom: 24px; }
.card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.stat-row { display: flex; gap: 12px; flex-wrap: wrap; }
.stat-tile { background: var(--surface-1); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; min-width: 150px; }
.stat-label { color: var(--text-secondary); font-size: 12px; margin-bottom: 6px; }
.stat-value { font-size: 28px; font-weight: 600; }
.stat-sub { color: var(--text-muted); font-size: 11px; margin-top: 4px; }
.meter-row { display: grid; grid-template-columns: 220px 1fr 56px; align-items: center; gap: 10px; margin: 6px 0; }
.meter-label { color: var(--text-secondary); font-size: 13px; }
.meter-track { height: 10px; border-radius: 5px; background: var(--series-blue-track); overflow: hidden; }
.meter-fill { height: 100%; background: var(--series-blue); border-radius: 5px; }
.meter-pct { font-size: 13px; text-align: right; font-variant-numeric: tabular-nums; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.data-table th { text-align: left; color: var(--text-secondary); font-weight: 600; font-size: 12px;
  border-bottom: 1px solid var(--gridline); padding: 8px 10px; }
.data-table td { border-bottom: 1px solid var(--gridline); padding: 8px 10px; vertical-align: top; }
.data-table tr:hover td { background: var(--surface-2); }
details { margin: 0; }
details > summary { cursor: pointer; }
.details-body { margin-top: 8px; padding: 10px 12px; background: var(--surface-2); border-radius: 6px;
  font-size: 12px; white-space: pre-wrap; font-family: ui-monospace, Consolas, monospace; max-height: 320px; overflow: auto; }
.section-gap { margin-bottom: 40px; }
.empty-state { color: var(--text-muted); font-size: 13px; padding: 16px 0; }
.note { color: var(--text-secondary); font-size: 12px; margin-top: 10px; padding: 8px 12px;
  border-left: 3px solid var(--status-warning); background: var(--surface-1); border-radius: 0 6px 6px 0; }
.tag { display: inline-block; margin-left: 6px; padding: 1px 7px; border-radius: 4px; font-size: 11px;
  color: var(--text-secondary); border: 1px solid var(--border); }
.tag-warn { border-color: var(--status-warning); color: var(--status-warning); }
</style>
"""
