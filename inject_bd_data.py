#!/usr/bin/env python3
"""
inject_bd_data.py — Injects real Qlik + HubSpot data into bd_cs_report HTML
Run AFTER pull_bd_data.py has generated bd_data_latest.json

Usage: python3 inject_bd_data.py [--data bd_data_latest.json] [--html bd_cs_report_W2021_2026.html]
"""

import json, re, sys, argparse
from pathlib import Path

# ─── HELPERS ───────────────────────────────────────────────────────────────────
def fmt_ty(v):
    """Format tỷ value: 306.09B, 53.08B, 39M"""
    if v is None: return "—"
    if v < 1:    return f"{v*1000:.0f}M"
    return f"{v:.2f}B"

def fmt_mom(pct, zero="—"):
    if pct is None: return zero
    sign = "▲" if pct > 0 else "▼"
    cls  = "green" if pct > 0 else ("red" if pct < 0 else "flat")
    return sign, f"{abs(pct):.1f}%", cls

def chip_class(pct):
    if pct is None: return "chip-blue"
    if pct > 0: return "chip-green"
    if pct < 0: return "chip-red"
    return "chip-gray"


# ─── BLOCK BUILDERS ────────────────────────────────────────────────────────────
def build_tab_chip(bd):
    rev = fmt_ty(bd["current_rev_ty"])
    pct = bd["mom_pct"]
    cls = chip_class(pct)
    if pct is not None:
        label = f"{rev} · {pct:+.1f}%"
    else:
        label = rev
    return f'<span class="kpi-chip chip {cls}">{label}</span>'


def build_header_stats(bd, month_label="May 2026", prev_month_label="Apr 2026"):
    rev_str = fmt_ty(bd["current_rev_ty"])
    rev_cls = "green" if (bd["mom_pct"] or 0) >= 0 else "red"
    mom_pct = bd["mom_pct"]
    mom_str = f"{mom_pct:+.1f}%" if mom_pct is not None else "—"
    mom_cls = "green" if (mom_pct or 0) >= 0 else "red"
    return f"""
        <div class="bds"><span class="bds-val {rev_cls}">{rev_str}</span><span class="bds-label">Revenue {month_label}</span></div>
        <div class="bds"><span class="bds-val {mom_cls}">{mom_str}</span><span class="bds-label">MoM vs {prev_month_label}</span></div>"""


def build_activities_block(bd, month_label="May 2026"):
    calls    = bd["calls"]
    emails   = bd["emails"]
    meetings = bd["meetings"]
    tasks    = bd["tasks"]
    notes    = bd["notes"]
    total    = calls + emails + meetings + tasks + notes

    def stat(val, label, color=""):
        cls = f" {color}" if color else ""
        return f"""          <div class="stat"><span class="stat-val{cls}">{val}</span><span class="stat-label">{label}</span></div>"""

    call_cls  = "green" if calls > 3 else ("red" if calls == 0 else "")
    email_cls = "green" if emails > 20 else ""
    meet_cls  = "green" if meetings > 2 else ""

    return f"""        <div class="card-title">Hubspot Activities — {month_label}</div>
        <div class="stat-row" style="margin-bottom:10px">
{stat(total, "Total Activities", "blue")}
{stat(calls, "Calls", call_cls)}
{stat(emails, "Emails", email_cls)}
{stat(meetings, "Meetings", meet_cls)}
{stat(tasks, "Tasks", "")}
{stat(notes, "Notes", "")}
        </div>"""


# ─── PATCH FUNCTIONS ────────────────────────────────────────────────────────────
def patch_bd_tabs(html: str, bds: dict) -> str:
    """Update all BD tab chips with real revenue + MoM"""
    order = [("hp","huyenptk"), ("ap","anhpnv"), ("ll","linhld"),
             ("dk","duyenltk"), ("hx","huonglx"), ("ln","lanlt2"), ("vy","vynk5")]

    name_map = {
        "hp": "HuyenPTK", "ap": "AnhPNV", "ll": "LinhLD",
        "dk": "DuyenLTK", "hx": "HuongLX", "ln": "LanLT2", "vy": "VyNK5",
    }

    for tab_id, bd_key in order:
        bd = bds.get(bd_key)
        display = name_map[tab_id]

        if bd_key == "vynk5":
            chip = '<span class="kpi-chip chip chip-blue">Pipeline</span>'
        elif bd_key == "huonglx":
            rev_m = int((bd["current_rev_ty"] or 0) * 1000)
            chip = f'<span class="kpi-chip chip chip-blue">{rev_m}M · {bd["mom_pct"]:+.1f}%</span>' if bd else \
                   '<span class="kpi-chip chip chip-blue">SME</span>'
        else:
            chip = build_tab_chip(bd) if bd else '<span class="kpi-chip chip chip-gray">—</span>'

        # Match button line for this tab
        pattern = (
            r'(<button[^>]+onclick="switchBD\(\'' + re.escape(tab_id) + r'\'[^>]+>)'
            r'[^<]*'          # name text
            r'(?:<span[^>]+kpi-chip[^/]*/span>)?'  # old chip (optional)
        )
        replacement = rf'\g<1>{display} {chip}'
        html, n = re.subn(pattern, replacement, html)
        if n == 0:
            print(f"  [WARN] tab patch failed for {tab_id}", file=sys.stderr)
    return html


def patch_bd_header(html: str, panel_id: str, bd: dict, name: str, meta: str,
                    month_label: str = "May 2026", prev_month_label: str = "Apr 2026") -> str:
    """Replace bds-val/bds-label block inside a bd-panel"""
    # Find the panel
    panel_start = html.find(f'id="bd-{panel_id}"')
    if panel_start == -1:
        print(f"  [WARN] panel bd-{panel_id} not found", file=sys.stderr)
        return html

    # Find bd-stats block inside this panel (first occurrence after panel_start)
    stats_start = html.find('<div class="bd-stats">', panel_start)
    if stats_start == -1:
        print(f"  [SKIP] no bd-stats in bd-{panel_id}", file=sys.stderr)
        return html

    # Find matching closing </div> for bd-stats by counting depth
    depth = 0
    i = stats_start
    stats_end = stats_start  # fallback
    while i < len(html):
        if html[i:i+4] == '<div':
            depth += 1
        elif html[i:i+6] == '</div>':
            depth -= 1
            if depth == 0:
                stats_end = i + 6
                break
        i += 1

    new_stats = f'<div class="bd-stats">{build_header_stats(bd, month_label, prev_month_label)}\n      </div>'
    return html[:stats_start] + new_stats + html[stats_end:]


def patch_bd_activities(html: str, panel_id: str, bd: dict, month_label="May 2026") -> str:
    """Replace the entire card containing HubSpot Activities for a panel"""
    panel_start = html.find(f'id="bd-{panel_id}"')
    if panel_start == -1:
        return html

    # Find "Hubspot Activities" card title within this panel
    search = 'Hubspot Activities'
    act_pos = html.find(search, panel_start)
    if act_pos == -1:
        print(f"  [WARN] no activities section in bd-{panel_id}", file=sys.stderr)
        return html

    # Find the card start (go back to find <div class="card">)
    card_start = html.rfind('<div class="card">', panel_start, act_pos)

    # Find the matching </div> for this card
    depth = 0
    i = card_start
    while i < len(html):
        if html[i:i+4] == '<div':
            depth += 1
        elif html[i:i+6] == '</div>':
            depth -= 1
            if depth == 0:
                card_end = i + 6
                break
        i += 1

    new_card = f'      <div class="card">\n{build_activities_block(bd, month_label)}\n      </div>'
    return html[:card_start] + new_card + html[card_end:]


# ─── MAIN ──────────────────────────────────────────────────────────────────────
MONTH_ABBR = {
    1:"Jan",2:"Feb",3:"Mar",4:"Apr",5:"May",6:"Jun",
    7:"Jul",8:"Aug",9:"Sep",10:"Oct",11:"Nov",12:"Dec"
}

def vn_month(abbr: str) -> str:
    """Convert English abbr → Vietnamese: May → T5, Apr → T4"""
    m = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
         "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
    return f"T{m.get(abbr, '?')}"


def patch_last_updated(html: str, generated: str) -> str:
    """Inject last-updated timestamp into the data-last-updated attribute"""
    html = re.sub(
        r'data-last-updated="[^"]*"',
        f'data-last-updated="{generated}"',
        html
    )
    return html


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="bd_data_latest.json")
    ap.add_argument("--html", default="bd_cs_report_W2021_2026.html")
    ap.add_argument("--out",  default=None)  # if None, overwrites html
    args = ap.parse_args()

    with open(args.data, encoding="utf-8") as f:
        data = json.load(f)

    # Build dynamic month labels
    month_abbr      = data.get("month_abbr", "May")
    prev_abbr       = data.get("prev_month_abbr", "Apr")
    year            = data.get("year", 2026)
    month_label     = f"{month_abbr} {year}"
    prev_month_label = f"{prev_abbr} {year if data.get('month',5) > 1 else year-1}"
    generated       = data.get("generated", "")

    html_path = Path(args.html)
    html = html_path.read_text(encoding="utf-8")
    bds  = data["bds"]

    print("Patching BD tabs…")
    html = patch_bd_tabs(html, bds)

    panel_map = {
        "hp": ("huyenptk", "Huyền PTK"),
        "ap": ("anhpnv",   "Anh PNV"),
        "ll": ("linhld",   "Linh LD"),
        "dk": ("duyenltk", "Duyên LTK"),
        "hx": ("huonglx",  "Hương LX"),
        "ln": ("lanlt2",   "Lan LT2"),
        "vy": ("vynk5",    "Vy NK5"),
    }

    for panel_id, (bd_key, name) in panel_map.items():
        bd = bds.get(bd_key)
        if not bd:
            continue
        if bd_key != "vynk5":
            print(f"  Patching {name} header…")
            html = patch_bd_header(html, panel_id, bd, name, "May 2026",
                                   month_label=month_label,
                                   prev_month_label=prev_month_label)
            print(f"  Patching {name} activities…")
            html = patch_bd_activities(html, panel_id, bd, month_label)

    # Patch last-updated timestamp
    if generated:
        html = patch_last_updated(html, generated)

    # Fix "AhPNV" typo in any remaining text
    html = html.replace("AhPNV", "AnhPNV")
    html = html.replace("bd-avatar\" style=\"background:#16A34A\">AP",
                        "bd-avatar\" style=\"background:#2563EB\">AP")

    out_path = Path(args.out) if args.out else html_path
    out_path.write_text(html, encoding="utf-8")
    print(f"\n✅ Updated → {out_path}")
    print(f"   Total team revenue: {data['totals']['current_rev_ty']:.2f} tỷ | MoM: {data['totals']['mom_pct']:+.1f}%")


if __name__ == "__main__":
    main()
