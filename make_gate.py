#!/usr/bin/env python3
"""
make_gate.py — Wrap HTML report in a lightweight password gate.

How it works:
  1. Base64-encode the real report HTML (prevents plain-text indexing by crawlers/AI)
  2. Generate SHA-256 hash of the password (never stores plain-text password)
  3. Produce a single gate HTML file: password form → JS hash check → atob() decode → render

Why NOT staticrypt:
  - staticrypt AES-decrypts 380KB of HTML in the browser → very slow / hangs
  - Base64 decode is instantaneous even for large files
  - Security goal: block AI crawlers + require password for casual viewers (not military-grade)

Usage:
    python3 make_gate.py --html index_raw.html --password "zbs2026mkt" --out index.html
    python3 make_gate.py --html index_raw.html --password-env REPORT_PASSWORD --out index.html
"""

import argparse, base64, hashlib, os, sys
from pathlib import Path


# ── SHA-256 of password (hex) ─────────────────────────────────────────────────
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── Gate HTML template ────────────────────────────────────────────────────────
# On correct password: decode base64 → Blob URL → window.location.href navigate.
# This avoids document.write() and iframe sandbox issues entirely.
GATE_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZBS Report — Đăng nhập</title>
<meta http-equiv="cache-control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="pragma" content="no-cache">
<meta http-equiv="expires" content="0">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
html,body{{
  height:100%;
  font-family:-apple-system,'Segoe UI',sans-serif;
  background:#010f2e;
}}
body{{
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;position:relative;overflow:hidden;
}}

/* decorative blobs */
body::before{{
  content:'';position:fixed;right:-120px;top:-120px;
  width:500px;height:500px;border-radius:50%;
  background:radial-gradient(circle,rgba(0,104,255,.22) 0%,transparent 70%);
  pointer-events:none;
}}
body::after{{
  content:'';position:fixed;left:-80px;bottom:-80px;
  width:360px;height:360px;border-radius:50%;
  background:radial-gradient(circle,rgba(55,222,231,.14) 0%,transparent 70%);
  pointer-events:none;
}}

/* card */
.card{{
  width:100%;max-width:400px;margin:24px;
  background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.1);
  border-radius:24px;padding:44px 40px;
  position:relative;z-index:1;
  box-shadow:0 32px 80px rgba(0,0,0,.5);
  backdrop-filter:blur(20px);
}}

/* logo */
.logo-row{{display:flex;align-items:center;gap:12px;margin-bottom:28px}}
.logo-box{{
  width:44px;height:44px;border-radius:12px;
  background:linear-gradient(135deg,#0068FF,#0050cc);
  display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:15px;color:#fff;letter-spacing:-.5px;
  box-shadow:0 0 0 2.5px rgba(55,222,231,.4),0 4px 12px rgba(0,104,255,.4);
  flex-shrink:0;
}}
.logo-text .t1{{font-size:14px;font-weight:700;color:#fff;line-height:1.2}}
.logo-text .t2{{font-size:11px;color:rgba(255,255,255,.4);line-height:1.4}}

/* badge */
.badge{{
  display:inline-flex;align-items:center;gap:5px;
  background:rgba(55,222,231,.1);
  border:1px solid rgba(55,222,231,.25);
  color:#37DEE7;font-size:11px;font-weight:600;
  padding:4px 10px;border-radius:20px;
  margin-bottom:18px;letter-spacing:.3px;
}}
.badge::before{{content:'🔒';font-size:10px}}

h1{{font-size:20px;font-weight:800;color:#fff;margin-bottom:6px;letter-spacing:-.3px}}
.sub{{font-size:13px;color:rgba(255,255,255,.4);margin-bottom:28px;line-height:1.5}}

/* form */
.field-label{{
  font-size:11px;font-weight:700;color:rgba(255,255,255,.45);
  text-transform:uppercase;letter-spacing:.9px;margin-bottom:7px;
}}
.pw-wrap{{position:relative}}
.pw-wrap input{{
  width:100%;
  padding:13px 46px 13px 16px;
  background:rgba(255,255,255,.06);
  border:1.5px solid rgba(255,255,255,.1);
  border-radius:12px;color:#fff;
  font-size:15px;font-family:inherit;
  outline:none;transition:border-color .2s,background .2s;
}}
.pw-wrap input:focus{{
  border-color:rgba(55,222,231,.55);
  background:rgba(255,255,255,.09);
}}
.pw-wrap input::placeholder{{color:rgba(255,255,255,.2)}}
.eye-btn{{
  position:absolute;right:13px;top:50%;transform:translateY(-50%);
  background:none;border:none;cursor:pointer;
  color:rgba(255,255,255,.3);padding:3px;border-radius:4px;
  transition:color .2s;
}}
.eye-btn:hover{{color:rgba(255,255,255,.7)}}

/* remember */
.rem-row{{
  display:flex;align-items:center;gap:8px;
  margin:12px 0 20px;cursor:pointer;
}}
.rem-row input{{accent-color:#37DEE7;width:15px;height:15px;cursor:pointer}}
.rem-row span{{font-size:13px;color:rgba(255,255,255,.4)}}

/* button */
.btn{{
  width:100%;padding:14px;
  background:linear-gradient(135deg,#0068FF 0%,#0055dd 100%);
  border:none;border-radius:12px;
  color:#fff;font-size:15px;font-weight:700;
  font-family:inherit;cursor:pointer;
  box-shadow:0 4px 20px rgba(0,104,255,.45);
  transition:all .18s;display:flex;
  align-items:center;justify-content:center;gap:7px;
}}
.btn:hover:not(:disabled){{
  background:linear-gradient(135deg,#1a76ff 0%,#0068FF 100%);
  box-shadow:0 6px 24px rgba(0,104,255,.55);
  transform:translateY(-1px);
}}
.btn:active{{transform:translateY(0)}}
.btn:disabled{{opacity:.6;cursor:not-allowed}}

/* error */
.err{{
  display:none;margin-top:12px;
  background:rgba(239,68,68,.12);
  border:1px solid rgba(239,68,68,.25);
  border-radius:10px;padding:10px 14px;
  color:#fca5a5;font-size:13px;
}}

/* spinner */
.spin{{
  width:15px;height:15px;
  border:2px solid rgba(255,255,255,.3);
  border-top-color:#fff;border-radius:50%;
  animation:rot .65s linear infinite;
}}
@keyframes rot{{to{{transform:rotate(360deg)}}}}
</style>
</head>
<body>
<div class="card">
  <div class="logo-row">
    <div class="logo-box">ZBS</div>
    <div class="logo-text">
      <div class="t1">Zalo Business Solutions</div>
      <div class="t2">BD & CS Performance Report</div>
    </div>
  </div>

  <div class="badge">W21 · T5/2026 · Nội bộ · v4</div>
  <h1>Xem báo cáo</h1>
  <p class="sub">Nhập mật khẩu để truy cập báo cáo tuần này.</p>

  <form onsubmit="doLogin(event)">
    <div class="field-label">Mật khẩu</div>
    <div class="pw-wrap">
      <input type="password" id="pw" placeholder="Nhập mật khẩu…" autocomplete="current-password" autofocus>
      <button type="button" class="eye-btn" onclick="toggleEye()" id="eye-btn">
        <svg id="eye-svg" width="17" height="17" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
          <circle cx="12" cy="12" r="3"/>
        </svg>
      </button>
    </div>

    <label class="rem-row">
      <input type="checkbox" id="rem" checked>
      <span>Nhớ trong 7 ngày</span>
    </label>

    <button class="btn" type="submit" id="btn">
      <span id="btn-txt">Vào báo cáo</span>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" id="btn-arr">
        <path d="M5 12h14M12 5l7 7-7 7"/>
      </svg>
    </button>

    <div class="err" id="err">❌ Mật khẩu không đúng — vui lòng thử lại.</div>
  </form>
</div>

<script>
const H = '{PWD_HASH}';
const C = '{CONTENT_B64}';
const SK = 'zbs_h', SE = 'zbs_e';

const sha = async s => {{
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
}};

const open = hash => {{
  try{{
    const bytes = Uint8Array.from(atob(C), c=>c.charCodeAt(0));
    const html  = new TextDecoder().decode(bytes);
    // Try Blob URL first, fallback to document.write
    try {{
      const url = URL.createObjectURL(new Blob([html],{{type:'text/html;charset=utf-8'}}));
      window.location.replace(url);
    }} catch(e2) {{
      // Fallback: document.write (works in all browsers)
      document.open(); document.write(html); document.close();
    }}
  }} catch(e) {{ alert('Lỗi: '+e.message); }}
}};

// auto-login
(async()=>{{
  try{{
    const exp = localStorage.getItem(SE);
    if(exp && Date.now()>+exp){{ localStorage.removeItem(SK); localStorage.removeItem(SE); return; }}
    const h = localStorage.getItem(SK)||sessionStorage.getItem(SK);
    if(h===H) open(h);
  }}catch{{}}
}})();

async function doLogin(e){{
  e.preventDefault();
  const pw = document.getElementById('pw').value.trim();
  if(!pw) return;
  const btn=document.getElementById('btn');
  btn.disabled=true;
  document.getElementById('btn-txt').textContent='Đang kiểm tra…';
  document.getElementById('btn-arr').style.display='none';
  btn.insertAdjacentHTML('afterbegin','<span class="spin"></span>');
  document.getElementById('err').style.display='none';

  const h = await sha(pw);
  if(h===H){{
    const rem = document.getElementById('rem').checked;
    if(rem){{ localStorage.setItem(SK,h); localStorage.setItem(SE,Date.now()+7*864e5); }}
    else    sessionStorage.setItem(SK,h);
    open(h);
  }} else {{
    document.getElementById('err').style.display='block';
    btn.disabled=false; btn.querySelector('.spin')?.remove();
    document.getElementById('btn-txt').textContent='Vào báo cáo';
    document.getElementById('btn-arr').style.display='';
    document.getElementById('pw').value='';
    document.getElementById('pw').focus();
  }}
}}

function toggleEye(){{
  const i=document.getElementById('pw');
  i.type = i.type==='password'?'text':'password';
}}
</script>
</body>
</html>
"""


def make_gate(html_content: str, password: str) -> str:
    pwd_hash = sha256_hex(password)
    content_b64 = base64.b64encode(html_content.encode("utf-8")).decode("ascii")
    return GATE_TEMPLATE.replace("{PWD_HASH}", pwd_hash).replace("{CONTENT_B64}", content_b64)


def main():
    ap = argparse.ArgumentParser(description="Wrap HTML in a lightweight password gate")
    ap.add_argument("--html",         required=True,  help="Input HTML file (the real report)")
    ap.add_argument("--out",          required=True,  help="Output gate HTML file")
    ap.add_argument("--password",     default=None,   help="Password (plain text)")
    ap.add_argument("--password-env", default=None,   help="Env var name that holds the password")
    args = ap.parse_args()

    # Resolve password
    if args.password:
        pwd = args.password
    elif args.password_env:
        pwd = os.environ.get(args.password_env, "")
        if not pwd:
            print(f"[ERROR] Env var '{args.password_env}' is not set or empty.", file=sys.stderr)
            sys.exit(1)
    else:
        print("[ERROR] Provide --password or --password-env", file=sys.stderr)
        sys.exit(1)

    html_in  = Path(args.html).read_text(encoding="utf-8")
    gate_out = make_gate(html_in, pwd)
    Path(args.out).write_text(gate_out, encoding="utf-8")

    size_kb = len(gate_out.encode()) / 1024
    print(f"✅ Gate HTML written → {args.out}  ({size_kb:.0f} KB)")
    print(f"   Password hash (SHA-256): {sha256_hex(pwd)[:16]}…")


if __name__ == "__main__":
    main()
