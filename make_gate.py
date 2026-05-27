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
GATE_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZBS BD & CS Report — Đăng nhập</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap');
*{{margin:0;padding:0;box-sizing:border-box}}
body{{
  font-family:'Nunito',-apple-system,sans-serif;
  background:#021C48;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  overflow:hidden;
  position:relative;
}}
body::before{{
  content:'';position:absolute;right:-80px;top:-80px;
  width:400px;height:400px;border-radius:50%;
  background:rgba(0,104,255,0.15);pointer-events:none;
}}
body::after{{
  content:'';position:absolute;left:-60px;bottom:-60px;
  width:280px;height:280px;border-radius:50%;
  background:rgba(55,222,231,0.1);pointer-events:none;
}}
.card{{
  background:rgba(255,255,255,0.04);
  border:1px solid rgba(255,255,255,0.1);
  border-radius:20px;
  padding:48px 44px;
  width:100%;max-width:420px;
  position:relative;z-index:1;
  backdrop-filter:blur(12px);
  box-shadow:0 24px 64px rgba(0,0,0,0.4);
}}
.logo-row{{display:flex;align-items:center;gap:14px;margin-bottom:32px}}
.logo{{
  width:48px;height:48px;
  background:#0068FF;border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  font-weight:800;font-size:18px;color:#fff;
  box-shadow:0 0 0 3px rgba(55,222,231,0.3);
  flex-shrink:0;
}}
.brand{{}}
.brand-name{{font-size:16px;font-weight:700;color:#fff}}
.brand-sub{{font-size:12px;color:rgba(255,255,255,0.45)}}
h1{{
  font-size:22px;font-weight:800;color:#fff;
  margin-bottom:6px;
}}
.desc{{
  font-size:13px;color:rgba(255,255,255,0.45);
  margin-bottom:28px;line-height:1.5;
}}
label{{
  display:block;font-size:12px;font-weight:700;
  color:rgba(255,255,255,0.5);text-transform:uppercase;
  letter-spacing:.8px;margin-bottom:8px;
}}
.input-wrap{{position:relative;margin-bottom:8px}}
input[type=password]{{
  width:100%;padding:12px 44px 12px 16px;
  background:rgba(255,255,255,0.07);
  border:1.5px solid rgba(255,255,255,0.12);
  border-radius:10px;color:#fff;
  font-size:15px;font-family:inherit;outline:none;
  transition:border-color .2s;
}}
input[type=password]:focus{{border-color:rgba(55,222,231,0.6);}}
input[type=password]::placeholder{{color:rgba(255,255,255,0.25)}}
.toggle-pw{{
  position:absolute;right:12px;top:50%;transform:translateY(-50%);
  background:none;border:none;cursor:pointer;
  color:rgba(255,255,255,0.35);padding:4px;
}}
.toggle-pw:hover{{color:rgba(255,255,255,0.7)}}
.remember-row{{
  display:flex;align-items:center;gap:8px;
  margin-bottom:22px;margin-top:10px;
}}
.remember-row input[type=checkbox]{{
  width:16px;height:16px;accent-color:#37DEE7;cursor:pointer;
}}
.remember-row label{{
  font-size:13px;color:rgba(255,255,255,0.5);
  text-transform:none;letter-spacing:0;margin:0;cursor:pointer;
}}
.btn{{
  width:100%;padding:13px;
  background:linear-gradient(135deg,#0068FF,#0050CC);
  border:none;border-radius:10px;
  color:#fff;font-size:15px;font-weight:700;
  font-family:inherit;cursor:pointer;
  transition:all .2s;position:relative;
  box-shadow:0 4px 16px rgba(0,104,255,0.4);
}}
.btn:hover{{background:linear-gradient(135deg,#1a78ff,#0060dd);transform:translateY(-1px)}}
.btn:active{{transform:translateY(0)}}
.btn:disabled{{opacity:0.6;cursor:not-allowed;transform:none}}
.error{{
  background:rgba(220,38,38,0.15);
  border:1px solid rgba(220,38,38,0.3);
  color:#FCA5A5;font-size:13px;
  padding:10px 14px;border-radius:8px;
  margin-top:12px;display:none;
}}
.spinner{{
  display:inline-block;width:16px;height:16px;
  border:2.5px solid rgba(255,255,255,0.3);
  border-top-color:#fff;border-radius:50%;
  animation:spin .7s linear infinite;
  margin-right:6px;vertical-align:middle;
}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.week-tag{{
  display:inline-block;
  background:rgba(55,222,231,0.15);
  color:#37DEE7;
  border:1px solid rgba(55,222,231,0.3);
  font-size:11px;font-weight:700;
  padding:3px 10px;border-radius:12px;
  margin-bottom:20px;letter-spacing:.5px;
}}
</style>
</head>
<body>
<div class="card">
  <div class="logo-row">
    <div class="logo">ZBS</div>
    <div class="brand">
      <div class="brand-name">Zalo Business Solutions</div>
      <div class="brand-sub">BD & CS Performance Report</div>
    </div>
  </div>
  <div class="week-tag">W21 · T5/2026 · Internal</div>
  <h1>Xem báo cáo</h1>
  <p class="desc">Báo cáo nội bộ — vui lòng nhập mật khẩu để tiếp tục.</p>

  <form id="gate-form" onsubmit="checkPassword(event)">
    <label for="pw">Mật khẩu</label>
    <div class="input-wrap">
      <input type="password" id="pw" placeholder="Nhập mật khẩu…" autocomplete="current-password" autofocus>
      <button type="button" class="toggle-pw" onclick="togglePw()" title="Hiện/ẩn mật khẩu">
        <svg id="eye-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
      </button>
    </div>
    <div class="remember-row">
      <input type="checkbox" id="remember" checked>
      <label for="remember">Nhớ trong 7 ngày</label>
    </div>
    <button class="btn" type="submit" id="submit-btn">Vào báo cáo →</button>
    <div class="error" id="err-msg">❌ Mật khẩu không đúng. Vui lòng thử lại.</div>
  </form>
</div>

<script>
const PWD_HASH = '{PWD_HASH}';
const STORE_KEY = 'zbs_report_auth';
const STORE_EXP = 'zbs_report_exp';
const CONTENT   = '{CONTENT_B64}';

async function sha256(str) {{
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}}

function renderReport() {{
  // atob() returns Latin-1 bytes; use TextDecoder to handle UTF-8 correctly
  const bytes = Uint8Array.from(atob(CONTENT), c => c.charCodeAt(0));
  const html = new TextDecoder('utf-8').decode(bytes);
  document.open(); document.write(html); document.close();
}}

// Auto-login from storage
(function() {{
  try {{
    const exp = localStorage.getItem(STORE_EXP);
    if (exp && Date.now() > parseInt(exp)) {{
      localStorage.removeItem(STORE_KEY);
      localStorage.removeItem(STORE_EXP);
      return;
    }}
    const stored = localStorage.getItem(STORE_KEY) || sessionStorage.getItem(STORE_KEY);
    if (stored === PWD_HASH) {{ renderReport(); }}
  }} catch(e) {{}}
}})();

async function checkPassword(e) {{
  e.preventDefault();
  const pw = document.getElementById('pw').value;
  if (!pw) return;

  const btn = document.getElementById('submit-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Đang kiểm tra…';
  document.getElementById('err-msg').style.display = 'none';

  const hash = await sha256(pw);
  if (hash === PWD_HASH) {{
    const remember = document.getElementById('remember').checked;
    if (remember) {{
      localStorage.setItem(STORE_KEY, hash);
      localStorage.setItem(STORE_EXP, Date.now() + 7*24*60*60*1000);
    }} else {{
      sessionStorage.setItem(STORE_KEY, hash);
    }}
    renderReport();
  }} else {{
    document.getElementById('err-msg').style.display = 'block';
    btn.disabled = false;
    btn.innerHTML = 'Vào báo cáo →';
    document.getElementById('pw').value = '';
    document.getElementById('pw').focus();
  }}
}}

function togglePw() {{
  const input = document.getElementById('pw');
  input.type = input.type === 'password' ? 'text' : 'password';
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
