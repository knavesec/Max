#!/usr/bin/env python3
"""
patch_max.py - DPAT Modern Report
==================================
Modernizes the HTML report output of the DPAT module in knavesec/Max.

INSTALL
-------
1. Copy this file into the same directory as max.py
2. Run it once:

       python3 patch_max.py

3. Run max.py dpat as normal:

       python3 max.py dpat -n ntds.dit -c hashcat.potfile -o outputdir --html --sanitize

No separate CSS file needed - everything is embedded in the generated HTML.

WHAT IT DOES
------------
  - Dark modern theme (Space Grotesk + IBM Plex Mono, GitHub-inspired palette)
  - Stat cards: Total Cracked + %, Domain Admins, Kerberoastable, High Value
  - Sidebar navigation wired to all detail pages
  - Severity pills on every summary row (Critical/High/Medium/Low/None)
  - Section card wrappers with row counts on every detail table
  - Back link on all detail pages
  - Print-friendly stylesheet

UNINSTALL
---------
    cp max.py.bak max.py
"""

import sys, os, shutil, re

TARGET = "max.py"
BACKUP = "max.py.bak"

if not os.path.isfile(TARGET):
    print(f"[!] {TARGET} not found. Run this from the same folder as max.py.")
    sys.exit(1)

with open(TARGET, "r", encoding="utf-8") as f:
    src = f.read()

if "DPAT_PATCHED_CONSOLIDATED" in src:
    print("[*] Already patched. Nothing to do.")
    print(f"    To re-patch, restore backup first:  cp {BACKUP} {TARGET}")
    sys.exit(0)

if "get_html" not in src or "write_html_report" not in src:
    print("[!] This does not look like the expected max.py. Aborting.")
    sys.exit(1)

if not os.path.isfile(BACKUP):
    shutil.copy2(TARGET, BACKUP)
    print(f"[+] Backed up {TARGET} -> {BACKUP}")
else:
    print(f"[~] {BACKUP} already exists - skipping backup")

applied = 0
skipped = 0

def patch(label, old, new):
    global src, applied, skipped
    if old in src:
        src = src.replace(old, new, 1)
        print(f"[+] {label}")
        applied += 1
    else:
        print(f"[~] SKIPPED: {label}")
        skipped += 1

OLD_P1 = 'return "<!DOCTYPE html>\\n" + "<html>\\n<head>\\n<link rel=\'stylesheet\' href=\'report.css\'>\\n</head>\\n" + "<body>\\n" + self.bodyStr  + "</body>\\n" + "</html>\\n"'

NEW_P1 = '# DPAT_PATCHED_CONSOLIDATED\n                import datetime as _dt\n                generated = _dt.datetime.now().strftime(\'%Y-%m-%d %H:%M\')\n                is_summary = getattr(self, \'_is_summary\', False)\n                css = "@import url(\'https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap\');*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}:root{--bg:#0d1117;--surf:#161b22;--surf2:#21262d;--bdr:rgba(48,54,61,1);--bdrf:rgba(48,54,61,.5);--tx:#e6edf3;--mu:#7d8590;--mu2:#545d68;--acc:#f0883e;--grn:#3fb950;--red:#f85149;--blu:#58a6ff;--fn:\'Space Grotesk\',system-ui,sans-serif;--fm:\'IBM Plex Mono\',\'Courier New\',monospace;--r:8px;--rs:4px;}html{font-size:14px;scroll-behavior:smooth}body{background:var(--bg);color:var(--tx);font-family:var(--fn);line-height:1.6;margin:0;padding:0;min-height:100vh}.dpat-bar{font-family:var(--fm);font-size:9px;letter-spacing:2.5px;color:var(--mu2);border-bottom:1px solid var(--bdr);padding:12px 40px;background:var(--bg)}.dpat-hdr{padding:24px 40px 0}.dpat-hdr h1{font-size:24px;font-weight:700;letter-spacing:-.3px;color:var(--tx);margin-bottom:4px}.dpat-meta{font-family:var(--fm);font-size:11px;color:var(--mu);margin-bottom:0;padding-bottom:0}.dpat-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1px;background:var(--bdr);border:1px solid var(--bdr);border-radius:var(--r);overflow:hidden;margin:20px 40px 0}.dpat-stat{background:var(--surf);padding:18px 20px}.dpat-slbl{font-family:var(--fm);font-size:9px;color:var(--mu);text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px}.dpat-sval{font-size:28px;font-weight:700;letter-spacing:-1px;line-height:1}.dpat-ssub{font-family:var(--fm);font-size:10px;color:var(--mu);margin-top:2px}.dpat-sbar{height:3px;background:var(--surf2);border-radius:2px;margin-top:8px;overflow:hidden}.dpat-sfil{height:100%;border-radius:2px}.cr{color:var(--red)}.co{color:var(--acc)}.cg{color:var(--grn)}.cb{color:var(--blu)}.fr{background:var(--red)}.fo{background:var(--acc)}.fg{background:var(--grn)}.fb{background:var(--blu)}.dpat-body{display:flex;min-height:calc(100vh - 200px)}.dpat-side{width:200px;min-width:200px;background:var(--surf);border-right:1px solid var(--bdr);padding:16px 0;flex-shrink:0}.dpat-side-lbl{font-family:var(--fm);font-size:9px;color:var(--mu2);text-transform:uppercase;letter-spacing:.8px;padding:0 16px 10px}.dpat-nav{padding:8px 16px;font-size:12px;color:var(--mu);display:flex;align-items:center;gap:8px;border-left:2px solid transparent;text-decoration:none;cursor:pointer}.dpat-nav:hover{background:var(--surf2);color:var(--tx)}.dpat-nav.active{border-left-color:var(--acc);color:var(--tx);background:var(--surf2)}.dpat-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;background:var(--mu2)}.dpat-dot.r{background:var(--red)}.dpat-dot.o{background:var(--acc)}.dpat-dot.b{background:var(--blu)}.dpat-dot.g{background:var(--grn)}.dpat-main{flex:1;padding:8px 36px 48px;overflow-x:auto}.dpat-sec{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r);margin-top:28px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.35)}.dpat-sec-hd{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;background:var(--surf2);border-bottom:1px solid var(--bdr)}.dpat-sec-ttl{font-size:13px;font-weight:600;color:var(--tx)}.dpat-sec-ct{font-family:var(--fm);font-size:10px;color:var(--mu)}.dpat-tbl-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--surf);display:table;margin:0}thead{background:var(--surf2)}th{font-family:var(--fm);font-size:9px;font-weight:500;color:var(--mu);text-transform:uppercase;letter-spacing:.8px;padding:10px 16px;text-align:left;white-space:nowrap;border-bottom:1px solid var(--bdr);user-select:none;cursor:pointer}th:hover{color:var(--tx)}th.sorttable_sorted::after{content:\' ↑\';color:var(--blu)}th.sorttable_sorted_reverse::after{content:\' ↓\';color:var(--blu)}td{padding:9px 16px;font-family:var(--fm);font-size:11px;color:var(--tx);border-bottom:1px solid var(--bdrf);max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}tr:last-child td{border-bottom:none}tbody tr:hover td{background:rgba(33,38,45,.7)}.pill{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:500;text-transform:uppercase;letter-spacing:.4px;border:1px solid;white-space:nowrap;font-family:var(--fm)}.p-crit{color:#ff7b72;border-color:rgba(218,54,51,.5);background:rgba(218,54,51,.12)}.p-high{color:#ffa657;border-color:rgba(189,86,29,.5);background:rgba(189,86,29,.12)}.p-med{color:#e3b341;border-color:rgba(210,153,34,.5);background:rgba(210,153,34,.12)}.p-low{color:#3fb950;border-color:rgba(35,134,54,.5);background:rgba(35,134,54,.12)}.p-none{color:var(--mu);border-color:var(--bdrf);background:transparent}a,a:visited{color:var(--blu);text-decoration:none;font-family:var(--fm);font-size:10px;padding:2px 9px;border:1px solid rgba(88,166,255,.3);border-radius:var(--rs);background:rgba(88,166,255,.07);white-space:nowrap;transition:background .12s}a:hover{background:rgba(88,166,255,.18);border-color:rgba(88,166,255,.5)}.dpat-back{color:var(--acc)!important;border-color:rgba(240,136,62,.35)!important;background:rgba(240,136,62,.08)!important;font-size:11px;padding:4px 12px;display:inline-block;margin:20px 0 8px}.dpat-back:hover{background:rgba(240,136,62,.18)!important}.dpat-crumb{padding:0 36px}pre{font-family:var(--fm);font-size:11px;line-height:1.55;background:var(--surf);border:1px solid var(--bdr);border-radius:var(--r);padding:18px 22px;color:var(--grn);margin:16px 0;overflow-x:auto;white-space:pre}::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:var(--bg)}::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:3px}::selection{background:rgba(88,166,255,.22)}@media print{:root{--bg:#fff;--surf:#fff;--surf2:#f5f5f5;--bdr:#ccc;--bdrf:#ddd;--tx:#111;--mu:#555;--mu2:#888;--acc:#b85c00;--blu:#0050bb;--grn:#1a7a30;--red:#b03030}.dpat-side{display:none}.dpat-main{padding:0}.dpat-sec{box-shadow:none;border:1px solid #ccc}a{border:none!important;background:none!important;padding:0!important}}"\n                sidebar = "<div class=\'dpat-side\'><div class=\'dpat-side-lbl\'>Sections</div><a class=\'dpat-nav\' href=\'All_User_Accounts_Cracked.html\'><span class=\'dpat-dot r\'></span>All Cracked</a><a class=\'dpat-nav\' href=\'Enabled_User_Accounts_Cracked.html\'><span class=\'dpat-dot r\'></span>Enabled Cracked</a><a class=\'dpat-nav\' href=\'Domain_Admin_Members_Cracked.html\'><span class=\'dpat-dot r\'></span>Domain Admins</a><a class=\'dpat-nav\' href=\'Enterprise_Admin_Accounts_Cracked.html\'><span class=\'dpat-dot r\'></span>Enterprise Admins</a><a class=\'dpat-nav\' href=\'High_Value_User_Accounts_Cracked.html\'><span class=\'dpat-dot r\'></span>High Value</a><a class=\'dpat-nav\' href=\'Kerberoastable_Users_Cracked.html\'><span class=\'dpat-dot o\'></span>Kerberoastable</a><a class=\'dpat-nav\' href=\'Accounts_Not_Requiring_Kerberos_Pre-Authentication_Cracked.html\'><span class=\'dpat-dot o\'></span>AS-REP Roastable</a><a class=\'dpat-nav\' href=\'Unconstrained_Delegation_Accounts_Cracked.html\'><span class=\'dpat-dot o\'></span>Unconstrained Deleg.</a><a class=\'dpat-nav\' href=\'Accounts_With_Passwords_That_Never_Expire_Cracked.html\'><span class=\'dpat-dot o\'></span>Never Expire</a><a class=\'dpat-nav\' href=\'Accounts_With_Passwords_Set_Over_1yr_Ago_Cracked.html\'><span class=\'dpat-dot b\'></span>Password Age</a><a class=\'dpat-nav\' href=\'Password_Reuse_Stats.html\'><span class=\'dpat-dot b\'></span>Reused Passwords</a><a class=\'dpat-nav\' href=\'Accounts_With_Explicit_Admin_Rights_Cracked.html\'><span class=\'dpat-dot b\'></span>Local Admin</a><a class=\'dpat-nav\' href=\'Accounts_With_Paths_To_High_Value_Targets_Cracked.html\'><span class=\'dpat-dot g\'></span>Path to HVT</a><a class=\'dpat-nav\' href=\'Accounts_With_Explicit_Controlling_Privileges_Cracked.html\'><span class=\'dpat-dot g\'></span>Controlling Privs</a></div>"\n                stat_cards = "<div class=\'dpat-stats\'><div class=\'dpat-stat\'><div class=\'dpat-slbl\'>Total Cracked</div><div class=\'dpat-sval cr\' id=\'sv1\'>—</div><div class=\'dpat-ssub\' id=\'ss1\'>of all accounts</div><div class=\'dpat-sbar\'><div class=\'dpat-sfil fr\' id=\'sb1\' style=\'width:0%\'></div></div></div><div class=\'dpat-stat\'><div class=\'dpat-slbl\'>Domain Admins Cracked</div><div class=\'dpat-sval co\' id=\'sv2\'>—</div><div class=\'dpat-ssub\' id=\'ss2\'>loading...</div><div class=\'dpat-sbar\'><div class=\'dpat-sfil fo\' id=\'sb2\' style=\'width:0%\'></div></div></div><div class=\'dpat-stat\'><div class=\'dpat-slbl\'>Kerberoastable Cracked</div><div class=\'dpat-sval co\' id=\'sv3\'>—</div><div class=\'dpat-ssub\' id=\'ss3\'>loading...</div><div class=\'dpat-sbar\'><div class=\'dpat-sfil fo\' id=\'sb3\' style=\'width:0%\'></div></div></div><div class=\'dpat-stat\'><div class=\'dpat-slbl\'>High Value Cracked</div><div class=\'dpat-sval cr\' id=\'sv4\'>—</div><div class=\'dpat-ssub\' id=\'ss4\'>loading...</div><div class=\'dpat-sbar\'><div class=\'dpat-sfil fr\' id=\'sb4\' style=\'width:0%\'></div></div></div></div>"\n                page_js = \'<script>(function(){function dpatToggleTheme(){var d=document.documentElement;var isLight=d.getAttribute(\\\'data-theme\\\')===\\\'light\\\';d.setAttribute(\\\'data-theme\\\',isLight?\\\'dark\\\':\\\'light\\\');var btn=document.getElementById(\\\'theme-btn\\\');if(btn)btn.textContent=isLight?\\\'Light\\\':\\\'Dark\\\';}var IS_SUMMARY=document.body.dataset.summary===\\\'1\\\';if(IS_SUMMARY){function findCount(kw){var rows=document.querySelectorAll(\\\'tbody tr\\\');for(var i=0;i<rows.length;i++){var cells=rows[i].querySelectorAll(\\\'td\\\');if(cells.length>=2&&cells[1].textContent.toLowerCase().indexOf(kw)>=0)return parseInt(cells[0].textContent)||0;}return null;}function setCard(vi,si,bi,v,sub,pct){if(v===null)return;document.getElementById(vi).textContent=v;document.getElementById(si).textContent=sub;document.getElementById(bi).style.width=Math.min(pct,100)+\\\'%\\\';}var c1=findCount(\\\'passwords discovered through cracking\\\');var totalHashes=findCount(\\\'password hashes\\\');var pct1=totalHashes>0?Math.round(c1*100/totalHashes):0;var pct1str=c1+\\\' (\\\'+pct1+\\\'%)\\\';setCard(\\\'sv1\\\',\\\'ss1\\\',\\\'sb1\\\',pct1str,\\\'of all password hashes\\\',pct1);var c2=findCount(\\\'domain admin members cracked\\\');setCard(\\\'sv2\\\',\\\'ss2\\\',\\\'sb2\\\',c2,\\\'domain admin accounts\\\',c2?Math.min(c2*15,100):0);var c3=findCount(\\\'kerberoastable users cracked\\\');setCard(\\\'sv3\\\',\\\'ss3\\\',\\\'sb3\\\',c3,\\\'kerberoastable cracked\\\',c3?Math.min(c3*10,100):0);var c4=findCount(\\\'high value user accounts cracked\\\');setCard(\\\'sv4\\\',\\\'ss4\\\',\\\'sb4\\\',c4,\\\'high value accounts\\\',c4?Math.min(c4*10,100):0);}if(IS_SUMMARY){var thead=document.querySelector(\\\'thead tr\\\');if(thead){var sevTh=document.createElement(\\\'th\\\');sevTh.textContent=\\\'Severity\\\';var ths=thead.querySelectorAll(\\\'th\\\');thead.insertBefore(sevTh,ths[ths.length-1]);}document.querySelectorAll(\\\'tbody tr\\\').forEach(function(row){var cells=row.querySelectorAll(\\\'td\\\');if(cells.length<2)return;var count=parseInt(cells[0].textContent)||0;var lbl=(cells[1].textContent||\\\'\\\').toLowerCase();var sev,cls;if(/domain admin|enterprise admin|schema admin/.test(lbl)){sev=\\\'Critical\\\';cls=\\\'p-crit\\\';}else if(/kerberoast|unconstrained|high value|never expire|path to/.test(lbl)){sev=\\\'High\\\';cls=\\\'p-high\\\';}else if(/local admin|no preauth|lm hash|reused|password age|as-rep|disabled|stale|history|inactive/.test(lbl)){sev=\\\'Medium\\\';cls=\\\'p-med\\\';}else if(count>0){sev=\\\'Low\\\';cls=\\\'p-low\\\';}else{sev=\\\'None\\\';cls=\\\'p-none\\\';}var td=document.createElement(\\\'td\\\');td.innerHTML=\\\'<span class="pill \\\'+cls+\\\'">\\\'+sev+\\\'</span>\\\';row.insertBefore(td,cells[cells.length-1]);});}})();</script>\'\n                if is_summary:\n                    body = (\n                        "<div class=\'dpat-hdr\'><h1>Password Security Report</h1>"\n                        "<div class=\'dpat-meta\'>Generated " + generated + " · BloodHound DPAT</div></div>"\n                        + stat_cards\n                        + "<div class=\'dpat-body\'>" + sidebar\n                        + "<div class=\'dpat-main\'>" + self.bodyStr + "</div></div>"\n                    )\n                    data_attr = \'1\'\n                else:\n                    body = (\n                        "<div class=\'dpat-crumb\'><a class=\'dpat-back\' href=\'Report.html\'>← Back to Report</a></div>"\n                        + "<div class=\'dpat-body\'>" + sidebar\n                        + "<div class=\'dpat-main\'>" + self.bodyStr + "</div></div>"\n                    )\n                    data_attr = \'0\'\n                return (\n                    "<!DOCTYPE html>"\n                    "<html lang=\'en\'>"\n                    "<head>"\n                    "<meta charset=\'utf-8\'>"\n                    "<meta name=\'viewport\' content=\'width=device-width,initial-scale=1\'>"\n                    "<title>DPAT Report</title>"\n                    "<style>" + css + "</style>"\n                    "</head>"\n                    "<body data-summary=\'" + data_attr + "\'>"\n                    "<div class=\'dpat-bar\'>DPAT \xa0//\xa0 DOMAIN PASSWORD AUDIT TOOL \xa0//\xa0 BLOODHOUND INTEGRATION</div>"\n                    + body + page_js\n                    + "</body></html>"\n                )'

patch("Patch 1: modern HTML shell with embedded CSS + JS", OLD_P1, NEW_P1)

_p2_m = re.search(r'( *)hb\.write_html_report\(filebase, filename_report\)', src)
_ind = _p2_m.group(1) if _p2_m else '        '
OLD_P2 = _ind + "hb.write_html_report(filebase, filename_report)"
NEW_P2 = _ind + "hb._is_summary = True\n" + _ind + "hb.write_html_report(filebase, filename_report)"
patch("Patch 2: flag summary page for stat cards", OLD_P2, NEW_P2)

OLD_P3 = '                html += "</table>"\n                self.build_html_body_string(html)'

NEW_P3 = '                html += "</table></div></div>"\n                title_text = headers[0] if headers else ""\n                row_count = len(list) if list else 0\n                section_head = (\n                    "<div class=\'dpat-sec\'>"\n                    "<div class=\'dpat-sec-hd\'>"\n                    "<span class=\'dpat-sec-ttl\'>" + str(title_text) + "</span>"\n                    "<span class=\'dpat-sec-ct\'>" + str(row_count) + " entries</span>"\n                    "</div><div class=\'dpat-tbl-wrap\'>"\n                )\n                html = section_head + html\n                self.build_html_body_string(html)'

patch("Patch 3: wrap tables in section cards with row counts", OLD_P3, NEW_P3)

with open(TARGET, "w", encoding="utf-8") as f:
    f.write(src)

status = "\u2713" if skipped == 0 else "!"
print(f"\n[{status}] Done - {applied} applied, {skipped} skipped.")
if skipped > 0:
    print("    Skipped patches mean max.py has changed upstream.")
    print("    The report will still work - skipped patches are enhancements only.")
print(f"\n    Run max.py dpat ... --html as normal.")
print(f"    No separate report.css needed.\n")
