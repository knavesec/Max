#!/usr/bin/env python3
"""
populate_test_data.py
=====================
Populates Neo4j with a synthetic CORP.LOCAL domain and generates
matching ntds.dit (secretsdump format) and hashcat.pot files.

Run from the Max directory:
    python3 populate_test_data.py

Generates:
    test_data/corp.ntds      - secretsdump format NTDS
    test_data/hashcat.pot    - hashcat potfile (cracked passwords)

Then run DPAT:
    python3 max.py dpat -u neo4j -p bloodhoundcommunityedition \
        -n test_data/corp.ntds -c test_data/hashcat.pot \
        -o test_data/report --html
"""

import requests
import json
import os
import hashlib
import struct
import random

NEO4J_URL  = "http://127.0.0.1:7474"
NEO4J_URI  = "/db/neo4j/tx/commit"
NEO4J_USER = "neo4j"
NEO4J_PASS = "bloodhoundcommunityedition"
DOMAIN     = "CORP.LOCAL"
DOMAIN_SID = "S-1-5-21-3580580-1234567890-987654321"

OUTPUT_DIR  = "test_data"
NTDS_FILE   = os.path.join(OUTPUT_DIR, "corp.ntds")
POT_FILE    = os.path.join(OUTPUT_DIR, "hashcat.pot")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Neo4j helpers ─────────────────────────────────────────────────

def run(query, params=None):
    data = {"statements": [{"statement": query, "parameters": params or {}}]}
    r = requests.post(
        NEO4J_URL + NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASS),
        headers={"Content-Type": "application/json"},
        json=data,
        timeout=30
    )
    resp = r.json()
    if resp.get("errors"):
        print(f"  [!] Query error: {resp['errors']}")
    return resp

def run_many(queries):
    data = {"statements": [{"statement": q} for q in queries]}
    r = requests.post(
        NEO4J_URL + NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASS),
        headers={"Content-Type": "application/json"},
        json=data,
        timeout=30
    )
    return r.json()

# ── NT hash helper ────────────────────────────────────────────────

def nt_hash(password):
    return hashlib.new("md4", password.encode("utf-16-le")).hexdigest().upper()

# ── Clear existing data ───────────────────────────────────────────

print("[*] Clearing existing data...")
run("MATCH (n) DETACH DELETE n")
print("[+] Database cleared")

# ══════════════════════════════════════════════════════════════════
# DOMAIN DATA DEFINITIONS
# ══════════════════════════════════════════════════════════════════

# Passwords — some will be "cracked" (in the pot file)
PASSWORDS = {
    # cracked passwords
    "Password1":    "cracked",
    "Welcome1":     "cracked",
    "Summer2023!":  "cracked",
    "Winter2024!":  "cracked",
    "Company1!":    "cracked",
    "P@ssw0rd":     "cracked",
    "Monday1!":     "cracked",
    "Football1":    "cracked",
    "Letmein1!":    "cracked",
    "Admin123!":    "cracked",
    "Service123":   "cracked",
    "Changeme1!":   "cracked",
    # uncracked — NT hash only, no pot entry
    "Xk9#mP2$vQ8@": "uncracked",
    "Ry7!nL4$wZ3#": "uncracked",
    "Qj6@kM8!xV5%": "uncracked",
    "Tz5#pN9@yW2!": "uncracked",
    "Bv3!rK7#uX4$": "uncracked",
}

# Users: (username, password, flags)
# flags: spn, nopreauthreq, neverexpire, admincount, enabled
USERS = [
    # ── Domain Admins (2 cracked, rest uncracked) ──
    ("administrator",    "Admin123!",    dict(spn=False, nopre=False, neverexp=True,  admincount=True,  enabled=True)),
    ("da_jsmith",        "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=True,  enabled=True)),
    ("da_bjones",        "Xk9#mP2$vQ8@",dict(spn=False, nopre=False, neverexp=False, admincount=True,  enabled=True)),
    ("da_mwilliams",     "Ry7!nL4$wZ3#",dict(spn=False, nopre=False, neverexp=False, admincount=True,  enabled=True)),

    # ── Enterprise Admins (1 cracked) ──
    ("ea_rdavis",        "Welcome1",     dict(spn=False, nopre=False, neverexp=False, admincount=True,  enabled=True)),
    ("ea_tnguyen",       "Qj6@kM8!xV5%",dict(spn=False, nopre=False, neverexp=False, admincount=True,  enabled=True)),

    # ── Schema Admins (1 cracked) ──
    ("schema_admin",     "Summer2023!",  dict(spn=False, nopre=False, neverexp=True,  admincount=True,  enabled=True)),

    # ── Kerberoastable (3 cracked) ──
    ("svc_sql",          "Service123",   dict(spn=True,  nopre=False, neverexp=True,  admincount=False, enabled=True)),
    ("svc_web",          "Service123",   dict(spn=True,  nopre=False, neverexp=True,  admincount=False, enabled=True)),
    ("svc_backup",       "Bv3!rK7#uX4$",dict(spn=True,  nopre=False, neverexp=True,  admincount=False, enabled=True)),
    ("svc_monitor",      "Tz5#pN9@yW2!",dict(spn=True,  nopre=False, neverexp=True,  admincount=False, enabled=True)),

    # ── AS-REP Roastable (2 cracked) ──
    ("asrep_user1",      "Password1",    dict(spn=False, nopre=True,  neverexp=False, admincount=False, enabled=True)),
    ("asrep_user2",      "Welcome1",     dict(spn=False, nopre=True,  neverexp=False, admincount=False, enabled=True)),
    ("asrep_user3",      "Xk9#mP2$vQ8@",dict(spn=False, nopre=True,  neverexp=False, admincount=False, enabled=True)),

    # ── High Value targets (3 cracked) ──
    ("hv_ceo",           "Company1!",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("hv_cfo",           "Winter2024!",  dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("hv_ciso",          "Ry7!nL4$wZ3#",dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Never-expire passwords (mix of cracked/uncracked) ──
    ("neverexp_user1",   "Password1",    dict(spn=False, nopre=False, neverexp=True,  admincount=False, enabled=True)),
    ("neverexp_user2",   "Monday1!",     dict(spn=False, nopre=False, neverexp=True,  admincount=False, enabled=True)),
    ("neverexp_user3",   "Xk9#mP2$vQ8@",dict(spn=False, nopre=False, neverexp=True,  admincount=False, enabled=True)),
    ("neverexp_user4",   "Qj6@kM8!xV5%",dict(spn=False, nopre=False, neverexp=True,  admincount=False, enabled=True)),

    # ── Reused passwords (Password1 shared by many) ──
    ("reuse_user1",      "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("reuse_user2",      "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("reuse_user3",      "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("reuse_user4",      "Welcome1",     dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("reuse_user5",      "Welcome1",     dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Inactive accounts (cracked) ──
    ("inactive_user1",   "Football1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("inactive_user2",   "Letmein1!",   dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Old passwords > 1yr (cracked) ──
    ("oldpwd_user1",     "P@ssw0rd",     dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("oldpwd_user2",     "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("oldpwd_user3",     "Changeme1!",   dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Local admin rights (cracked) ──
    ("localadmin_user1", "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("localadmin_user2", "Monday1!",     dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Controlling privileges (cracked) ──
    ("ctrl_user1",       "Admin123!",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("ctrl_user2",       "Ry7!nL4$wZ3#",dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Disabled accounts (cracked) ──
    ("disabled_user1",   "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=False)),
    ("disabled_user2",   "Welcome1",     dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=False)),

    # ── Path to HVT (cracked) ──
    ("pathvht_user1",    "Summer2023!",  dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("pathvht_user2",    "Company1!",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Unconstrained delegation (cracked) ──
    ("uncon_user1",      "Winter2024!",  dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),

    # ── Regular users (mix) ──
    ("user_asmith",      "Password1",    dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("user_bjohnson",    "Welcome1",     dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("user_cwilson",     "Xk9#mP2$vQ8@",dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("user_dtaylor",     "Ry7!nL4$wZ3#",dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
    ("user_emartinez",   "Qj6@kM8!xV5%",dict(spn=False, nopre=False, neverexp=False, admincount=False, enabled=True)),
]

# Groups
GROUPS = [
    ("Domain Admins",      f"{DOMAIN_SID}-512", True),
    ("Enterprise Admins",  f"{DOMAIN_SID}-519", True),
    ("Schema Admins",      f"{DOMAIN_SID}-518", True),
    ("Domain Controllers", f"{DOMAIN_SID}-516", True),
    ("Domain Users",       f"{DOMAIN_SID}-513", False),
    ("IT Admins",          f"{DOMAIN_SID}-1100",False),
    ("Help Desk",          f"{DOMAIN_SID}-1101",False),
    ("Finance",            f"{DOMAIN_SID}-1102",False),
]

# Computers
COMPUTERS = [
    ("DC01",        True,  True),   # name, isdc, unconstraineddelegation
    ("DC02",        True,  True),
    ("WEB01",       False, False),
    ("SQL01",       False, False),
    ("WORKST01",    False, False),
    ("WORKST02",    False, False),
    ("WORKST03",    False, False),
]

# ══════════════════════════════════════════════════════════════════
# CREATE DOMAIN NODE
# ══════════════════════════════════════════════════════════════════
print("[*] Creating domain...")
run(f"""
CREATE (:Domain {{
    name: '{DOMAIN}',
    objectid: '{DOMAIN_SID}',
    highvalue: true
}})
""")
print("[+] Domain created")

# ══════════════════════════════════════════════════════════════════
# CREATE GROUPS
# ══════════════════════════════════════════════════════════════════
print("[*] Creating groups...")
for gname, goid, hv in GROUPS:
    run(f"""
    CREATE (:Group {{
        name: '{gname}@{DOMAIN}',
        objectid: '{goid}',
        highvalue: {str(hv).lower()},
        domain: '{DOMAIN}'
    }})
    """)
print(f"[+] {len(GROUPS)} groups created")

# ══════════════════════════════════════════════════════════════════
# CREATE USERS
# ══════════════════════════════════════════════════════════════════
print("[*] Creating users...")
import time
now = int(time.time())
one_year_ago = now - (366 * 86400)
two_years_ago = now - (730 * 86400)
six_months_ago = now - (183 * 86400)

for i, (uname, pwd, flags) in enumerate(USERS):
    uid = f"{DOMAIN_SID}-{2000+i}"
    fqname = f"{uname.upper()}@{DOMAIN}"
    ntds_name = f"{DOMAIN}\\{uname}"

    # Set pwdlastset: old password users get >1yr ago, inactive get >6mo ago
    if "oldpwd" in uname:
        pwdlastset = two_years_ago
    elif "inactive" in uname:
        pwdlastset = two_years_ago
    else:
        pwdlastset = now - random.randint(1, 180) * 86400

    # lastlogon: inactive users haven't logged in for >6 months
    if "inactive" in uname:
        lastlogon = two_years_ago
    else:
        lastlogon = now - random.randint(1, 30) * 86400

    nh = nt_hash(pwd)
    is_cracked = PASSWORDS[pwd] == 'cracked'

    run(
        "CREATE (:User {"
        "name: $name, objectid: $objectid, domain: $domain, "
        "enabled: $enabled, hasspn: $hasspn, dontreqpreauth: $dontreqpreauth, "
        "pwdneverexpires: $pwdneverexpires, admincount: $admincount, "
        "highvalue: false, pwdlastset: $pwdlastset, lastlogon: $lastlogon, "
        "lastlogontimestamp: $lastlogontimestamp, ntds_uname: $ntds_uname, "
        "nt_hash: $nt_hash, cracked: $cracked, password: $password})",
        {
            "name":               fqname,
            "objectid":           uid,
            "domain":             DOMAIN,
            "enabled":            flags['enabled'],
            "hasspn":             flags['spn'],
            "dontreqpreauth":     flags['nopre'],
            "pwdneverexpires":    flags['neverexp'],
            "admincount":         flags['admincount'],
            "pwdlastset":         pwdlastset,
            "lastlogon":          lastlogon,
            "lastlogontimestamp": lastlogon,
            "ntds_uname":         ntds_name,
            "nt_hash":            nh,
            "cracked":            is_cracked,
            "password":           pwd if is_cracked else None,
        }
    )

print(f"[+] {len(USERS)} users created")

# ══════════════════════════════════════════════════════════════════
# CREATE COMPUTERS
# ══════════════════════════════════════════════════════════════════
print("[*] Creating computers...")
for i, (cname, isdc, uncon) in enumerate(COMPUTERS):
    cid = f"{DOMAIN_SID}-{3000+i}"
    run(f"""
    CREATE (:Computer {{
        name: '{cname}.{DOMAIN}',
        objectid: '{cid}',
        domain: '{DOMAIN}',
        enabled: true,
        unconstraineddelegation: {str(uncon).lower()},
        highvalue: {str(isdc).lower()},
        haslaps: false
    }})
    """)
print(f"[+] {len(COMPUTERS)} computers created")

# ══════════════════════════════════════════════════════════════════
# GROUP MEMBERSHIPS
# ══════════════════════════════════════════════════════════════════
print("[*] Creating group memberships...")

memberships = [
    # Domain Admins
    ("DA_JSMITH",       "Domain Admins"),
    ("DA_BJONES",       "Domain Admins"),
    ("DA_MWILLIAMS",    "Domain Admins"),
    ("ADMINISTRATOR",   "Domain Admins"),
    # Enterprise Admins
    ("EA_RDAVIS",       "Enterprise Admins"),
    ("EA_TNGUYEN",      "Enterprise Admins"),
    # Schema Admins
    ("SCHEMA_ADMIN",    "Schema Admins"),
    # IT Admins
    ("LOCALADMIN_USER1","IT Admins"),
    ("LOCALADMIN_USER2","IT Admins"),
    ("CTRL_USER1",      "IT Admins"),
    # Finance (high value group)
    ("HV_CFO",          "Finance"),
    ("HV_CEO",          "Finance"),
]

for uname, gname in memberships:
    run(f"""
    MATCH (u:User {{name: '{uname}@{DOMAIN}'}})
    MATCH (g:Group {{name: '{gname}@{DOMAIN}'}})
    CREATE (u)-[:MemberOf]->(g)
    """)

# Domain Controllers group membership
for cname, isdc, _ in COMPUTERS:
    if isdc:
        run(f"""
        MATCH (c:Computer {{name: '{cname}.{DOMAIN}'}})
        MATCH (g:Group {{name: 'Domain Controllers@{DOMAIN}'}})
        CREATE (c)-[:MemberOf]->(g)
        """)

# All users → Domain Users
for uname, _, _ in USERS:
    run(f"""
    MATCH (u:User {{name: '{uname.upper()}@{DOMAIN}'}})
    MATCH (g:Group {{name: 'Domain Users@{DOMAIN}'}})
    CREATE (u)-[:MemberOf]->(g)
    """)

print("[+] Group memberships created")

# ══════════════════════════════════════════════════════════════════
# HIGH VALUE TARGETS
# ══════════════════════════════════════════════════════════════════
print("[*] Setting high value targets...")
hvt_users = ["HV_CEO", "HV_CFO", "HV_CISO"]
for u in hvt_users:
    run(f"""
    MATCH (u:User {{name: '{u}@{DOMAIN}'}})
    SET u.highvalue = true
    """)
# DCs are already highvalue
print("[+] High value targets set")

# ══════════════════════════════════════════════════════════════════
# EDGES: AdminTo (local admin rights)
# ══════════════════════════════════════════════════════════════════
print("[*] Creating AdminTo edges...")
admin_edges = [
    ("LOCALADMIN_USER1", "WORKST01"),
    ("LOCALADMIN_USER1", "WORKST02"),
    ("LOCALADMIN_USER2", "WORKST03"),
    ("CTRL_USER1",       "SQL01"),
    ("DA_JSMITH",        "DC01"),
    ("DA_BJONES",        "DC01"),
    ("DA_BJONES",        "DC02"),
    ("ADMINISTRATOR",    "DC01"),
    ("ADMINISTRATOR",    "DC02"),
]
for uname, cname in admin_edges:
    run(f"""
    MATCH (u:User {{name: '{uname}@{DOMAIN}'}})
    MATCH (c:Computer {{name: '{cname}.{DOMAIN}'}})
    CREATE (u)-[:AdminTo]->(c)
    """)
print("[+] AdminTo edges created")

# ══════════════════════════════════════════════════════════════════
# EDGES: Paths to HVTs
# ══════════════════════════════════════════════════════════════════
print("[*] Creating paths to HVTs...")
# GenericAll on a high value user = path to HVT
run(f"""
MATCH (u:User {{name: 'PATHVHT_USER1@{DOMAIN}'}})
MATCH (t:User {{name: 'HV_CEO@{DOMAIN}'}})
CREATE (u)-[:GenericAll]->(t)
""")
run(f"""
MATCH (u:User {{name: 'PATHVHT_USER2@{DOMAIN}'}})
MATCH (t:User {{name: 'HV_CFO@{DOMAIN}'}})
CREATE (u)-[:GenericAll]->(t)
""")
# Also give pathvht_user1 a path via group membership to DA
run(f"""
MATCH (u:User {{name: 'PATHVHT_USER1@{DOMAIN}'}})
MATCH (g:Group {{name: 'IT Admins@{DOMAIN}'}})
CREATE (u)-[:MemberOf]->(g)
""")
print("[+] HVT paths created")

# ══════════════════════════════════════════════════════════════════
# EDGES: Controlling privileges (WriteDACL, Owns, etc.)
# ══════════════════════════════════════════════════════════════════
print("[*] Creating controlling privilege edges...")
run(f"""
MATCH (u:User {{name: 'CTRL_USER1@{DOMAIN}'}})
MATCH (t:User {{name: 'DA_JSMITH@{DOMAIN}'}})
CREATE (u)-[:WriteDACL]->(t)
""")
run(f"""
MATCH (u:User {{name: 'CTRL_USER2@{DOMAIN}'}})
MATCH (t:Group {{name: 'Domain Admins@{DOMAIN}'}})
CREATE (u)-[:Owns]->(t)
""")
print("[+] Controlling privilege edges created")

# ══════════════════════════════════════════════════════════════════
# EDGES: Unconstrained delegation paths
# ══════════════════════════════════════════════════════════════════
print("[*] Creating unconstrained delegation paths...")
run(f"""
MATCH (u:User {{name: 'UNCON_USER1@{DOMAIN}'}})
MATCH (c:Computer {{name: 'DC01.{DOMAIN}'}})
CREATE (u)-[:AdminTo]->(c)
""")
print("[+] Unconstrained delegation paths created")

# ══════════════════════════════════════════════════════════════════
# GENERATE NTDS FILE (secretsdump format)
# ══════════════════════════════════════════════════════════════════
# Format: DOMAIN\username:RID:LMhash:NThash:::
print("[*] Generating NTDS file...")

LM_EMPTY = "aad3b435b51404eeaad3b435b51404ee"  # empty LM hash

ntds_lines = []
for i, (uname, pwd, flags) in enumerate(USERS):
    rid = 2000 + i
    nh = nt_hash(pwd)
    ntds_name = f"{DOMAIN}\\{uname}"
    ntds_lines.append(f"{ntds_name}:{rid}:{LM_EMPTY}:{nh}:::")

# Add some computer accounts
for i, (cname, _, _) in enumerate(COMPUTERS):
    rid = 3000 + i
    ntds_lines.append(f"{DOMAIN}\\{cname}$:{rid}:{LM_EMPTY}:{nt_hash('ComputerPass' + str(i))}:::")

with open(NTDS_FILE, "w") as f:
    f.write("\n".join(ntds_lines) + "\n")

print(f"[+] NTDS file written: {NTDS_FILE} ({len(ntds_lines)} entries)")

# ══════════════════════════════════════════════════════════════════
# GENERATE HASHCAT POT FILE
# ══════════════════════════════════════════════════════════════════
# Format: NThash:password
print("[*] Generating hashcat pot file...")

# Collect unique cracked passwords
cracked_hashes = {}
for uname, pwd, flags in USERS:
    if PASSWORDS[pwd] == "cracked":
        h = nt_hash(pwd)
        cracked_hashes[h] = pwd

pot_lines = [f"{h}:{pwd}" for h, pwd in cracked_hashes.items()]

with open(POT_FILE, "w") as f:
    f.write("\n".join(pot_lines) + "\n")

print(f"[+] Pot file written: {POT_FILE} ({len(pot_lines)} cracked hashes)")

# ══════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════
total = len(USERS)
cracked = sum(1 for _, pwd, _ in USERS if PASSWORDS[pwd] == "cracked")
enabled = sum(1 for _, _, f in USERS if f["enabled"])

print(f"""
[✓] Test data ready!

    Domain:    {DOMAIN}
    Users:     {total} total, {enabled} enabled
    Cracked:   {cracked} ({cracked*100//total}%)
    NTDS:      {NTDS_FILE}
    Pot file:  {POT_FILE}

    Sections populated:
      ✓ Domain Admins cracked (2 of 4)
      ✓ Enterprise Admins cracked (1 of 2)
      ✓ Schema Admins cracked (1 of 1)
      ✓ Kerberoastable cracked (2 of 4)
      ✓ AS-REP Roastable cracked (2 of 3)
      ✓ High Value cracked (2 of 3)
      ✓ Never-expire passwords cracked
      ✓ Password reuse (Password1 x5, Welcome1 x3)
      ✓ Inactive accounts cracked
      ✓ Old passwords (>1yr) cracked
      ✓ Local admin rights cracked
      ✓ Controlling privileges cracked
      ✓ Paths to HVTs cracked
      ✓ Unconstrained delegation paths cracked
      ✓ Disabled accounts cracked

    Now run DPAT (unpatched first for comparison):

    python3 max.py -u neo4j -p bloodhoundcommunityedition dpat \\
        -n {NTDS_FILE} -c {POT_FILE} \\
        -o test_data/report_before --html
""")
