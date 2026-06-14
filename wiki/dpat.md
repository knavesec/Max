## Module: dpat

The BloodHound Domain Password Audit Tool. Performs comprehensive password analytics using the BloodHound CE database, an NTDS.dit file, and a password cracking potfile (Hashcat/JTR).

### Fork Attribution

This module is based on:
- **[DPAT](https://github.com/clr2of8/DPAT)** by clr2of8 - Original Domain Password Audit Tool
- **[Max](https://github.com/knavesec/Max)** by knavesec - BloodHound extension toolkit

### What This Module Analyzes

* Password length distribution & statistics
* Password reuse across ALL accounts (cracked and uncracked)
* Blank password detection
* Default AD complexity compliance
* Accounts with passwords that never expire (cracked)
* Kerberoastable users (cracked)
* High value domain group members (cracked)
* Domain Admins, Enterprise Admins, Builtin Administrators (cracked)
* Accounts with paths to unconstrained delegation objects (cracked)
* Accounts with paths to high value targets (cracked)
* Unsupported/End-of-Life operating systems
* Group membership ranking (users by number of groups)
* ... and more!

### New Features in This Fork

#### Enhanced Password Analysis
- **Password Reuse Detection** - Shows ALL shared password hashes, not just cracked passwords
- **Blank Password Detection** - Identifies accounts with empty passwords (NT hash `31d6cfe0d16ae931b73c59d7e0c089c0`)
- **LM Hash Support** - Improved LM hash cracking support in potfiles (credit: aidanstansfield)
- **Default Complexity Check** - Shows if passwords meet the 3-of-4 AD complexity rule
- **Weighted Risk Groups** - "Highest Risk Groups" uses weighted scoring (`cracked_users × percentage`) rather than just percentage. This ensures large compromised groups rank higher than tiny groups with 100% cracked

#### BloodHound CE Fixes
- **Builtin Administrators Group** - Fixed detection with new collector's domain name appending
- **Unsupported OS Detection** - Finds EOL Windows systems with Windows 11 false positive fix

#### New HTML Report
A single-file, self-contained HTML report styled after Windows Server 2008 ADUC:

- **Portable** - All assets embedded, no external files needed
- **Interactive** - Clickable stats, charts, usernames, and groups
- **User Details** - Click any user to see groups, password info, and password sharing
- **Group Membership Ranking** - Users sorted by group count
- **Search & Export** - Filter tables and export to CSV
- **Browser Navigation** - Back/forward buttons work via URL hash

[Back to Max-BloodHound-CE](../README.md) | [Original Max](https://github.com/knavesec/Max)

---

### Quick Start

```bash
# Set Neo4j password
export NEO4J_PASSWORD='your-password'

# Generate report (auto-opens in browser)
python3 max.py dpat -n customer.ntds -c hashcat.potfile
```

That's it! The HTML report is generated automatically.

---

### Command Line Options

| Flag | Description |
|------|-------------|
| `-n, --ntds` | NTDS file name (secretsdump format) |
| `-c, --crackfile` | Potfile of cracked passwords (Hashcat/JTR format) |
| `-o, --output` | Output base name for HTML report (default: report) |
| `-t, --threads` | Number of threads for parsing (default: 2) |
| `-s, --sanitize` | Partially redact passwords and hashes in report |
| `-S, --store` | Keep parsed data in BloodHound database after completion |
| `--noparse` | Skip parsing, use data already stored in BloodHound |
| `--clear` | Remove all NTDS/password data from BloodHound database |
| `--less` | Skip intensive queries (for large environments >50-75k objects) |
| `-p, --password` | Search for all users with a specific password |
| `-u, --username` | Look up password for a specific user |
| `--own-cracked` | Mark all cracked users as "Owned" in BloodHound |
| `--add-crack-note` | Add a note to cracked users |

---

### Output

The tool generates a single HTML report (`report_YYYYMMDD_HHMM.html`) styled after Windows Server 2008 ADUC:

- Full interactive drill-down capability
- All raw data and statistics
- Clickable usernames, groups, and charts
- CSV export on every table
- Contains everything needed (CSS, JS, icons embedded as base64)

The report auto-opens in your browser.

---

### Notes

* If you already have a parsed and cracked NTDS.dit file, you're ready for the tool. See "NTDS.dit Extraction & Parsing" below if needed.
* For large AD environments (>50-75k objects), use the `--less` flag to skip intensive queries
* The tool uploads data to BloodHound, runs queries, then cleanses the data (unless `--store` is used)
* The `-c/--crackfile` expects Hashcat/JTR potfile format: `nthash:password` or `lmhash:password`
* Use `--store` to keep data in the database, then `--noparse` on subsequent runs to skip parsing
* Search for specific users (`-u`) or passwords (`-p`) works best with `--noparse` when data is already stored

---

### NTDS.dit Extraction & Parsing

This walkthrough is from the original [DPAT](https://github.com/clr2of8/DPAT) tool.

Your NTDS file should be in this format:
```
domain\username:RID:lmhash:nthash:::
```

#### Step 1: Dump from Domain Controller

Execute in an administrative command prompt on a domain controller:

```cmd
ntdsutil "ac in ntds" "ifm" "cr fu c:\temp" q q
```

This creates `Active Directory\ntds.dit` and `registry\SYSTEM`.

#### Step 2: Extract with secretsdump

```bash
secretsdump.py -system registry/SYSTEM -ntds "Active Directory/ntds.dit" LOCAL -outputfile customer
```

For password history (note: may have issues on Win2K16 TP4+):
```bash
secretsdump.py -system registry/SYSTEM -ntds "Active Directory/ntds.dit" LOCAL -outputfile customer -history
```

On Kali Linux, try `impacket-secretsdump` if `secretsdump.py` isn't found.

#### Step 3: Crack the Hashes

Use Hashcat or John the Ripper to crack the hashes. The potfile format should be:
```
nthash:password
```

Or for LM hashes:
```
lmhash:PASSWORD
```

---

### Examples

**Basic usage - generate HTML report:**
```bash
python3 max.py dpat -n customer.ntds -c hashcat.potfile
```

**Custom output name:**
```bash
python3 max.py dpat -n customer.ntds -c hashcat.potfile -o audit_results
# Creates: audit_results_20240115_1430.html
```

**Sanitized report (redacted passwords/hashes):**
```bash
python3 max.py dpat -n customer.ntds -c hashcat.potfile --sanitize
```

**Large environment (skip intensive queries):**
```bash
python3 max.py dpat -n customer.ntds -c hashcat.potfile --less
```

**Store data for later analysis:**
```bash
# First run - parse and store
python3 max.py dpat -n customer.ntds -c hashcat.potfile --store

# Later runs - skip parsing
python3 max.py dpat --noparse
```

**Search for specific password:**
```bash
python3 max.py dpat --noparse -p "Summer2024!"
```

**Look up user's password:**
```bash
python3 max.py dpat --noparse -u "admin@domain.local"
```

**Mark cracked users as owned:**
```bash
python3 max.py dpat -n customer.ntds -c hashcat.potfile --own-cracked
```

---

### Report Sections

The HTML report includes these sections:

#### Overview
- Summary statistics with clickable links to detail pages
- Password length distribution chart
- Password age distribution chart
- Top groups by cracked percentage chart
- Password complexity breakdown chart
- Password reuse severity chart

#### Password Stats
- LM Hashes (Non-Blank)
- Users with Username Matching Password
- Password Length Stats
- Password Complexity Stats
- Password Reuse Stats (with drill-down to see all users per hash)

#### All Groups
- Groups ranked by cracked percentage
- Click any group to see all members with their password status

#### All Accounts
- All User Accounts
- All User Accounts Cracked
- Enabled User Accounts Cracked

#### Privileged Accounts
- High Value User Accounts
- Domain Admin Members
- Enterprise Admin Members
- Administrator Group Members
- Group Membership Ranking (users by number of groups)

#### Escalation Paths
- Kerberoastable Users Cracked
- Accounts Not Requiring Kerberos Pre-Authentication Cracked
- Unconstrained Delegation Accounts Cracked
- Inactive Accounts Cracked
- Accounts With Passwords Set Over 1yr Ago Cracked
- Accounts With Passwords That Never Expire Cracked
- Various path-based attack vectors

#### Infrastructure Risk
- Unsupported Operating Systems (EOL Windows)

#### User Details (click any username)
- Enabled/Disabled status
- Cracked status
- Password length
- Password (if cracked, with blank password indicator)
- Default Complexity Met (Yes/No)
- NT Hash
- LM Hash (if non-blank)
- Group Memberships (clickable)
- Shares Password With (other users with same hash)
