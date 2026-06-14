# Max - BloodHound CE Edition Wiki

Welcome to the Max-BloodHound-CE wiki! This fork extends the original Max toolkit with enhanced password auditing and a modern HTML reporting interface.

## Fork Attribution

This project is based on:
- **[DPAT](https://github.com/clr2of8/DPAT)** by clr2of8 - Original Domain Password Audit Tool
- **[Max](https://github.com/knavesec/Max)** by knavesec - BloodHound extension toolkit

## Modules

### Password Auditing
- **[dpat](dpat.md)** - Domain Password Audit Tool - The main module for password analysis with HTML reporting

### Information Gathering
- **[get-info](get-info.md)** - Extract information from BloodHound (users, groups, paths, etc.)
- **[query](query.md)** - Run custom Cypher queries against BloodHound
- **[export](export.md)** - Export BloodHound data

### Marking & Tagging
- **[mark-owned](mark-owned.md)** - Mark objects as owned in BloodHound
- **[mark-hvt](mark-hvt.md)** - Mark high value targets

### Relationship Management
- **[add-spns](add-spns.md)** - Add SPN relationships
- **[add-spw](add-spw.md)** - Add "shares password with" relationships
- **[del-edge](del-edge.md)** - Delete edges from the graph

### Fun
- **[pet-max](pet-max.md)** - Pet the good boy!

## Quick Start

```bash
# Clone the repository
git clone https://github.com/exploit-development/Max-BloodHound-CE.git
cd Max-BloodHound-CE

# Install dependencies
pip3 install -r requirements.txt

# Set Neo4j password
export NEO4J_PASSWORD='your-password'

# Generate a password audit report
python3 max.py dpat -n customer.ntds -c hashcat.potfile
```

## Key Features of This Fork

### Enhanced DPAT Module
- Single-file portable HTML reports (Windows 2008 ADUC style)
- Password reuse detection for ALL hashes (not just cracked)
- Blank password detection
- LM hash cracking improvements
- Unsupported OS detection with Windows 11 fix
- Builtin Administrators group fix for BloodHound CE
- Interactive clickable reports with user detail pages
- Group membership ranking
- Highest risk weights for groups
- Built-in CSV export on every table
- Summary statistics page

See the [dpat documentation](dpat.md) for full details.
