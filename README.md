# Maximizing BloodHound with a simple suite of tools

## Description

New Release:

- [dpat](https://github.com/knavesec/Max/blob/master/wiki/dpat.md) - The BloodHound Domain Password Audit Tool (DPAT)

A simple suite of tools:
- [get-info](https://github.com/knavesec/Max/blob/master/wiki/get-info.md) - Pull lists of information from the Neo4j database
- [mark-owned](https://github.com/knavesec/Max/blob/master/wiki/mark-owned.md) - Mark a list of objects as Owned
- [mark-hvt](https://github.com/knavesec/Max/blob/master/wiki/mark-hvt.md) - Mark a list of objects as High Value Targets
- [query](https://github.com/knavesec/Max/blob/master/wiki/query.md) - Run a raw Cypher query and return output
- [export](https://github.com/knavesec/Max/blob/master/wiki/export.md) - Export all outbound controlling privileges of a domain object to a CSV file
- [del-edge](https://github.com/knavesec/Max/blob/master/wiki/del-edge.md) - Delete an edge from the database
- [add-spns](https://github.com/knavesec/Max/blob/master/wiki/add-spns.md) - Create HasSPNConfigured relationships, new attack primitive
- [add-spw](https://github.com/knavesec/Max/blob/master/wiki/add-spw.md) - Create SharesPasswordWith relationships
- [dpat](https://github.com/knavesec/Max/blob/master/wiki/dpat.md) - The BloodHound Domain Password Audit Tool (DPAT)
- [pet-max](https://github.com/knavesec/Max/blob/master/wiki/pet-max.md) - Dogsay, happiness for stressful engagements

This was released with screenshots & use-cases on the following blogs: [Max Release](https://whynotsecurity.com/blog/max/),  [Updates & Primitives](https://whynotsecurity.com/blog/max2/) & [DPAT](https://whynotsecurity.com/blog/max3/)

A new potential attack primitive was added to this tool during my research, see the `add-spns` section for full details.


## Usage

### Installation

Ideally there shouldn't be much to install, but I've included a requirements.txt file just in case. Tested on Kali Linux & Windows 10, all functionality should work for both linux and Windows operating systems.

`pip3 install -r requirements.txt`

### Neo4j Creds

Neo4j credentials can be hardcoded at the beginning of the script, they can be provided as CLI arguments, or stored as environment variables. If either parameter  is left blank, you will be prompted for the uname/password. To use environment variables, it is probably easiest to add a line (e.g., `export NEO4J_USERNAME='neo4j'`) within *~/.bashrc* or *~/.zshrc*  to store the username since it isn't really sensitive. The database password can be set within your shell's tab prior to running Max. Adding a space before the export command should prevent it from appearing within history.

```bash
 export NEO4J_PASSWORD='bloodhound' # Notice whitespace before 'export'
python3 max.py {module} {args}

```

```
python3 max.py -u neo4j -p neo4j {module} {args}
```

```
python3 max.py {module} {args}
Neo4j Username: neo4j
Neo4j Password:
```

### Quick Use

Getting help in general, and module specific
```
python3 max.py -h
python3 max.py {module} -h
```

Importing owned objects into BH
```
python3 max.py mark-owned -f owned.txt
python3 max.py mark-owned -f owned.txt --add-note "Owned by repeated local admin"
```

Get list of users
```
python3 max.py get-info --users
python3 max.py get-info --users --enabled

USER01@DOMAIN.LOCAL
USER02@DOMAIN.LOCAL
...
```

Get list of objects in a target group
```
python3 max.py get-info --group-members "domain controllers@domain.local"
```

Get a list of computers that a user has administrative rights to
```
python3 max.py get-info --adminto USER01@DOMAIN.LOCAL
```

Get a list of owned objects with the notes for each
```
python3 max.py get-info --owned --get-note
```

Running a query - return a list of all users with a path to DA
```
python3 max.py query -q "MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) MATCH (n)-[*1..]->(m) RETURN DISTINCT(n.name)"
```

Delete an edge from the database
```
python3 max.py del-edge CanRDP
```

Add HasSPNConfigured relationship using the information stored within BloodHound, or with a GetUserSPNs impacket file
```
python3 max.py add-spns -b
python3 max.py add-spns -i getuserspns-raw-output.txt
```

DPAT
```
python3 max.py dpat -n ~/client/ntds.dit -c ~/.hashcat/hashcat.potfile -o ouputdir --html --sanitize
```

Pet max
```
python3 max.py pet-max
```

#### Object Files & Specification

Objects in file, must contain FQDN within, capitalization does not matter. This also applies to whenever a CLI username/computer name is supplied.

```
user01@domain.local      <- will be added / correct CLI input
group01@domain.local     <- will be added / correct CLI input
computer01.domain.local  <- will be added / correct CLI input
ComPutEr01.doMAIn.LOcaL  <- will be added / correct CLI input
user02                   <- will not be added / incorrect CLI input
computer02               <- will not be added / incorrect CLI input
```

## Further work

I hope to include an `analyze` function to provide some sort functionality similar to PlumHound/Cypheroth. Lastly, thinking about creating a Powershell version for those running Neo4j on Windows, but I'm trash at Powershell so TBD.

Any other features and improvements welcome, find me @knavesec in the BloodHoundGang Slack channel and on Twitter


## Contributors

I'd like to especially thank those who have contributed their time to developing & improving this tool:

* [Nic Losby @blurbdust](https://twitter.com/blurbdust) (DPAT Module)
* [Scott Brink @_sandw1ch](https://twitter.com/_sandw1ch) (Various)
