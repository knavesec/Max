
# Maximizing BloodHound with a simple suite of tools

## Description

A simple suite of tools:
- [get-info](#module-get-info) - Pull lists of information from the Neo4j database
- [mark-owned](#module-mark-owned) - Mark a list of objects as Owned
- [mark-hvt](#module-mark-hvt) - Mark a list of objects as High Value Targets
- [query](#module-query) - Run a raw Cypher query and return output
- [del-edge](#module-del-edge) - Delete an edge from the database
- [add-spns](#module-add-spns) - Create HasSPNConfigured relationships
- [add-spw](#module-add-spw) - Create SharesPasswordWith relationships
- [pet-max](#module-pet-max) - Dogsay, happiness for stressful engagements

This was released with screenshots & use-cases on the following blogs: https://whynotsecurity.com/blog/max/ & https://whynotsecurity.com/blog/max2/

A new potential attack primitive was added to this tool during my research, see the `add-spns` section for full details.

## Usage

### Installation

Ideally there shouldn't be much to install, it uses pythons standard libraries. You may have to `pip3 install` a library or two if you don't have it. Tested on Kali linux.

### Neo4j Creds

Neo4j credentials can be hardcoded at the beginning of the script *OR* they can be provided as CLI

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
python3 max.py query "MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) MATCH (n)-[*1..]->(m) RETURN DISTINCT(n.name)"
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

Pet max
```
python3 max.py pet-max
```

### In Depth Usage & Modules

#### General

Getting help in general, and module specific
```
python3 max.py -h
python3 max.py {module} -h
```

There are 8 modules: `get-info`, `mark-owned`, `mark-hvt`, `query`, `del-edge`, `add-spns`, `add-spw`, `pet-max`

#### Module: get-info

Basic module to extract information from the database with easy output to a bash-flow workspace

```
usage: max.py get-info [-h]
                       (--users | --comps | --groups | --groups-full | --group-members GROUPMEMS | --das | --dasessions | --nolaps | --unconst | --npusers | --passnotreq | --sidhist | --unsupported | --sessions UNAMESESS | --adminto UNAMEADMINTO | --adminsof COMP | --owned | --owned-groups | --hvt | --desc | --admincomps)
                       [--get-note] [-l]

optional arguments:
  -h, --help            show this help message and exit
  --users               Return a list of all domain users
  --comps               Return a list of all domain computers
  --groups              Return a list of all domain groups
  --groups-full         Return a list of all domain groups with all respective group members
  --group-members GROUPMEMS
                        Return a list of all members of an input GROUP
  --das                 Return a list of all Domain Admins
  --dasessions          Return a list of Domain Admin sessions
  --nolaps              Return a list of all computers without LAPS
  --unconst             Return a list of all objects configured with Unconstrained Delegation
  --npusers             Return a list of all users that don't require Kerberos Pre-Auth (AS-REP roastable)
  --passnotreq          Return a list of all users that have PasswordNotRequired flag set to true
  --sidhist             Return a list of objects configured with SID History
  --unsupported         Return a list of computers running an unsupported OS
  --sessions UNAMESESS  Return a list of computers that UNAME has a session on
  --adminto UNAMEADMINTO
                        Return a list of computers that UNAME is a local administrator to
  --adminsof COMP       Return a list of users that are administrators to COMP
  --owned               Return all objects that are marked as owned
  --owned-groups        Return groups of all owned objects
  --hvt                 Return all objects that are marked as High Value Targets
  --desc                Return all objects with the description field populated, also returns description for easy grepping
  --admincomps          Return all computers with admin privileges to another computer [Comp1-AdminTo->Comp2]
  --get-note            Optional, return the "notes" attribute for whatever objects are returned
  -l                    Optional, apply labels to the columns returned
```

Few things to note:

* `users`, `comps`, `groups`, `das`, `unconst`, `npusers`, `passnotreq`, `owned`, `hvt`, `nolaps`, `dasessions` all return simple lists
* `groups-full` returns all domain groups with their respective members in the format `group@domain.local - member_node_name`
* `group-members` returns all AD objects that are members of the input `GROUP`
* `owned-groups` returns a list of owned objects with a list of all groups they are a member of, nice for grepping and targeting
* `desc` returns all objects configured with a description in the format `objectname - description text`
* `admincomps` returns computers that are configured with admin rights for another computer in the format `admincomp.domain.local - victimcomp.domain.local`. Useful for printspooler + relay attacks
* `adminto` returns a all computers `UNAME` is local admin to. Useful for offline cred spraying & dumps
* `adminsof` returns a list of all the users that have administrative privileges to `COMP`
* `sessions` returns a list of all computers that a user has a session on
* `sidhist` returns a list of objects configured with SID History in the format `username - sid - foreign domain - foreign object name (if found)`
* `unsupported` returns a list of all machines running unsupported operating systems, with the OS version
* `get-note` returns the notes of each object, typically used with the `add-note` function in the `mark-*` modules
* `-l` apply column labels as a header. All queries with `get-info` do not return column headers (like "UserName","ComputerName","Description",etc) by default with the query

#### Module: mark-owned

Bulk import of owned assets into the database

```
python3 max.py mark-owned -h
usage: max.py mark-owned [-h] [-f FILENAME] [--add-note NOTES] [--clear]

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        Filename containing AD objects (must have FQDN attached)
  --add-note NOTES      Notes to add to all marked objects (method of compromise)
  --clear               Removed owned marker from all objects
```

Few things to note:

* `clear` will set the 'owned' attribute to false for every object
* `add-note` will set a note on all object, it's found in the BloodHound GUI. This can also be retrieved via the `get-notes` flag in the `get-info` module
* `FILENAME` contents must include FQDN similar to the naming style of BloodHound objects. For more info see the "Object Files & Specification" section

Query being run: ```MATCH (n) WHERE n.name="uname" SET n.owned=true RETURN n```

#### Module: mark-hvt

Bulk import of high value targets into the database

```
python3 max.py mark-hvt -h
usage: max.py mark-hvt [-h] [-f FILENAME] [--add-note NOTES] [--clear]

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        Filename containing AD objects (must have FQDN attached)
  --add-note NOTES      Notes to add to all marked objects (reason for HVT status)
  --clear               Remove HVT marker from all objects
```

Few things to note:

* `clear` will set the 'highvalue' attribute to false for every object
* `add-note` will set a note on all object, it's found in the BloodHound GUI. This can also be retrieved via the `get-notes` flag in the `get-info` module
* `FILENAME` contents must include FQDN similar to the naming style of BloodHound objects. For more info see the "Object Files & Specification" section

Query being run: ```MATCH (n) WHERE n.name="uname" SET n.highvalue=true RETURN n```

#### Module: query

For the advanced BloodHound user, experience with Cypher queries required. Allows for running raw Cypher queries and returning the output to the terminal

```
python3 max.py query -h
usage: max.py query [-h] QUERY

positional arguments:
  QUERY       Query designation

optional arguments:
  -h, --help  show this help message and exit
```

Few things to note:

* Invalid syntax will return a syntax error and Neo4j debugging instructions  
* Must return node attributes like: `n.name`, `n.description`, `n.owned`, etc (there are many more)
* Unlike other modules, the notes in "Object Files & Specification" do not all apply, any object name must include FQDN but also must be capitalized, just like any query run in the browser
* Main benefit is not having to copy-paste out of the Neo4j browser console

#### Module: del-edge

Module for deleting an edge type from the database (warning: irreversible)

```
python3 max.py del-edge -h
usage: max.py del-edge [-h] EDGENAME

positional arguments:
  EDGENAME    Edge name, example: CanRDP, ExecuteDCOM, etc

optional arguments:
  -h, --help  show this help message and exit
```

Few things to note:
* `EDGENAME` is CaseSensitive
* This is not reversible, it will delete all edges of this type from the database. Re-importing the BH data will put the relationships back

Query being run: ```MATCH p=()-[r:{edge}]->() DELETE r RETURN COUNT(DISTINCT(p))```

#### Module: add-spns

Adds the HasSPNConfigured relationship to objects in the database. This compromise path is based on the theory that service accounts store their cleartext credentials in LSA secrets and are easily retrieved with the right privileges. A Service Principal Name (SPN) identifies where service accounts are configured, and therefore may indicate that there are stored credentials in LSA secrets. The function creates a relationship based on this relationship: access to a computer could lead to the compromise of that user. In my experience it's accurate roughly 2/3s of the time, though it varies from client to client.

```
python3 max.py add-spns -h
usage: max.py add-spns [-h] (-b | -f FILENAME | -i IFILENAME)

optional arguments:
  -h, --help            show this help message and exit
  -b, --bloodhound      Uses information already stored in BloodHound (must have already ingested 'Detailed' user information)
  -f FILENAME, --file FILENAME
                        Standard file Format: Computer, User
  -i IFILENAME, --impacket IFILENAME
                        Impacket file Format: Output of GetUserSPNs.py
```

Few things to note:
* These relationships are NOT guaranteed, just sometimes an avenue for escalation
* `-b` flag is the easiest, it will use the SPN information already stored in BH, though it requires that detailed data was ingested (collectionmethod All/ObjectProps)
* `-i` Impacket style is super simple as well, it basically takes the raw input from GetUserSPNs as a file input. No need to edit the file, just `GetUserSPNs > file.txt` -> `max add-spns -i file.txt`
* `-f` More tedious than the previous two, but sometimes necessary. Raw file input of `Computer, User`, one per line, relationship created would be `Computer - HasSPNConfigured -> User`

Query being run: ```MATCH (n:User {name:"uname"}) MATCH (m:Computer {name:"comp"}}) MERGE (m)-[r:HasSPNConfigured {isacl: false}]->(n) RETURN n,m```

#### Module: add-spw

Adds the SharesPasswordWith relationship to objects in the database. Takes a list of objects, then creates bidirectional edges between all objects, indicating a possible pivot path between the objects. Mostly useful for analysis, this was taken from porterhau5's BloodHound-Owned tool.

```
python3 max.py add-spw -h
usage: max.py add-spw [-h] [-f FILENAME]

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        Filename containing AD objects, one per line (must have FQDN attached)
```

Few things to note:
* File is simply a list of AD objects, one per line, with the full FQDN attached. Useful for AD user pwd reuse as well as repeated local administrator
* A bidirectional relationship will be created between every single node in that file (unless the node doesn't exist)
* Not super practical for actual tests since you need to know in advance which objects have shared passwords, but nice for analysis to see who now has a path to DA with the relationship applied

Query being run: ```MATCH (n {name:"name1"}),(m {name:"name2"}) MERGE (n)-[r1:SharesPasswordWith {isacl: false}]->(m) MERGE (m)-[r2:SharesPasswordWith {isacl: false}]->(n) RETURN n,m```

#### Module: pet-max

"Arguably the most important contribution to this project" - me

Basically dogsay, he says things and spreads happiness.

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
