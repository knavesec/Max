# Maximizing BloodHound with a simple suite of tools

## Description

A simple suite of tools:
- Pull lists of information from the Neo4j database
- Mark a list of objects as Owned
- Mark a list of objects as High Value Targets

## Usage

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

Get list of users (apply quiet -q to remove "Username" label)
```
python3 max.py get-info --users

UserName
USER01@DOMAIN.LOCAL
USER02@DOMAIN.LOCAL
...
```

Get a list of computers that a user has administrative rights to
```
python3 max.py get-info --adminto USER01@DOMAIN.LOCAL
```

Get a list of owned objects with the notes for each
```
python3 max.py get-info --owned --get-note
```

### In Depth Usage & Modules

#### General

Getting help in general, and module specific
```
python3 max.py -h
python3 max.py {module} -h
```

There are 3 modules: `get-info`, `mark-owned`, `mark-hvt`

#### Module: get-info

```
python3 max.py get-info -h
usage: max.py get-info [-h] (--users | --comps | --groups | --das | --unconst | --npusers | --adminto UNAME | --adminsof COMP | --owned | --hvt | --desc | --admincomps) [--get-note] [-q]

optional arguments:
  -h, --help       show this help message and exit
  --users          Return a list of all domain users
  --comps          Return a list of all domain computers
  --groups         Return a list of all domain groups
  --das            Return a list of all Domain Admins
  --unconst        Return a list of all objects configured with Unconstrained Delegation
  --npusers        Return a list of all users that don't require Kerberos Pre-Auth (AS-REP roastable)
  --adminto UNAME  Return a list of computers that UNAME is a local administrator to
  --adminsof COMP  Return a list of users that are administrators to COMP
  --owned          Return all objects that are marked as owned
  --hvt            Return all objects that are marked as High Value Targets
  --desc           Return all users with the description field populated (also returns description)
  --admincomps     Return all computers with admin privileges to another computer [Comp1-AdminTo->Comp2]
  --get-note       Return the "notes" attribute for whatever objects are returned
  -q               Quiet mode, suppress column headers from output
```

Few things to note:

* `users`, `comps`, `groups`, `das`, `unconst`, `npusers`, `owned`, `hvt` all return simple lists
* `desc` returns users configured with a description in the format `username@domain.local - description`
* `admincomps` returns computers that are configured with admin rights for another computer in the format `admincomp.domain.local - victimcomp.domain.local`. Useful for relay attacks
* `adminto` returns a all computers `UNAME` is local admin to. Useful for offline cred spraying & dumps
* `adminsof` returns a list of all the users that have administrative privileges to `COMP`
* `get-note` returns the notes of each object, typically used with the `add-note` function in the `mark-*` modules
* `-q` suppresses column headers. All queries with `get-info` return column headers (like "UserName","ComputerName","Description",etc) with the query. If outputting to a file this should be used so the header does not contaminate the first line of your data

#### Module: mark-owned

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

#### Module: mark-hvt

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

I hope to include an `analyze` function to provide some sort functionality similar to PlumHound/Cypheroth. Also hoping to include a `query` function that would allow using custom queries to retrive lists. TBD

Any other features and improvements welcome, find me @knavesec in the BloodHoundGang Slack channel and on Twitter
