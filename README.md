# Maximizing BloodHound with a simple suite of tools

## Description

A simple suite of tools:
- Pull lists of information from the Neo4j database
- Mark a list of objects as Owned
- Mark a list of objects as High Value Targets

## Usage

#### Quick Use

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

#### Basics

```
python3 max.py -h
usage: max.py [-h] [-u USERNAME] [-p PASSWORD] [--url URL] {get-info,mark-owned,mark-hvt} ...

Maximizing Bloodhound. Max is a good boy.

positional arguments:
  {get-info,mark-owned,mark-hvt}
    get-info            Get info for users, computers, etc
    mark-owned          Mark objects as Owned
    mark-hvt            Mark items as High Value Targets (HVTs)

optional arguments:
  -h, --help            show this help message and exit

Main Arguments:
  -u USERNAME           Neo4j database username (Default: neo4j)
  -p PASSWORD           Neo4j database password (Default: bloodhound)
  --url URL             Neo4j database URL (Default: http://127.0.0.1:7474)
```

#### Neo4j Database

Neo4j credentials can be hardcoded at the beginning of the script OR they can be provided as CLI

#### Mark-* option files

Objects in file must contain FQDN within, capitalization does not matter. This also applies to whenever a CLI username/computer name is supplied.

```
user01@domain.local      <- will be added
group01@domain.local     <- will be added
computer01.domain.local  <- will be added
ComPutEr01.domain.local  <- will be added
user02                   <- will not be added
computer02               <- will not be added
```

## Further work

I hope to include an `analyze` function to provide some sort functionality similar to PlumHound/Cypheroth. TDB

Any other features and improvements welcome, find me @knavesec in the BloodHoundGang Slack channel and on Twitter
