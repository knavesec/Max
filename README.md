# Max: a good boy

## Maximizing BloodHound with a simple suite of tools

### Description

A simple suite of tools:
- Pull lists of information from the Neo4j database
- Mark a list of objects as Owned
- Mark a list of objects as High Value Targets

### Usage

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
