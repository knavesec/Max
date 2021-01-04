## Module: get-info

Basic module to extract information from the database with easy output to a bash-flow workspace

There are a few things you can extract with this module:
* Users, computers and groups
* Group members
* Computers that a user is administrator to
* Computer to computer administrator rights
* ... and more!


#### Notes

* `users`, `comps`, `groups`, `das`, `dasessions`, `nolaps`, `unconst`, `npusers`, `kerb`, `kerb-la`, `passnotreq`, `owned`, `hvt`  all return simple lists and take no inputs
* `groups-full` returns all domain groups with their respective members in the format `group@domain.local - member_node_name`
* `group-members` returns all AD objects that are members of the input `GROUP`
* `owned-groups` returns a list of owned objects with a list of all groups they are a member of, nice for grepping and targeting
* `desc` returns all objects configured with a description in the format `objectname - description text`
* `admincomps` returns computers that are configured with admin rights for another computer in the format `admincomp.domain.local - victimcomp.domain.local`. Useful for printspooler + relay attacks
* `adminto` returns a all computers `UNAME` is local admin to. Useful for offline cred spraying & dumps
* `adminsof` returns a list of all the users that have administrative privileges to `COMP`
* `sessions` returns a list of all computers that a user has a session on
* `sidhist` returns a list of objects configured with SID History in the format `username - sid - foreign domain - foreign object name (if found)`
* `foreignprivs` returns a list of all cross-domain privileges on the network in the format `object1@domain1 - edgename - object2@domain2`
* `unsupported` returns a list of all machines running unsupported operating systems, with the OS version
* `get-note` returns the notes of each object, typically used with the `add-note` function in the `mark-*` modules
* `-l` apply column labels as a header. All queries with `get-info` do not return column headers (like "UserName","ComputerName","Description",etc) by default with the query
* `-e/--enabled` returns only the enabled users from the applicable query (only working for `--users` and `--passnotreq`)


#### Examples

```
python3 max.py get-info --users

USER1@DOMAIN.LOCAL
...
```

```
python3 max.py get-info --admincomps

COMPUTER1.DOMAIN.LOCAL - COMPUTER2.DOMAIN.LOCAL
...
```

```
python3 max.py get-info --foreignprivs -l

ObjectName - EdgeName - VictimObjectName
COMP1.DOMAIN1.LOCAL - EdgeName - COMP2.DOMAIN2.LOCAL
USER1@DOMAIN2.LOCAL - EdgeName - GROUP1@DOMAIN3.LOCAL
...
```

```
python3 max.py get-info --adminto USER@DOMAIN.LOCAL

COMP1.DOMAIN.LOCAL
COMP2.DOMAIN.LOCAL
...
```

```
python3 max.py get-info --desc

USER1@DOMAIN.LOCAL - This user is super cool
USER3@DOMAIN2.LOCAL - This user's password is Password1!
...
```
