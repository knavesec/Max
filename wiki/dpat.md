## Module: dpat

Module to perform password analytics based off the BloodHound database, an NTDS.dit file, and a password cracking potfile (JTR/hashcat).

A few things that this module will look for:
* Password length & reuse stats
* Accounts with passwords that never expire cracked
* Kerberoastable users cracked
* High value domain group members cracked
* Accounts with paths to unconstrained delegation objects cracked
* ... and more!


#### Notes

* If you already have a parsed and cracked NTDS.dit file, you're ready for the tool. If you haven't, or don't know how to do such, see the original DPAT tool: https://github.com/clr2of8/DPAT. These tools are very similar, but the Max version interacts with BloodHound and doesn't require manually retrieving domain group members.
* If your AD environment contains a high level of objects (>50-75k), some of these queries may take a long time, consider using the `--less` flag to eliminate high-intensity queries

* This function uploads usernames/hashes/passwords to the BloodHound database, then uses Cypher queries to perfom analytics. Afterwards it will cleanse the data
* The `--store` flag will make sure the parsed data stays in the database after completion, if the data is already stored then you can use the `--noparse` flag to skip the initial parsing and mapping phase
* The `--clear` flag will remove all independently
* The `--less` flag won't run intensive queries
* The `--sanitize` flag will make sure all passwords and hashes are partially obfuscated
* The `-o/--outputfile` will specify where the output file/s are written, for the `--html` flag the output will be a directory with all the files, for the `--csv` flag it will be a single filename
* The `--threads` flag will increase the amount of threads used in NTDS & Potfile parsing, as well as mapping the users to the BloodHound database. It will not impact the queries/stats themselves
* If you're looking for a specific user's password, you can search using the `-u/--username` flag and inputting the username in either BloodHound format (`user@domain.local`) or NTDS format (`domain.local/user`). This is best used with the `--noparse` option when things are already stored in the DB
* If you're looking for all accounts using a certain password, you can search using the `-e/--password` flag and inputting the target password. Again, best used with the `--noparse` flag with info already stored


#### Examples

```
python3 max.py dpat -p ~/.hashcat/hashcat.potfile -n ./ntds.dit --sanitize

<Function output>
<Ascii password analysis output>
```

```
python3 max.py dpat --noparse -o outputdir --html

<Function output>
<Html files written to outputdir/ >
```

```
*after already having stored the hash information in BH

python3 max.py dpat --noparse

<Function output>
<Ascii password analysis output>
```

```
python3 max.py dpat --noparse --password Fall2020

[+] Searching for users with password Fall2020
[+] Users: 1

USER1@DOMAIN.LOCAL
```

```
python3 max.py dpat --noparse --username USER1@DOMAIN.LOCAL

[+] Searching for password for user USER1@DOMAIN.LOCAL
[+] Password for user USER1@DOMAIN.LOCAL: Fall2020
```


#### Output Examples

![HTML Output](https://github.com/knavesec/Max/blob/dpat/wiki/screenshots/dpat-htmloutput.png "HTML Output")
![HTML Output2](https://github.com/knavesec/Max/blob/dpat/wiki/screenshots/dpat-html-hashes.png "HTML Output2")
