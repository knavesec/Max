## Module: dpat

Module to perform password analytics based off the BloodHound database, an NTDS.dit file, and a password cracking potfile (JTR/hashcat).

A few things that this module will look for:
* Password length & reuse stats
* Accounts with passwords that never expire cracked
* Kerberoastable users cracked
* High value domain group members cracked
* Accounts with paths to unconstrained delegation objects cracked
* ... and more!

This module with full usage details was released in this blog post: [whynotsecurity.com/blog/max3](https://whynotsecurity.com/blog/max3/)

![HTML Output](https://github.com/knavesec/Max/blob/dpat/wiki/screenshots/dpat-htmloutput.png)

![HTML Hashes](https://github.com/knavesec/Max/blob/dpat/wiki/screenshots/dpat-htmlhashes.png)

[Back to Max](https://github.com/knavesec/Max)


#### Notes

* If you already have a parsed and cracked NTDS.dit file, you're ready for the tool. If you haven't, or don't know how to do such, see the "NTDS.dit Extraction & Parsing" section below.
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


#### Output Examples

![HTML Output](https://github.com/knavesec/Max/blob/dpat/wiki/screenshots/dpat-htmloutput.png "HTML Output")
![HTML Output2](https://github.com/knavesec/Max/blob/dpat/wiki/screenshots/dpat-htmlhashes.png "HTML Output2")


#### NTDS.dit Extraction & Parsing

This walkthrough is taken directly from the original DPAT tool, available here: [DPAT](https://github.com/clr2of8/DPAT)

Your customer.ntds file should be in this format:
> domain\username:RID:lmhash:nthash:::

You can get this file by first dumping the password hashes from your domain controller by executing the following command in an administrative command prompt on a domain controller. Just make sure you have enough disk space to store the output in c:\\temp. The amount of space needed will be slightly larger than the size of the ntds.dit file that is currently on the disk, as this performs a backup of that file and some registry settings.

```
ntdsutil "ac in ntds" "ifm" "cr fu c:\temp" q q
```

The ntdsutil command will create the two files, `Active Directory\ntds.dit` and `registry\SYSTEM`, that are needed. You can then turn this output into the format expected by DPAT using [secretsdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py). Secretsdump comes pre-installed on Kali Linux or can be easily installed on Windows using [these instructions](https://medium.com/@airman604/installing-impacket-on-windows-ded7ba8bec9a).

```
secretsdump.py -system registry/SYSTEM -ntds "Active Directory/ntds.dit" LOCAL -outputfile customer
```

If you would like to report on password history, include the `-history` flag as shown below. Note: Jan/2020 Josh Wright reported that the history hashes are not exported correctly on ntds.dit files from Win2K16 TP4 and later. See this [issue](https://github.com/SecureAuthCorp/impacket/issues/656).

```
secretsdump.py -system registry/SYSTEM -ntds "Active Directory/ntds.dit" LOCAL -outputfile customer -history
```

Note: Try using `impacket-secretsdump` instead of `secretsdump.py` on Kali Linux if secrectsdump.py can't be found.

The command above will create a file called "customer.ntds" which you will use with this tool (DPAT) as well as for password cracking. You can now proceed with your password cracking efforts to create a crack file in this format (which is the default output of the Hashcat tool):

>nthash:password

Or for LM Hashes:
>lmhashLeftOrRight:leftOrRightHalfPasswordUpcased

The DPAT tool also supports output from John the Ripper (same format as hashcat.potfile but prepended with $NT$ or $LM$)


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
