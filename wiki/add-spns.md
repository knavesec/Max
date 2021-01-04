## Module: add-spns

Adds the HasSPNConfigured relationship to objects in the database. This compromise path is based on the theory that service accounts store their cleartext credentials in LSA secrets and are easily retrieved with the right privileges. A Service Principal Name (SPN) identifies where service accounts are configured, and therefore may indicate that there are stored credentials in LSA secrets. The function creates a relationship based on this relationship: access to a computer could lead to the compromise of that user. In my experience it's accurate roughly 2/3s of the time, though it varies from client to client.

Theory, screenshots and usage can be found in the release blog post: [https://whynotsecurity.com/blog/max2/](https://whynotsecurity.com/blog/max2/)


#### Notes

* These relationships are NOT guaranteed, just sometimes an avenue for escalation
* `-b` flag is the easiest, it will use the SPN information already stored in BH, though it requires that detailed data was ingested (collectionmethod All/ObjectProps)
* `-i` Impacket style is super simple as well, it basically takes the raw input from GetUserSPNs as a file input. No need to edit the file, just `GetUserSPNs > file.txt` -> `max add-spns -i file.txt`
* `-f` More tedious than the previous two, but sometimes necessary. Raw file input of `Computer, User`, one per line, relationship created would be `Computer - HasSPNConfigured -> User`


#### Examples


```
python3 max.py add-spns -b
```

```
GetUserSpns.py domain.local/user:Password > impacket.txt

python3 max.py add-spns -i impacket.txt
```

```
Contents of file.txt
Computer1.domain.local, User1.domain.local
Computer2.domain.local, User2.domain.local
...

python3 max.py add-spns -f file.txt
```
