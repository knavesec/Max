## Module: add-spw

Adds the SharesPasswordWith relationship to objects in the database. Takes a list of objects, then creates bidirectional edges between all objects, indicating a possible pivot path between the objects. Mostly useful for analysis, this was taken from porterhau5's BloodHound-Owned tool.

[Back to Max](https://github.com/knavesec/Max)


#### Notes

* File is simply a list of AD objects, one per line, with the full FQDN attached. Useful for AD user pwd reuse as well as repeated local administrator
* A bidirectional relationship will be created between every single node in that file (unless the node doesn't exist)
* Not super practical for actual tests since you need to know in advance which objects have shared passwords, but nice for analysis to see who now has a path to DA with the relationship applied


#### Examples


```
Contents of file.txt
Computer1.domain.local
Computer2.domain.local
...

python3 max.py add-spw -f file.txt
```
