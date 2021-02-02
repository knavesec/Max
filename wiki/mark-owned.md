## Module: mark-owned

Bulk import of owned assets into the database

[Back to Max](https://github.com/knavesec/Max)


#### Notes

* `--clear` will set the 'owned' attribute to false for every object
* `--add-note` will set a note on all object, it's found in the BloodHound GUI. This can also be retrieved via the `--get-notes` flag in the `get-info` module
* `FILENAME` contents must include FQDN similar to the naming style of BloodHound objects. For more info see the "Object Files & Specification" section of the overall readme


#### Examples

```
python3 max.py mark-owned -f object-list.txt
```

```
python3 max.py mark-owned -f object-list.txt --add-note "owned via repeated local admin"
```

```
python3 max.py mark-owned --clear
```
