## Module: mark-hvt

Bulk import of HVT objects into the database


#### Notes

* `--clear` will set the 'highvalue' attribute to false for every object (including those set by default, be careful)
* `--add-note` will set a note on all object, it's found in the BloodHound GUI. This can also be retrieved via the `--get-notes` flag in the `get-info` module
* `FILENAME` contents must include FQDN similar to the naming style of BloodHound objects. For more info see the "Object Files & Specification" section of the overall readme


#### Examples

```
python3 max.py mark-hvt -f object-list.txt
```

```
python3 max.py mark-hvt -f object-list.txt --add-note "PCI assets"
```

```
python3 max.py mark-hvt --clear
```
