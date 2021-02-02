## Module: del-edge

Module for deleting an edge type from the database (warning: irreversible)

[Back to Max](https://github.com/knavesec/Max)


#### Notes

* `EDGENAME` is CaseSensitive
* This is not reversible, it will delete all edges of this type from the database. Re-importing the BH data will put the relationships back


#### Examples

```
python3 max.py del-edge CanRDP
```
