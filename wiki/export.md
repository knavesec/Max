## Module: export

This module will export all direct properties of the input node, exporting all the data to an Excel file


#### Notes

* `NODENAME` is requires BloodHound format with the domain attached
* It will output all data to the file `USER_NAME_FULL@DOMAIN.LOCAL.csv`


#### Examples

```
python3 max.py export "Domain users@domain.local"
```
