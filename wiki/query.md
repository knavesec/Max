## Module: query

For the advanced BloodHound user, experience with Cypher queries required. Allows for running raw Cypher queries and returning the output to the terminal

[Back to Max](https://github.com/knavesec/Max)


#### Notes

* Invalid syntax will return a syntax error and Neo4j debugging instructions  
* Must return node attributes like: `n.name`, `n.description`, `n.owned`, etc (there are many more), or a full path (specified with the path flag)
* `-q/--query` Should be used for a single query to run, returning the output to the command line
* `-f/--file` Should be used for a file containing queries, one per line, meant for mass changes (no output returned per query)
* `path` flag indicates the output is a full path
* `d/delim` Is a flag where a new output delimeter can be set to separate outputs. Default is `output1 - output2` with the "-" being the changable delimeter. Doesn't apply to path outputs
* Unlike other modules, the notes in "Object Files & Specification" do not all apply, any object name must include FQDN but also must be capitalized, just like any query run in the browser
* Main benefit is not having to copy-paste out of the Neo4j browser console


#### Examples

Return all users with a path to DAs
```
python3 max.py query "match (u:User)-[r*1..]->(g:Group) where g.objectid ends with '-512' return u.name"
```

Return amount of computers each user is admin to, and output separated by commas (CSV)
```
python3 max.py query "match (u:User)-[r:MemberOf|AdminTo*1..]->(c:Computer) return u.name,count(c.name) order by count(c.name) desc" -d ","
```

Return the path from Domain Users to Domain Admins
```
python3 max.py query "match p=allShortestPaths((g1:Group {name:'DOMAIN USERS@DOMAIN.LOCAL'})-[*1..]->(g2:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) return p" --path
```

Run queries specified in a file
```
python3 max.py query -f query-file.txt
```
