## Module: query

For the advanced BloodHound user, experience with Cypher queries required. Allows for running raw Cypher queries and returning the output to the terminal


#### Notes

* Invalid syntax will return a syntax error and Neo4j debugging instructions  
* Must return node attributes like: `n.name`, `n.description`, `n.owned`, etc (there are many more)
* Unlike other modules, the notes in "Object Files & Specification" do not all apply, any object name must include FQDN but also must be capitalized, just like any query run in the browser
* Main benefit is not having to copy-paste out of the Neo4j browser console


#### Examples

Return all users with a path to DAs
```
python3 max.py query "match (u:User)-[r*1..]->(g:Group) where g.objectid ends with '-512' return u.name"
```

Return amount of computers each user is admin to
```
python3 max.py query "match (u:User)-[r:MemberOf|AdminTo*1..]->(c:Computer) return u.name,count(c.name) order by count(c.name) desc"
```
