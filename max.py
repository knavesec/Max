#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
import argparse
import json
import random
import csv
import binascii
import math
import os
import multiprocessing
import webbrowser
import getpass
import datetime
try:
    import html as htmllib
except ImportError:
    import cgi as htmllib
from itertools import zip_longest


# option to hardcode URL & URI or put them in environment variables, these will be used for neo4j database "default" location
global_url = "http://127.0.0.1:7474" if (not os.environ.get('NEO4J_URL', False)) else os.environ['NEO4J_URL']
global_uri = "/db/neo4j/tx/commit" if (not os.environ.get('NEO4J_URI', False)) else os.environ['NEO4J_URI']

# option to hardcode creds or put them in environment variables, these will be used as the username and password "defaults"
global_username = 'neo4j' if (not os.environ.get('NEO4J_USERNAME', False)) else os.environ['NEO4J_USERNAME']
global_password = 'bloodhound' if (not os.environ.get('NEO4J_PASSWORD', False)) else os.environ['NEO4J_PASSWORD'] 

def do_test(args):

    try:
        requests.get(args.url + global_uri)
        return True
    except:
        return False


def do_query(args, query, data_format=None):

    data_format = [data_format, "row"][data_format == None]
    data = {
        "statements" : [
            {
                "statement" : query,
                "resultDataContents" : [ data_format ]
            }
        ]
    }
    headers = {'Content-type': 'application/json', 'Accept': 'application/json; charset=UTF-8'}
    auth = HTTPBasicAuth(args.username, args.password)

    r = requests.post(args.url + global_uri, auth=auth, headers=headers, json=data)

    if r.status_code == 401:
        print("Authentication error: the supplied credentials are incorrect for the Neo4j database, specify new credentials with -u & -p or hardcode your credentials at the top of the script")
        exit()
    elif r.status_code >= 300:
        print("Failed to retrieve data. Server returned status code: {}".format(r.status_code))
        exit()
    else:
        return r


def get_query_output(entry,delimeter,cols_len=None,path=False):

    if path:
        try:
            nodes = entry['graph']['nodes']
            edges = entry['graph']['relationships']
            node_end_list = []
            node_dict = {}
            edge_dict = {}

            for node in nodes:
                node_dict[node['id']] = node['properties']['name']

            for edge in edges:
                edge_dict[node_dict[edge['startNode']]] = ["-", edge['type'], "->", node_dict[edge['endNode']]]
                node_end_list.append(node_dict[edge['endNode']])

            for key in edge_dict.keys():
                if key not in node_end_list:
                    first_node = key

            path = [first_node]
            key = first_node
            while key in edge_dict:

                for item in edge_dict[key]:
                    path.append(item)
                key = path[len(path)-1]

            return " ".join(path)
        except:
            return "Path not found :("
    else:
        try:
            return " {} ".format(delimeter).join(entry["row"])
        except:
            if cols_len == 1:
                pass
            else:
                return " {} ".format(delimeter).join(map(str,entry["row"]))


def get_info(args):

    # key : {query: "", columns: []}
    queries = {
        "users" : {
            "query" : "MATCH (u:User) {enabled} RETURN u.name",
            "columns" : ["UserName"]
        },
        "comps" : {
            "query" : "MATCH (n:Computer) RETURN n.name",
            "columns" : ["ComputerName"]
        },
        "groups" : {
            "query" : "MATCH (n:Group) RETURN n.name",
            "columns" : ["GroupName"]
        },
        "group-members" : {
            "query" : "MATCH (g:Group {{name:\"{gname}\"}}) MATCH (n)-[r:MemberOf*1..]->(g) RETURN DISTINCT n.name",
            "columns" : ["ObjectName"]
        },
        "group-list" : {
            "query" : "MATCH (u {{name:\"{uname}\"}}) MATCH (u)-[r:MemberOf*1..]->(g:Group) RETURN DISTINCT g.name",
            "columns" : ["GroupName"]
        },
        "groups-full" : {
            "query" : "MATCH (n),(g:Group) MATCH (n)-[r:MemberOf]->(g) RETURN DISTINCT g.name,n.name",
            "columns" : ["GroupName","MemberName"]
        },
        "das" : {
            "query" : "MATCH (n:User)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN DISTINCT n.name",
            "columns" : ["UserName"]
        },
        "dasess" : {
            "query" : "MATCH (u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' WITH COLLECT(u) AS das MATCH (u2:User)<-[r2:HasSession]-(c:Computer) WHERE u2 IN das RETURN DISTINCT u2.name,c.name ORDER BY u2.name",
            "columns" : ["UserName","ComputerName"]
        },
        "dcs" : {
            "query" : "MATCH (n:Computer)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' RETURN DISTINCT n.name",
            "columns" : ["ComputerName"]
        },
        "unconstrained" : {
            "query" : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-516' MATCH (c:Computer)-[MemberOf]->(g) WITH COLLECT(c) AS dcs MATCH (n {unconstraineddelegation:true}) WHERE NOT n IN dcs RETURN n.name",
            "columns" : ["ObjectName"]
        },
        "nopreauth" : {
            "query" : "MATCH (n:User) WHERE n.dontreqpreauth=TRUE RETURN n.name",
            "columns" : ["UserName"]
        },
        "kerberoastable" : {
            "query" : "MATCH (n:User {hasspn:true}) RETURN n.name",
            "columns" : ["UserName"]
        },
        "kerberoastableLA" : {
            "query" : "MATCH (n:User {hasspn:true}) MATCH p=shortestPath((n)-[r:AdminTo|MemberOf*1..4]->(c:Computer)) RETURN DISTINCT n.name",
            "columns" : ["UserName"]
        },
        "sessions" : {
            "query" : "MATCH (m {{name:'{uname}'}})<-[r:HasSession]-(n:Computer) RETURN DISTINCT n.name",
            "columns" : ["ComputerName"]
        },
        "localadmin" : {
            "query" : "MATCH (m {{name:'{uname}'}})-[r:AdminTo|MemberOf*1..4]->(n:Computer) RETURN DISTINCT n.name",
            "columns" : ["ComputerName"]
        },
        "adminsof" : {
            "query" : "MATCH p=shortestPath((m:Computer {{name:'{comp}'}})<-[r:AdminTo|MemberOf*1..]-(n)) RETURN DISTINCT n.name",
            "columns" : ["UserName"]
        },
        "owned" : {
            "query" : "MATCH (n) WHERE n.owned=true RETURN n.name",
            "columns" : ["ObjectName"]
        },
        "owned-groups" : {
            "query" : "MATCH (n {owned:true}) MATCH (n)-[r:MemberOf*1..]->(g:Group) RETURN DISTINCT n.name,g.name",
            "columns" : ["ObjectName","GroupName"]
        },
        "hvt" : {
            "query" : "MATCH (n) WHERE n.highvalue=true RETURN n.name",
            "columns" : ["ObjectName"]
        },
        "desc" : {
            "query" : "MATCH (n) WHERE n.description IS NOT NULL RETURN n.name,n.description",
            "columns" : ["ObjectName","Description"]
        },
        "admincomps" : {
            "query" : "MATCH (n:Computer),(m:Computer) MATCH (n)-[r:MemberOf|AdminTo*1..]->(m) RETURN DISTINCT n.name,m.name ORDER BY n.name",
            "columns" : ["AdminComputerName","VictimCompterName"]
        },
        "nolaps" : {
            "query" : "MATCH (c:Computer {haslaps:false}) RETURN c.name",
            "columns" : ["ComputerName"]
        },
        "passnotreq" : {
            "query" : "MATCH (u:User {{passwordnotreqd:true}}) {enabled} RETURN u.name",
            "columns" : ["UserName"]
        },
        "passlastset" : {
            "query" : "MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - ({days} * 86400)) AND NOT u.pwdlastset IN [-1.0,0.0] RETURN u.name,date(datetime({{epochSeconds:toInteger(u.pwdlastset)}})) AS changedate ORDER BY changedate DESC",
            "columns" : ["UserName", "DateChanged"]
        },
        "sidhist" : {
            "query" : "MATCH (n) WHERE n.sidhistory<>[] UNWIND n.sidhistory AS x OPTIONAL MATCH (d:Domain) WHERE x CONTAINS d.objectid OPTIONAL MATCH (m {objectid:x}) RETURN n.name,x,d.name,m.name ORDER BY n.name",
            "columns" : ["ObjectName","SID","DomainName","ForeignObjectName"]
        },
        "unsupos" : {
            "query" : "MATCH (c:Computer) WHERE c.operatingsystem =~ '.*(2000|2003|2008|xp|vista| 7 |me).*' RETURN c.name,c.operatingsystem",
            "columns" : ["ComputerName","OperatingSystem"]
        },
        "foreignprivs" : {
            "query" : "MATCH p=(n1)-[r]->(n2) WHERE NOT n1.domain=n2.domain RETURN DISTINCT n1.name,TYPE(r),n2.name ORDER BY TYPE(r)",
            "columns" : ["ObjectName","EdgeName","VictimObjectName"]
        },
        "owned-to-hvts" : {
            "query" : "MATCH shortestPath((n {owned:True})-[*1..]->(m {highvalue:True})) RETURN DISTINCT n.name",
            "columns" : ["UserName"]
        },
        "path" : {
            "query" : "MATCH p=shortestPath((n1 {{name:'{start}'}})-[rels*1..]->(n2 {{name:'{end}'}})) RETURN p",
            "columns" : ["Path"]
        },
        "paths-all" : {
            "query" : "MATCH p=allShortestPaths((n1 {{name:'{start}'}})-[rels*1..]->(n2 {{name:'{end}'}})) RETURN p",
            "columns" : ["Path"]
        },
        "hvtpaths" : {
            "query" : "MATCH p=allShortestPaths((n1 {{name:'{start}'}})-[rels*1..]->(n2 {{highvalue:true}})) RETURN p",
            "columns" : ["Path"]
        },
        "ownedpaths" : {
            "query" : "MATCH p=allShortestPaths((n1 {owned:true})-[rels*1..]->(n2 {highvalue:true})) RETURN p",
            "columns" : ["Path"]
        },
        "ownedadmins" : {
            "query": "match (u:User {owned: True})-[r:AdminTo|MemberOf*1..]->(c:Computer) return c.name, \"AdministratedBy\", u.name order by c, u",
            "columns": ["ComputerName", "HasAdmin", "UserName"]
        }
    }

    query = ""
    cols = []
    data_format = "row"
    if (args.users):
        query = queries["users"]["query"]
        cols = queries["users"]["columns"]
    elif (args.comps):
        query = queries["comps"]["query"]
        cols = queries["comps"]["columns"]
    elif (args.groups):
        query = queries["groups"]["query"]
        cols = queries["groups"]["columns"]
    elif (args.groupsfull):
        query = queries["groups-full"]["query"]
        cols = queries["groups-full"]["columns"]
    elif (args.das):
        query = queries["das"]["query"]
        cols = queries["das"]["columns"]
    elif (args.dasess):
        query = queries["dasess"]["query"]
        cols = queries["dasess"]["columns"]
    elif (args.dcs):
        query = queries["dcs"]["query"]
        cols = queries["dcs"]["columns"]
    elif (args.unconstrained):
        query = queries["unconstrained"]["query"]
        cols = queries["unconstrained"]["columns"]
    elif (args.nopreauth):
        query = queries["nopreauth"]["query"]
        cols = queries["nopreauth"]["columns"]
    elif (args.kerberoastable):
        query = queries["kerberoastable"]["query"]
        cols = queries["kerberoastable"]["columns"]
    elif (args.kerberoastableLA):
        query = queries["kerberoastableLA"]["query"]
        cols = queries["kerberoastableLA"]["columns"]
    elif (args.passnotreq):
        query = queries["passnotreq"]["query"]
        cols = queries["passnotreq"]["columns"]
    elif (args.passlastset != ""):
        query = queries["passlastset"]["query"].format(days=args.passlastset.strip())
        cols = queries["passlastset"]["columns"]
    elif (args.sidhist):
        query = queries["sidhist"]["query"]
        cols = queries["sidhist"]["columns"]
    elif (args.unsupos):
        query = queries["unsupos"]["query"]
        cols = queries["unsupos"]["columns"]
    elif (args.owned):
        query = queries["owned"]["query"]
        cols = queries["owned"]["columns"]
    elif (args.ownedgroups):
        query = queries["owned-groups"]["query"]
        cols = queries["owned-groups"]["columns"]
    elif (args.hvt):
        query = queries["hvt"]["query"]
        cols = queries["hvt"]["columns"]
    elif (args.desc):
        query = queries["desc"]["query"]
        cols = queries["desc"]["columns"]
    elif (args.admincomps):
        query = queries["admincomps"]["query"]
        cols = queries["admincomps"]["columns"]
    elif (args.nolaps):
        query = queries["nolaps"]["query"]
        cols = queries["nolaps"]["columns"]
    elif (args.foreignprivs):
        query = queries["foreignprivs"]["query"]
        cols = queries["foreignprivs"]["columns"]
    elif (args.ownedtohvts):
        query = queries["owned-to-hvts"]["query"]
        cols = queries["owned-to-hvts"]["query"]
    elif (args.unamesess != ""):
        query = queries["sessions"]["query"].format(uname=args.unamesess.upper().strip())
        cols = queries["sessions"]["columns"]
    elif (args.unameadminto != ""):
        query = queries["localadmin"]["query"].format(uname=args.unameadminto.upper().strip())
        cols = queries["localadmin"]["columns"]
    elif (args.comp != ""):
        query = queries["adminsof"]["query"].format(comp=args.comp.upper().strip())
        cols = queries["adminsof"]["columns"]
    elif (args.grouplist != ""):
        query = queries["group-list"]["query"].format(uname=args.grouplist.upper().strip())
        cols = queries["group-list"]["columns"]
    elif (args.groupmems != ""):
        query = queries["group-members"]["query"].format(gname=args.groupmems.upper().strip())
        cols = queries["group-members"]["columns"]
    elif (args.ownedadmins):
        query = queries["ownedadmins"]["query"]
        cols = queries["ownedadmins"]["columns"]
    elif (args.path != ""):
        start = args.path.split(',')[0].strip().upper()
        end = args.path.split(',')[1].strip().upper()
        query = queries["path"]["query"].format(start=start,end=end)
        cols = queries["path"]["columns"]
        data_format = "graph"
    elif (args.pathsall != ""):
        start = args.pathsall.split(',')[0].strip().upper()
        end = args.pathsall.split(',')[1].strip().upper()
        query = queries["paths-all"]["query"].format(start=start,end=end)
        cols = queries["paths-all"]["columns"]
        data_format = "graph"
    elif (args.hvtpaths != ""):
        start = args.hvtpaths.split(',')[0].strip().upper()
        query = queries["hvtpaths"]["query"].format(start=start)
        cols = queries["hvtpaths"]["columns"]
        data_format = "graph"
    elif (args.ownedpaths != ""):
        query = queries["ownedpaths"]["query"]
        cols = queries["ownedpaths"]["columns"]
        data_format = "graph"

    if args.getnote:
        query = query + ",n.notes"
        cols.append("Notes")

    if args.enabled and "{enabled}" in query:
        query = query.format(enabled="WHERE u.enabled=true")
    elif "{enabled}" in query:
        query = query.format(enabled="")
    else:
        pass

    r = do_query(args, query, data_format=data_format)
    x = json.loads(r.text)
    # print(r.text)
    entry_list = x["results"][0]["data"]
    # print(entry_list)

    if cols[0] == "Path":
        for entry in entry_list:
            print(get_query_output(entry,args.delimeter,path=True))

    else:
        if args.label:
            print(" - ".join(cols))
        for entry in entry_list:
            print(get_query_output(entry,args.delimeter,cols_len=len(cols)))


def mark_owned(args):

    if (args.clear):

        query = 'MATCH (n) WHERE n.owned=true SET n.owned=false'
        r = do_query(args,query)
        print("[+] 'Owned' attribute removed from all objects.")

    else:

        note_string = ""
        if args.notes != "":
            note_string = "SET n.notes=\"" + args.notes + "\""

        f = open(args.filename).readlines()

        for line in f:

            query = 'MATCH (n) WHERE n.name="{uname}" SET n.owned=true {notes} RETURN n'.format(uname=line.upper().strip(),notes=note_string)
            r = do_query(args, query)

            fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
            if r.text == fail_resp:
                print("[-] AD Object: " + line.upper().strip() + " could not be marked as owned")
            else:
                print("[+] AD Object: " + line.upper().strip() + " marked as owned successfully")


def mark_hvt(args):

    if (args.clear):

        query = 'MATCH (n) WHERE n.highvalue=true SET n.highvalue=false'
        r = do_query(args,query)
        print("[+] 'High Value' attribute removed from all objects.")

    else:

        note_string = ""
        if args.notes != "":
            note_string = "SET n.notes=\"" + args.notes + "\""

        f = open(args.filename).readlines()

        for line in f:

            query = 'MATCH (n) WHERE n.name="{uname}" SET n.highvalue=true {notes} RETURN n'.format(uname=line.upper().strip(),notes=note_string)
            r = do_query(args, query)

            fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
            if r.text == fail_resp:
                print("[-] AD Object: " + line.upper().strip() + " could not be marked as HVT")
            else:
                print("[+] AD Object: " + line.upper().strip() + " marked as HVT successfully")


def query_func(args):

    data_format = ["row", "graph"][args.path]
    queries = []

    if args.file == None and args.query == None:
        print("Error: query requires -q/--query or -f/--file input")
        return
    elif args.query:
        queries.append(args.query)
    elif args.file != None:
        queries = open(args.file,'r').readlines()

    for i in range(0,len(queries)):

        r = do_query(args, queries[i], data_format=data_format)
        x = json.loads(r.text)

        try:
            entry_list = x["results"][0]["data"]
            cols_len = 0

            for entry in entry_list:
                if not args.path:
                    cols_len = len(entry['row'])
                output = get_query_output(entry, args.delimeter, cols_len=cols_len, path=args.path)
                if output != None and args.file == None:
                    print(output)

            if args.file != None:
                print("Query {} executed".format(i+1))

        except:
            if x['errors'][0]['code'] == "Neo.ClientError.Statement.SyntaxError":
                print("Neo4j syntax error")
                print(x['errors'][0]['message'])
            else:
                print("Uncaught error, sry")


def export_func(args):

    edges = [
        "MemberOf",
        "HasSession",
        "AdminTo",
        "AllExtendedRights",
        "AddMember",
        "ForceChangePassword",
        "GenericAll",
        "GenericWrite",
        "Owns",
        "WriteDacl",
        "WriteOwner",
        "ReadLAPSPassword",
        "ReadGMSAPassword",
        "Contains",
        "GpLink",
        "CanRDP",
        "CanPSRemote",
        "ExecuteDCOM",
        "AllowedToDelegate",
        "AddAllowedToAct",
        "AllowedToAct",
        "SQLAdmin",
        "HasSIDHistory",
        "HasSPNConfigured",
        "SharesPasswordWith"
    ]

    node_name = args.NODENAME.upper().strip()
    query = "MATCH (n1 {{name:'{node_name}'}}) MATCH (n1)-[r:{edge}]->(n2) RETURN DISTINCT n2.name"

    data = []

    for edge in edges:
        print("[*] Running " + edge + " collection...")

        statement = query.format(node_name=node_name, edge=edge)

        r = do_query(args, statement)
        x = json.loads(r.text)

        try:
            entry_list = x["results"][0]["data"]

            list = [edge]
            for value in entry_list:
                try:
                    list.append(value["row"][0])
                except:
                    if len(value["row"]) == 1:
                        pass
                    else:
                        pass

            if len(list) == 1:
                pass
            else:
                data.append(list)

            print("[+] Completed " + edge + " collection: " + str(len(entry_list)) + " relationships found")

        except:
            if x['errors'][0]['code'] == "Neo.ClientError.Statement.SyntaxError":
                print("Neo4j syntax error")
                print(x['errors'][0]['message'])
            else:
                print("Uncaught error, sry")

    export_data = zip_longest(*data, fillvalue='')
    filename = node_name.replace(" ","_") + ".csv"
    with open(filename,'w', encoding='utf-8', newline='') as file:
        wr = csv.writer(file)
        wr.writerows(export_data)
    file.close()


def delete_edge(args):
    if args.STARTINGNODE:
        query = 'MATCH ({{name:"{startingnode}"}})-[r:{edge}]->() DELETE r RETURN COUNT (DISTINCT("{startingnode}"))'.format(edge=args.EDGENAME,startingnode=args.STARTINGNODE)
        filters = 'with \'{startingnode}\' starting node'.format(startingnode=args.STARTINGNODE)
    else:
        query = 'MATCH p=()-[r:{edge}]->() DELETE r RETURN COUNT(DISTINCT(p))'.format(edge=args.EDGENAME) 
        filters = ''                          
    r = do_query(args,query)
    number = int(json.loads(r.text)['results'][0]['data'][0]['row'][0] / 2)
    print("[+] '{edge}' edge removed from {number} object relationships {filters}".format(edge=args.EDGENAME,number=number,filters=filters))


def add_spns(args):

    statement = "MATCH (n:User {{name:\"{uname}\"}}) MATCH (m:Computer {{name:\"{comp}\"}}) MERGE (m)-[r:HasSPNConfigured {{isacl: false}}]->(n) return n,m"
    # [ [computer, user], ... ]
    objects = []

    if args.filename != "":
        lines = open(args.filename).readlines()
        for line in lines:
            try:
                objects.append([line.split(',')[0].strip().upper(), line.split(',')[1].strip().upper()])
            except:
                print("[?] Failed parse for: " + line)

    elif args.ifilename != "":
        lines = open(args.ifilename).readlines()
        lines = lines[4:] # trim first 4 output lines
        spns = []
        i = 0
        while (i != len(lines) and lines[i].strip() != ''):
            spns.append(list(filter(('').__ne__,lines[i].strip().split("  ")))) # impacket uses a 2 space value between items, use this split hack to get around spaces in values
            i += 1
        for line in spns:
            try:
                spn = line[0].split('/')[1].split(':')[0].strip().upper()
                uname = line[1].strip().upper()
                domain = '.'.join(line[2].strip().split("DC=")[1:]).replace(',','').upper()
                if domain not in spn:
                    spn = spn + '.' + domain
                uname = uname + '@' + domain
                if [spn,uname] not in objects:
                    objects.append([spn,uname])
            except:
                print("[?] Failed parse for: " + line[0].strip() + " and " + line[1].strip())

    elif args.blood:

        statement1 = "MATCH (n:User {hasspn:true}) RETURN n.name,n.serviceprincipalnames"
        r = do_query(args,statement1)
        try:
            spns = json.loads(r.text)['results'][0]['data']
            print("[*] BloodHound data queried successfully")
            for user in spns:
                uname = user['row'][0]
                domain = uname.split("@")[1]
                for fullspn in user['row'][1]:
                    try:
                        spn = fullspn.split('/')[1].split(':')[0].strip().upper()
                        if domain not in spn:
                            spn = spn + "." + domain
                        if [spn,uname] not in objects:
                            objects.append([spn,uname])
                    except:
                        print("[?] Failed parse for user " + uname + " and SPN " + fullspn)
        except:
            print("[-] Error querying database")

    else:
        print("Invalid Option")

    count = 0
    for set in objects:

        query = statement.format(uname=set[1],comp=set[0])

        r = do_query(args, query)

        fail_resp = '{"results":[{"columns":["n","m"],"data":[]}],"errors":[]}'
        if r.text == fail_resp:
            print("[-] Relationship " + set[0] + " -- HasSPNConfigured -> " + set[1] + " could not be added")
        else:
            print("[+] Relationship " + set[0] + " -- HasSPNConfigured -> " + set[1] + " added")
            count = count + 1

    print('[+] HasSPNConfigured relationships created: ' + str(count))


def add_spw(args):

    statement = "MATCH (n {{name:\"{name1}\"}}),(m {{name:\"{name2}\"}}) MERGE (n)-[r1:SharesPasswordWith]->(m) MERGE (m)-[r2:SharesPasswordWith]->(n) return n,m"

    objs = open(args.filename,'r').readlines()

    count = 0

    for i in range(0,len(objs)):
        name1 = objs[i].strip().upper()
        print("[+] Creating relationships for " + name1)
        for j in range(i + 1,len(objs)):
            name2 = objs[j].strip().upper()
            #print("query: " + str(i) + ' ' + str(j))
            query = statement.format(name1=name1,name2=name2)
            r = do_query(args,query)

            fail_resp = '{"results":[{"columns":["n","m"],"data":[]}],"errors":[]}'
            if r.text != fail_resp:
                count = count + 1

    print("[+] SharesPasswordWith relationships created: " + str(count))


# code from https://github.com/clr2of8/DPAT/blob/master/dpat.py#L64
def dpat_sanitize(args, pass_or_hash):
    if not args.sanitize:
        return pass_or_hash
    else:
        sanitized_string = pass_or_hash
        lenp = len(pass_or_hash)
        if lenp == 32:
            sanitized_string = pass_or_hash[0:4] + \
                "*"*(lenp-8) + pass_or_hash[lenp-5:lenp-1]
        elif lenp > 2:
            sanitized_string = pass_or_hash[0] + \
                "*"*(lenp-2) + pass_or_hash[lenp-1]
        return sanitized_string


def dpat_parse_ntds(lines, ntds_parsed):
    for line in lines:
        if ":::" not in line or '$' in line: #filters out other lines in ntds/computer obj
            continue
        line = line.replace("\r", "").replace("\n", "")
        if (line == ""):
            continue
        else:
            line = line.split(":")
        # [ username, domain, rid, LM, NT, plaintext||None]
        to_append = []
        if (line[0].split("\\")[0] == line[0]):
            # no domain found, local account
            to_append.append(line[0])
            to_append.append("")
        else:
            to_append.append(line[0].split("\\")[1])
            to_append.append(line[0].split("\\")[0])
        to_append.append(line[1])
        to_append.append(line[2])
        to_append.append(line[3])
        ntds_parsed.append(to_append)


def dpat_map_users(args, users, potfile):
    count = 0
    for user in users:
        try:
            nt_hash = user[4]
            lm_hash = user[3]
            ntds_uname = '/'.join(filter(None, [user[1], user[0]])).replace("\\","\\\\").replace("'","\\'")
            username = str(user[0].upper().strip() + "@" + user[1].upper().strip()).replace("\\","\\\\").replace("'","\\'")
            cracked_bool = 'false'
            password = None
            password_query = ''
            if nt_hash in potfile:
                cracked_bool = 'true'
                password = potfile[nt_hash]
            elif lm_hash != "aad3b435b51404eeaad3b435b51404ee" and lm_hash in potfile:
                cracked_bool = 'true'
                password = potfile[lm_hash]

            if password != None:
                if "$HEX[" in password:
                    print("[!] found $HEX[], stripping and unpacking")
                    password = binascii.unhexlify( str( password.split("[")[1].replace("]", "") ) ).decode("utf-8")
                password = password.replace("\\","\\\\").replace("'","\\'")
                password_query = "SET u.password='{pwd}'".format(pwd=password)

            cracked_query = "SET u.cracked={cracked_bool} SET u.nt_hash='{nt_hash}' SET u.lm_hash='{lm_hash}' SET u.ntds_uname='{ntds_uname}' {password}".format(cracked_bool=cracked_bool,nt_hash=nt_hash,lm_hash=lm_hash,ntds_uname=ntds_uname,password=password_query)
            query1 = "MATCH (u:User) WHERE u.name='{username1}' OR (u.name STARTS WITH '{username2}@' AND u.objectid ENDS WITH '-{rid}') {cracked_query} RETURN u.name,u.objectid".format(username1=username, username2=user[0].replace("\\","\\\\").replace("'","\\'").upper(), rid=user[2].upper(), cracked_query=cracked_query)

            r1 = do_query(args,query1)
            bh_users = json.loads(r1.text)['results'][0]['data']

            # if bh_users == [] then the user was not found in BH
            if bh_users != []:
                count = count + 1

        except Exception as g:
            print("[-] Mapping ERROR: {} FOR USER {}".format(g, user[0]))
            # print('{}'.format(g))
            # print(query1)
            pass

    return count


def dpat_func(args):

    query_counts = {}

    if args.clear:
        print("[+] Clearing attributes from all users: cracked, password, nt_hash, lm_hash, ntds_uname")
        clear_query = "MATCH (u:User) REMOVE u.cracked REMOVE u.nt_hash REMOVE u.lm_hash REMOVE u.ntds_uname REMOVE u.password"
        do_query(args,clear_query)
        return

    if ((args.output) and (not args.csv and not args.html)):
        print("[-] Error, --output requires --csv and/or --html type output flags")
        return

    if not args.noparse:

        if args.ntdsfile != None:
            ntds = open(args.ntdsfile, 'r').readlines()
        else:
            print("[-] Error, Need NTDS file")
            return
        if args.crackfile == None:
            print("[-] Error, Need crackfile")
            return

        try:
            print("[+] Processing NTDS")
            num_lines = len(ntds)
            # create threads to parse file
            procs = []
            manager = multiprocessing.Manager()
            ntds_parsed = manager.list()
            num_threads = int(args.num_threads)
            for t in range(0, num_threads):
                start = math.ceil((num_lines / num_threads) * t)
                end = math.ceil((num_lines / num_threads) * (t + 1))
                p = multiprocessing.Process(target=dpat_parse_ntds, args=(ntds[ start : end ], ntds_parsed, ))
                p.start()
                procs.append(p)
            for p_ in procs:
                p_.join()
            # destroy managed list
            """
            ntds_parsed = {
              [uname, domain, rid, lm hash, nt hash, password] ....
            }
            """
            ntds_parsed = list(ntds_parsed)
            # done parsing

            print("[+] Processing Potfile")
            # password stats like counting reused cracked passwords

            potfile = {}
            with open(args.crackfile,'r') as pot:
                for line in pot.readlines():
                    try:
                        line = line.strip().replace("$NT$", "").replace("$LM$", "")
                        if (line == ""):
                            continue
                        line = line.split(":")

                        if len(line[0]) != 32:
                            continue

                        potfile[line[0]] = line[1]

                    except:
                        pass

            print('[+] Mapping NTDS users to BloodHound data')

            num_lines = len(ntds_parsed)

            # create threads to parse file
            procs = []
            num_threads = int(args.num_threads)
            for t in range(0, num_threads):
                start = math.ceil((num_lines / num_threads) * t)
                end = math.ceil((num_lines / num_threads) * (t + 1))
                p = multiprocessing.Process(target=dpat_map_users, args=(args, ntds_parsed[ start : end ], potfile, ))
                p.start()
                procs.append(p)
            for p_ in procs:
                p_.join()


            count_query = "MATCH (u:User) WHERE u.cracked IS NOT NULL RETURN COUNT(u.name)"
            r = do_query(args,count_query)
            resp = json.loads(r.text)['results'][0]['data']
            count = resp[0]['row'][0]
            print("[+] BloodHound data queried successfully, {} NTDS users mapped to BH data".format(count))
            if count < 10:
                print("[-] Warning: Less than 10 users mapped to BloodHound entries, verify the NTDS data matches the Neo4j data, continuing...")

        except Exception as e:
            print("[-] Error, {}".format(e))
            return

    ###
    ### Searching for specific user/password
    ###
    # TODO: do this stuff pre-processing for the love
    # TODO: Output other info like hashes, full names, etc

    if args.passwd:
        print("[+] Searching for users with password '{}'".format(args.passwd))
        query = "MATCH (u:User {{cracked:true}}) WHERE u.password='{pwd}' RETURN u.name".format(pwd=args.passwd.replace("\\","\\\\").replace("'","\\'"))
        r = do_query(args,query)
        resp = json.loads(r.text)['results'][0]['data']
        print("[+] Users: {}\n".format(len(resp)))
        for entry in resp:
            print(entry['row'][0])
        return

    if args.usern:
        print("[+] Searching for password for user {}".format(args.usern))
        query = "MATCH (u:User) WHERE toUpper(u.name)='{uname}' OR toUpper(u.ntds_uname)='{uname}' RETURN u.name,u.password".format(uname=args.usern.upper().replace("\\","\\\\").replace("'","\\'"))
        r = do_query(args,query)
        resp = json.loads(r.text)['results'][0]['data']
        if resp == []:
            print("[-] User {uname} not found".format(uname=args.usern))
        elif resp[0]['row'][1] == None:
            print("[-] User {uname} not cracked, no password found".format(uname=args.usern))
        else:
            print("[+] Password for user {uname}: {pwd}".format(uname=args.usern,pwd=dpat_sanitize(args, resp[0]['row'][1])))
        return

    ###
    ### Automated Cypher Queries for standard stuff, outputting users
    ###

    queries = [
        {
            'query' : "MATCH (u:User) RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "All User Accounts"
        },
        {
            'query' : "MATCH (u:User {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "All User Accounts Cracked"
        },
        {
            "query" : "MATCH p=(u:User {cracked:true}) WHERE u.enabled = TRUE RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Enabled User Accounts Cracked"
        },
        {
            'query' : "MATCH p=(u:User {cracked:true})-[r:MemberOf*1..]->(g:Group {highvalue:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "High Value User Accounts Cracked"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH (u:User)-[r:MemberOf*1..]->(g) RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "Domain Admin Members"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH (u:User {cracked:true})-[r:MemberOf*1..]->(g) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Domain Admin Members Cracked"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-519' MATCH (u:User)-[r:MemberOf*1..]->(g) RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "Enterprise Admin Members"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-519' MATCH (u:User {cracked:true})-[r:MemberOf*1..]->(g) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Enterprise Admin Accounts Cracked"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-544' MATCH (u:User)-[r:MemberOf]->(g) RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "Administrator Group Members"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-544' MATCH (u:User {cracked:true})-[r:MemberOf]->(g) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Administrator Group Member Accounts Cracked"
        },
        {
            'query' : "MATCH (u:User {cracked:true,hasspn:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Kerberoastable Users Cracked"
        },
        {
            'query' : "MATCH (u:User {cracked:true,dontreqpreauth:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Accounts Not Requiring Kerberos Pre-Authentication Cracked"
        },
        {
            'query' : "MATCH (u:User {cracked:true,unconstraineddelegation:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Unconstrained Delegation Accounts Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true}) WHERE u.lastlogon < (datetime().epochseconds - (182 * 86400)) AND NOT u.lastlogon IN [-1.0, 0.0] RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Inactive Accounts (Last Used Over 6mos Ago) Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true}) WHERE u.pwdlastset < (datetime().epochseconds - (365 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Passwords Set Over 1yr Ago Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true,pwdneverexpires:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Passwords That Never Expire Cracked"
        },
    ]

    intense_queries = [
        {
            "query" : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-516' MATCH (c:Computer)-[MemberOf]->(g) WITH COLLECT(c) AS dcs MATCH (u:User {cracked:true}),(n {unconstraineddelegation:true}),p=shortestPath((u)-[r*1..]->(n)) WHERE NOT n IN dcs AND NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT u=n RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash,n.name",
            "label" : "Accounts With Paths To Unconstrained Delegation Objects Cracked (Excluding DCs)"
        },
        {
            "query" : "MATCH (u:User {cracked:true}),(n {highvalue:true}),p=shortestPath((u)-[r*1..]->(n)) WHERE NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT u=n RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Paths To High Value Targets Cracked"
        },
        {
            "query" : "MATCH p1=(u:User {cracked:true})-[r:AdminTo]->(n1) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Explicit Admin Rights Cracked"
        },
        {
            "query" : "MATCH p2=(u:User {cracked:true})-[r1:MemberOf*1..]->(g:Group)-[r2:AdmintTo]->(n2) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Group Delegated Admin Rights Cracked"
        },
        {
            "query" : "MATCH p1=(u:User {cracked:true})-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|CanRDP|CanPSRemote|ExecuteDCOM|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory]->(n1) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Explicit Controlling Privileges Cracked"
        },
        {
            "query" : "MATCH p2=(u:User {cracked:true})-[r1:MemberOf*1..]->(g:Group)-[r2:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|CanRDP|CanPSRemote|ExecuteDCOM|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory]->(n2) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Group Delegated Controlling Privileges Cracked"
        }
    ]

    if not args.less:
        queries = queries + intense_queries
    else:
        print("[*] Less flag enabled, omitting high-intensity queries")


    """
    [
        {
            'label' : "query title",
            'enabled' : "list of enabled users related to the query"
            'disabled' : "list of disabled users related to the query"
        }
    ]
    """
    query_output_data = []

    hashes = {}
    query = "MATCH (u:User) WHERE u.nt_hash IS NOT NULL RETURN u.nt_hash,u.ntds_uname"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']

    for entry in resp:
        if entry['row'][0] not in hashes:
            hashes[entry['row'][0]] = [entry['row'][1]]
        else:
            hashes[entry['row'][0]].append(entry['row'][1])
    import time
    for search_value in queries:

        # start = time.time()

        query = search_value['query']
        label = search_value['label']
        if (label not in query_counts):
            query_counts[label] = 0
        print("[+] Querying for \"" + label + "\"")
        dat = { 'label' : label }
        dat['enabled'] = []
        dat['disabled'] = []

        r = do_query(args,query)
        resp = json.loads(r.text)['results'][0]['data']
        # end = time.time()
        # print("[*] Done in {} seconds".format(end-start))
        for entry in resp:
            query_counts[label] += 1 # TODO
            status_flag = "disabled"
            if entry['row'][0]:
                status_flag = "enabled"

            if "cracked" in label.lower():
                try:
                    user = [entry['row'][1], entry['row'][2], len(entry['row'][2]), entry['row'][3]]
                    dat[status_flag].append(user)
                except:
                    pass
            else:
                try:
                    share_count = len(hashes[entry['row'][2]])
                    if share_count > 30:
                        all_hashes_shared = "Shared Hash List > 30"
                    else:
                        all_hashes_shared = ', '.join(hashes[entry['row'][2]])
                    user = [entry['row'][1], entry['row'][2], all_hashes_shared, share_count, entry['row'][3]]
                    dat[status_flag].append(user)
                except:
                    pass

        if "cracked" in label.lower():
            dat['columns'] = ["Username", "Password", "Password Length", "NT Hash"]
            dat['enabled'] = sorted(dat['enabled'], key = lambda x: -1 if x[1] is None else len(x[1]), reverse=True)
            dat['disabled'] = sorted(dat['disabled'], key = lambda x: -1 if x[1] is None else len(x[1]), reverse=True)

        else:
            dat['columns'] = ["Username", "NT Hash", "Users Sharing this Hash", "Share Count", "Password"]
            dat['enabled'] = sorted(dat['enabled'], key = lambda x: -1 if x[3] is None else x[3], reverse=True)
            dat['disabled'] = sorted(dat['disabled'], key = lambda x: -1 if x[3] is None else x[3], reverse=True)

        query_output_data.append(dat)

    ###
    ### Get the Group Stats ready
    ###
    # TODO: Output group members in html output

    if not args.less:

        print("[+] Querying for Group Statistics")
        group_query_data = {}
        group_data = []

        query = "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN DISTINCT g.name,u.name,u.cracked"
        r = do_query(args,query)
        resp = json.loads(r.text)['results'][0]['data']
        for entry in resp:
            group_name = entry['row'][0]
            username = entry['row'][1]
            crack_status = entry['row'][2]

            if group_name not in group_query_data:
                group_query_data[group_name] = [[username,crack_status]]
            else:
                group_query_data[group_name].append([username,crack_status])

        for group_name in group_query_data:
            cracked_total = sum(user[1] == True for user in group_query_data[group_name])
            if cracked_total == 0:
                continue
            perc = round(100 * float(cracked_total / len(group_query_data[group_name])), 2)
            group_data.append([group_name,perc,cracked_total,len(group_query_data[group_name])])
        group_data = sorted(group_data, key = lambda x: x[1], reverse=True)

    ###
    ### Get the Overall Stats ready
    ###

    print("[+] Generating Overall Statistics")

    # all password hashes
    query = "MATCH (u:User) WHERE u.cracked IS NOT NULL RETURN u.ntds_uname,u.password,u.nt_hash,u.pwdlastset"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    num_pass_hashes = len(resp)
    num_pass_hashes_list = []
    for entry in resp:
        length = ''
        if entry['row'][1] != None:
            length = len(entry['row'][1])
        try:
            num_pass_hashes_list.append([entry['row'][0], entry['row'][1], length, entry['row'][2], datetime.datetime.fromtimestamp(entry['row'][3])], )
        except:
            num_pass_hashes_list.append([entry['row'][0], entry['row'][1], length, entry['row'][2], ''], )
    num_pass_hashes_list = sorted(num_pass_hashes_list, key = lambda x: -1 if x[1] is None else len(x[1]), reverse=True)

    # unique password hashes
    query = "MATCH (u:User) RETURN COUNT(DISTINCT(u.nt_hash))"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    num_uniq_hash = resp[0]['row'][0]

    # passwords cracked, uniques
    query = "MATCH (u:User {cracked:True}) RETURN COUNT(DISTINCT(u)),COUNT(DISTINCT(u.password))"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    num_cracked = resp[0]['row'][0]
    num_uniq_cracked = resp[0]['row'][1]

    # password percentages
    if (num_pass_hashes > 0):
        perc_total_cracked = "{:2.2f}".format((float(num_cracked) / float(num_pass_hashes) * 100))
        perc_uniq_cracked = "{:2.2f}".format((float(num_uniq_cracked) / float(num_uniq_hash) * 100))
    else:
        # avoid div by zero
        perc_total_cracked = 00.00
        perc_uniq_cracked = 00.00

    # lm hash stats
    query = "MATCH (u:User) WHERE u.lm_hash IS NOT NULL AND NOT u.lm_hash='aad3b435b51404eeaad3b435b51404ee' RETURN u.lm_hash,count(u.lm_hash)"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    lm_hash_counts = {}
    for entry in resp:
        lm_hash_counts[entry['row'][0]] = entry['row'][1]
    non_blank_lm = sum(lm_hash_counts.values())
    uniq_lm = len(lm_hash_counts)

    # lm hash users
    query = "MATCH (u:User) WHERE u.lm_hash IS NOT NULL AND NOT u.lm_hash='aad3b435b51404eeaad3b435b51404ee' RETURN u.name,u.lm_hash"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']

    lm_hash_list = []
    for entry in resp:
        user = [entry['row'][0], dpat_sanitize(args, entry['row'][1])]
        user.append(lm_hash_counts[entry['row'][1]])
        lm_hash_list.append(user)
    lm_hash_list = sorted(lm_hash_list, key = lambda x: x[2], reverse=True)

    # matching username/password
    query = "MATCH (u:User {cracked:true}) WHERE toUpper(SPLIT(u.name,'@')[0])=toUpper(u.password) RETURN u.ntds_uname,u.password,u.nt_hash"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    user_pass_match_list = []
    for entry in resp:
        user_pass_match_list.append([entry['row'][0],dpat_sanitize(args,entry['row'][1]),len(entry['row'][1]),entry['row'][2]])
    user_pass_match = len(user_pass_match_list)

    # Get Password Length Stats
    query = "MATCH (u:User {cracked:true}) WHERE NOT u.password='' RETURN  COUNT(SIZE(u.password)), SIZE(u.password) AS sz ORDER BY sz DESC"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    password_lengths = []
    for entry in resp:
        password_lengths.append(entry['row'])

    # Get Password (Complexity) Stats
    # sort from most reused to least reused dict to list of tuples
    # get the first instance of not repeated password to be min'd later
    query = "MATCH (u:User {cracked:true}) WHERE NOT u.password='' RETURN COUNT(u.password) AS countpwd, u.password ORDER BY countpwd DESC"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    repeated_passwords = []
    tot_num_repeated_passwords = len(resp)
    for entry in resp:
        if entry['row'][0] > 1:
            repeated_passwords.append(entry['row'])
    num_repeated_passwords = len(repeated_passwords)

    # Passwords not meeting Complexity Requirement
    special_chars = """`~!@#$%^&*()-_=+,<.>/?;:"'{}[]|\\"""
    rules = [
        lambda s: any(x.isupper() for x in s),
        lambda s: any(x.islower() for x in s),
        lambda s: any(x.isdigit() for x in s),
        lambda s: any(x in special_chars for x in s)
    ]

    query = "MATCH (u:User {cracked:true}) WHERE NOT u.password='' RETURN u.password,u.ntds_uname"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    password_complexity = []
    for entry in resp:
        if sum(rule(entry['row'][0]) for rule in rules) >= 3:
            password_complexity.append([entry['row'][1],entry['row'][0],True])
        else:
            password_complexity.append([entry['row'][1],entry['row'][0],False])
    password_complexity = sorted(password_complexity, key = lambda x: x[2])

    # all stats
    stats = [
        [num_pass_hashes, "Password Hashes", ["NTDS Username", "Password", "Password Length", "NT Hash", "Pwd Last Set"], num_pass_hashes_list], #, ntds_parsed],
        [num_uniq_hash, "Unique Password Hashes"],
        [num_cracked, "Passwords Discovered Through Cracking"],
        [perc_total_cracked, "Percent of Passwords Cracked"],
        [perc_uniq_cracked, "Percent of Unique Passwords Cracked"],
        [non_blank_lm, "LM Hashes (Non-Blank)", ["NTDS Username", "LM Hash", "Shared Count"], lm_hash_list],
        [uniq_lm, "Unique LM Hashes (Non-Blank)"],
        [user_pass_match, "Users with Username Matching Password", ["NTDS Username", "Password", "Password Length", "NT Hash"], user_pass_match_list],
        [len(password_lengths), "Password Length Stats", ['Count', 'Number of Characters'], password_lengths],
        [len(password_complexity), "Password Complexity Stats", ['Username', 'Password', "Meets Complexity Requirements"], password_complexity],
        [len(repeated_passwords), "Password Reuse Stats", ['Count', 'Password'], repeated_passwords],
    ]

    if not args.less:
        stats.append([len(group_data), "Groups Cracked by Percentage",  ["Group Name", "Percent Cracked", "Cracked Users", "Total Users"], group_data])

    # set all users with cracked passwords as owned
    if args.own_cracked:
        print("[+] Marking cracked users as owned")
        own_cracked_query="MATCH (u:User {cracked:True}) SET u.owned=true"
        do_query(args,own_cracked_query)
    
    # Add a note to users with cracked passwords indicating that they have been cracked
    if args.add_crack_note:
        print('[+] Adding notes to cracked users')
        add_crack_note_query="MATCH (u:User {cracked=True} SET u.notes=\"Password Cracked\""
        do_query(args,add_crack_note_query)

    # clear the "cracked" tag
    if not args.store and not args.noparse:
        print("[+] Purging information from the database")
        clear_query = "MATCH (u:User) REMOVE u.cracked REMOVE u.nt_hash REMOVE u.lm_hash REMOVE u.ntds_uname REMOVE u.password"
        do_query(args,clear_query)

    ###
    ### Output methods
    ###

    if args.csv:

        full_data = []

        for item in query_output_data:
            label = item['label']
            enable_label = label + " - Enabled"
            disable_label = label + " - Disabled"
            item_enabled = [x[0] for x in item['enabled']]
            item_disabled = [x[0] for x in item['disabled']]
            item_enabled.insert(0,enable_label)
            item_disabled.insert(0,disable_label)

            full_data.append(item_enabled)
            full_data.append(item_disabled)

        export_data = zip_longest(*full_data, fillvalue='')
        filename = args.output.replace(".csv", "") + ".csv" #node_name.replace(" ","_") + ".csv"
        with open(filename,'w', encoding='utf-8', newline='') as file:
            wr = csv.writer(file)
            wr.writerows(export_data)
        file.close()
        print("[+] All data written to {}.csv".format(args.output))

    # use "if" specifically so you can output both html & csv on the same run
    # This code heavily modified from the original DPAT tool, credit where it's due
    if args.html:

        if not os.path.exists(args.output):
            os.makedirs(args.output)

        filebase = args.output + "/"
        filename_report = "Report.html"

        # write report.css
        css_styling =  ""
        css_styling += "table, th, td { \n"
        css_styling += "    border: 1px solid black; \n"
        css_styling += "    border-collapse: collapse; \n"
        css_styling += "    text-align: center; \n"
        css_styling += "} \n"
        css_styling += " \n"
        css_styling += "th, td { \n"
        css_styling += "    padding: 5px; \n"
        css_styling += "} \n"
        css_styling += " \n"
        css_styling += "th { \n"
        css_styling += "    border-bottom-width: 2px; \n"
        css_styling += "} \n"
        css_styling += " \n"
        css_styling += "body { \n"
        css_styling += "    justify-content: center; \n"
        css_styling += "} \n"
        css_styling += " \n"
        css_styling += "table { \n"
        css_styling += "    box-shadow: 0 7px 8px -4px rgba(0,0,0,.2),0 12px 17px 2px rgba(0,0,0,.14),0 5px 22px 4px rgba(0,0,0,.12)!important; \n"
        css_styling += "    margin-top: 30px; \n"
        css_styling += "} \n"
        css_styling += " \n"
        css_styling += "tr:nth-child(even) { \n"
        css_styling += "    background: #d1d3d2; \n"
        css_styling +="}"

        f = open(os.path.join(filebase,"report.css"),'w')
        f.writelines(css_styling)
        f.close()

        class HtmlBuilder:
            bodyStr = ""

            def build_html_body_string(self, str):
                self.bodyStr += str + "</br>\n"

            def get_html(self):
                return "<!DOCTYPE html>\n" + "<html>\n<head>\n<link rel='stylesheet' href='report.css'>\n</head>\n" + "<body>\n" + self.bodyStr  + "</body>\n" + "</html>\n"

            def add_table_to_html(self, list, headers=[], col_to_not_escape=None):
                html = '<table border="1">\n'
                html += "<tr>"
                for header in headers:
                    if header is not None:
                        html += "<th>" + str(header) + "</th>"
                    else:
                        html += "<th></th>"
                html += "</tr>\n"
                for line in list:
                    html += "<tr>"
                    col_num = 0
                    for column in line:
                        if column is not None:
                            col_data = column
                            if ((("Password") in headers[col_num] and not "Password Length" in headers[col_num]) or ("Hash" in headers[col_num] and not "Users Sharing this Hash" in headers[col_num]) or ("History" in headers[col_num])):
                                col_data = dpat_sanitize(args, column)
                            if col_num != col_to_not_escape:
                                col_data = htmllib.escape(str(col_data))
                            html += "<td>" + col_data + "</td>"
                        else:
                            html += "<td></td>"
                        col_num += 1
                    html += "</tr>\n"
                html += "</table>"
                self.build_html_body_string(html)

            def write_html_report(self, filebase, filename):
                f = open(os.path.join(filebase, filename), "w")
                f.write(self.get_html())
                f.close()
                return filename


        hb = HtmlBuilder()
        summary_table = []
        summary_table_headers = ("Count", "Description", "More Info")

        print("[+] Writing HTML files")

        # add overall stats
        for stat in stats:

            if len(stat) == 2:
                summary_table.append((stat[0], stat[1],""))

            else:
                hbt = HtmlBuilder()
                hbt.add_table_to_html(stat[3], stat[2])
                filename = hbt.write_html_report(filebase, ''.join([stat[1].replace(' ','_'),".html"]))
                summary_table.append((stat[0], stat[1],"<a href=\"" + filename + "\">Details</a>"))

        # add BH query results
        for item in query_output_data:

            cols = item['columns']
            cols.append("Status")

            all_entries = []
            for entry in item['enabled']:
                entry.append('Enabled')
                all_entries.append(entry)
            for entry in item['disabled']:
                entry.append('Disabled')
                all_entries.append(entry)

            hbt = HtmlBuilder()
            hbt.add_table_to_html(all_entries, cols)
            filename = hbt.write_html_report(filebase, ''.join([item['label'].replace(' ','_'),".html"]))
            summary_table.append((len(all_entries), item['label'],"<a href=\"" + filename + "\">Details</a>"))

        hb.add_table_to_html(summary_table, summary_table_headers, 2)
        hb.write_html_report(filebase, filename_report)
        print("[+] Report has been written to the \"" + filename_report + "\" file in the \"" + filebase + "\" directory")

        # prompt user to open the report
        # the code to prompt user to open the file was borrowed from the DPAT tool which borrowed it from the EyeWitness tool https://github.com/ChrisTruncer/EyeWitness
        print('[+] Would you like to open the report now? [Y/n]')
        while True:
            response = input().lower().rstrip('\r')
            if ((response == "") or (response == 'y') or (response == "yes")):
                webbrowser.open(os.path.join("file://" + os.getcwd(),
                                            filebase, filename_report))
                break
            elif ((response == 'n') or (response == "no")):
                break
            else:
                print("[-] Please respond with y or n")


    if args.output == "":
        print("[+] Outputting Stats to Terminal...")

        # Output to CLI

        print("")
        print("")
        print("{:^92}".format("Overall Statistics"))
        print(" " + "="*96)
        print("|{:^10}|{:^85}|".format("Count", "Description"))
        print(" " + "="*96)

        for set in stats:
             print("|{:^10}|{:^85}|".format(set[0], set[1]))

        for item in query_output_data:
            print("|{:^10}|{:^85}|".format(len(item['enabled']) + len(item['disabled']),item['label']))

        print(" " + "="*96)
        print("")
        print("")
        print("{:^92}".format("Password Length Stats"))
        print(" " + "="*96)
        print("|{:^10}|{:^85}|".format("Count", "Description"))
        print(" " + "="*96)
        for pw_len in password_lengths:
            print("|{:^10}|{:^85}|".format(pw_len[0], "{} Characters".format(pw_len[1])))
        print(" " + "="*96)
        print("")
        print("")
        print("{:^92}".format("Password Reuse Stats (Top 10%)"))
        print(" " + "="*96)
        print("|{:^10}|{:^85}|".format("Count", "Description"))
        print(" " + "="*96)
        for i in range(0,min(num_repeated_passwords, math.ceil( tot_num_repeated_passwords * 0.10 ))): # cap at 50 reused passwords
            print("|{:^10}|{:^85}|".format(repeated_passwords[i][0], dpat_sanitize(args, repeated_passwords[i][1])))
        print(" " + "="*96)
        print("")
        print("")


def pet_max():

    messages = [
        "Max is a good boy",
        "Woof!",
        "Bark!",
        "Bloodhound is great!",
        "Black Lives Matter!",
        "Wear a mask!",
        "Hack the planet!",
        "10/10 would pet - @blurbdust",
        "dogsay > cowsay - @b1gbroth3r",
        "much query, very sniff - @vexance"
    ]

    max = """
                                        \\   /
         /|                   ______     \\ |
        { (                  /( ) ^ `--o  |/
         \ \________________/     ____/
          \                       /
           (    >    ___   >     )
            \_      )   \____\  \\\\
             )   /\ (         `. ))
             (  {  \_\_       / //
              \_\_  '''       '''
               '''
    """

    m = messages[random.randint(0,len(messages)-1)]
    num = 47 - len(m) - 15
    message = ""
    message = message + ' '*num + " -------" + '-'*len(m) + "------- \n"
    message = message + ' '*num + "{       " + m          + "       }\n"
    message = message + ' '*num + " -------" + '-'*len(m) + "     -- "

    print(message + max)


def main():

    parser = argparse.ArgumentParser(description="Maximizing Bloodhound. Max is a good boy.")

    general = parser.add_argument_group("Optional Arguments")

    # generic function parameters
    general.add_argument("-u",dest="username",default=global_username,help="Neo4j database username (Default: {})".format(global_username))
    general.add_argument("-p",dest="password",default=global_password,help="Neo4j database password (Default: {})".format(global_password))
    general.add_argument("--url",dest="url",default=global_url,help="Neo4j database URL (Default: {})".format(global_url))

    # three options for the function
    parser._positionals.title = "Available Modules"
    switch = parser.add_subparsers(dest='command')
    getinfo = switch.add_parser("get-info",help="Get info for users, computers, etc")
    markowned = switch.add_parser("mark-owned",help="Mark objects as Owned")
    markhvt = switch.add_parser("mark-hvt",help="Mark items as High Value Targets (HVTs)")
    query = switch.add_parser("query",help="Run a raw query & return results (must return node attributes like n.name or n.description)")
    export = switch.add_parser("export",help="Export a user or groups raw privileges to a csv file")
    deleteedge = switch.add_parser("del-edge",help="Remove every edge of a certain type. Why filter when you can delete? (Warning, irreversible)")
    addspns = switch.add_parser("add-spns",help="Create 'HasSPNConfigured' relationships with targets from a file or stored BloodHound data. Adds possible path of compromise edge via cleartext service account credentials stored within LSA Secrets")
    addspw = switch.add_parser("add-spw",help="Create 'SharesPasswordWith' relationships with targets from a file. Adds edge indicating two objects share a password (repeated local administrator)")
    dpat = switch.add_parser("dpat",help="BloodHound Domain Password Audit Tool, run cracked user-password analysis tied with BloodHound through a Hashcat potfile & NTDS")
    petmax = switch.add_parser("pet-max",help="Pet max, hes a good boy (pet me again, I say different things)")

    # GETINFO function parameters
    getinfo_switch = getinfo.add_mutually_exclusive_group(required=True)
    getinfo_switch.add_argument("--users",dest="users",default=False,action="store_true",help="Return a list of all domain users")
    getinfo_switch.add_argument("--comps",dest="comps",default=False,action="store_true",help="Return a list of all domain computers")
    getinfo_switch.add_argument("--groups",dest="groups",default=False,action="store_true",help="Return a list of all domain groups")
    getinfo_switch.add_argument("--groups-full",dest="groupsfull",default=False,action="store_true",help="Return a list of all domain groups with all respective group members")
    getinfo_switch.add_argument("--group-members",dest="groupmems",default="",help="Return a list of all members of an input GROUP@DOMAIN.LOCAL")
    getinfo_switch.add_argument("--group-list",dest="grouplist",default="",help="Return a list of all groups of an input USERNAME@DOMAIN.LOCAL")
    getinfo_switch.add_argument("--das",dest="das",default=False,action="store_true",help="Return a list of all Domain Admins")
    getinfo_switch.add_argument("--dasessions",dest="dasess",default=False,action="store_true",help="Return a list of Domain Admin sessions")
    getinfo_switch.add_argument("--dcs",dest="dcs",default=False,action="store_true",help="Return a list of all Domain Controllers")
    getinfo_switch.add_argument("--nolaps",dest="nolaps",default=False,action="store_true",help="Return a list of all computers without LAPS")
    getinfo_switch.add_argument("--unconst",dest="unconstrained",default=False,action="store_true",help="Return a list of all objects configured with Unconstrained Delegation")
    getinfo_switch.add_argument("--npusers",dest="nopreauth",default=False,action="store_true",help="Return a list of all users that don't require Kerberos Pre-Auth (AS-REP roastable)")
    getinfo_switch.add_argument("--kerb",dest="kerberoastable",default=False,action="store_true",help="Return a list of Kerberoastable users")
    getinfo_switch.add_argument("--kerb-la",dest="kerberoastableLA",default=False,action="store_true",help="Return a list of Kerberoastable users that have Local Admin rights in at least one place")
    getinfo_switch.add_argument("--passnotreq",dest="passnotreq",default=False,action="store_true",help="Return a list of all users that have PasswordNotRequired flag set to true")
    getinfo_switch.add_argument("--passlastset",dest="passlastset",default="",help="Return a list of all users that have their password last set over X days ago, ordered by date")
    getinfo_switch.add_argument("--sidhist",dest="sidhist",default=False,action="store_true",help="Return a list of objects configured with SID History")
    getinfo_switch.add_argument("--foreignprivs",dest="foreignprivs",default=False,action="store_true",help="Return a list of objects that have controlling privileges into other domains")
    getinfo_switch.add_argument("--unsupported",dest="unsupos",default=False,action="store_true",help="Return a list of computers running an unsupported OS")
    getinfo_switch.add_argument("--sessions",dest="unamesess",default="",help="Return a list of computers that UNAME@DOMAIN.LOCAL has a session on")
    getinfo_switch.add_argument("--adminto",dest="unameadminto",default="",help="Return a list of computers that UNAME@DOMAIN.LOCAL is a local administrator to")
    getinfo_switch.add_argument("--adminsof",dest="comp",default="",help="Return a list of users that are administrators to COMP.DOMAIN.LOCAL")
    getinfo_switch.add_argument("--owned",dest="owned",default=False,action="store_true",help="Return all objects that are marked as owned")
    getinfo_switch.add_argument("--owned-groups",dest="ownedgroups",default=False,action="store_true",help="Return groups of all owned objects")
    getinfo_switch.add_argument("--owned-to-hvts",dest="ownedtohvts",default=False,action="store_true",help="Return all owned objects with paths to High Value Targets")
    getinfo_switch.add_argument("--hvt",dest="hvt",default=False,action="store_true",help="Return all objects that are marked as High Value Targets")
    getinfo_switch.add_argument("--desc",dest="desc",default=False,action="store_true",help="Return all objects with the description field populated, also returns description for easy grepping")
    getinfo_switch.add_argument("--admincomps",dest="admincomps",default=False,action="store_true",help="Return all computers with admin privileges to another computer [Comp1-AdminTo->Comp2]")
    getinfo_switch.add_argument("--path",dest="path",default="",help="Return the shortest path between two comma separated input nodes \"NODE1@DOMAIN.LOCAL, NODE 2@DOMAIN.LOCAL\" ")
    getinfo_switch.add_argument("--paths-all",dest="pathsall",default="",help="Return all paths between two comma separated input nodes \"NODE1@DOMAIN.LOCAL, NODE 2@DOMAIN.LOCAL\" ")
    getinfo_switch.add_argument("--hvt-paths",dest="hvtpaths",default="",help="Return all paths from the input node to HVTs")
    getinfo_switch.add_argument("--owned-paths",dest="ownedpaths",default=False,action="store_true",help="Return all paths from owned objects to HVTs")
    getinfo_switch.add_argument("--owned-admins", dest="ownedadmins",default=False,action="store_true",help="Return all computers owned users are admins to")

    getinfo.add_argument("--get-note",dest="getnote",default=False,action="store_true",help="Optional, return the \"notes\" attribute for whatever objects are returned")
    getinfo.add_argument("-l",dest="label",action="store_true",default=False,help="Optional, apply labels to the columns returned")
    getinfo.add_argument("-e","--enabled",dest="enabled",action="store_true",default=False,help="Optional, only return enabled domain users (only works for --users and --passnotreq flags as of now)")
    getinfo.add_argument("-d", "--delim",dest="delimeter", default="-", required=False, help="Flag to specify output delimeter between attributes (default '-')")

    # MARKOWNED function paramters
    markowned.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markowned.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (method of compromise)")
    markowned.add_argument("--clear",dest="clear",action="store_true",help="Remove owned marker from all objects")

    # MARKHVT function parameters
    markhvt.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markhvt.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (reason for HVT status)")
    markhvt.add_argument("--clear",dest="clear",action="store_true",help="Remove HVT marker from all objects")

    # QUERY function arguments
    query.add_argument("-q", "--query", dest="query", default=None, help="Single query designation")
    query.add_argument("-f", "--file", dest="file", default=None, help="File full of queries (will not show any query output)")
    query.add_argument("--path",dest="path", default=False, required=False, action="store_true", help="Flag to indicate output is a path")
    query.add_argument("-d", "--delim",dest="delimeter", default="-", required=False, help="Flag to specify output delimeter between attributes (default '-')")

    # EXPORT function parameters
    export.add_argument("NODENAME",help="Full name of node to extract info about (UNAME@DOMAIN/COMP.DOMAIN)")
    # export.add_argument("-t","--transitive",dest="transitive",action="store_true",help="Incorporate rights granted through nested groups ()")

    # DELETEEDGE function parameters
    deleteedge.add_argument("EDGENAME",help="Edge name, example: CanRDP, ExecuteDCOM, etc")
    deleteedge.add_argument("--starting-node",dest="STARTINGNODE",default="",required=False,help="Remove relationship from a specific node.")

    # ADDSPNS function parameters
    addspns_switch = addspns.add_mutually_exclusive_group(required=True)
    addspns_switch.add_argument("-b","--bloodhound",dest="blood",action="store_true",help="Uses information already stored in BloodHound (must have already ingested 'Detailed' user information)")
    addspns_switch.add_argument("-f","--file",dest="filename",default="",help="Standard file Format: Computer, User")
    addspns_switch.add_argument("-i","--impacket",dest="ifilename",default="",help="Impacket file Format: Output of GetUserSPNs.py")

    # ADDSPW function parameters
    addspw.add_argument("-f","--file",dest="filename",default="",required=True,help="Filename containing AD objects, one per line (must have FQDN attached)")

    # DPAT function parameters
    dpat.add_argument("-n","--ntds",dest="ntdsfile",default=None,required=False,help="NTDS file name")
    dpat.add_argument("-c","--crackfile",dest="crackfile",default=None,required=False,help="Potfile of cracked passwords, in either Hashcat/JTR format")
    dpat.add_argument("--noparse",dest="noparse",action="store_true",required=False,help="Don't parse any files, assume data is already stored in BloodHound")
    dpat.add_argument("--less",dest="less",action="store_true",required=False,help="Don't include high-intensity queries, recommended for large-scale AD environments (>50-75k objects)")
    dpat.add_argument("-p","--password",dest="passwd",default="",required=False,help="Returns all users using the argument as a password")
    dpat.add_argument("-u","--username",dest="usern",default="",required=False,help="Returns the password for the user if cracked")
    dpat.add_argument("-t","--threads",dest="num_threads",default=2,required=False,help="Number of threads to parse files, default 2")
    dpat.add_argument("-s","--sanitize",dest="sanitize",action="store_true",required=False,help="Sanitize the report by partially redacting passwords and hashes")
    dpat.add_argument("-S","--store",dest="store",action="store_true",required=False,help="Store all NTDS/Password data within the BH database, adds password/NT Hash/etc to each mapped user for easy access")
    dpat.add_argument("--clear",dest="clear",action="store_true",required=False,help="Clear all NTDS/Password data from the BH database")
    dpat.add_argument("-o","--output",dest="output",default="",required=False,help="Output file/dir name to store results, ASCII art if not set")
    dpat.add_argument("--csv",dest="csv",action="store_true",required=False,help="Store the output in a CSV format")
    dpat.add_argument("--html",dest="html",action="store_true",required=False,help="Store the output in HTML format")
    dpat.add_argument("--own-cracked", dest="own_cracked", action="store_true", required=False, help="Mark all users with cracked passwords as owned")
    dpat.add_argument("--add-crack-note",dest="add_crack_note",action="store_true",required=False,help="Add a note to cracked users indicating they have been cracked")

    args = parser.parse_args()


    if not do_test(args):
        print("Connection error: restart Neo4j console or verify the the following URL is available: {}".format(args.url))
        exit()

    if args.command == None:
        print("Error: use a module or use -h/--help to see help")
        return

    if args.username == "":
        args.username = input("Neo4j Username: ")
    if args.password == "":
        args.password = getpass.getpass(prompt="Neo4j Password: ")

    if args.command == "get-info":
        get_info(args)
    elif args.command == "mark-owned":
        if args.filename == "" and args.clear == False:
            print("Module mark-owned requires either -f filename or --clear options")
        else:
            mark_owned(args)
    elif args.command == "mark-hvt":
        if args.filename == "" and args.clear == False:
            print("Module mark-hvt requires either -f filename or --clear options")
        else:
            mark_hvt(args)
    elif args.command == "query":
        query_func(args)
    elif args.command == "export":
        export_func(args)
    elif args.command == "del-edge":
        delete_edge(args)
    elif args.command == "add-spns":
        add_spns(args)
    elif args.command == "add-spw":
        add_spw(args)
    elif args.command == "dpat":
        dpat_func(args)
    elif args.command == "pet-max":
        pet_max()
    # else:
    #     print("Error: use a module or use -h/--help to see help")


if __name__ == "__main__":
    main()
