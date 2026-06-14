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
                try:
                    node_dict[node['id']] = node['properties']['name']
                except:
                    node_dict[node['id']] = node['properties']['objectid']

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
            "query" : "MATCH (c:Computer) WHERE toLower(c.operatingsystem) =~ '.*(2000|2003|2008|xp|vista| 7 |me).*' RETURN c.name,c.operatingsystem",
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
        },
        "staleaccounts" : {
            "query" : "WITH datetime().epochseconds - ({threshold_days} * 86400) AS threshold MATCH (u:User {{enabled:TRUE}}) WHERE u.lastlogon < threshold AND u.lastlogontimestamp < threshold RETURN u.name",
            "columns" : ["UserName"]
        },
        "stalecomputers" : {
            # I'm not 100% sure if this is the last time the machine account logged in, or the last time a user logged into the machine. 
            # The general answer from MS seems to be "Don't use this, use event viewer"
            # Either way, this is the only relevant atribute bloodhound provides
            "query" : "WITH datetime().epochseconds - ({threshold_days} * 86400) AS threshold MATCH (c:Computer {{enabled:TRUE}}) WHERE c.lastlogon < threshold AND c.lastlogontimestamp < threshold RETURN c.name",
            "columns" : ["ComputerName"]
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
    elif (args.staleaccounts):
        query = queries["staleaccounts"]["query"].format(threshold_days=args.threshold)
        cols = queries["staleaccounts"]["columns"]
    elif (args.stalecomputers):
        query = queries["stalecomputers"]["query"].format(threshold_days=args.threshold)
        cols = queries["stalecomputers"]["columns"]
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

            if args.userpass is True or args.store:
                uname, passwd = line.strip().split(':')
                uname = uname.upper()
                if args.store:
                    passwd_query = "SET n.password=\"" + passwd + "\""
                else:
                    passwd_query = ""
            else:
                uname = line.upper().strip()

            query = 'MATCH (n) WHERE n.name="{uname}" SET n.owned=true {notes} {passwd} RETURN n'.format(uname=uname,passwd=passwd_query,notes=note_string)
            r = do_query(args, query)

            fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
            if r.text == fail_resp:
                print("[-] AD Object: " + uname + " could not be marked as owned")
            else:
                print("[+] AD Object: " + uname + " marked as owned successfully")


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
    for obj in objects:

        query = statement.format(uname=obj[1],comp=obj[0])

        r = do_query(args, query)

        fail_resp = '{"results":[{"columns":["n","m"],"data":[]}],"errors":[]}'
        if r.text == fail_resp:
            print("[-] Relationship " + obj[0] + " -- HasSPNConfigured -> " + obj[1] + " could not be added")
        else:
            print("[+] Relationship " + obj[0] + " -- HasSPNConfigured -> " + obj[1] + " added")
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
            elif lm_hash != "aad3b435b51404eeaad3b435b51404ee" and lm_hash[:16] in potfile and lm_hash[16:] in potfile:
                cracked_bool = 'true'
                password = potfile[lm_hash[:16]] + potfile[lm_hash[16:]]

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


def fetch_assets():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_files = {
        'bootstrap_css': os.path.join(script_dir, 'assets', 'bootstrap.min.css'),
        'bootstrap_js':  os.path.join(script_dir, 'assets', 'bootstrap.bundle.min.js'),
        'chartjs':       os.path.join(script_dir, 'assets', 'chart.umd.min.js'),
    }
    fallback_urls = {
        'bootstrap_css': 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
        'bootstrap_js':  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
        'chartjs':       'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
    }
    assets = {}
    for key, path in local_files.items():
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                assets[key] = f.read()
        else:
            print("[-] Local asset missing: {}, trying network...".format(path))
            try:
                r = requests.get(fallback_urls[key], timeout=15)
                assets[key] = r.text if r.status_code == 200 else ''
            except Exception:
                assets[key] = ''
    return assets


def dpat_func(args):

    query_counts = {}

    if args.clear:
        print("[+] Clearing attributes from all users: cracked, password, nt_hash, lm_hash, ntds_uname")
        clear_query = "MATCH (u:User) REMOVE u.cracked REMOVE u.nt_hash REMOVE u.lm_hash REMOVE u.ntds_uname REMOVE u.password"
        do_query(args,clear_query)
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

                        if len(line[0]) not in [16, 32]:
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
            'query' : "match p = (k:Group)<-[:MemberOf*1..]-(m) where k.highvalue = true WITH [ n in nodes(p) WHERE n:User] as ulist UNWIND (ulist) as u RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "High Value User Accounts"
        },
        {
            'query' : "match p = (k:Group)<-[:MemberOf*1..]-(m) where k.highvalue = true WITH [ n in nodes(p) WHERE n:User] as ulist UNWIND (ulist) as u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "High Value User Accounts Cracked"
        },
        {
            'query' : "match p = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid =~ '(?i)S-1-5-.*-512' with [ n IN nodes(p) WHERE n:User] as dalist unwind (dalist) as u RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "Domain Admin Members"
        },
        {
            'query' : "match p = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid =~ '(?i)S-1-5-.*-512' with [ n IN nodes(p) WHERE n:User] as dalist unwind (dalist) as u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Domain Admin Members Cracked"
        },
        {
            'query' : "match p = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid =~ '(?i)S-1-5-.*-519' with [ n IN nodes(p) WHERE n:User] as dalist unwind (dalist) as u RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "Enterprise Admin Members"
        },
        {
            'query' : "match p = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid =~ '(?i)S-1-5-.*-519' with [ n IN nodes(p) WHERE n:User] as dalist unwind (dalist) as u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            'label' : "Enterprise Admin Accounts Cracked"
        },
        {
            'query' : "match p = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid =~ '(?i).*S-1-5-.*-544' with [ n IN nodes(p) WHERE n:User] as dalist unwind (dalist) as u RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password",
            'label' : "Administrator Group Members"
        },
        {
            'query' : "match p = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid =~ '(?i).*S-1-5-.*-544' with [ n IN nodes(p) WHERE n:User] as dalist unwind (dalist) as u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
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
            "query" : "match k = (n:Group)<-[:MemberOf*1..]-(m) where n.objectid ENDS WITH '-516' AND NOT (n = m) with [c in nodes(k) WHERE c:Computer] as dcs match p = shortestPath((n)-[:HasSession|AdminTo|Contains|AZLogicAppContributor*1..]->(m {unconstraineddelegation: true})) where not (n = m) AND NOT ( m IN dcs ) with [ n IN nodes(p) WHERE n:User] as ulist UNWIND ulist as u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
            "label" : "Accounts With Paths To Unconstrained Delegation Objects Cracked (Excluding DCs)"
        },
        {
            "query" : "match p = shortestPath((u)-[*1..]->(n)) where n.highvalue = true AND u <> n WITH [n in nodes(p) WHERE n:User] as ulist UNWIND(ulist) as u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
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
            "query" : "MATCH p2=(n)-[r1:MemberOf*1..]->(g:Group)-[r2:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|CanRDP|CanPSRemote|ExecuteDCOM|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory]->(n2) WITH [u in nodes(p2) WHERE u:User] AS ulist UNWIND(ulist) AS u MATCH (u {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash",
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
                    user = [entry['row'][1], entry['row'][2], share_count, entry['row'][3]]
                    dat[status_flag].append(user)
                except:
                    pass

        if "cracked" in label.lower():
            dat['columns'] = ["Username", "Password", "Password Length", "NT Hash"]
            dat['enabled'] = sorted(dat['enabled'], key = lambda x: -1 if x[1] is None else len(x[1]), reverse=True)
            dat['disabled'] = sorted(dat['disabled'], key = lambda x: -1 if x[1] is None else len(x[1]), reverse=True)

        else:
            dat['columns'] = ["Username", "NT Hash", "Users Sharing this Hash", "Password"]
            dat['enabled'] = sorted(dat['enabled'], key = lambda x: -1 if x[2] is None else x[2], reverse=True)
            dat['disabled'] = sorted(dat['disabled'], key = lambda x: -1 if x[2] is None else x[2], reverse=True)

        query_output_data.append(dat)

    ###
    ### Get the Group Stats ready
    ###
    # TODO: Output group members in html output

    if not args.less:

        print("[+] Querying for Group Statistics")
        group_query_data = {}
        group_members = {}
        group_data = []

        # one-hop for accurate per-group stats (recursive inflates parent groups)
        stats_query = "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN DISTINCT g.name,u.name,u.ntds_uname,u.enabled,u.cracked,size(u.password),u.password,u.nt_hash,u.lm_hash,u.pwdlastset"
        r = do_query(args, stats_query)
        resp = json.loads(r.text)['results'][0]['data']
        for entry in resp:
            group_name   = entry['row'][0]
            username     = entry['row'][1]
            ntds_uname   = entry['row'][2]
            enabled      = entry['row'][3]
            crack_status = entry['row'][4]
            pwd_len      = entry['row'][5]
            password     = entry['row'][6]
            nt_hash      = entry['row'][7]
            lm_hash      = entry['row'][8]
            pwdlastset   = entry['row'][9]

            if group_name not in group_query_data:
                group_query_data[group_name] = []
                group_members[group_name] = []
            group_query_data[group_name].append([username, crack_status])
            group_members[group_name].append([username, ntds_uname, enabled, crack_status, pwd_len, password, nt_hash, lm_hash, pwdlastset])

        for group_name in group_query_data:
            cracked_total = sum(u[1] == True for u in group_query_data[group_name])
            perc = round(100 * float(cracked_total / len(group_query_data[group_name])), 2)
            group_data.append([group_name, perc, cracked_total, len(group_query_data[group_name])])
        group_data = sorted(group_data, key=lambda x: x[2], reverse=True)

        # Build user → groups mapping and user info for clickable user details
        # Key by ntds_uname since that's what tables display
        user_groups = {}
        user_info = {}
        for group_name, members in group_members.items():
            for m in members:
                ntds_uname = m[1]  # Tables use ntds_uname format
                if ntds_uname and ntds_uname not in user_groups:
                    user_groups[ntds_uname] = []
                    user_info[ntds_uname] = {
                        'name': m[0],
                        'enabled': m[2],
                        'cracked': m[3],
                        'pwd_len': m[4],
                        'password': m[5],
                        'nt_hash': m[6],
                        'lm_hash': m[7],
                        'pwdlastset': m[8]
                    }
                if ntds_uname:
                    user_groups[ntds_uname].append(group_name)

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
    print("[+] Querying for LM hash statistics")
    query = "MATCH (u:User) WHERE u.lm_hash IS NOT NULL AND NOT u.lm_hash='aad3b435b51404eeaad3b435b51404ee' RETURN u.lm_hash,count(u.lm_hash)"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    lm_hash_counts = {}
    for entry in resp:
        lm_hash_counts[entry['row'][0]] = entry['row'][1]
    non_blank_lm = sum(lm_hash_counts.values())
    uniq_lm = len(lm_hash_counts)

    # lm hash users
    query = "MATCH (u:User) WHERE u.lm_hash IS NOT NULL AND NOT u.lm_hash='aad3b435b51404eeaad3b435b51404ee' RETURN u.ntds_uname,u.lm_hash,u.enabled,u.cracked,u.password"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']

    lm_hash_list = []
    for entry in resp:
        ntds_uname = entry['row'][0]
        lm_hash = entry['row'][1]
        enabled = entry['row'][2]
        cracked = entry['row'][3]
        password = entry['row'][4]
        enabled_display = "Enabled" if enabled else "Disabled"
        password_display = dpat_sanitize(args, password) if cracked and password else ""
        shared_count = lm_hash_counts[lm_hash]
        lm_hash_list.append([ntds_uname, enabled_display, dpat_sanitize(args, lm_hash), password_display, shared_count])
    lm_hash_list = sorted(lm_hash_list, key = lambda x: x[4], reverse=True)

    # matching username/password
    print("[+] Querying for username matching password")
    query = "MATCH (u:User {cracked:true}) WHERE toUpper(SPLIT(u.name,'@')[0])=toUpper(u.password) RETURN u.ntds_uname,u.password,u.nt_hash"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    user_pass_match_list = []
    for entry in resp:
        user_pass_match_list.append([entry['row'][0],dpat_sanitize(args,entry['row'][1]),len(entry['row'][1]),entry['row'][2]])
    user_pass_match = len(user_pass_match_list)

    # Get Password Length Stats
    print("[+] Querying for password length distribution")
    query = "MATCH (u:User {cracked:true}) WHERE NOT u.password='' RETURN  COUNT(SIZE(u.password)), SIZE(u.password) AS sz ORDER BY sz DESC"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    password_lengths = []
    for entry in resp:
        password_lengths.append(entry['row'])

    # Get Password (Complexity) Stats
    # sort from most reused to least reused dict to list of tuples
    # Get all shared hashes (regardless of cracked status) with password if known
    print("[+] Querying for shared password hashes")
    query = "MATCH (u:User) WHERE u.nt_hash IS NOT NULL RETURN COUNT(u.nt_hash) AS count, u.nt_hash, COLLECT(DISTINCT u.password)[0] AS password ORDER BY count DESC"
    r = do_query(args, query)
    resp = json.loads(r.text)['results'][0]['data']
    shared_hashes = []
    for entry in resp:
        count = entry['row'][0]
        nt_hash = entry['row'][1]
        password = entry['row'][2] if entry['row'][2] else None
        if count > 1:
            shared_hashes.append([count, nt_hash, password])
    num_shared_hashes = len(shared_hashes)

    # Get users per shared hash for drill-down
    print("[+] Querying users per shared hash ({} hashes)".format(num_shared_hashes))
    hash_users = {}
    for sh in shared_hashes:
        nt_hash = sh[1]
        query = "MATCH (u:User) WHERE u.nt_hash='{}' RETURN u.ntds_uname, u.enabled, u.cracked".format(nt_hash)
        r = do_query(args, query)
        resp_users = json.loads(r.text)['results'][0]['data']
        hash_users[nt_hash] = [entry['row'] for entry in resp_users]

    # Keep old format for backward compatibility (cracked passwords only)
    repeated_passwords = [[sh[0], sh[2]] for sh in shared_hashes if sh[2]]
    num_repeated_passwords = len(repeated_passwords)
    tot_num_repeated_passwords = num_repeated_passwords
    password_users = {sh[2]: hash_users[sh[1]] for sh in shared_hashes if sh[2]}

    # Passwords not meeting Complexity Requirement
    print("[+] Analyzing password complexity")
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

    # End-of-Life / Unsupported Operating Systems
    print("[+] Querying for unsupported operating systems")
    eol_query = """
    MATCH (c:Computer)
    WHERE c.operatingsystem =~ '(?i).*Windows.*(2000|2003|2008|2012|xp|vista|7|8|10|me|nt).*'
    AND NOT c.operatingsystem =~ '(?i).*Windows.*11.*'
    RETURN c.name, c.operatingsystem, c.enabled
    ORDER BY c.operatingsystem
    """
    r = do_query(args, eol_query)
    resp = json.loads(r.text)['results'][0]['data']
    eol_computers = [[entry['row'][0], entry['row'][1], 'Yes' if entry['row'][2] else 'No'] for entry in resp]
    num_eol_computers = len(eol_computers)

    # all stats
    stats = [
        [num_pass_hashes, "Password Hashes", ["NTDS Username", "Password", "Password Length", "NT Hash", "Pwd Last Set"], num_pass_hashes_list], #, ntds_parsed],
        [num_uniq_hash, "Unique Password Hashes"],
        [num_cracked, "Passwords Discovered Through Cracking"],
        [perc_total_cracked, "Percent of Passwords Cracked"],
        [perc_uniq_cracked, "Percent of Unique Passwords Cracked"],
        [non_blank_lm, "LM Hashes (Non-Blank)", ["NTDS Username", "Status", "LM Hash", "Password", "Shared Count"], lm_hash_list],
        [uniq_lm, "Unique LM Hashes (Non-Blank)"],
        [user_pass_match, "Users with Username Matching Password", ["NTDS Username", "Password", "Password Length", "NT Hash"], user_pass_match_list],
        [len(password_lengths), "Password Length Stats", ['Count', 'Number of Characters'], password_lengths],
        [len(password_complexity), "Password Complexity Stats", ['Username', 'Password', "Meets Complexity Requirements"], password_complexity],
        [num_shared_hashes, "Password Reuse Stats", ['Users', 'NT Hash', 'Password'], shared_hashes],
        [num_eol_computers, "Unsupported Operating Systems", ["Computer Name", "Operating System", "Enabled"], eol_computers],
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

    # Generate HTML report (always uses retro Windows 2008 theme)
    args.retro = True

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    base = args.output.rstrip('/\\') if args.output else "report"
    output_file = "{}_{}.html".format(base, timestamp)

    print("[+] Fetching assets for offline report...")
    assets = fetch_assets()
    if not assets.get('bootstrap_css'):
        print("[-] Warning: Could not fetch Bootstrap CSS, report may have limited styling")

    category_map = {
        'Summary': 'Overview',
        'Password Hashes': 'Password Stats',
        'LM Hashes (Non-Blank)': 'Password Stats',
        'Users with Username Matching Password': 'Password Stats',
        'Password Length Stats': 'Password Stats',
        'Password Complexity Stats': 'Password Stats',
        'Password Reuse Stats': 'Password Stats',
        'Groups Cracked by Percentage': 'All Groups',
        'Group Membership Ranking': 'Privileged Accounts',
        'All User Accounts': 'All Accounts',
        'All User Accounts Cracked': 'All Accounts',
        'Enabled User Accounts Cracked': 'All Accounts',
        'High Value User Accounts': 'Privileged Accounts',
        'High Value User Accounts Cracked': 'Privileged Accounts',
        'Domain Admin Members': 'Privileged Accounts',
        'Domain Admin Members Cracked': 'Privileged Accounts',
        'Enterprise Admin Members': 'Privileged Accounts',
        'Enterprise Admin Accounts Cracked': 'Privileged Accounts',
        'Administrator Group Members': 'Privileged Accounts',
        'Administrator Group Member Accounts Cracked': 'Privileged Accounts',
        'Kerberoastable Users Cracked': 'Escalation Paths',
        'Accounts Not Requiring Kerberos Pre-Authentication Cracked': 'Escalation Paths',
        'Unconstrained Delegation Accounts Cracked': 'Escalation Paths',
        'Inactive Accounts (Last Used Over 6mos Ago) Cracked': 'Escalation Paths',
        'Accounts With Passwords Set Over 1yr Ago Cracked': 'Escalation Paths',
        'Accounts With Passwords That Never Expire Cracked': 'Escalation Paths',
        'Accounts With Paths To Unconstrained Delegation Objects Cracked (Excluding DCs)': 'Escalation Paths',
        'Accounts With Paths To High Value Targets Cracked': 'Escalation Paths',
        'Accounts With Explicit Admin Rights Cracked': 'Escalation Paths',
        'Accounts With Group Delegated Admin Rights Cracked': 'Escalation Paths',
        'Accounts With Explicit Controlling Privileges Cracked': 'Escalation Paths',
        'Accounts With Group Delegated Controlling Privileges Cracked': 'Escalation Paths',
        'Unsupported Operating Systems': 'Infrastructure Risk',
    }
    category_order = ['Overview', 'Password Stats', 'All Groups', 'All Accounts',
                      'Privileged Accounts', 'Escalation Paths', 'Infrastructure Risk']

    class SingleFileHtmlBuilder:

        def __init__(self, assets, args, cat_order, report_name='report'):
            self.assets = assets
            self.args = args
            self.sections = []
            self.section_categories = {}
            self.cat_order = list(cat_order)
            self.deferred_scripts = []
            self.report_name = report_name
            # Icons for retro mode table rows
            self.user_icon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgBAMAAACBVGfHAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAElBMVEUAAAAAAAD////AwMAAAIAAAP/jaa47AAAAAXRSTlMAQObYZgAAAAFiS0dEAmYLfGQAAAAHdElNRQfiBBAHOBQ6y591AAAAiklEQVQoz52QwQ3DIBAEQUoBrF0BujTAJQ3Ykgvwg/5bCZwjsRfLD2dfMBpYuBD+TQSQfvaOAJ7EL8Al6OtJtYAFEcmJQBO08BVNeC5kdOG90h2zWJIzWgYwJXOtcks4WiTzZ70Rj5ZhBExldBiYhf5qhuqLR7hgPLPnUSvcka1aEgmW/RKcZnwzH3+2Gx0TJwQiAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE4LTA0LTE2VDA3OjU2OjIwLTA0OjAw5EF/4AAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wNC0xNlQwNzo1NjoyMC0wNDowMJUcx1wAAAAASUVORK5CYII='
            self.group_icon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAG1BMVEUAAAAAAACAgIDAwMD/////AACAAAAAAIAAAP9Yj2HtAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBhoANiXlpBdAAAABXElEQVQ4y42TPXKEMAyFodoWjMmkxTcwYpKalS+QAm7AXgHaVHDslX8xxpmJZihWT5/0rLWL4n9R1hSZfG2jypVnlDOfdIvyFyQGIqSsmRAZwf4SXSKELqy7CFF3Rh+AdMPjoV0NSqHM2KG8UvIG1LUKQpkKshNVVmCsr66dtB2uFEB3HQGIKGnAyLGKO8FAkREaREc4V17Q5Z3gd4HKyY4TdC8nNESQncHkAYJgJowcDIFmuaWvpxkNNpbwrqyj09XTC3zwIfWQnt0J1EOwD4IHwE0PSwRXT+fUwhiW6BECEMwpvF+HPLmS17tjffWMCBGu57lb1LuCIJR2t25GJBRmtfbgdHncH2sZewaA9gX4tZxIaaqp4zy/YJl/EkK0C8Vrmk5kNceAj1lHO53ItuorAreH9jgOzcR2gkAKfG/p+96Ofd9X2Pbfm7BRrMeRII/dxueaIvl3/1e8AYOsgIp+47wjAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE4LTA2LTI2VDAwOjU0OjM3LTA0OjAws+TK4AAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wNi0yNlQwMDo1NDozNy0wNDowMMK5clwAAAAASUVORK5CYII='
            self.computer_icon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAIVBMVEUAAACAgIDAwMAAAAD///8AgIAA//8AAIAAAP8A/wAAgACZBxulAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBBMBJCt84jxJAAAA5UlEQVQ4y62TyxHCIBCGoYQFGghJASBagJEGMk6sxbsXW/Dq0SpNsuSxPEad8ePGNz9kNwtjExwobEZoApiwz+l+tQjlCTAL3kYnfSFqt6KI6FeouJTFGQ86JKLDi2PR9x3WkIjrfeSWCuxWnQrsyumPwpVEUnlZhNamotTE38VmpohotkMyCGfywyChzgsrZHZyJVQomKNYASggpkLBfQwEEd09zugn8XguL2NArOI1i2m4dx+PUjoVJhvQFgON9GS1lcXAcU+XBlcIQBzwIVD4pPD8VdpBbHmmCJP/FyHApIvBwBu9bp7SZvn+ewAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxOC0wNC0xOVQwMTozNjo0My0wNDowMNV8Hl4AAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTgtMDQtMTlUMDE6MzY6NDMtMDQ6MDCkIabiAAAAAElFTkSuQmCC'
            self.folder_icon = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAGFBMVEUAAACZmQAAAAD4+Pj//5nMzGb/zJn////5no2yAAAAAXRSTlMAQObYZgAAAAFiS0dEBxZhiOsAAAAHdElNRQfiBhgXARMJeV+TAAABE0lEQVQ4y82TzQ3CMAyFywhtxb1iA1QWQLJ858AGlvcfAfs5aRMTceapaoVfPv9FTNMPzdDyFb/s0H3LxkqhjFwexXhuYyAjB5CRE0jI9X3qNVfZkXUfautSFQkzL9nwIAlJNixExKSJELGgQJlge9jzJQPnzeoJL4uPDAiORB3B3pM34J52hADg1BVXE3ZbA785sCZVBULt5BwtAUuTCypEiSNVNCmM8UTTrsxTL66kzRyOYOGoXYuXRB40wLrVbkAUttdRg33dFL16Lj264siF9OThZkBcKqFVrYSfjWVo7MuIdkBcNoBzV1K2YQQ+Gqk8HPtGYXZIK1EuNJwyIGagGE2RSNHudR5qmW5jff2F/1wfr4rjk5A1shsAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTgtMDYtMjRUMjM6MDE6MTktMDQ6MDDthFzGAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE4LTA2LTI0VDIzOjAxOjE5LTA0OjAwnNnkegAAAABJRU5ErkJggg=='

        def _sid(self, text):
            return ''.join(c if c.isalnum() else '_' for c in str(text))[:60]

        def _make_table(self, data, headers, col_to_not_escape=None, row_icon=None):
            if not data:
                return '<p class="text-muted fst-italic">No data found.</p>'
            is_retro = getattr(self.args, 'retro', False)
            # Known empty password hash
            EMPTY_PWD_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'
            html = '<div class="table-responsive"><table class="clean-table">\n'
            html += '<thead><tr>'
            for h in headers:
                html += '<th>{}</th>'.format(htmllib.escape(str(h)) if h else '')
            html += '</tr></thead>\n<tbody>\n'
            for row in data:
                html += '<tr>'
                # Check if this row has the empty password hash
                row_has_empty_hash = any(str(c).lower() == EMPTY_PWD_HASH for c in row if c)
                for col_num, cell in enumerate(row):
                    val = str(cell) if cell is not None else ''
                    original_val = val  # Keep original for username lookup
                    col_name = str(headers[col_num]) if col_num < len(headers) else ''
                    is_pwd_col = "Password" in col_name and "Password Length" not in col_name
                    is_username_col = "Username" in col_name or col_name == "User"
                    if (is_pwd_col or
                            ("Hash" in col_name and "Users Sharing this Hash" not in col_name) or
                            ("History" in col_name)):
                        val = dpat_sanitize(self.args, val)
                    if col_to_not_escape is None or col_num != col_to_not_escape:
                        val = htmllib.escape(val)
                    # Mark blank passwords with styled indicator
                    if is_pwd_col and val == '' and row_has_empty_hash:
                        val = '<em style="color:#888;font-style:italic;">blank password</em>'
                    if col_num == 0 and row_icon and is_retro:
                        val = '<img src="{}" class="row-icon">{}'.format(row_icon, val)
                    # Make usernames clickable
                    if is_username_col and original_val:
                        val = self.make_username_clickable(original_val, val)
                    html += '<td>{}</td>'.format(val)
                html += '</tr>\n'
            html += '</tbody></table></div>\n'
            return html

        def add_section(self, section_id, title, content_html, category='Other', deferred_js='', sidebar=True):
            self.sections.append({'id': section_id, 'title': title, 'content': content_html, 'sidebar': sidebar})
            self.section_categories[section_id] = category
            if sidebar and category not in self.cat_order:
                self.cat_order.append(category)
            if deferred_js:
                self.deferred_scripts.append(deferred_js)

        def build_homepage(self, homepage_data, summary_table_html):
            total = homepage_data['total_users']
            cracked = homepage_data['total_cracked']
            perc = homepage_data['perc_cracked']
            user_pass = homepage_data['username_eq_password']
            lm = homepage_data['lm_hashes']
            crack_bar_w = min(100, int(float(perc))) if perc else 0
            is_retro = getattr(self.args, 'retro', False)
            bar_bg = '' if is_retro else 'background:#4b5563;'

            # weighted risk score to filter top 10, then sort final list by percentage
            top_groups = sorted(
                sorted(homepage_data.get('top_groups', []),
                       key=lambda x: x[2] * (x[1] / 100.0), reverse=True)[:10],
                key=lambda x: x[1], reverse=True)

            # password lengths ascending by length
            pw_lengths = sorted(homepage_data.get('password_lengths', []), key=lambda x: x[0], reverse=True)
            max_len_count = max((x[0] for x in pw_lengths), default=1)

            # complexity counts
            pw_complexity = homepage_data.get('password_complexity', [])
            meets = sum(1 for x in pw_complexity if x[2])
            fails = len(pw_complexity) - meets
            total_c = meets + fails
            meets_pct = round(100 * meets / total_c, 1) if total_c else 0
            fails_pct = round(100 * fails / total_c, 1) if total_c else 0

            # reused passwords
            repeated = homepage_data.get('repeated_passwords', [])

            # query output data lookup
            qod = {}
            for item in homepage_data.get('query_output_data', []):
                qod[item['label']] = len(item['enabled']) + len(item['disabled'])

            # --- Stat cards ---
            if is_retro:
                # Get all the stats
                da_total = qod.get('Domain Admin Members', 0)
                da_cracked = qod.get('Domain Admin Members Cracked', 0)
                da_pct = round(100 * da_cracked / da_total, 1) if da_total else 0
                ea_total = qod.get('Enterprise Admin Members', 0)
                ea_cracked = qod.get('Enterprise Admin Accounts Cracked', 0)
                ea_pct = round(100 * ea_cracked / ea_total, 1) if ea_total else 0
                admin_total = qod.get('Administrator Group Members', 0)
                admin_cracked = qod.get('Administrator Group Member Accounts Cracked', 0)
                admin_pct = round(100 * admin_cracked / admin_total, 1) if admin_total else 0
                kerb_cracked = qod.get('Kerberoastable Users Cracked', 0)
                asrep_cracked = qod.get('Accounts Not Requiring Kerberos Pre-Authentication Cracked', 0)
                uncon_cracked = qod.get('Unconstrained Delegation Accounts Cracked', 0)
                inactive_cracked = qod.get('Inactive Accounts (Last Used Over 6mos Ago) Cracked', 0)
                old_pwd_cracked = qod.get('Accounts With Passwords Set Over 1yr Ago Cracked', 0)
                no_expire_cracked = qod.get('Accounts With Passwords That Never Expire Cracked', 0)
                hv_cracked = qod.get('High Value User Accounts Cracked', 0)
                all_cracked_count = qod.get('All User Accounts Cracked', 0)
                enabled_cracked = qod.get('Enabled User Accounts Cracked', 0)
                # Calculate hygiene percentages (of cracked accounts)
                enabled_pct = round(100 * enabled_cracked / all_cracked_count, 1) if all_cracked_count else 0
                inactive_pct = round(100 * inactive_cracked / all_cracked_count, 1) if all_cracked_count else 0
                old_pwd_pct = round(100 * old_pwd_cracked / all_cracked_count, 1) if all_cracked_count else 0
                no_expire_pct = round(100 * no_expire_cracked / all_cracked_count, 1) if all_cracked_count else 0

                # Windows 2008 MMC detail view style tables
                tbl_style = 'width:100%;border-collapse:collapse;font-size:11px;'
                th_style = 'background:#fff;border-right:1px solid #d4d0c8;border-bottom:1px solid #d4d0c8;padding:3px 8px;text-align:left;font-weight:normal;'
                td_style = 'border-bottom:1px solid #f0f0f0;border-right:1px solid #f0f0f0;padding:2px 6px;'
                td_num = td_style + 'text-align:right;font-weight:bold;'
                bar_cell = 'width:100px;padding:2px 4px;'

                def make_bar(pct):
                    return '<div class="progress" style="height:12px;"><div class="progress-bar" style="width:{}%"></div></div>'.format(pct)

                def row_click(section_title):
                    sid = self._sid(section_title)
                    return 'style="cursor:pointer;" onclick="navigateTo(\'{}\');"'.format(sid)

                cards = (
                    # Row 1: Password Audit Summary + Privileged Account Exposure
                    '<div style="display:flex;gap:8px;margin-bottom:8px;">'
                    '<fieldset class="win98-fieldset" style="flex:1;"><legend>Password Audit Summary</legend>'
                    '<table style="{}">'.format(tbl_style) +
                    '<tr><th style="{}">Metric</th><th style="{}">Value</th><th style="{}">Visual</th></tr>'.format(th_style, th_style, th_style + bar_cell) +
                    '<tr {}><td style="{}">Total Accounts</td><td style="{}">{}</td><td style="{}"></td></tr>'.format(row_click('All User Accounts'), td_style, td_num, total, td_style + bar_cell) +
                    '<tr {}><td style="{}">Passwords Cracked</td><td style="{}">{} ({}%)</td><td style="{}">{}</td></tr>'.format(row_click('All User Accounts Cracked'), td_style, td_num, cracked, perc, td_style + bar_cell, make_bar(float(perc) if perc else 0)) +
                    '<tr {}><td style="{}">Username = Password</td><td style="{}">{}</td><td style="{}"></td></tr>'.format(row_click('Users with Username Matching Password'), td_style, td_num, user_pass, td_style + bar_cell) +
                    '<tr {}><td style="{}">LM Hashes Present</td><td style="{}">{}</td><td style="{}"></td></tr>'.format(row_click('LM Hashes (Non-Blank)'), td_style, td_num, lm, td_style + bar_cell) +
                    '</table></fieldset>'
                    '<fieldset class="win98-fieldset" style="flex:1;"><legend>Privileged Account Exposure</legend>'
                    '<table style="{}">'.format(tbl_style) +
                    '<tr><th style="{}">Account Type</th><th style="{}">Total</th><th style="{}">Cracked</th><th style="{}">Percent</th><th style="{}">Visual</th></tr>'.format(th_style, th_style, th_style, th_style, th_style + bar_cell) +
                    '<tr {}><td style="{}">Domain Admins</td><td style="{}">{}</td><td style="{}">{}</td><td style="{}">{}%</td><td style="{}">{}</td></tr>'.format(row_click('Domain Admin Members Cracked'), td_style, td_num, da_total, td_num, da_cracked, td_num, da_pct, td_style + bar_cell, make_bar(da_pct)) +
                    '<tr {}><td style="{}">Enterprise Admins</td><td style="{}">{}</td><td style="{}">{}</td><td style="{}">{}%</td><td style="{}">{}</td></tr>'.format(row_click('Enterprise Admin Accounts Cracked'), td_style, td_num, ea_total, td_num, ea_cracked, td_num, ea_pct, td_style + bar_cell, make_bar(ea_pct)) +
                    '<tr {}><td style="{}">Administrator Group</td><td style="{}">{}</td><td style="{}">{}</td><td style="{}">{}%</td><td style="{}">{}</td></tr>'.format(row_click('Administrator Group Member Accounts Cracked'), td_style, td_num, admin_total, td_num, admin_cracked, td_num, admin_pct, td_style + bar_cell, make_bar(admin_pct)) +
                    '</table></fieldset>'
                    '</div>'
                    # Row 2: Account Hygiene + Attack Surface
                    '<div style="display:flex;gap:8px;">'
                    '<fieldset class="win98-fieldset" style="flex:1;"><legend>Account Hygiene (of {} cracked)</legend>'.format(all_cracked_count) +
                    '<table style="{}">'.format(tbl_style) +
                    '<tr><th style="{}">Issue</th><th style="{}">Count</th><th style="{}">% of Cracked</th></tr>'.format(th_style, th_style, th_style + bar_cell) +
                    '<tr {}><td style="{}">Enabled Accounts</td><td style="{}">{}</td><td style="{}">{}</td></tr>'.format(row_click('Enabled User Accounts Cracked'), td_style, td_num, enabled_cracked, td_style + bar_cell, make_bar(enabled_pct)) +
                    '<tr {}><td style="{}">Inactive (6+ months)</td><td style="{}">{}</td><td style="{}">{}</td></tr>'.format(row_click('Inactive Accounts (Last Used Over 6mos Ago) Cracked'), td_style, td_num, inactive_cracked, td_style + bar_cell, make_bar(inactive_pct)) +
                    '<tr {}><td style="{}">Passwords Over 1yr</td><td style="{}">{}</td><td style="{}">{}</td></tr>'.format(row_click('Accounts With Passwords Set Over 1yr Ago Cracked'), td_style, td_num, old_pwd_cracked, td_style + bar_cell, make_bar(old_pwd_pct)) +
                    '<tr {}><td style="{}">Never-Expiring</td><td style="{}">{}</td><td style="{}">{}</td></tr>'.format(row_click('Accounts With Passwords That Never Expire Cracked'), td_style, td_num, no_expire_cracked, td_style + bar_cell, make_bar(no_expire_pct)) +
                    '</table></fieldset>'
                    '<fieldset class="win98-fieldset" style="flex:1;"><legend>Attack Surface (Cracked)</legend>'
                    '<table style="{}">'.format(tbl_style) +
                    '<tr><th style="{}">Category</th><th style="{}">Count</th></tr>'.format(th_style, th_style) +
                    '<tr {}><td style="{}">Kerberoastable Users</td><td style="{}">{}</td></tr>'.format(row_click('Kerberoastable Users Cracked'), td_style, td_num, kerb_cracked) +
                    '<tr {}><td style="{}">AS-REP Roastable</td><td style="{}">{}</td></tr>'.format(row_click('Accounts Not Requiring Kerberos Pre-Authentication Cracked'), td_style, td_num, asrep_cracked) +
                    '<tr {}><td style="{}">Unconstrained Delegation</td><td style="{}">{}</td></tr>'.format(row_click('Unconstrained Delegation Accounts Cracked'), td_style, td_num, uncon_cracked) +
                    '<tr {}><td style="{}">High Value Cracked</td><td style="{}">{}</td></tr>'.format(row_click('High Value User Accounts Cracked'), td_style, td_num, hv_cracked) +
                    '</table></fieldset>'
                    '</div>'
                )
            else:
                cards = (
                    '<div class="row g-3 mb-4">'
                    '<div class="col-md-3"><div class="card border p-3 h-100">'
                    '<div class="text-muted small mb-1">Total Accounts</div>'
                    '<div class="h3 fw-bold mb-0">{total}</div>'
                    '</div></div>'
                    '<div class="col-md-3"><div class="card border p-3 h-100">'
                    '<div class="text-muted small mb-1">Passwords Cracked</div>'
                    '<div class="h3 fw-bold mb-0">{cracked} <span class="fs-6 fw-normal text-muted">{perc}%</span></div>'
                    '</div></div>'
                    '<div class="col-md-3"><div class="card border p-3 h-100">'
                    '<div class="text-muted small mb-1">Username = Password</div>'
                    '<div class="h3 fw-bold mb-0">{user_pass}</div>'
                    '</div></div>'
                    '<div class="col-md-3"><div class="card border p-3 h-100">'
                    '<div class="text-muted small mb-1">LM Hashes Present</div>'
                    '<div class="h3 fw-bold mb-0">{lm}</div>'
                    '</div></div>'
                    '</div>'
                ).format(total=total, cracked=cracked, perc=perc, user_pass=user_pass, lm=lm)

            # --- Top groups with search ---
            group_bars = ''
            for idx, g in enumerate(top_groups):
                gname = htmllib.escape(g[0].split('@')[0][:45])
                gperc = g[1]
                gcracked = g[2]
                gtotal = g[3]
                bar_w = min(100, int(float(gperc)))
                group_bars += (
                    '<div class="group-item mb-2" data-name="{raw}" '
                    'style="cursor:pointer;" onclick="navigateTo(\'grp_detail_{idx}\');">'
                    '<div class="d-flex justify-content-between small mb-1">'
                    '<span>{name}</span>'
                    '<span class="text-muted">{c}/{t} &nbsp;<strong>{p}%</strong></span>'
                    '</div>'
                    '<div class="progress" style="height:14px;">'
                    '<div class="progress-bar" style="{bar_bg}width:{w}%"></div>'
                    '</div></div>'
                ).format(raw=gname.lower(), idx=idx, name=gname, c=gcracked, t=gtotal, p=gperc, w=bar_w, bar_bg=bar_bg)

            if not group_bars:
                group_bars = '<p class="text-muted small">No group data available.</p>'

            # --- Privileged accounts — compact single card ---
            def priv_bar_row(label, total_key, cracked_key):
                t = qod.get(total_key, 0)
                c = qod.get(cracked_key, 0)
                w = min(100, int(100 * c / t)) if t else 0
                pct = round(100 * c / t, 1) if t else 0
                return (
                    '<div class="mb-2">'
                    '<div class="d-flex justify-content-between small mb-1">'
                    '<span>{label}</span>'
                    '<span class="text-muted">{c}/{t} &nbsp;<strong>{pct}%</strong></span>'
                    '</div>'
                    '<div class="progress" style="height:14px;">'
                    '<div class="progress-bar" style="{bar_bg}width:{w}%"></div>'
                    '</div></div>'
                ).format(label=label, c=c, t=t, pct=pct, w=w, bar_bg=bar_bg)

            def priv_count_row(label, cracked_key):
                c = qod.get(cracked_key, 0)
                return (
                    '<div class="d-flex justify-content-between small py-1 border-bottom">'
                    '<span>{label}</span>'
                    '<span><strong>{c}</strong> cracked</span>'
                    '</div>'
                ).format(label=label, c=c)

            priv_card_content = (
                priv_bar_row('Domain Admins', 'Domain Admin Members', 'Domain Admin Members Cracked')
                + priv_bar_row('Enterprise Admins', 'Enterprise Admin Members', 'Enterprise Admin Accounts Cracked')
                + priv_bar_row('Admin Group', 'Administrator Group Members', 'Administrator Group Member Accounts Cracked')
                + '<hr class="my-2">'
                + priv_count_row('Kerberoastable', 'Kerberoastable Users Cracked')
                + priv_count_row('AS-REP Roastable', 'Accounts Not Requiring Kerberos Pre-Authentication Cracked')
                + priv_count_row('Unconstrained Delegation', 'Unconstrained Delegation Accounts Cracked')
            )
            priv_card_html = '<div class="small fw-semibold mb-3">Privileged Account Exposure</div>' + priv_card_content

            if is_retro:
                row2 = (
                    '<div style="display:flex;gap:8px;margin-bottom:8px;">'
                    '<fieldset class="win98-fieldset" style="flex:1;">'
                    '<legend>Highest Risk Groups</legend>'
                    '{bars}'
                    '</fieldset>'
                    '<fieldset class="win98-fieldset" style="flex:1;">'
                    '<legend>Password Length Distribution</legend>'
                    '{len_placeholder}'
                    '</fieldset>'
                    '</div>'
                )
            else:
                row2 = (
                    '<div class="row g-3 mb-4">'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Highest Risk Groups</div>'
                    '{bars}'
                    '</div></div>'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Password Length Distribution</div>'
                    '{len_placeholder}'
                    '</div></div>'
                    '</div>'
                )

            row3 = ''

            # --- Password length distribution ---
            len_section_id = self._sid('Password Length Stats')
            len_bars = ''
            for count, length in pw_lengths:
                bar_w = int(100 * count / max_len_count) if max_len_count else 0
                len_bars += (
                    '<div class="d-flex align-items-center mb-1 small" '
                    'style="cursor:pointer;" onclick="navigateTo(\'{sid}\');">'
                    '<span style="width:28px;text-align:right;margin-right:8px;">{length}</span>'
                    '<div class="progress flex-grow-1" style="height:14px;">'
                    '<div class="progress-bar" style="{bar_bg}width:{w}%">'
                    '<span class="ms-1">{count}</span>'
                    '</div></div></div>'
                ).format(sid=len_section_id, length=length, count=count, w=bar_w, bar_bg=bar_bg)
            if not len_bars:
                len_bars = '<p class="text-muted small">No data.</p>'

            # --- Complexity ---
            complexity_section_id = self._sid('Password Complexity Stats')
            complexity_html = (
                '<div style="cursor:pointer;" onclick="navigateTo(\'{sid}\');">'
                '<div class="d-flex justify-content-between small mb-1">'
                '<span>Meets Complexity</span><span>{meets} ({meets_pct}%)</span></div>'
                '<div class="progress mb-3" style="height:14px;">'
                '<div class="progress-bar" style="{bar_bg}width:{meets_w}%"></div></div>'
                '<div class="d-flex justify-content-between small mb-1">'
                '<span>Fails Complexity</span><span>{fails} ({fails_pct}%)</span></div>'
                '<div class="progress mb-3" style="height:14px;">'
                '<div class="progress-bar" style="width:{fails_w}%;{bar_bg}"></div></div>'
                '</div>'
                '<div class="text-muted" style="font-size:.72rem;">of {total_c} cracked passwords</div>'
            ).format(sid=complexity_section_id, meets=meets, meets_pct=meets_pct, meets_w=int(meets_pct),
                     fails=fails, fails_pct=fails_pct, fails_w=int(fails_pct), total_c=total_c, bar_bg=bar_bg)

            # --- Top reused passwords ---
            reuse_rows = ''
            for i, rp in enumerate(repeated[:15]):
                count, password = rp[0], rp[1]
                reuse_rows += (
                    '<tr><td style="font-family:monospace;">{pwd}</td>'
                    '<td class="text-center">{count}</td></tr>'
                ).format(pwd=htmllib.escape(str(password)), count=count)
            reuse_html = (
                '<div style="max-height:280px;overflow-y:auto;">'
                '<table class="clean-table mb-0">'
                '<thead><tr>'
                '<th>Password</th><th class="text-center">Users</th>'
                '</tr></thead><tbody>'
                + (reuse_rows or '<tr><td colspan="2" class="text-muted">No reused passwords.</td></tr>')
                + '</tbody></table></div>'
            )

            row2 = row2.format(bars=group_bars, len_placeholder=len_bars)

            # --- Enabled vs disabled cracked ---
            cracked_enabled = 0
            cracked_disabled = 0
            for item in homepage_data.get('query_output_data', []):
                if item['label'] == 'All User Accounts Cracked':
                    cracked_enabled  = len(item['enabled'])
                    cracked_disabled = len(item['disabled'])
                    break
            ev_total = cracked_enabled + cracked_disabled
            ev_e_w = int(100 * cracked_enabled  / ev_total) if ev_total else 0
            ev_d_w = int(100 * cracked_disabled / ev_total) if ev_total else 0
            enabled_disabled_html = (
                '<div class="d-flex justify-content-between small mb-1">'
                '<span>Enabled (Active Threat)</span><span><strong>{e}</strong></span></div>'
                '<div class="progress mb-3" style="height:14px;">'
                '<div class="progress-bar" style="{bar_bg}width:{ew}%"></div></div>'
                '<div class="d-flex justify-content-between small mb-1">'
                '<span>Disabled (Lower Risk)</span><span><strong>{d}</strong></span></div>'
                '<div class="progress" style="height:14px;">'
                '<div class="progress-bar" style="width:{dw}%;{bar_bg}"></div></div>'
                '<div class="text-muted mt-2" style="font-size:.72rem;">of {total} cracked accounts</div>'
            ).format(e=cracked_enabled, ew=ev_e_w, d=cracked_disabled, dw=ev_d_w, total=ev_total, bar_bg=bar_bg)

            # --- Account hygiene scorecard ---
            inactive_c   = qod.get('Inactive Accounts (Last Used Over 6mos Ago) Cracked', 0)
            old_pwd_c    = qod.get('Accounts With Passwords Set Over 1yr Ago Cracked', 0)
            no_expire_c  = qod.get('Accounts With Passwords That Never Expire Cracked', 0)
            hygiene_html = (
                '<div class="d-flex justify-content-between align-items-center border-bottom py-2 small">'
                '<span>Inactive Accounts Cracked</span><span style="font-weight:bold;">{a}</span></div>'
                '<div class="d-flex justify-content-between align-items-center border-bottom py-2 small">'
                '<span>Passwords Over 1 Year Old Cracked</span><span style="font-weight:bold;">{b}</span></div>'
                '<div class="d-flex justify-content-between align-items-center py-2 small">'
                '<span>Never-Expiring Passwords Cracked</span><span style="font-weight:bold;">{c}</span></div>'
            ).format(a=inactive_c, b=old_pwd_c, c=no_expire_c)

            # --- Password age breakdown ---
            age_buckets = homepage_data.get('password_age_buckets', [])
            age_buckets = sorted(age_buckets, key=lambda x: x[1], reverse=True)
            age_total = max(sum(b[1] for b in age_buckets), 1)
            age_bars = ''
            for label, count in age_buckets:
                bar_w = int(100 * count / age_total)
                age_bars += (
                    '<div class="d-flex align-items-center mb-2 small">'
                    '<span style="width:110px;flex-shrink:0;">{label}</span>'
                    '<div class="progress flex-grow-1 me-2" style="height:14px;">'
                    '<div class="progress-bar" style="{bar_bg}width:{w}%"></div></div>'
                    '<span style="width:30px;text-align:right;">{count}</span>'
                    '</div>'
                ).format(label=label, count=count, w=bar_w, bar_bg=bar_bg)
            if not age_bars:
                age_bars = '<p class="text-muted small">No password age data.</p>'

            # --- Password reuse severity ---
            repeated = homepage_data.get('repeated_passwords', [])
            max_reuse_count = repeated[0][0] if repeated else 1
            reuse_rows_html = ''
            reuse_section_id = self._sid('Password Reuse Stats')
            for count, password in repeated[:10]:
                bar_w = int(100 * count / max_reuse_count)
                pwd_escaped = htmllib.escape(str(password))
                reuse_rows_html += (
                    '<div class="d-flex align-items-center mb-2 small" '
                    'style="cursor:pointer;" onclick="navigateTo(\'{sid}\');">'
                    '<span style="width:140px;flex-shrink:0;overflow:hidden;'
                    'text-overflow:ellipsis;white-space:nowrap;font-family:monospace;"'
                    ' title="{pwd}">{pwd}</span>'
                    '<div class="progress flex-grow-1 me-2" style="height:14px;">'
                    '<div class="progress-bar" style="{bar_bg}width:{w}%"></div></div>'
                    '<span style="width:50px;text-align:right;">{count} users</span>'
                    '</div>'
                ).format(sid=reuse_section_id, pwd=pwd_escaped, w=bar_w, count=count, bar_bg=bar_bg)
            if not reuse_rows_html:
                reuse_rows_html = '<p class="text-muted small">No reused passwords found.</p>'
            reuse_severity_html = (
                reuse_rows_html +
                '<div class="text-muted mt-1" style="font-size:.72rem;">'
                'Top reused passwords by number of users</div>'
            )

            # --- Assemble rows ---
            if is_retro:
                row4 = (
                    '<div style="display:flex;gap:8px;margin-bottom:8px;">'
                    '<fieldset class="win98-fieldset" style="flex:1;">'
                    '<legend>Password Complexity</legend>'
                    '{complexity}</fieldset>'
                    '<fieldset class="win98-fieldset" style="flex:1;">'
                    '<legend>Password Reuse Severity</legend>'
                    '{reuse}</fieldset>'
                    '</div>'
                ).format(complexity=complexity_html, reuse=reuse_severity_html)

                row5 = ''
                row6 = ''
            else:
                row4 = (
                    '<div class="row g-3 mb-4">'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '{priv}</div></div>'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Password Complexity</div>'
                    '{complexity}</div></div>'
                    '</div>'
                ).format(priv=priv_card_html, complexity=complexity_html)

                row5 = (
                    '<div class="row g-3 mb-4">'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Password Age</div>'
                    '{age}</div></div>'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Enabled vs Disabled Cracked</div>'
                    '{ev}</div></div>'
                    '</div>'
                ).format(age=age_bars, ev=enabled_disabled_html)

                row6 = (
                    '<div class="row g-3 mb-4">'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Account Hygiene</div>'
                    '{hygiene}</div></div>'
                    '<div class="col-md-6"><div class="card border p-3 h-100">'
                    '<div class="small fw-semibold mb-3">Password Reuse Severity</div>'
                    '{reuse}</div></div>'
                    '</div>'
                ).format(hygiene=hygiene_html, reuse=reuse_severity_html)

            search_js = ''
            page_title = 'Active Directory Users and Computers' if is_retro else 'Password Audit'
            content = '<h2>{}</h2>\n'.format(page_title) + cards + row2 + row4 + row5 + row6
            return content, search_js

        def add_group_drill_section(self, group_data, group_members, category='All Groups'):
            is_retro = getattr(self.args, 'retro', False)
            rows = ''
            for i, g in enumerate(group_data):
                gname    = g[0]
                gperc    = g[1]
                gcracked = g[2]
                gtotal   = g[3]
                detail_id = 'grp_detail_{}'.format(i)

                # build per-group detail section (hidden, not in sidebar)
                EMPTY_PWD_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'
                members = sorted(group_members.get(gname, []), key=lambda x: (not x[3], str(x[1] or '')))
                member_rows = ''
                for m in members:
                    # m = [u.name, ntds_uname, enabled, cracked, pwd_len, password, nt_hash]
                    uname_raw = str(m[1]) if m[1] else ''  # Use ntds_uname for clickable lookup
                    uname = htmllib.escape(uname_raw)
                    enabled = 'Yes' if m[2] else 'No'
                    cracked = 'Yes' if m[3] else 'No'
                    pwdlen  = str(m[4]) if m[4] is not None else '-'
                    password = htmllib.escape(str(m[5])) if m[5] else ''
                    nt_hash = htmllib.escape(str(m[6])) if m[6] else ''
                    # Mark blank passwords
                    if password == '' and str(m[6]).lower() == EMPTY_PWD_HASH:
                        password = '<em style="color:#888;font-style:italic;">blank password</em>'
                    if is_retro:
                        uname = '<img src="{}" class="row-icon">{}'.format(self.user_icon, uname)
                    # Make username clickable
                    uname = self.make_username_clickable(uname_raw, uname)
                    member_rows += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td style="font-family:monospace;">{}</td><td style="font-family:monospace;font-size:10px;">{}</td></tr>'.format(
                        uname, enabled, cracked, pwdlen, password, nt_hash)
                detail_content = (
                    '<h2>{}</h2>\n'.format(htmllib.escape(gname)) +
                    '<p class="text-muted small">{cracked} cracked &nbsp;|&nbsp; '
                    '{total} total members &nbsp;|&nbsp; {perc}%</p>'.format(
                        cracked=gcracked, total=gtotal, perc=gperc) +
                    '<div class="table-responsive">'
                    '<table class="clean-table">'
                    '<thead><tr>'
                    '<th>Username</th><th>Enabled</th><th>Cracked</th><th>Pwd Len</th><th>Password</th><th>NT Hash</th>'
                    '</tr></thead><tbody>' + member_rows + '</tbody></table></div>'
                )
                self.add_section(detail_id, gname, detail_content, category, sidebar=False)

                # row in the groups index table
                group_cell = htmllib.escape(gname)
                if is_retro:
                    group_cell = '<img src="{}" class="row-icon">{}'.format(self.group_icon, group_cell)
                rows += (
                    '<tr class="group-row" data-name="{raw}" style="cursor:pointer;"'
                    ' onclick="navigateTo(\'{did}\')">'
                    '<td><a href="#" onclick="return false;" style="text-decoration:none;color:inherit;">'
                    '{name}</a></td>'
                    '<td>{perc}%</td><td>{cracked}</td><td>{total}</td></tr>'
                ).format(
                    raw=htmllib.escape(gname.lower()), did=detail_id,
                    name=group_cell, perc=gperc,
                    cracked=gcracked, total=gtotal)

            search_html = (
                '<div class="mb-3">'
                '<input type="text" id="group-page-search" class="form-control form-control-sm"'
                ' placeholder="Search groups..." style="max-width:300px;">'
                '</div>'
            )
            table_html = (
                '<div class="table-responsive">'
                '<table class="clean-table">'
                '<thead><tr>'
                '<th>Group Name</th><th>% Cracked</th>'
                '<th>Cracked Users</th><th>Total Members</th>'
                '</tr></thead><tbody>' + rows + '</tbody></table></div>'
            )
            search_js = (
                "var gps=document.getElementById('group-page-search');"
                "if(gps){gps.addEventListener('input',function(){"
                "var q=this.value.toLowerCase();"
                "document.querySelectorAll('.group-row').forEach(function(row){"
                "row.style.display=row.getAttribute('data-name').includes(q)?'':'none';"
                "});});}"
            )
            content = '<h2>Groups</h2>\n' + search_html + table_html
            self.add_section('groups_drill', 'Groups', content, category, deferred_js=search_js)

        def add_group_membership_ranking_section(self, user_groups, user_info, category='Privileged Accounts'):
            """Show all users ranked by number of group memberships (highest first)"""
            is_retro = getattr(self.args, 'retro', False)
            EMPTY_PWD_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'

            # Build list of users with group counts, sorted by count descending
            user_list = []
            for username, groups in user_groups.items():
                info = user_info.get(username, {})
                group_count = len(groups)
                enabled = info.get('enabled')
                cracked = info.get('cracked')
                password = info.get('password') or ''
                nt_hash = info.get('nt_hash') or ''
                user_list.append([username, group_count, enabled, cracked, password, nt_hash])

            # Sort by group count descending, then by username
            user_list = sorted(user_list, key=lambda x: (-x[1], str(x[0] or '').lower()))

            rows = ''
            for u in user_list:
                uname_raw = str(u[0]) if u[0] else ''
                uname = htmllib.escape(uname_raw)
                group_count = u[1]
                enabled = 'Yes' if u[2] else 'No'
                cracked = 'Yes' if u[3] else 'No'
                password = htmllib.escape(str(u[4])) if u[4] else ''
                nt_hash = htmllib.escape(str(u[5])) if u[5] else ''

                # Mark blank passwords
                if password == '' and str(u[5]).lower() == EMPTY_PWD_HASH:
                    password = '<em style="color:#888;font-style:italic;">blank password</em>'

                if is_retro:
                    uname_display = '<img src="{}" class="row-icon">{}'.format(self.user_icon, uname)
                else:
                    uname_display = uname

                # Make username clickable
                uname_display = self.make_username_clickable(uname_raw, uname_display)

                rows += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td style="font-family:monospace;">{}</td><td style="font-family:monospace;font-size:10px;">{}</td></tr>'.format(
                    uname_display, group_count, enabled, cracked, password, nt_hash)

            table_html = (
                '<div class="table-responsive"><table class="clean-table">'
                '<thead><tr><th>Username</th><th>Groups</th><th>Enabled</th><th>Cracked</th><th>Password</th><th>NT Hash</th></tr></thead>'
                '<tbody>' + rows + '</tbody></table></div>'
            )

            # Add search box
            section_id = 'group_membership_ranking'
            search_html = (
                '<div style="margin-bottom:8px;">'
                '<input type="text" id="search_{sid}" placeholder="Search usernames..." '
                'class="form-control form-control-sm" style="max-width:300px;">'
                '</div>'
            ).format(sid=section_id)
            search_js = (
                "document.getElementById('search_{sid}').addEventListener('input',function(){{"
                "var q=this.value.toLowerCase();"
                "document.querySelectorAll('#{sid} tbody tr').forEach(function(row){{"
                "row.style.display=row.innerText.toLowerCase().includes(q)?'':'none';"
                "}});}})"
            ).format(sid=section_id)

            content = '<h2>Group Membership Ranking</h2>\n' + search_html + table_html
            self.add_section(section_id, 'Group Membership Ranking', content, category, deferred_js=search_js)

        def add_password_reuse_drill_section(self, shared_hashes, hash_users, category='Password Stats'):
            """shared_hashes: [[count, nt_hash, password], ...], hash_users: {nt_hash: [[name, enabled, cracked], ...]}"""
            is_retro = getattr(self.args, 'retro', False)
            EMPTY_PWD_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'
            rows = ''
            for i, sh in enumerate(shared_hashes):
                count = sh[0]
                nt_hash = sh[1]
                password = sh[2]
                detail_id = 'pwd_reuse_detail_{}'.format(i)
                hash_escaped = htmllib.escape(str(nt_hash))
                # Mark blank passwords
                if password:
                    pwd_display = htmllib.escape(str(password))
                elif str(nt_hash).lower() == EMPTY_PWD_HASH:
                    pwd_display = '<em style="color:#888;font-style:italic;">blank password</em>'
                else:
                    pwd_display = ''

                # build per-hash detail section (hidden, not in sidebar)
                users = hash_users.get(nt_hash, [])
                user_rows = ''
                for u in users:
                    uname_raw = str(u[0]) if u[0] else ''
                    uname = htmllib.escape(uname_raw)
                    enabled = 'Yes' if u[1] else 'No'
                    cracked = 'Yes' if u[2] else 'No'
                    if is_retro:
                        uname = '<img src="{}" class="row-icon">{}'.format(self.user_icon, uname)
                    # Make username clickable
                    uname = self.make_username_clickable(uname_raw, uname)
                    user_rows += '<tr><td>{}</td><td>{}</td><td>{}</td><td style="font-family:monospace;">{}</td><td style="font-family:monospace;font-size:10px;">{}</td></tr>'.format(
                        uname, enabled, cracked, pwd_display, hash_escaped)

                # Title shows password if known, otherwise hash
                if password:
                    title = 'Password: <span style="font-family:monospace;">{}</span>'.format(htmllib.escape(str(password)))
                    subtitle = 'Hash: <span style="font-family:monospace;font-size:10px;">{}</span>'.format(hash_escaped)
                elif str(nt_hash).lower() == EMPTY_PWD_HASH:
                    title = 'Password: <em style="color:#888;font-style:italic;">blank password</em>'
                    subtitle = 'Hash: <span style="font-family:monospace;font-size:10px;">{}</span>'.format(hash_escaped)
                else:
                    title = 'Hash: <span style="font-family:monospace;">{}</span>'.format(hash_escaped)
                    subtitle = ''

                detail_content = (
                    '<h2>{}</h2>\n'.format(title) +
                    '<p class="text-muted small">{} users share this hash{}</p>'.format(count, ' &nbsp;|&nbsp; ' + subtitle if subtitle else '') +
                    '<div class="table-responsive">'
                    '<table class="clean-table">'
                    '<thead><tr>'
                    '<th>Username</th><th>Enabled</th><th>Cracked</th><th>Password</th><th>NT Hash</th>'
                    '</tr></thead><tbody>' + user_rows + '</tbody></table></div>'
                )
                sidebar_title = (htmllib.escape(str(password))[:20] if password else hash_escaped[:12] + '...')
                self.add_section(detail_id, sidebar_title, detail_content, category, sidebar=False)

                # row in the password reuse index table
                rows += (
                    '<tr class="reuse-row" data-pwd="{raw}" style="cursor:pointer;"'
                    ' onclick="navigateTo(\'{did}\')">'
                    '<td class="text-center">{count}</td>'
                    '<td style="font-family:monospace;font-size:10px;">{hash}</td>'
                    '<td style="font-family:monospace;">{pwd}</td></tr>'
                ).format(raw=(hash_escaped + (password or '')).lower(), did=detail_id,
                         count=count, hash=hash_escaped, pwd=pwd_display)

            if is_retro:
                search_html = (
                    '<div class="mb-3">'
                    '<input type="text" id="reuse-page-search" class="win98-input"'
                    ' style="width:200px;" placeholder="Search...">'
                    '</div>'
                )
            else:
                search_html = (
                    '<div class="mb-3">'
                    '<input type="text" id="reuse-page-search" class="form-control form-control-sm"'
                    ' placeholder="Search..." style="max-width:300px;">'
                    '</div>'
                )
            table_html = (
                '<div class="table-responsive">'
                '<table class="clean-table">'
                '<thead><tr>'
                '<th class="text-center">Users</th><th>NT Hash</th><th>Password</th>'
                '</tr></thead><tbody>' + rows + '</tbody></table></div>'
            )
            search_js = (
                "var rps=document.getElementById('reuse-page-search');"
                "if(rps){rps.addEventListener('input',function(){"
                "var q=this.value.toLowerCase();"
                "document.querySelectorAll('.reuse-row').forEach(function(row){"
                "row.style.display=row.getAttribute('data-pwd').includes(q)?'':'none';"
                "});});}"
            )
            content = '<h2>Password Reuse Stats</h2>\n' + search_html + table_html
            self.add_section(self._sid('Password Reuse Stats'), 'Password Reuse Stats', content, category, deferred_js=search_js)

        def register_user_details(self, user_groups, user_info):
            """Store user data for clickable user detail pages"""
            self.user_groups = user_groups
            self.user_info = user_info
            self.user_sections_created = set()

        def register_group_detail_ids(self, group_data):
            """Store mapping of group names to their detail IDs"""
            self.group_detail_ids = {}
            for i, g in enumerate(group_data):
                self.group_detail_ids[g[0]] = 'grp_detail_{}'.format(i)

        def register_hash_users(self, hash_users):
            """Store hash_users for password sharing lookup"""
            self.hash_users = hash_users

        def get_user_detail_id(self, username):
            """Get consistent section ID for a user"""
            return 'user_detail_' + self._sid(username)

        def ensure_user_section(self, username):
            """Create user detail section if not already created"""
            if not hasattr(self, 'user_groups') or username in self.user_sections_created:
                return
            if username not in self.user_groups:
                return

            # Mark as created FIRST to prevent recursion from shared passwords
            self.user_sections_created.add(username)

            is_retro = getattr(self.args, 'retro', False)
            EMPTY_PWD_HASH = '31d6cfe0d16ae931b73c59d7e0c089c0'
            detail_id = self.get_user_detail_id(username)
            info = self.user_info.get(username, {})
            groups = self.user_groups.get(username, [])

            uname_escaped = htmllib.escape(str(username))
            enabled = 'Yes' if info.get('enabled') else 'No'
            cracked = 'Yes' if info.get('cracked') else 'No'
            pwd_len = str(info.get('pwd_len')) if info.get('pwd_len') is not None else ''
            password = htmllib.escape(str(info.get('password'))) if info.get('password') else ''
            nt_hash = htmllib.escape(str(info.get('nt_hash'))) if info.get('nt_hash') else ''

            # LM hash (blank LM hash is aad3b435b51404eeaad3b435b51404ee)
            BLANK_LM_HASH = 'aad3b435b51404eeaad3b435b51404ee'
            lm_hash_raw = info.get('lm_hash')
            if lm_hash_raw and str(lm_hash_raw).lower() != BLANK_LM_HASH:
                lm_hash = htmllib.escape(str(lm_hash_raw))
            else:
                lm_hash = ''

            # Password complexity check
            pwd_raw = info.get('password')
            if pwd_raw:
                special_chars = """`~!@#$%^&*()-_=+,<.>/?;:"'{}[]|\\"""
                rules_met = sum([
                    any(x.isupper() for x in pwd_raw),
                    any(x.islower() for x in pwd_raw),
                    any(x.isdigit() for x in pwd_raw),
                    any(x in special_chars for x in pwd_raw)
                ])
                complexity_met = 'Yes' if rules_met >= 3 else 'No'
            else:
                complexity_met = ''

            # Mark blank passwords
            if password == '' and str(info.get('nt_hash', '')).lower() == EMPTY_PWD_HASH:
                password = '<em style="color:#888;font-style:italic;">blank password</em>'

            # Format password last set date
            pwdlastset_raw = info.get('pwdlastset')
            if pwdlastset_raw and pwdlastset_raw not in [-1.0, 0.0, None]:
                try:
                    from datetime import datetime
                    pwd_last_set = datetime.fromtimestamp(int(pwdlastset_raw)).strftime('%Y-%m-%d')
                except:
                    pwd_last_set = ''
            else:
                pwd_last_set = ''

            # Build group membership table
            group_rows = ''
            for g in sorted(groups):
                g_escaped = htmllib.escape(str(g))
                if is_retro:
                    g_cell = '<img src="{}" class="row-icon">{}'.format(self.group_icon, g_escaped)
                else:
                    g_cell = g_escaped
                # Make row clickable if group detail exists
                grp_detail_id = self.group_detail_ids.get(g) if hasattr(self, 'group_detail_ids') else None
                if grp_detail_id:
                    group_rows += '<tr style="cursor:pointer;" onclick="navigateTo(\'{}\');"><td>{}</td></tr>'.format(grp_detail_id, g_cell)
                else:
                    group_rows += '<tr><td>{}</td></tr>'.format(g_cell)

            # Build "Shares Password With" table
            shares_with_rows = ''
            shares_with_count = 0
            user_nt_hash = info.get('nt_hash')
            if user_nt_hash and hasattr(self, 'hash_users'):
                shared_users = self.hash_users.get(user_nt_hash, [])
                for su in sorted(shared_users, key=lambda x: str(x[0] or '')):
                    su_name = str(su[0]) if su[0] else ''
                    if su_name and su_name != username:  # Exclude current user
                        shares_with_count += 1
                        su_escaped = htmllib.escape(su_name)
                        su_enabled = 'Yes' if su[1] else 'No'
                        su_group_count = len(self.user_groups.get(su_name, []))
                        if is_retro:
                            su_cell = '<img src="{}" class="row-icon">{}'.format(self.user_icon, su_escaped)
                        else:
                            su_cell = su_escaped
                        # Make clickable if user data exists
                        if su_name in self.user_groups:
                            self.ensure_user_section(su_name)
                            su_detail_id = self.get_user_detail_id(su_name)
                            shares_with_rows += '<tr style="cursor:pointer;" onclick="navigateTo(\'{}\');"><td>{}</td><td>{}</td><td>{}</td></tr>'.format(su_detail_id, su_cell, su_enabled, su_group_count)
                        else:
                            shares_with_rows += '<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(su_cell, su_enabled, su_group_count)

            # Header with user icon in retro mode
            if is_retro:
                header_html = '<h2><img src="{}" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;">{}</h2>\n'.format(self.user_icon, uname_escaped)
            else:
                header_html = '<h2>{}</h2>\n'.format(uname_escaped)

            detail_content = (
                header_html +
                '<div class="table-responsive">'
                '<table class="clean-table">'
                '<thead><tr><th>Property</th><th>Value</th></tr></thead>'
                '<tbody>'
                '<tr><td>Enabled</td><td>{}</td></tr>'.format(enabled) +
                '<tr><td>Cracked</td><td>{}</td></tr>'.format(cracked) +
                '<tr><td>Password Length</td><td>{}</td></tr>'.format(pwd_len) +
                '<tr><td>Password Last Set</td><td>{}</td></tr>'.format(pwd_last_set) +
                '<tr><td>Password</td><td style="font-family:monospace;">{}</td></tr>'.format(password) +
                '<tr><td>Default Complexity Met</td><td>{}</td></tr>'.format(complexity_met) +
                '<tr><td>NT Hash</td><td style="font-family:monospace;font-size:10px;">{}</td></tr>'.format(nt_hash) +
                '<tr><td>LM Hash</td><td style="font-family:monospace;font-size:10px;">{}</td></tr>'.format(lm_hash) +
                '</tbody></table></div>' +
                '<p style="font-weight:bold;margin-top:16px;margin-bottom:8px;">Group Memberships ({} groups)</p>\n'.format(len(groups)) +
                '<div class="table-responsive">'
                '<table class="clean-table">'
                '<thead><tr><th>Group Name</th></tr></thead>'
                '<tbody>' + (group_rows or '<tr><td class="text-muted">No group memberships found</td></tr>') + '</tbody></table></div>'
            )
            # Add "Shares Password With" section if applicable
            if shares_with_count > 0:
                detail_content += (
                    '<p style="font-weight:bold;margin-top:16px;margin-bottom:8px;">Shares Password With ({} users)</p>\n'.format(shares_with_count) +
                    '<div class="table-responsive">'
                    '<table class="clean-table">'
                    '<thead><tr><th>Username</th><th>Enabled</th><th>Groups</th></tr></thead>'
                    '<tbody>' + shares_with_rows + '</tbody></table></div>'
                )
            self.add_section(detail_id, uname_escaped[:30], detail_content, 'User Details', sidebar=False)

        def make_username_clickable(self, username, display_html):
            """Wrap username in clickable link if user data available"""
            if not hasattr(self, 'user_groups') or username not in self.user_groups:
                return display_html
            self.ensure_user_section(username)
            detail_id = self.get_user_detail_id(username)
            return '<a href="#" onclick="navigateTo(\'{}\');return false;" style="color:inherit;text-decoration:none;">{}</a>'.format(detail_id, display_html)

        def add_table_section(self, title, data, headers, col_to_not_escape=None, category='Other', row_icon=None):
            is_retro = getattr(self.args, 'retro', False)
            section_id = self._sid(title)
            content = '<h2>{}</h2>\n'.format(htmllib.escape(title))
            deferred_js = ''
            if is_retro:
                export_btn = (
                    '<button onclick="exportTableCSV(\'{sid}\',\'{fname}\')" '
                    'class="win98-btn">Export CSV</button>'
                ).format(sid=section_id, fname=title.replace("'", ''))
            else:
                export_btn = (
                    '<button onclick="exportTableCSV(\'{sid}\',\'{fname}\')" '
                    'class="btn btn-sm btn-outline-secondary">'
                    'Export CSV</button>'
                ).format(sid=section_id, fname=title.replace("'", ''))

            if len(data) > 20:
                search_id = 'search_{}'.format(section_id)
                if is_retro:
                    content += (
                        '<div class="d-flex justify-content-between align-items-center mb-3">'
                        '<input type="text" id="{sid}" class="win98-input"'
                        ' style="width:200px;" placeholder="Search...">'
                        '{btn}'
                        '</div>'
                    ).format(sid=search_id, btn=export_btn)
                else:
                    content += (
                        '<div class="d-flex justify-content-between align-items-center mb-3">'
                        '<input type="text" id="{sid}" class="form-control form-control-sm"'
                        ' style="max-width:300px;" placeholder="Search...">'
                        '{btn}'
                        '</div>'
                    ).format(sid=search_id, btn=export_btn)
                deferred_js = (
                    "var s=document.getElementById('{sid}');"
                    "if(s){{s.addEventListener('input',function(){{"
                    "var q=this.value.toLowerCase();"
                    "document.querySelectorAll('#{secid} tbody tr').forEach(function(row){{"
                    "row.style.display=row.textContent.toLowerCase().includes(q)?'':'none';"
                    "}});}});}}"
                ).format(sid=search_id, secid=section_id)
            else:
                content += (
                    '<div class="d-flex justify-content-end mb-2">{btn}</div>'
                ).format(btn=export_btn)

            content += self._make_table(data, headers, col_to_not_escape, row_icon=row_icon)
            self.add_section(section_id, title, content, category, deferred_js=deferred_js)

        def render(self):
            # only sidebar=True sections go into the nav
            cats = {}
            for sec in self.sections:
                if not sec.get('sidebar', True):
                    continue
                cat = self.section_categories.get(sec['id'], 'Other')
                cats.setdefault(cat, []).append(sec)

            first_id = self.sections[0]['id'] if self.sections else ''

            is_retro = getattr(self.args, 'retro', False)

            if is_retro:
                retro_icons = {
                    'overview': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAHlBMVEUAAACAgIDAwMAAAAD///8AAIAAAP8A//8A/wAAgAC2abgYAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBBMBJTGYm/RyAAAA40lEQVQ4y+2TwRHCIBBFYWxAIA2EpIBkiAWQ2RYswdiKZ292K7sIsiSOzujRzy0vf4HPrhAkqZj2IknbUq1J3yX7blUGDZTyGciZV/oEdC7rMDOwZJ04OP8OLH/wPTg+xUBfNAkC96IZRj1sAqPaYatzg0FFIByXah+gMiitIpBQySfA98ZjvQWXa5oMVAFuCWBzj0RpbHidPoQC3XoLDWAbAk1vIC2N9VEGDX7Ky0Ecx9lwgwEfrxgGmhkm0NEQSlVHipXwDasRJ4fFC1YOpSkRs448KiSy429EeaReKEX/YYJ3Kka5U2zoYhIAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTgtMDQtMTlUMDE6Mzc6NDktMDQ6MDCeziouAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE4LTA0LTE5VDAxOjM3OjQ5LTA0OjAw75OSkgAAAABJRU5ErkJggg==',
                    'password': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAFVBMVEUAAAAAAACAgID////AwMCAgAD//wA+bLkQAAAAAXRSTlMAQObYZgAAAAFiS0dEAxEMTPIAAAAHdElNRQfiBhgXECILfny5AAABb0lEQVQ4y3XUwY6DIBCAYTTpXdB4XqD7ABuId4F6N00fwMTl/R9hZ1DbAV2uvx8wbS1j2+K8YVerUkpeBsGYOhN4WqmvWpapNuZHG6elnfOiQxjvQRsZ16zUNgR+d0OE8DsXQKpnXHgfp0eTASG/hygEj+s6U+AxLK4bIyUQrLjDTjKMID4kCQ1BQOinaaSCQ4hC9cuyru+9UIwYFh57EDRYiwESgFz4LSC4Egl8BAy4iwSKQfRjALFmIpEU4pQLJDrgXoVAokMiYFxHPnkdnE0ElTwRk0JJlPUvA2tYKUGhg33BemYEr+Ws9941t4yk++pgLPwYOSW4FdzLBwg5afEMMClQUlkaCIHg7BbY05gPwaO7PdwktwdJk497wN0OkvanAU4ZyRxHqPFinMxxBDgfTinnSA/ydpLlHPs143yaYwuv+T1HS0O9v/WwT5CWBPKFOHEVKgD1VWCdavBdPIeKsxq2a9jV4v/8zUDJwB9rdZH7D025BwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxOC0wNi0yNFQyMzoxNjozNC0wNDowMO0k/sIAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTgtMDYtMjRUMjM6MTY6MzQtMDQ6MDCceUZ+AAAAAElFTkSuQmCC',
                    'groups': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAG1BMVEUAAAAAAACAgIDAwMD/////AACAAAAAAIAAAP9Yj2HtAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBhoANiXlpBdAAAABXElEQVQ4y42TPXKEMAyFodoWjMmkxTcwYpKalS+QAm7AXgHaVHDslX8xxpmJZihWT5/0rLWL4n9R1hSZfG2jypVnlDOfdIvyFyQGIqSsmRAZwf4SXSKELqy7CFF3Rh+AdMPjoV0NSqHM2KG8UvIG1LUKQpkKshNVVmCsr66dtB2uFEB3HQGIKGnAyLGKO8FAkREaREc4V17Q5Z3gd4HKyY4TdC8nNESQncHkAYJgJowcDIFmuaWvpxkNNpbwrqyj09XTC3zwIfWQnt0J1EOwD4IHwE0PSwRXT+fUwhiW6BECEMwpvF+HPLmS17tjffWMCBGu57lb1LuCIJR2t25GJBRmtfbgdHncH2sZewaA9gX4tZxIaaqp4zy/YJl/EkK0C8Vrmk5kNceAj1lHO53ItuorAreH9jgOzcR2gkAKfG/p+96Ofd9X2Pbfm7BRrMeRII/dxueaIvl3/1e8AYOsgIp+47wjAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE4LTA2LTI2VDAwOjU0OjM3LTA0OjAws+TK4AAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wNi0yNlQwMDo1NDozNy0wNDowMMK5clwAAAAASUVORK5CYII=',
                    'user': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgBAMAAACBVGfHAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAG1BMVEUAAAAAAACAgIDAwMD///8AAP8AAIAA/wAAgABQLitQAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBhoANhnKy2vHAAAAz0lEQVQoz3WRwQ3CMAxFSydIVBigBvXeJuJODdx78AJIzQqswNjYTppEiP5T8vT9YztNsy/LMnpqQWRtJmfHGiOwYpC7swVc7iK9dcigxVLhnREgkX003CQCt3LrR83EExEtfEd8oKnA0fuUkUCHrLEuYceYHaSPiKEC4ihgYQP3VwDxK3HYFoOKE2ar20Ad7hm8nxLQ8a8UcB4g7wtWojCtLw45xMGCEApmMwAMkgwm7SsJBLhKO+Adj6wEPvkX/pT0zQ/gvqAWG7ZG81d/AWo7TDvY8wf6AAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE4LTA2LTI2VDAwOjU0OjI1LTA0OjAw6NHbVwAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wNi0yNlQwMDo1NDoyNS0wNDowMJmMY+sAAAAASUVORK5CYII=',
                    'privileged': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAIVBMVEUAAAAAAACAgICAgADAwMD//wCAAAAAAP//AAAAgID///82L8m0AAAAAXRSTlMAQObYZgAAAAFiS0dECmjQ9FYAAAAHdElNRQfiBhoANiJ7wILjAAABk0lEQVQ4y52TQW6DMBBFQV1ky+A4UXZBqHvsmANQwwGA+ACVoihbVqgnqbhtZ8ZJQ4IjVR2JjZ+e53tsoui/BVyv1pckhiCBWSUv1ucgfgVmq3meJSFBa62CO+VoLHcyRqGRLoCwtkJjCYwxlVawACigkS17aDSeUl0D2SqUyqCgOJVO5oAaWJ8qfwDr2pi6ZgOiRyO3NSqChQNW4UeSomHwS7VKojeHJWaKtcAtSgJtMYuFAoYi4SBYofFSqFyQUXaNU1l5VVJDxW+hPJ6c2oueFUEdbC3o2KWrGrWPPUiN5h40qPL9eOrhZlib0bzIkCkqdc2A7sLo1A9Ktqg4RyC+Z0JFOlIYwOAzbViRXkEQbwcOlZ2xAGSLygcBGEe+P7W5XD4BnEPFOSWi3YgET4KxziBdJ2lWPRQRfCMZALZ0cFlmTYdjRyEaSBk9BNmtHb8BHNUKdpMn1CBrWkE3RfexAviaJlZ6Eor77eIm4zRNgytJmP9rq4E3fhZ+fwj3LNyADAs4TRcU+FkUQRBDWPhj/QAjj3hNe84b6QAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxOC0wNi0yNlQwMDo1NDozNC0wNDowMIIM0H0AAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTgtMDYtMjZUMDA6NTQ6MzQtMDQ6MDDzUWjBAAAAAElFTkSuQmCC',
                    'escalation': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgBAMAAACBVGfHAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAFVBMVEUAAACAgAD//wAAAADAwMCAgID///9p8MOBAAAAAXRSTlMAQObYZgAAAAFiS0dEBmFmuH0AAAAHdElNRQfiBhgXEB29GFGEAAAA8klEQVQoz4WRTY6EIBBGMYZ9o3KAcSazphuZvQ3lWsPPCaq9/xGGQieNq/lWxcvjg6QY+0sjbqxO042fqgbdh3j256y1Ys1Xr6f5UNqVedbNBdKZx7hy1dE8FJB29KwCHO0Uo3mD5Ezcd/OoQXLa+Qq80MYJtBBi6AUBQLtmIKUcenkrxqIXuG/b5u+bz68AOkQwsiS3JMBlcfCz5+Ds6SMpG36kfAO9EyI69yhgJIOFkBbvSp5kcAwGjhuHUYCtDGZCAlsZrCVQGyHoaK8dylyMiUr/67gaweWOExSjtRysOCLLqhR3Vp85lzld1ky33uMvgdtPRe2jaewAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTgtMDYtMjRUMjM6MTY6MjktMDQ6MDBAWZ+cAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE4LTA2LTI0VDIzOjE2OjI5LTA0OjAwMQQnIAAAAABJRU5ErkJggg==',
                    'file': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAQAAADZc7J/AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAHdElNRQfiBhgXBwzSK/XgAAAAjElEQVRIx+2VQQrAIAwE1+K/oz9rX5ZeiopaTazFHronETMOIRCDK44hiDP5jY1H6pZ7gJEhNsm/iQHAjwBUIJSAEmF15aEBoRcqAwKDwdiTu8LAdxB5bP9JOwoDkgFeNKjD5xvc2wh7oLVRGNSR8w2+PImr54BGAP8cyLLeQL1YGgbHECDuWtF6LytPTdMhXzC2L6sAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTgtMDYtMjRUMjM6MDc6MTItMDQ6MDDinXh7AAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE4LTA2LTI0VDIzOjA3OjEyLTA0OjAwk8DAxwAAAABJRU5ErkJggg==',
                    'user_row': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgBAMAAACBVGfHAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAHlBMVEUAAAAAAADAwMD///+AgIAAAP8A/wAAgAAA//8AAIC9Gt0uAAAAAXRSTlMAQObYZgAAAAFiS0dEAxEMTPIAAAAHdElNRQfiBhoANhpTwjp9AAABGElEQVQoz11RPU/DMBA1ElLXpoihY+JKdMVqvQNBwA84Ws+V7NlUtvsHIlYYInT/lju7gSZvyr28D58txB8qwlyM50vmqhDVRDAlFqoaO2QzHxELdT/OlPXZ0bbtA81KbVW2tNpamm+kLBmttMl6TiDUQlxrnVLyHCFlTYqng3PE5BIWiBcdUyFYQY71BwvIs1BNw8T28+49pRCoJS/7uN+fgBSBEjZc+tx1HUAKBqVcMfG6OwGAvzWAavPGiqMLsAvQA+Cq/+JWHcAEQGYAhTgebKAIBIMEskRtqYL+pvSdV4+WTs76HyzELMZIDka5vplzzhvCQAgS+L5HXOL5NnlTM1RkT/J4EcFPtMzz/5uJajKXZxy+fwEZGmb3BrpUIAAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxOC0wNi0yNlQwMDo1NDoyNi0wNDowMNk5wcoAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTgtMDYtMjZUMDA6NTQ6MjYtMDQ6MDCoZHl2AAAAAElFTkSuQmCC',
                    'group_row': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAG1BMVEUAAAAAAACAgIDAwMD/////AACAAAAAAIAAAP9Yj2HtAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBhoANiXlpBdAAAABXElEQVQ4y42TPXKEMAyFodoWjMmkxTcwYpKalS+QAm7AXgHaVHDslX8xxpmJZihWT5/0rLWL4n9R1hSZfG2jypVnlDOfdIvyFyQGIqSsmRAZwf4SXSKELqy7CFF3Rh+AdMPjoV0NSqHM2KG8UvIG1LUKQpkKshNVVmCsr66dtB2uFEB3HQGIKGnAyLGKO8FAkREaREc4V17Q5Z3gd4HKyY4TdC8nNESQncHkAYJgJowcDIFmuaWvpxkNNpbwrqyj09XTC3zwIfWQnt0J1EOwD4IHwE0PSwRXT+fUwhiW6BECEMwpvF+HPLmS17tjffWMCBGu57lb1LuCIJR2t25GJBRmtfbgdHncH2sZewaA9gX4tZxIaaqp4zy/YJl/EkK0C8Vrmk5kNceAj1lHO53ItuorAreH9jgOzcR2gkAKfG/p+96Ofd9X2Pbfm7BRrMeRII/dxueaIvl3/1e8AYOsgIp+47wjAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE4LTA2LTI2VDAwOjU0OjM3LTA0OjAws+TK4AAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wNi0yNlQwMDo1NDozNy0wNDowMMK5clwAAAAASUVORK5CYII=',
                    'folder': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAGFBMVEUAAACZmQAAAAD4+Pj//5nMzGb/zJn////5no2yAAAAAXRSTlMAQObYZgAAAAFiS0dEBxZhiOsAAAAHdElNRQfiBhgXARMJeV+TAAABE0lEQVQ4y82TzQ3CMAyFywhtxb1iA1QWQLJ858AGlvcfAfs5aRMTceapaoVfPv9FTNMPzdDyFb/s0H3LxkqhjFwexXhuYyAjB5CRE0jI9X3qNVfZkXUfautSFQkzL9nwIAlJNixExKSJELGgQJlge9jzJQPnzeoJL4uPDAiORB3B3pM34J52hADg1BVXE3ZbA785sCZVBULt5BwtAUuTCypEiSNVNCmM8UTTrsxTL66kzRyOYOGoXYuXRB40wLrVbkAUttdRg33dFL16Lj264siF9OThZkBcKqFVrYSfjWVo7MuIdkBcNoBzV1K2YQQ+Gqk8HPtGYXZIK1EuNJwyIGagGE2RSNHudR5qmW5jff2F/1wfr4rjk5A1shsAAAAldEVYdGRhdGU6Y3JlYXRlADIwMTgtMDYtMjRUMjM6MDE6MTktMDQ6MDDthFzGAAAAJXRFWHRkYXRlOm1vZGlmeQAyMDE4LTA2LTI0VDIzOjAxOjE5LTA0OjAwnNnkegAAAABJRU5ErkJggg==',
                    'keys': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAFVBMVEUAAAAAAACAgID////AwMCAgAD//wA+bLkQAAAAAXRSTlMAQObYZgAAAAFiS0dEAxEMTPIAAAAHdElNRQfiBhgXECILfny5AAABb0lEQVQ4y3XUwY6DIBCAYTTpXdB4XqD7ABuId4F6N00fwMTl/R9hZ1DbAV2uvx8wbS1j2+K8YVerUkpeBsGYOhN4WqmvWpapNuZHG6elnfOiQxjvQRsZ16zUNgR+d0OE8DsXQKpnXHgfp0eTASG/hygEj+s6U+AxLK4bIyUQrLjDTjKMID4kCQ1BQOinaaSCQ4hC9cuyru+9UIwYFh57EDRYiwESgFz4LSC4Egl8BAy4iwSKQfRjALFmIpEU4pQLJDrgXoVAokMiYFxHPnkdnE0ElTwRk0JJlPUvA2tYKUGhg33BemYEr+Ws9941t4yk++pgLPwYOSW4FdzLBwg5afEMMClQUlkaCIHg7BbY05gPwaO7PdwktwdJk497wN0OkvanAU4ZyRxHqPFinMxxBDgfTinnSA/ydpLlHPs143yaYwuv+T1HS0O9v/WwT5CWBPKFOHEVKgD1VWCdavBdPIeKsxq2a9jV4v/8zUDJwB9rdZH7D025BwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxOC0wNi0yNFQyMzoxNjozNC0wNDowMO0k/sIAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTgtMDYtMjRUMjM6MTY6MzQtMDQ6MDCceUZ+AAAAAElFTkSuQmCC',
                    'key_escalation': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAJ1BMVEUAAACAgIAAAADAwMD///+AgAAAgAAA/wD//wCAAAD/AAAAAIAAAP9IayNCAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBhgXEB4kEQA+AAABtklEQVQ4y5WSv0/CQBiGjybdocWdvhQs6qJg4uBCuYGQLlwgYXZxd5AdQ3Kzm24qix2dmUhH/ii/uyv0h3TwTdrhe/rcd73vGEtTa5iwXAAw5vZ1rltZ3aLvWrUB1xk5GfDocVxdHoJnilVXr6apw88Uqz6ndBSgZjnFOlO1js95iO5zTrFmkhIIzh08Lp8yxR7LFRCsfVrpfJlTSPAaTiDFEG9YPhy7kCA97gVyjV6MLo4bUwBoBlI6vfgTWKxShUDf47x9J8V7/I0OfWYUs9SQDHERvwJSpooyboA+GYhxiUCmXZRhItDDdgdB+0qBPm8yQmC7V6fCSwb94X7/Q3WzLfpBLaz9j5AA/MNQDorgMcfV7ihohbL2vzZ0vjtkUzSKEqIm1ErHiShlvoknPEpCAtkMSbkVE6rf0xBzAikv0xX1jBLuhYV7osAgipKkJNhjAi6netsvCpKAvnFFwQDmch/FDsxeKFAbhGFRYKyjAHNLV1ddLQ1Ul6LAhAaklAR7ZkCtXxJmYwOYA1YEMgXl2OMqMKsAbF4FrFEFEP9uXgWsRVVzOl1xeleLaYudVqqAhT+lX0JHtGZEwbNxAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE4LTA2LTI0VDIzOjE2OjMwLTA0OjAwGWva0QAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOC0wNi0yNFQyMzoxNjozMC0wNDowMGg2Ym0AAAAASUVORK5CYII=',
                    'computer': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwBAMAAAClLOS0AAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAIVBMVEUAAACAgIDAwMAAAAD///8AgIAA//8AAIAAAP8A/wAAgACZBxulAAAAAXRSTlMAQObYZgAAAAFiS0dEBI9o2VEAAAAHdElNRQfiBBMBJCt84jxJAAAA5UlEQVQ4y62TyxHCIBCGoYQFGghJASBagJEGMk6sxbsXW/Dq0SpNsuSxPEad8ePGNz9kNwtjExwobEZoApiwz+l+tQjlCTAL3kYnfSFqt6KI6FeouJTFGQ86JKLDi2PR9x3WkIjrfeSWCuxWnQrsyumPwpVEUnlZhNamotTE38VmpohotkMyCGfywyChzgsrZHZyJVQomKNYASggpkLBfQwEEd09zugn8XguL2NArOI1i2m4dx+PUjoVJhvQFgON9GS1lcXAcU+XBlcIQBzwIVD4pPD8VdpBbHmmCJP/FyHApIvBwBu9bp7SZvn+ewAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxOC0wNC0xOVQwMTozNjo0My0wNDowMNV8Hl4AAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTgtMDQtMTlUMDE6MzY6NDMtMDQ6MDCkIabiAAAAAElFTkSuQmCC',
                }
                cat_icons = {
                    'Overview': retro_icons['folder'],
                    'Password Stats': retro_icons['folder'],
                    'All Groups': retro_icons['folder'],
                    'All Accounts': retro_icons['folder'],
                    'Privileged Accounts': retro_icons['folder'],
                    'Escalation Paths': retro_icons['folder'],
                    'Infrastructure Risk': retro_icons['folder'],
                }
                # Submenu item icons by category
                item_icons = {
                    'Overview': retro_icons['computer'],
                    'Password Stats': retro_icons['keys'],
                    'All Groups': retro_icons['group_row'],
                    'Escalation Paths': retro_icons['key_escalation'],
                    'Infrastructure Risk': retro_icons['computer'],
                }
                nav_html = '<div class="tree-root">\n'
                nav_html += '<div class="tree-node">'
                nav_html += '<span class="tree-toggle" onclick="toggleTree(this)">&#9660;</span>'
                nav_html += '<img src="{}" class="tree-icon">'.format(retro_icons['folder'])
                nav_html += '<span class="tree-label">Active Directory Users and Computers</span></div>\n'
                nav_html += '<div class="tree-children">\n'
                for cat_name in self.cat_order:
                    if cat_name not in cats:
                        continue
                    nav_html += '<div class="tree-node">'
                    nav_html += '<span class="tree-toggle" onclick="toggleTree(this)">&#9660;</span>'
                    nav_html += '<img src="{}" class="tree-icon">'.format(retro_icons['folder'])
                    nav_html += '<span class="tree-label">{}</span></div>\n'.format(htmllib.escape(cat_name))
                    nav_html += '<div class="tree-children">\n'
                    # Use group icon for Groups category, user icon for everything else
                    item_icon = item_icons.get(cat_name, self.user_icon)
                    for sec in cats[cat_name]:
                        active = ' active' if sec['id'] == first_id else ''
                        nav_html += (
                            '<a class="tree-item{active}" href="#" '
                            'data-section="{sid}" title="{title}">'
                            '<img src="{icon}" class="tree-icon">{title}</a>\n'
                        ).format(
                            active=active,
                            sid=sec['id'],
                            title=htmllib.escape(sec['title']),
                            icon=item_icon,
                        )
                    nav_html += '</div>\n'
                nav_html += '</div>\n</div>\n'
            else:
                cat_icons = {
                    'Overview': '&#9632;',
                    'Password Stats': '&#35;',
                    'All Groups': '&#128101;',
                    'All Accounts': '&#128100;',
                    'Privileged Accounts': '&#9733;',
                    'Escalation Paths': '&#9888;',
                    'Infrastructure Risk': '&#128187;',
                }
                nav_html = ''
                for cat_name in self.cat_order:
                    if cat_name not in cats:
                        continue
                    nav_html += '<div class="cat-section">\n'
                    nav_html += '<div class="cat-title">{}</div>\n'.format(htmllib.escape(cat_name))
                    icon = cat_icons.get(cat_name, '&#8226;')
                    for sec in cats[cat_name]:
                        active = ' active' if sec['id'] == first_id else ''
                        nav_html += (
                            '<a class="nav-link{active}" href="#" '
                            'data-section="{sid}" title="{title}">'
                            '<span class="nav-icon">{icon}</span>{title}</a>\n'
                        ).format(
                            active=active,
                            sid=sec['id'],
                            title=htmllib.escape(sec['title']),
                            icon=icon,
                        )
                    nav_html += '</div>\n'

            section_divs = ''
            for i, sec in enumerate(self.sections):
                display = 'block' if i == 0 else 'none'
                section_divs += '<div id="{}" class="section-pane" style="display:{};">\n{}\n</div>\n'.format(
                    sec['id'], display, sec['content'])

            if is_retro:
                custom_css = (
                    "*{font-family:Verdana,Arial,sans-serif !important;}"
                    "body{margin:0;padding:0;background:#fff;font-size:11px;}"
                    ".window{display:flex;flex-direction:column;height:100vh;background:#fff;border:1px solid #919b9c;}"
                    ".title-bar{background:linear-gradient(180deg,#0a246a,#0a246a,#a6caf0);padding:3px 6px;"
                    "display:flex;align-items:center;}"
                    ".title-bar-text{color:#fff;font-weight:700;font-size:11px;text-shadow:1px 1px #000;}"
                    ".menu-bar{background:#ece9d8;border-bottom:1px solid #919b9c;padding:2px 4px;"
                    "font-size:11px;color:#000;}"
                    ".toolbar{background:linear-gradient(180deg,#ece9d8,#d4d0c8);border-bottom:1px solid #919b9c;"
                    "padding:2px 4px;}"
                    ".content-wrapper{display:flex;flex:1;overflow:hidden;border-top:1px solid #fff;}"
                    ".sidebar{width:280px;min-width:280px;background:#fff;"
                    "border-right:1px solid #919b9c;overflow-y:auto;padding:4px;}"
                    ".tree-root{}"
                    ".tree-node{display:flex;align-items:center;gap:2px;padding:1px 0;cursor:default;}"
                    ".tree-toggle{width:16px;text-align:center;font-size:8px;cursor:pointer;color:#000;}"
                    ".tree-icon{width:16px;height:16px;}"
                    ".tree-label{color:#000;font-size:11px;}"
                    ".tree-children{margin-left:18px;border-left:1px dotted #999;}"
                    ".tree-children.collapsed{display:none;}"
                    ".tree-item{display:flex;align-items:center;gap:4px;padding:1px 4px;"
                    "cursor:pointer;text-decoration:none;color:#000;font-size:11px;line-height:1.4;margin-left:2px;}"
                    ".tree-item:hover{background:#316ac5;color:#fff;}"
                    ".tree-item.active{background:#316ac5;color:#fff;}"
                    ".main-content{flex:1;overflow-y:auto;padding:8px;background:#fff;}"
                    ".status-bar{background:#ece9d8;border-top:1px solid #919b9c;padding:2px 8px;"
                    "font-size:11px;color:#000;display:flex;}"
                    ".status-field{border-right:1px solid #919b9c;padding-right:8px;margin-right:8px;}"
                    "h2{margin:0 0 8px 0;font-size:11px;font-weight:bold;color:#000;border:none;padding:0;}"
                    ".clean-table{width:100%;border-collapse:collapse;font-size:11px;background:#fff;}"
                    ".clean-table th{background:#fff;border-right:1px solid #d4d0c8;border-bottom:1px solid #d4d0c8;"
                    "padding:3px 8px;text-align:left;font-weight:normal;color:#000;cursor:default;"
                    "white-space:nowrap;position:relative;}"
                    ".clean-table th:after{content:'\\25B4';margin-left:4px;font-size:8px;color:#000;}"
                    ".clean-table td{border-bottom:1px solid #f0f0f0;border-right:1px solid #f0f0f0;padding:2px 6px;color:#000;}"
                    ".clean-table td:first-child{display:flex;align-items:center;gap:4px;}"
                    ".clean-table .row-icon{width:16px;height:16px;vertical-align:middle;}"
                    ".clean-table tbody tr:hover{background:#316ac5;color:#fff;}"
                    ".clean-table tbody tr:hover td{color:#fff;}"
                    ".clean-table tbody tr.selected{background:#316ac5;color:#fff;}"
                    ".progress{height:14px;background:#fff;border:1px solid #919b9c;border-radius:0 !important;}"
                    ".progress-bar{height:100%;background:#316ac5;border-radius:0 !important;}"
                    ".win98-fieldset{background:#fff;border:1px solid #d4d0c8;padding:8px;margin:0 0 8px 0;}"
                    ".win98-fieldset legend{font-size:11px;font-weight:bold;color:#000;padding:0 4px;background:#fff;}"
                    ".win98-fieldset *{font-size:11px !important;}"
                    ".win98-fieldset .stat-value{font-size:14px !important;font-weight:bold;color:#000;}"
                    ".win98-fieldset .stat-label{font-size:11px !important;color:#000;}"
                    ".win98-fieldset .stat-sub{font-size:10px !important;color:#000;}"
                    ".win98-fieldset .progress{height:14px !important;margin-bottom:4px;}"
                    ".win98-fieldset hr{border:none;border-top:1px solid #d4d0c8;margin:6px 0;}"
                    ".d-flex{display:flex;}.justify-content-between{justify-content:space-between;}"
                    ".align-items-center{align-items:center;}.flex-grow-1{flex-grow:1;}"
                    ".mb-1{margin-bottom:4px;}.mb-2{margin-bottom:6px;}.mb-3{margin-bottom:8px;}"
                    ".me-2{margin-right:6px;}.mt-1{margin-top:4px;}.mt-2{margin-top:6px;}"
                    ".py-1{padding-top:2px;padding-bottom:2px;}.py-2{padding-top:4px;padding-bottom:4px;}"
                    ".border-bottom{border-bottom:1px solid #d4d0c8;}"
                    ".text-muted{color:#000 !important;}.text-center{text-align:center;}"
                    ".small{font-size:11px !important;}.fw-bold,.fw-semibold,strong{font-weight:bold;}"
                    ".btn{background:linear-gradient(180deg,#f5f5f5,#e1e1e1);border:1px solid #acacac;"
                    "border-radius:3px;padding:3px 12px;font-size:11px;font-family:'Segoe UI',Tahoma,sans-serif;"
                    "cursor:pointer;color:#000;font-family:Verdana,Arial,sans-serif;}"
                    ".btn:hover{background:linear-gradient(180deg,#e8f4fc,#c4e5f6);border-color:#3c7fb1;}"
                    ".btn:active{background:#c4e5f6;}"
                    ".win98-btn{background:#f0f0f0;border:2px outset #fff;border-color:#fff #808080 #808080 #fff;"
                    "padding:2px 10px;font-size:11px;font-family:Verdana,Arial,sans-serif;"
                    "cursor:pointer;color:#000;}"
                    ".win98-btn:hover{background:#e0e0e0;}"
                    ".win98-btn:active{border-style:inset;border-color:#808080 #fff #fff #808080;padding:3px 9px 1px 11px;}"
                    ".win98-input{background:#fff;border:2px inset #fff;border-color:#808080 #fff #fff #808080;"
                    "padding:2px 4px;font-size:11px;font-family:Verdana,Arial,sans-serif;color:#000;}"
                    ".win98-input:focus{outline:none;}"
                )
            else:
                custom_css = (
                    "body{font-size:.875rem;overflow:hidden;background:#fff;}"
                    ".sidebar{width:230px;min-width:230px;height:100vh;overflow-y:auto;"
                    "background:#1f2937;flex-shrink:0;}"
                    ".sidebar-header{color:#fff;font-weight:700;font-size:.9rem;"
                    "padding:.9rem 1rem;border-bottom:1px solid #374151;}"
                    ".cat-section{margin-top:.5rem;}"
                    ".cat-title{color:#6b7280;font-size:.65rem;font-weight:700;"
                    "text-transform:uppercase;letter-spacing:.1em;padding:.5rem 1rem .2rem;}"
                    ".sidebar .nav-link{display:flex;align-items:flex-start;gap:.6rem;"
                    "padding:.4rem 1rem;color:#d1d5db;text-decoration:none;font-size:.8rem;"
                    "border-left:3px solid transparent;line-height:1.3;}"
                    ".sidebar .nav-link:hover{color:#fff;background:#374151;}"
                    ".sidebar .nav-link.active{color:#fff;background:#374151;"
                    "border-left:3px solid #60a5fa;}"
                    ".nav-icon{font-size:.9rem;width:16px;text-align:center;flex-shrink:0;}"
                    ".main-content{flex:1;height:100vh;overflow-y:auto;padding:1.5rem;background:#fff;}"
                    "h2{font-size:1.15rem;border-bottom:2px solid #d1d5db;padding-bottom:.4rem;"
                    "margin-bottom:1rem;color:#4b5563;}"
                    ".clean-table{border-collapse:collapse;width:100%;}"
                    ".clean-table th{background:none;color:#6b7280;font-weight:600;"
                    "text-transform:uppercase;font-size:.7rem;letter-spacing:.05em;"
                    "padding:.75rem .5rem;border-bottom:2px solid #e5e7eb;}"
                    ".clean-table td{padding:.6rem .5rem;border-bottom:1px solid #f3f4f6;color:#374151;}"
                    ".clean-table tbody tr:hover{background:#f9fafb;}"
                )

            nav_selector = '.tree-item' if is_retro else '.sidebar .nav-link'
            nav_js = (
                "function showSection(id){{"
                "document.querySelectorAll('.section-pane').forEach(function(p){{p.style.display='none';}});"
                "document.querySelectorAll('{sel}').forEach(function(l){{l.classList.remove('active');}});"
                "var pane=document.getElementById(id);"
                "if(pane)pane.style.display='block';"
                "var link=document.querySelector('[data-section=\"'+id+'\"]');"
                "if(link)link.classList.add('active');}}"
                "function navigateTo(id){{"
                "if(location.hash!=='#'+id){{history.pushState(null,null,'#'+id);}}"
                "showSection(id);}}"
                "window.addEventListener('hashchange',function(){{"
                "var id=location.hash.slice(1);"
                "if(id)showSection(id);}});"
                "window.addEventListener('load',function(){{"
                "var id=location.hash.slice(1);"
                "if(id)showSection(id);}});"
                "document.querySelectorAll('{sel}').forEach(function(link){{"
                "link.addEventListener('click',function(e){{"
                "e.preventDefault();"
                "navigateTo(this.getAttribute('data-section'));"
                "}});}});"
                "function exportTableCSV(secId,filename){{"
                "var table=document.querySelector('#'+secId+' table');"
                "if(!table)return;"
                "var rows=Array.from(table.querySelectorAll('tr')).filter(function(r){{return r.style.display!=='none';}});"
                "var csv=rows.map(function(row){{"
                "return Array.from(row.querySelectorAll('th,td')).map(function(cell){{"
                "return '\"'+cell.textContent.trim().replace(/\"/g,'\"\"')+'\"';"
                "}}).join(',');}}).join('\\n');"
                "var a=document.createElement('a');"
                "a.href='data:text/csv;charset=utf-8,'+encodeURIComponent(csv);"
                "var now=new Date();var ts=now.getFullYear()+('0'+(now.getMonth()+1)).slice(-2)+('0'+now.getDate()).slice(-2)+'_'+('0'+now.getHours()).slice(-2)+('0'+now.getMinutes()).slice(-2);"
                "a.download=reportName+'_'+filename.replace(/ /g,'_')+'_'+ts+'.csv';a.click();}}"
            ).format(sel=nav_selector)
            nav_js = "var reportName='{}';\n".format(self.report_name) + nav_js
            if is_retro:
                nav_js += (
                    "function toggleTree(el){"
                    "var children=el.parentNode.nextElementSibling;"
                    "if(children && children.classList.contains('tree-children')){"
                    "children.classList.toggle('collapsed');"
                    "el.innerHTML=children.classList.contains('collapsed')?'&#9654;':'&#9660;';"
                    "}}"
                )

            if is_retro:
                html_template = (
                    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
                    "<meta charset=\"UTF-8\">\n"
                    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n"
                    "<title>Active Directory Users and Computers</title>\n"
                    "<style>{bootstrap_css}</style>\n"
                    "<style>{custom_css}</style>\n"
                    "</head>\n<body>\n"
                    "<div class=\"window\">\n"
                    "  <div class=\"title-bar\">\n"
                    "    <span class=\"title-bar-text\">Active Directory Users and Computers</span>\n"
                    "  </div>\n"
                    "  <div class=\"menu-bar\">File &nbsp; Action &nbsp; View &nbsp; Help</div>\n"
                    "  <div class=\"toolbar\"></div>\n"
                    "  <div class=\"content-wrapper\">\n"
                    "    <div class=\"sidebar\">\n"
                    "      {nav_html}\n"
                    "    </div>\n"
                    "    <div class=\"main-content\">{section_divs}</div>\n"
                    "  </div>\n"
                    "  <div class=\"status-bar\"><span class=\"status-field\">Ready</span></div>\n"
                    "</div>\n"
                    "<script>{bootstrap_js}</script>\n"
                    "<script>{nav_js}</script>\n"
                    "{deferred_scripts}"
                    "</body>\n</html>"
                )
            else:
                html_template = (
                    "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
                    "<meta charset=\"UTF-8\">\n"
                    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n"
                    "<title>Password Audit</title>\n"
                    "<style>{bootstrap_css}</style>\n"
                    "<style>{custom_css}</style>\n"
                    "</head>\n<body>\n"
                    "<div style=\"display:flex;height:100vh;\">\n"
                    "  <div class=\"sidebar\">\n"
                    "    <div class=\"sidebar-header\">Password Audit</div>\n"
                    "    {nav_html}\n"
                    "  </div>\n"
                    "  <div class=\"main-content\">{section_divs}</div>\n"
                    "</div>\n"
                    "<script>{bootstrap_js}</script>\n"
                    "<script>{nav_js}</script>\n"
                    "{deferred_scripts}"
                    "</body>\n</html>"
                )

            return html_template.format(
                bootstrap_css=self.assets.get('bootstrap_css', ''),
                custom_css=custom_css,
                nav_html=nav_html,
                section_divs=section_divs,
                bootstrap_js=self.assets.get('bootstrap_js', ''),
                nav_js=nav_js,
                deferred_scripts=''.join(
                    '<script>{}</script>\n'.format(s) for s in self.deferred_scripts
                ),
            )

        def write(self, filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(self.render())

    report_base = os.path.splitext(os.path.basename(output_file))[0]
    sfhb = SingleFileHtmlBuilder(assets, args, category_order, report_name=report_base)

    # Register user details for clickable usernames
    if not args.less and 'user_groups' in locals() and 'user_info' in locals():
        sfhb.register_user_details(user_groups, user_info)
    # Register group detail IDs for clickable group rows
    if not args.less and 'group_data' in locals():
        sfhb.register_group_detail_ids(group_data)
    # Register hash_users for password sharing lookup
    if 'hash_users' in locals():
        sfhb.register_hash_users(hash_users)

    print("[+] Building HTML report...")

    # summary section
    summary_rows = []
    for stat in stats:
        summary_rows.append([stat[0], stat[1]])
    for item in query_output_data:
        summary_rows.append([len(item['enabled']) + len(item['disabled']), item['label']])

    # password age buckets
    now = datetime.datetime.now()
    age_buckets = [
        ('Under 90 days',  0),
        ('90 to 180 days', 0),
        ('180 to 365 days', 0),
        ('1 to 2 years',   0),
        ('Over 2 years',   0),
    ]
    age_counts = [0, 0, 0, 0, 0]
    for entry in num_pass_hashes_list:
        dt = entry[4]
        if not dt or dt == '':
            continue
        try:
            days = (now - dt).days
            if   days < 90:  age_counts[0] += 1
            elif days < 180: age_counts[1] += 1
            elif days < 365: age_counts[2] += 1
            elif days < 730: age_counts[3] += 1
            else:            age_counts[4] += 1
        except Exception:
            pass
    age_buckets = [(age_buckets[i][0], age_counts[i]) for i in range(5)]

    # reuse severity — count affected users, not unique passwords
    reuse_stats = {
        '2+ users':  sum(p[0] for p in repeated_passwords if p[0] >= 2),
        '5+ users':  sum(p[0] for p in repeated_passwords if p[0] >= 5),
        '10+ users': sum(p[0] for p in repeated_passwords if p[0] >= 10),
    }

    homepage_data = {
        'total_users': num_pass_hashes,
        'total_cracked': num_cracked,
        'perc_cracked': perc_total_cracked,
        'username_eq_password': user_pass_match,
        'lm_hashes': non_blank_lm,
        'top_groups': group_data if not args.less else [],
        'password_lengths': password_lengths,
        'repeated_passwords': repeated_passwords,
        'password_complexity': password_complexity,
        'query_output_data': query_output_data,
        'password_age_buckets': age_buckets,
        'reuse_stats': reuse_stats,
    }
    summary_content, chart_js = sfhb.build_homepage(
        homepage_data, sfhb._make_table(summary_rows, ['Count', 'Description'])
    )
    sfhb.add_section('summary', 'Summary', summary_content,
                     category_map.get('Summary', 'Overview'), deferred_js=chart_js)

    # stat detail sections
    # Tables with username columns need user icons, computer tables need computer icons
    user_tables = ['Password Hashes', 'LM Hashes (Non-Blank)',
                   'Users with Username Matching Password', 'Password Complexity Stats']
    computer_tables = ['Unsupported Operating Systems']
    for stat in stats:
        if len(stat) == 4:
            if stat[1] == 'Groups Cracked by Percentage':
                continue
            if stat[1] == 'Password Reuse Stats':
                continue  # handled separately with drill-down
            if stat[1] in user_tables:
                icon = sfhb.user_icon
            elif stat[1] in computer_tables:
                icon = sfhb.computer_icon
            else:
                icon = None
            sfhb.add_table_section(stat[1], stat[3], stat[2],
                                   category=category_map.get(stat[1], 'Password Stats'),
                                   row_icon=icon)

    # Password reuse with drill-down to see users per shared hash
    print("[+] Building password reuse drill-down section")
    sfhb.add_password_reuse_drill_section(shared_hashes, hash_users,
                                          category=category_map.get('Password Reuse Stats', 'Password Stats'))

    if not args.less:
        print("[+] Building group drill-down sections")
        sfhb.add_group_drill_section(group_data, group_members,
                                     category=category_map.get('Groups Cracked by Percentage', 'All Groups'))
        print("[+] Building group membership ranking")
        sfhb.add_group_membership_ranking_section(user_groups, user_info,
                                     category=category_map.get('Group Membership Ranking', 'Privileged Accounts'))

    # per-category cracked user sections
    print("[+] Building user account sections")
    for item in query_output_data:
        cols = list(item['columns']) + ['Status']
        all_entries = [list(e) + ['Enabled'] for e in item['enabled']] + \
                      [list(e) + ['Disabled'] for e in item['disabled']]
        # Sort: "All User Accounts" alphabetically by username, others by share count/password length
        if item['label'] == 'All User Accounts':
            all_entries = sorted(all_entries, key=lambda x: str(x[0] or '').lower())
        else:
            sort_idx = 2
            all_entries = sorted(all_entries, key=lambda x: -1 if x[sort_idx] is None else x[sort_idx], reverse=True)
        sfhb.add_table_section(item['label'], all_entries, cols,
                               category=category_map.get(item['label'], 'User Accounts'),
                               row_icon=sfhb.user_icon)

    sfhb.write(output_file)
    print("[+] Report written to: {}".format(output_file))

    # Open report in browser
    webbrowser.open('file://' + os.path.abspath(output_file))


def pet_max():

    messages = [
        "Max is a good boy",
        "Woof!",
        "Bark!",
        "Bloodhound (Legacy) is great!",
        "Black Lives Matter!",
        "Wear a mask!",
        "Hack the planet!",
        "10/10 would pet - @blurbdust",
        "dogsay > cowsay - @b1gbroth3r",
        "much query, very sniff - @vexance",
        "can has treat? - @thetoddluci0"
    ]

    max = r"""
                                        \   /
         /|                   ______     \ |
        { (                  /( ) ^ `--o  |/
         \ \________________/     ____/
          \                       /
           (    >    ___   >     )
            \_      )   \____\  \\
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
    getinfo_switch.add_argument("--stale-accounts", dest="staleaccounts",default=False,action="store_true",help="Return a list of all users that are enable but have not logged into the domain recently. Configure with --stale-threshold.")
    getinfo_switch.add_argument("--stale-computers", dest="stalecomputers",action="store_true",help="Return a list of all computers which are enabled but have not logged into the domain recently. Configure with --stale-threshold.")

    getinfo.add_argument("--get-note",dest="getnote",default=False,action="store_true",help="Optional, return the \"notes\" attribute for whatever objects are returned")
    getinfo.add_argument("-l",dest="label",action="store_true",default=False,help="Optional, apply labels to the columns returned")
    getinfo.add_argument("-e","--enabled",dest="enabled",action="store_true",default=False,help="Optional, only return enabled domain users (only works for --users and --passnotreq flags as of now)")
    getinfo.add_argument("-d", "--delim",dest="delimeter", default="-", required=False, help="Flag to specify output delimeter between attributes (default '-')")
    getinfo.add_argument("--stale-threshold", dest="threshold", default=90,type=int, help="Number of days an account can have failed to log in for in order to be considered stale. Default: 90 days")

    # MARKOWNED function paramters
    markowned.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markowned.add_argument("--userpass", action="store_true",help="Treat input file as a USER:PASS file")
    markowned.add_argument('-s', '--store',action="store_true", help="Record the password in the database. (Implies --userpass)")
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
    dpat.add_argument("-o","--output",dest="output",default="",required=False,help="Output base name for HTML report (default: report)")
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
            # Check this here as it's a continuable error
            if args.store == True and args.userpass ==False:
                print('[!] -s or --store passed, assuming the input file is in user:pass format!')
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
