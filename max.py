#!/usr/bin/python3

import requests
from requests.auth import HTTPBasicAuth
import sys
import argparse
import json
import random
import re
from itertools import zip_longest
import csv
import binascii
import math
import os
import numpy
try:
    import html as htmllib
except ImportError:
    import cgi as htmllib

# option to hardcode URL & URI
global_url = "http://127.0.0.1:7474"
global_uri = "/db/data/transaction/commit"

# option to hardcode creds, these will be used as the username and password "defaults"
global_username = "neo4j"
global_password = "bloodhound"


def do_test(args):

    try:
        requests.get(args.url + global_uri)
        return True
    except:
        return False


def do_query(args, query):

    data = {"statements":[{"statement":query}]}
    headers = {'Content-type': 'application/json', 'Accept': 'application/json; charset=UTF-8'}
    auth = HTTPBasicAuth(args.username, args.password)

    r = requests.post(args.url + global_uri, auth=auth, headers=headers, json=data)

    if r.status_code == 401:
        print("Authentication error: the supplied credentials are incorrect for the Neo4j database, specify new credentials with -u & -p or hardcode your credentials at the top of the script")
        exit()
    else:
        return r


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
        "groups-full" : {
            "query" : "MATCH (n),(g:Group) MATCH (n)-[r:MemberOf]->(g) RETURN DISTINCT g.name,n.name",
            "columns" : ["GroupName","MemberName"]
            },
        "das" : {
            "query" : "MATCH p=(n:User)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN DISTINCT n.name",
            "columns" : ["UserName"]
            },
        "dasess" : {
            "query" : "MATCH (u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' WITH COLLECT(u) AS das MATCH (u2:User)<-[r2:HasSession]-(c:Computer) WHERE u2 IN das RETURN DISTINCT u2.name,c.name ORDER BY u2.name",
            "columns" : ["UserName","ComputerName"]
            },
        "unconstrained" : {
            "query" : "MATCH (n) WHERE n.unconstraineddelegation=TRUE RETURN n.name",
            "columns" : ["ObjectName"]
            },
        "nopreauth" : {
            "query" : "MATCH (n:User) WHERE n.dontreqpreauth=TRUE RETURN n.name",
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
            "columns" : ["AdminComputerName","CompterName"]
            },
        "nolaps" : {
            "query" : "MATCH (c:Computer {haslaps:false}) RETURN c.name",
            "columns" : ["ComputerName"]
            },
        "passnotreq" : {
            "query" : "MATCH (u:User {{passwordnotreqd:true}}) {enabled} RETURN u.name",
            "columns" : ["UserName"]
        },
        "sidhist" : {
            "query" : "MATCH (n) WHERE n.sidhistory<>[] UNWIND n.sidhistory AS x OPTIONAL MATCH (d:Domain) WHERE x CONTAINS d.objectid OPTIONAL MATCH (m {objectid:x}) RETURN n.name,x,d.name,m.name ORDER BY n.name",
            "columns" : ["ObjectName","SID","DomainName","ForeignObjectName"]
        },
        "unsupos" : {
            "query" : "MATCH (c:Computer) WHERE c.operatingsystem =~ '.*(2000|2003|2008|xp|vista| 7 |me).*' RETURN c.name,c.operatingsystem",
            "columns" : ["ComputerName","OperatingSystem"]
        }
    }

    query = ""
    cols = []
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
    elif (args.unconstrained):
        query = queries["unconstrained"]["query"]
        cols = queries["unconstrained"]["columns"]
    elif (args.nopreauth):
        query = queries["nopreauth"]["query"]
        cols = queries["nopreauth"]["columns"]
    elif (args.passnotreq):
        query = queries["passnotreq"]["query"]
        cols = queries["passnotreq"]["columns"]
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
    elif (args.unamesess != ""):
        query = queries["sessions"]["query"].format(uname=args.unamesess.upper().strip())
        cols = queries["sessions"]["columns"]
    elif (args.unameadminto != ""):
        query = queries["localadmin"]["query"].format(uname=args.unameadminto.upper().strip())
        cols = queries["localadmin"]["columns"]
    elif (args.comp != ""):
        query = queries["adminsof"]["query"].format(comp=args.comp.upper().strip())
        cols = queries["adminsof"]["columns"]
    elif (args.groupmems != ""):
        query = queries["group-members"]["query"].format(gname=args.groupmems.upper().strip())
        cols = queries["group-members"]["columns"]

    if args.getnote:
        query = query + ",n.notes"
        cols.append("Notes")

    if args.enabled and "{enabled}" in query:
        query = query.format(enabled="WHERE u.enabled=true")
    elif "{enabled}" in query:
        query = query.format(enabled="")
    else:
        pass

    r = do_query(args, query)
    x = json.loads(r.text)
    #print(r.text)
    entry_list = x["results"][0]["data"]

    if args.label:
        print(" - ".join(cols))
    for value in entry_list:
        try:
            print(" - ".join(value["row"]))
        except:
            if len(cols) == 1:
                pass
            else:
                print(" - ".join(map(str,value["row"])))


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

    r = do_query(args, args.QUERY)
    x = json.loads(r.text)

    try:
        entry_list = x["results"][0]["data"]

        for value in entry_list:
            try:
                print(" - ".join(value["row"]))
            except:
                if len(value["row"]) == 1:
                    pass
                else:
                    print(" - ".join(map(str,value["row"])))

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

    node_name = args.NODE_NAME.upper().strip()
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

    query = 'MATCH p=()-[r:{edge}]->() DELETE r RETURN COUNT(DISTINCT(p))'.format(edge=args.EDGENAME)
    r = do_query(args,query)
    number = int(json.loads(r.text)['results'][0]['data'][0]['row'][0] / 2)
    print("[+] '{edge}' edge removed from {number} object relationships".format(edge=args.EDGENAME,number=number))


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
def sanitize(args, pass_or_hash):
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


def dpat_func(args):

    cracked = {}
    cracked_user_info = {}
    lm_hashes = {}
    nt_hashes = {}

    query_counts = {}
    password_lengths = {}

    if (args.ntdsfile != None):
        ntds = open(args.ntdsfile, 'r').readlines()
    else:
        print("[-] Error, Need NTDS file")
        return
    if (args.potfile != None):
        potfile = open(args.potfile, 'r').readlines()
    else:
        print("[-] Error, Need potfile")
        return

    if ((args.outputfile) and (not args.csv and not args.html)):
        print("[-] Error, --outputfile requires --csv and/or --html type output flags")
        return

    try:
        print("[+] Processing NTDS")
        ntds_parsed = []
        # ntds_cracked = []
        for line in ntds:
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
            if (line[3] not in nt_hashes):
                nt_hashes[line[3]] = []
            nt_hashes[line[3]].append(line[0])
            to_append.append(None)
            ntds_parsed.append(to_append)

        print("[+] Processing Potfile")
        # password stats like counting reused cracked passwords
        for user in ntds_parsed:
            # LM found
            if (user[3] != "aad3b435b51404eeaad3b435b51404ee"):
                if (user[3] not in lm_hashes):
                    lm_hashes[user[3]] = []
                full_uname = '/'.join(filter(None, [user[1], user[0]]))
                lm_hashes[user[3]].append(full_uname)

            for line in potfile:
                line = line.replace("\r", "").replace("\n", "")
                if (line == ""):
                    continue
                line = line.replace("$NT$", "").replace("$LM$", "").split(":")

                # match NT hash
                if (line[0] == user[4]):
                    # found in potfile, cracked
                    if ("$HEX[" in line[1]):
                        print("[!] found $HEX[], stripping and unpacking")
                        user[5] = binascii.unhexlify( str( line[1].split("[")[1].replace("]", "") ) ).decode("utf-8")
                    else:
                        if (user[4] == "31d6cfe0d16ae931b73c59d7e0c089c0"):
                            user[5] = ""
                        else:
                            user[5] = line[1]
                    if (user[5] not in cracked):
                        cracked[user[5]] = 0
                    cracked[user[5]] += 1

        try:
            print('[+] Mapping NTDS users to BloodHound data')
            for i in range(0,len(ntds_parsed)):
                # [ username, domain, rid, LM, NT, plaintext||None, bh username, sid]
                # try query1 to see if we can resolve the users based off solely username+domain
                try:
                    user = ntds_parsed[i]
                    crack_query = ""
                    if user[5] is not None:
                        crack_query = 'SET u.cracked=true'
                    query1 = "MATCH (u:User) WHERE u.name='{username}' {crack_query} RETURN u.name,u.objectid".format(username=str(user[0].upper().strip() + "@" + user[1].upper().strip()), crack_query=crack_query)
                    r = do_query(args,query1)
                    bh_users = json.loads(r.text)['results'][0]['data']
                    if bh_users == []:
                        # try matching based off username and rid
                        query2 = "MATCH (u:User) WHERE u.name STARTS WITH '{username}@' AND u.objectid ENDS WITH '-{rid}' {crack_query} RETURN u.name,u.objectid".format(username=user[0].upper(), rid=user[2].upper(), crack_query=crack_query)
                        r = do_query(args,query2)
                        bh_users = json.loads(r.text)['results'][0]['data']

                    bh_username = bh_users[0]['row'][0]
                    bh_sid = bh_users[0]['row'][1]

                    ntds_parsed[i].append(bh_username)

                    cracked_user_info[bh_sid] = ntds_parsed[i]

                except Exception as g:
                    # user doesn't have an entry in AD, disregard and cleanup stats
                    # current_lm = ntds_parsed[i][3]
                    # if (current_lm == "aad3b435b51404eeaad3b435b51404ee"):
                    #     pass
                    # elif (lm_hashes[current_lm] != 1):
                    #     lm_hashes[current_lm] -= 1
                    # else:
                    #     lm_hashes.pop(current_lm, None)
                    # curent_nt = ntds_parsed[i][4]
                    # if (nt_hashes[curent_nt] != 1):
                    #     nt_hashes[curent_nt] -= 1
                    # else:
                    #     nt_hashes.pop(curent_nt, None)
                    pass


        except Exception as f:
            print("[-] Error: {}".format(f))
            return

        print("[+] BloodHound data queried successfully, {} NTDS users mapped to BH data".format(len(ntds_parsed)))

    except Exception as e:
        print("[-] Error, {}".format(e))
        return

    ###
    ### Searching for specific user/password
    ###

    if args.passwd:
        print("[+] Searching for users with password {}".format(args.passwd))
        for user in cracked_user_info:
            if (cracked_user_info[user][5] == args.passwd):
                if (cracked_user_info[user][1] != ''):
                    print("{}".format(cracked_user_info[user][6]))
                else:
                    print("{}".format(cracked_user_info[user][0]))

        return
    if args.usern:
        for user in cracked_user_info:
            if (user[1] != ''):
                if (cracked_user_info[userRecord][6] == args.usern.upper()):
                    print("{}:{}".format(cracked_user_info[user][6], sanitize(args, cracked_user_info[user][5])))
            else:
                continue
                #if (user[0].upper() == args.usern.split("@")[0]):
                #    print(sanitize(args, user[5]))

        return

    ###
    ### Automated Cypher Queries for standard stuff, outputting users
    ###

    queries = [
        {
            'query' : "MATCH (u:User) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "All User Accounts"
        },
        {
            'query' : "MATCH (u:User {cracked:true}) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "All User Accounts Cracked"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH (u:User)-[r:MemberOf*1..]->(g) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Domain Admin Members"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH (u:User {cracked:true})-[r:MemberOf*1..]->(g) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Domain Admin Members Cracked"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-519' MATCH (u:User)-[r:MemberOf*1..]->(g) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Enterprise Admin Members"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-519' MATCH (u:User {cracked:true})-[r:MemberOf*1..]->(g) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Enterprise Admin Accounts Cracked"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-544' MATCH (u:User)-[r:MemberOf]->(g) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Administrator Group Members"
        },
        {
            'query' : "MATCH (g:Group) WHERE g.objectid ENDS WITH '-544' MATCH (u:User {cracked:true})-[r:MemberOf]->(g) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Administrator Group Member Accounts Cracked"
        },
        {
            'query' : "MATCH (u:User {cracked:true,hasspn:true}) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Kerberoastable Users Cracked"
        },
        {
            'query' : "MATCH (u:User {cracked:true,dontreqpreauth:true}) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Accounts Not Requiring Kerberos Pre-Authentication Cracked"
        },
        {
            'query' : "MATCH (u:User {cracked:true,unconstraineddelegation:true}) RETURN DISTINCT u.name,u.objectid,u.enabled",
            'label' : "Unconstrained Delegation Accounts Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true}),(n {unconstraineddelegation:true}),p=shortestPath((u)-[r*1..]->(n)) WHERE NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT u=n RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Paths To Unconstrained Delegation Objects Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true}),(n {highvalue:true}),p=shortestPath((u)-[r*1..]->(n)) WHERE NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT u=n RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Paths To High Value Targets Cracked"
        },
        {
            "query" : "MATCH p1=(u1:User {cracked:true})-[r:AdminTo]->(n1),p2=(u2:User {cracked:true})-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n2) WITH COLLECT(u1)+COLLECT(u2) AS users UNWIND users AS u RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Local Admin Rights Cracked"
        },
        {
            "query" : "MATCH p1=(u:User {cracked:true})-[r:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|CanRDP|CanPSRemote|ExecuteDCOM|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory]->(n1) RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Explicit Controlling Privileges Cracked"
        },
        {
            "query" : "MATCH p2=(u:User {cracked:true})-[r1:MemberOf*1..]->(g:Group)-[r2:AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ReadLAPSPassword|ReadGMSAPassword|CanRDP|CanPSRemote|ExecuteDCOM|AllowedToDelegate|AddAllowedToAct|AllowedToAct|SQLAdmin|HasSIDHistory]->(n2) RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Group Delegated Controlling Privileges Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true}) WHERE u.pwdlastset < (datetime().epochseconds - (365 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Passwords Set > 1yr Ago Cracked"
        },
        {
            "query" : "MATCH (u:User {cracked:true,pwdneverexpires:true}) RETURN DISTINCT u.name,u.objectid,u.enabled",
            "label" : "Accounts With Passwords That Never Expire Cracked"
        }
    ]

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

    for search_value in queries:

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
        for entry in resp:
            query_counts[label] += 1 #TODO
            status_flag = "disabled"
            if entry['row'][2]:
                status_flag = "enabled"

            if "cracked" in label.lower():
                try:
                    length = ''
                    if cracked_user_info[entry['row'][1]][5] != None:
                        length = len(cracked_user_info[entry['row'][1]][5])
                    full_uname = '/'.join(filter(None, [cracked_user_info[entry['row'][1]][1], cracked_user_info[entry['row'][1]][0]]))
                    dat[status_flag].append([full_uname, cracked_user_info[entry['row'][1]][5], length, cracked_user_info[entry['row'][1]][4]])
                #     else:
                #         dat['disabled'].append(cracked_user_info[entry['row'][1]])
                except:
                    pass
            else:
                try:
                    full_uname = '/'.join(filter(None, [cracked_user_info[entry['row'][1]][1], cracked_user_info[entry['row'][1]][0]]))
                    all_hashes_shared = ', '.join(nt_hashes[cracked_user_info[entry['row'][1]][4]])
                    if len(nt_hashes[cracked_user_info[entry['row'][1]][4]]) > 30:
                        all_hashes_shared = "Shared Hash List > 30"
                    dat[status_flag].append( [full_uname, cracked_user_info[entry['row'][1]][4], all_hashes_shared, len(nt_hashes[cracked_user_info[entry['row'][1]][4]]), cracked_user_info[entry['row'][1]][5] ])
                except:
                    pass

        if "cracked" in label.lower():
            dat['columns'] = ["Username", "Password", "Password Length", "NT Hash"]
        else:
            dat['columns'] = ["Username", "NT Hash", "Users Sharing this Hash", "Share Count", "Password"]

        query_output_data.append(dat)

    ###
    ### Get the Overall Stats ready
    ###

    print("[+] Querying for Group Statistics")
    percent_cracked_groups = []
    query = "MATCH p2=(u2:User)-[r2:MemberOf]->(g2:Group),p3=(u3:User {cracked:true})-[r3:MemberOf]->(g2:Group) RETURN g2.name, COUNT(DISTINCT(u3))*100/COUNT(DISTINCT(u2)), COUNT(DISTINCT(u3.name)), COUNT(DISTINCT(u2.name)) ORDER BY COUNT(DISTINCT(u3))*100/COUNT(DISTINCT(u2)) DESC"
    r = do_query(args,query)
    resp = json.loads(r.text)['results'][0]['data']
    for entry in resp:
        group_name = entry['row'][0]
        percent = entry['row'][1]
        cracked_users = entry['row'][2]
        total_users = entry['row'][3]
        percent_cracked_groups.append([group_name, percent, cracked_users, total_users])

    percent_cracked_groups_number = len(percent_cracked_groups)

    print("[+] Generating Overall Statistics")
    num_pass_hashes = len(ntds_parsed)
    num_pass_hashes_list = []
    for user in ntds_parsed:
        full_uname = '/'.join(filter(None, [user[1], user[0]]))
        length = ''
        if user[5] != None:
            length = len(user[5])
        num_pass_hashes_list.append([full_uname, user[5], length, user[4]])

    num_uniq_hash = len(nt_hashes)
    num_cracked = sum(cracked.values())
    num_uniq_cracked = len(cracked)
    if (num_pass_hashes > 0):
        perc_total_cracked = "{:2.2f}".format((float(num_cracked) / float(num_pass_hashes) * 100))
        perc_uniq_cracked = "{:2.2f}".format((float(num_uniq_cracked) / float(num_uniq_hash) * 100))
    else:
        # avoid div by zero
        perc_total_cracked = 00.00
        perc_uniq_cracked = 00.00

    # get number of DAs to match DPAT, assume connection works since we mapped all users already
    non_blank_lm = 0 #sum(lm_hashes.values())
    uniq_lm = len(lm_hashes)
    lm_hash_list = []
    for lm_hash in lm_hashes:
        non_blank_lm += len(lm_hashes[lm_hash])
        for user in lm_hashes[lm_hash]:
            lm_hash_list.append([user, lm_hash, len(lm_hashes[lm_hash])])

    user_pass_match_list = []
    for user in cracked_user_info:
        if cracked_user_info[user][5] == None:
            pass
        else:
            if cracked_user_info[user][0].lower() == cracked_user_info[user][5].lower():
                full_uname = '/'.join(filter(None, [cracked_user_info[user][1], cracked_user_info[user][0]]))
                length = len(cracked_user_info[user][5])
                user_pass_match_list.append([full_uname, cracked_user_info[user][5], length, cracked_user_info[user][4]])
    user_pass_match = len(user_pass_match_list)

    # Get Password Length Stats
    for password in cracked:
        pw_len = len(password)
        if (pw_len not in password_lengths):
            password_lengths[pw_len] = 0
        password_lengths[pw_len] += cracked[password]

    stats = [
        [num_pass_hashes, "Password Hashes", ["NTDS Username", "Password", "Password Length", "NT Hash"], num_pass_hashes_list], #, ntds_parsed],
        [num_uniq_hash, "Unique Password Hashes"],
        [num_cracked, "Passwords Discovered Through Cracking"],
        [perc_total_cracked, "Percent of Passwords Cracked"],
        [perc_uniq_cracked, "Percent of Unique Passwords Cracked"],
        [non_blank_lm, "LM Hashes (Non-Blank)", ["NTDS Username", "LM Hash", "Shared Count"], lm_hash_list],
        [uniq_lm, "Unique LM Hashes (Non-Blank)"],
        [user_pass_match, "Users with Username Matching Password", ["NTDS Username", "Password", "Password Length", "NT Hash"], user_pass_match_list],
        [percent_cracked_groups_number, "Groups Cracked by Percentage",  ["Group Name", "Percent Cracked", "Cracked Users", "Total Users"], percent_cracked_groups]
    ]

    # Get Password (Complexity) Stats
    # sort from most reused to least reused dict to list of tuples
    # get the first instance of not repeated password to be min'd later
    num_repeated_passwords = 0
    cracked = sorted(cracked.items(), key=lambda x: x[1], reverse=True)

    for i in range(0, len(cracked)):
        if (cracked[i][1] == 1):
            num_repeated_passwords = i
            break

    # clear the "cracked" tag
    clear_query = "MATCH (u:User {cracked:true}) REMOVE u.cracked"
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
            item['enabled'].insert(0,enable_label)
            item['disabled'].insert(0,disable_label)

            full_data.append(item['enabled'])
            full_data.append(item['disabled'])

        export_data = zip_longest(*full_data, fillvalue='')
        filename = args.outputfile.replace(".csv", "") + ".csv" #node_name.replace(" ","_") + ".csv"
        with open(filename,'w', encoding='utf-8', newline='') as file:
            wr = csv.writer(file)
            wr.writerows(export_data)
        file.close()
        print("[+] All data written to {}.csv".format(args.outputfile))

    # use "if" specifically so you can output both html & csv on the same run
    # This code heavily modified from the original DPAT tool, credit where it's due
    if args.html:

        if not os.path.exists(args.outputfile):
            os.makedirs(args.outputfile)

        filebase = args.outputfile + "/"
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
                                col_data = sanitize(args, column)
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

        # print(css_styling)

    if args.outputfile == "":
        print("[+] Outputting Stats to Terminal...")

        # Output to CLI

        print("")
        print("")
        print("{:^82}".format("Overall Statistics"))
        print(" " + "="*86)
        print("|{:^10}|{:^75}|".format("Count", "Description"))
        print(" " + "="*86)

        for set in stats:
             print("|{:^10}|{:^75}|".format(set[0], set[1]))

        for item in query_output_data:
            print("|{:^10}|{:^75}|".format(len(item['enabled']) + len(item['disabled']),item['label']))

        print(" " + "="*86)
        print("")
        print("")
        print("{:^82}".format("Password Length Stats"))
        print(" " + "="*86)
        print("|{:^10}|{:^75}|".format("Count", "Description"))
        print(" " + "="*86)
        for pw_len in sorted(password_lengths.keys(), reverse=True):
            print("|{:^10}|{:^75}|".format(password_lengths[pw_len], "{} Characters".format(pw_len)))
        print(" " + "="*86)
        print("")
        print("")
        print("{:^82}".format("Password Reuse Stats (Top 10%)"))
        print(" " + "="*86)
        print("|{:^10}|{:^75}|".format("Count", "Description"))
        print(" " + "="*86)
        for i in range(0, min(num_repeated_passwords, math.ceil( len(cracked) * 0.10 ), 50)): # cap at 50 reused passwords
            if cracked[i][0] != '':
                print("|{:^10}|{:^75}|".format(cracked[i][1], sanitize(args, cracked[i][0])))
        print(" " + "="*86)
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
        "dogsay > cowsay - @b1gbroth3r"
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
    dpat = switch.add_parser("dpat",help="Based off Domain Password Audit Tool, run cracked user-password analysis tied with BloodHound through a Hashcat potfile & NTDS")
    petmax = switch.add_parser("pet-max",help="Pet max, hes a good boy (pet me again, I say different things)")

    # GETINFO function parameters
    getinfo_switch = getinfo.add_mutually_exclusive_group(required=True)
    getinfo_switch.add_argument("--users",dest="users",default=False,action="store_true",help="Return a list of all domain users")
    getinfo_switch.add_argument("--comps",dest="comps",default=False,action="store_true",help="Return a list of all domain computers")
    getinfo_switch.add_argument("--groups",dest="groups",default=False,action="store_true",help="Return a list of all domain groups")
    getinfo_switch.add_argument("--groups-full",dest="groupsfull",default=False,action="store_true",help="Return a list of all domain groups with all respective group members")
    getinfo_switch.add_argument("--group-members",dest="groupmems",default="",help="Return a list of all members of an input GROUP")
    getinfo_switch.add_argument("--das",dest="das",default=False,action="store_true",help="Return a list of all Domain Admins")
    getinfo_switch.add_argument("--dasessions",dest="dasess",default=False,action="store_true",help="Return a list of Domain Admin sessions")
    getinfo_switch.add_argument("--nolaps",dest="nolaps",default=False,action="store_true",help="Return a list of all computers without LAPS")
    getinfo_switch.add_argument("--unconst",dest="unconstrained",default=False,action="store_true",help="Return a list of all objects configured with Unconstrained Delegation")
    getinfo_switch.add_argument("--npusers",dest="nopreauth",default=False,action="store_true",help="Return a list of all users that don't require Kerberos Pre-Auth (AS-REP roastable)")
    getinfo_switch.add_argument("--passnotreq",dest="passnotreq",default=False,action="store_true",help="Return a list of all users that have PasswordNotRequired flag set to true")
    getinfo_switch.add_argument("--sidhist",dest="sidhist",default=False,action="store_true",help="Return a list of objects configured with SID History")
    getinfo_switch.add_argument("--unsupported",dest="unsupos",default=False,action="store_true",help="Return a list of computers running an unsupported OS")
    getinfo_switch.add_argument("--sessions",dest="unamesess",default="",help="Return a list of computers that UNAME has a session on")
    getinfo_switch.add_argument("--adminto",dest="unameadminto",default="",help="Return a list of computers that UNAME is a local administrator to")
    getinfo_switch.add_argument("--adminsof",dest="comp",default="",help="Return a list of users that are administrators to COMP")
    getinfo_switch.add_argument("--owned",dest="owned",default=False,action="store_true",help="Return all objects that are marked as owned")
    getinfo_switch.add_argument("--owned-groups",dest="ownedgroups",default=False,action="store_true",help="Return groups of all owned objects")
    getinfo_switch.add_argument("--hvt",dest="hvt",default=False,action="store_true",help="Return all objects that are marked as High Value Targets")
    getinfo_switch.add_argument("--desc",dest="desc",default=False,action="store_true",help="Return all objects with the description field populated, also returns description for easy grepping")
    getinfo_switch.add_argument("--admincomps",dest="admincomps",default=False,action="store_true",help="Return all computers with admin privileges to another computer [Comp1-AdminTo->Comp2]")

    getinfo.add_argument("--get-note",dest="getnote",default=False,action="store_true",help="Optional, return the \"notes\" attribute for whatever objects are returned")
    getinfo.add_argument("-l",dest="label",action="store_true",default=False,help="Optional, apply labels to the columns returned")
    getinfo.add_argument("-e","--enabled",dest="enabled",action="store_true",default=False,help="Optional, only return enabled domain users (only works for --users and --passnotreq flags as of now)")

    # MARKOWNED function paramters
    markowned.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markowned.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (method of compromise)")
    markowned.add_argument("--clear",dest="clear",action="store_true",help="Remove owned marker from all objects")

    # MARKHVT function parameters
    markhvt.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markhvt.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (reason for HVT status)")
    markhvt.add_argument("--clear",dest="clear",action="store_true",help="Remove HVT marker from all objects")

    # QUERY function arguments
    query.add_argument("QUERY",help="Query designation")

    # EXPORT function parameters
    export.add_argument("NODE_NAME",help="Full name of node to extract info about (UNAME@DOMAIN/COMP.DOMAIN)")
    export.add_argument("-t","--transitive",dest="transitive",action="store_true",help="Incorporate rights granted through nested groups (beta)")

    # DELETEEDGE function parameters
    deleteedge.add_argument("EDGENAME",help="Edge name, example: CanRDP, ExecuteDCOM, etc")

    # ADDSPNS function parameters
    addspns_switch = addspns.add_mutually_exclusive_group(required=True)
    addspns_switch.add_argument("-b","--bloodhound",dest="blood",action="store_true",help="Uses information already stored in BloodHound (must have already ingested 'Detailed' user information)")
    addspns_switch.add_argument("-f","--file",dest="filename",default="",help="Standard file Format: Computer, User")
    addspns_switch.add_argument("-i","--impacket",dest="ifilename",default="",help="Impacket file Format: Output of GetUserSPNs.py")

    # ADDSPW function parameters
    addspw.add_argument("-f","--file",dest="filename",default="",required=True,help="Filename containing AD objects, one per line (must have FQDN attached)")

    # DPAT function parameters
    dpat.add_argument("-n","--ntds",dest="ntdsfile",default="",required=True,help="NTDS file name")
    dpat.add_argument("-p","--pot",dest="potfile",default="",required=True,help="Hashcat potfile")
    dpat.add_argument("-e","--password",dest="passwd",default="",required=False,help="Returns all users using the argument as a password")
    dpat.add_argument("-u","--username",dest="usern",default="",required=False,help="Returns the password for the user if cracked")
    dpat.add_argument("-s","--sanitize",dest="sanitize",action="store_true",required=False,help="Sanitize the report by partially redacting passwords and hashes")
    dpat.add_argument("-o","--outputfile",dest="outputfile",default="",required=False,help="Output filename to store results, cli if none")
    dpat.add_argument("--csv",dest="csv",action="store_true",required=False,help="Store the output in a CSV format")
    dpat.add_argument("--html",dest="html",action="store_true",required=False,help="Store the output in HTML format")

    args = parser.parse_args()


    if not do_test(args):
        print("Connection error: restart Neo4j console or verify the the following URL is available: {}".format(args.url))
        exit()

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
    else:
        print("Error: use a module or use -h/--help to see help")


if __name__ == "__main__":
    main()
