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

# option to hardcode URL & URI
global_url = "http://127.0.0.1:7474"
global_uri = "/db/data/transaction/commit"

# option to hardcode creds, these will be used as the username and password "defaults"
global_username = "neo4j"
global_password = "bloodhound"

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
    "HasSIDHistory"
]


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

    if args.enabled:
        query = query.format(enabled="WHERE u.enabled=true")
    else:
        query = query.format(enabled="")

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

    print('HasSPNConfigured relationships created: ' + str(count))


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

    print("SharesPasswordWith relationships created: " + str(count))


def dpat_func(args):

    print("DPAT Function")
    '''
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    testlab.local\bob:1000:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::
    testlab.local\tom:1001:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b:::
    '''
    '''
    query1 = "match (u:User) where u.name='{username}' return u.name,u.objectid".format(username=username)

    query2 = "match (u:User) where u.name starts with '{username}@' and u.objectid ends with '-{rid}' return u.name,u.objectid".format(username=user, rid=rid)
    '''
    # [user1, user2, ...]
    lm = []

    cracked = {}

    if (args.ntdsfile != None):
        ntds = open(args.ntdsfile, 'r').readlines()
    else:
        print("Error: Need NTDS file")
        return
    if (args.potfile != None):
        potfile = open(args.potfile, 'r').readlines()
    else:
        print("Error: Need potfile")
        return
    try:
        ntds_parsed = []
        for line in ntds:
            line = line.replace("\r", "").replace("\n", "")
            if (line == ""):
                continue
            # [ username, domain, rid, LM, NT, plaintext||None]
            to_append = []
            if (line.split(":")[0].split("\\")[0] == line.split(":")[0]):
                # no domain found, local account
                if (line.split(":")[0][-1:] == "$"):
                    # computer account, skip
                    continue 
                to_append.append(line.split(":")[0])
                to_append.append("")
            else:
                to_append.append(line.split(":")[0].split("\\")[1])
                to_append.append(line.split(":")[0].split("\\")[0])
            to_append.append(line.split(":")[1])
            to_append.append(line.split(":")[2])
            to_append.append(line.split(":")[3])
            to_append.append(None)
            ntds_parsed.append(to_append)
        print(ntds_parsed)

        # password stats like counting reused cracked passwords
        for user in ntds_parsed:
            for line in potfile:
                line = line.replace("\r", "").replace("\n", "")
                if (user[3] != "aad3b435b51404eeaad3b435b51404ee"):
                    # LM found
                    lm.append(user)
                if (line.split(":")[0] == user[4]):
                    # found in potfile, cracked
                    if ("$HEX[" in line.split(":")[1]):
                        print("found $HEX[]")
                        user[5] = binascii.unhexlify( str( line.split(":")[1].split("[")[1].replace("]", "") ) )
                    else:
                        user[5] = line.split(":")[1]
                    if (user[5] not in cracked):
                        cracked[user[5]] = 0
                    cracked[user[5]] += 1
                if (user[4] == "31d6cfe0d16ae931b73c59d7e0c089c0"):
                    user[5] = ""

        try:
            for user in ntds_parsed:
                # [ username, domain, rid, LM, NT, plaintext||None]
                # try query1 to see if we can resolve the users 
                if (user[1] != ""):
                    query = "match (u:User) where u.name='{username}' return u.name,u.objectid".format(username=str(user[0].upper() + "@" + user[1].upper()))
                else:
                    query = "match (u:User) where u.name starts with '{username}@' and u.objectid ends with '-{rid}' return u.name,u.objectid".format(username=user[0].upper(), rid=user[2].upper())
                r = do_query(args,query)
                bh_users = json.loads(r.text)['results'][0]['data']
                print("[*] BloodHound data queried successfully")
                for bh_user in bh_users:
                    print(bh_user)
        except Exception as f:
            print("got error")
            print(f)
            return


        print(ntds_parsed)
        print(cracked)
    except Exception as e:
        print("Got error:")
        print(e.print_exc())
        return

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
    dpat.add_argument("-s","--sanitize",dest="sanitize",action="store_true",required=False,help="Sanitize the report by partially redacting passwords and hashes")

    args = parser.parse_args()


    if not do_test(args):
        print("Connection error: restart Neo4j console or verify the the following URL is available: http://127.0.0.1:7474")
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
