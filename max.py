import requests
from requests.auth import HTTPBasicAuth
import sys
import argparse
import json

# option to hardcode URL & URI
global_url = "http://127.0.0.1:7474"
global_uri = "/db/data/transaction/commit"

# option to hardcode creds, these will be used as the username and password "defaults"
global_username = "neo4j"
global_password = "bloodhound"


def test_url(url):

        data = {"statements":[{"statement":query}]}
        headers = {'Content-type': 'application/json', 'Accept': 'application/json; charset=UTF-8'}
        auth = HTTPBasicAuth(args.username, args.password)

        return requests.post(args.url + global_uri, auth=auth, headers=headers, json=data)


def do_query(args, query):

        data = {"statements":[{"statement":query}]}
        headers = {'Content-type': 'application/json', 'Accept': 'application/json; charset=UTF-8'}
        auth = HTTPBasicAuth(args.username, args.password)

        return requests.post(args.url + global_uri, auth=auth, headers=headers, json=data)


def get_info(args):


    # key : {query: "", columns: []}
    queries = {
        "users" : "MATCH (n:User) RETURN n.name",
        "comps" : "MATCH (n:Computer) RETURN n.name",
        "das" : "MATCH p =(n:User)-[r:MemberOf*1..]->(g:Group) WHERE g.name=~'DOMAIN ADMINS@.*' RETURN n.name",
        "unconstrained" : "MATCH (n) WHERE n.unconstraineddelegation=TRUE RETURN n.name",
        "nopreauth" : "MATCH (n:User) WHERE n.dontreqpreauth=TRUE RETURN n.name",
        "local-admin" : "MATCH p=shortestPath((m:User {{name:\"{uname}\"}})-[r:AdminTo|MemberOf*1..]->(n:Computer)) RETURN n.name",
        "adminsOf" : "MATCH p=shortestPath((m:Computer {{name:\"{comp}\"}})<-[r:AdminTo|MemberOf*1..]-(n:User)) RETURN n.name",
        "owned" : "MATCH (n) WHERE n.owned=true RETURN n.name",
        "hvt" : "MATCH (n) WHERE n.highvalue=true RETURN n.name",
        "desc" : "MATCH (n:User) WHERE n.description IS NOT NULL RETURN n.name,n.description"
    }

    query = ""
    if (args.users):
        query = queries["users"]
    elif (args.comps):
        query = queries["comps"]
    elif (args.das):
        query = queries["das"]
    elif (args.unconstrained):
        query = queries["unconstrained"]
    elif (args.nopreauth):
        query = queries["nopreauth"]
    elif (args.owned):
        query = queries["owned"]
    elif (args.hvt):
        query = queries["hvt"]
    # elif (args.desc):
    #     query = queries["desc"]
    elif (args.uname != ""):
        query = queries["local-admin"].format(uname=args.uname.upper().strip())
    elif (args.comp != ""):
        query = queries["adminsOf"].format(comp=args.comp.upper().strip())

    r = do_query(args, query)
    x = json.loads(r.text)
    entry_list = x["results"][0]["data"]

    # if (args.desc):
    #     pass
    # else:
    for value in entry_list:
        print(value["row"][0])


def mark_owned(args):

    f = open(args.filename).readlines()

    note_string = ""
    if args.notes != "":
        note_string = "SET n.notes=\"" + args.notes + "\""

    for line in f:

        query = 'MATCH (n) WHERE n.name="{uname}" SET n.owned=true {notes} RETURN n'.format(uname=line.upper().strip(),notes=note_string)
        r = do_query(args, query)

        fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
        if r.text == fail_resp:
            print("[-] AD Object: " + line.upper().strip() + " could not be marked as owned")
        else:
            print("[+] AD Object: " + line.upper().strip() + " marked as owned successfully")


def mark_hvt(args):

    f = open(args.filename).readlines()

    note_string = ""
    if args.notes != "":
        note_string = "SET n.notes=\"" + args.notes + "\""

    for line in f:

        query = 'MATCH (n) WHERE n.name="{uname}" SET n.highvalue=true {notes} RETURN n'.format(uname=line.upper().strip(),notes=note_string)
        r = do_query(args, query)

        fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
        if r.text == fail_resp:
            print("[-] AD Object: " + line.upper().strip() + " could not be marked as HVT")
        else:
            print("[+] AD Object: " + line.upper().strip() + " marked as HVT successfully")



def main():

    parser = argparse.ArgumentParser(description="Maximizing Bloodhound. Max is a good boy.")

    general = parser.add_argument_group("Main Arguments")

    # generic function parameters
    general.add_argument("-u",dest="username",default=global_username,help="Neo4j database username (Default: {})".format(global_username))
    general.add_argument("-p",dest="password",default=global_password,help="Neo4j database password (Default: {})".format(global_password))
    general.add_argument("--url",dest="url",default=global_url,help="Neo4j database URL (Default: {})".format(global_url))

    # three options for the function
    switch = parser.add_subparsers(dest='command')
    getinfo = switch.add_parser("get-info",help="Get info for users, computers, etc")
    markowned = switch.add_parser("mark-owned",help="Mark objects as owned")
    markhvt = switch.add_parser("mark-hvt",help="Mark items as High Value Targets (HVTs)")


    # GETINFO function parameters
    getinfo_switch = getinfo.add_mutually_exclusive_group(required=True)
    getinfo_switch.add_argument("--users",dest="users",default=False,action="store_true",help="Return a list of all domain users")
    getinfo_switch.add_argument("--comps",dest="comps",default=False,action="store_true",help="Return a list of all domain computers")
    getinfo_switch.add_argument("--das",dest="das",default=False,action="store_true",help="Return a list of all Domain Admins")
    getinfo_switch.add_argument("--unconst",dest="unconstrained",default=False,action="store_true",help="Return a list of all objects configured with Unconstrained Delegation")
    getinfo_switch.add_argument("--npusers",dest="nopreauth",default=False,action="store_true",help="Return a list of all users that don't require Kerberos Pre-Auth (AS-REP roastable)")
    getinfo_switch.add_argument("--adminto",dest="uname",default="",help="Return a list of computers that UNAME is a local administrator to")
    getinfo_switch.add_argument("--adminsof",dest="comp",default="",help="Return a list of users that are administrators to COMP")
    getinfo_switch.add_argument("--owned",dest="owned",default=False,action="store_true",help="Return all objects that are marked as owned")
    getinfo_switch.add_argument("--hvt",dest="hvt",default=False,action="store_true",help="Return all objects that are marked as High Value Targets")
#    getinfo_switch.add_argument("--desc",dest="desc",default=False,action="store_true",help="Return all users with the description field populated (also returns description)")

    # MARKOWNED function paramters
    markowned.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (method of compromise)")
    markowned.add_argument("filename",help="Filename containing AD objects (must have FQDN attached)")

    # MARKHVT function parameters
    markhvt.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (reason for HVT status)")
    markhvt.add_argument("filename",help="Filename containing AD objects (must have FQDN attached)")

    args = parser.parse_args()


    if args.command == "get-info":
        get_info(args)
    elif args.command == "mark-owned":
        mark_owned(args)
    elif args.command == "mark-hvt":
        mark_hvt(args)
    else:
        print "Error"



if __name__ == "__main__":
    main()
