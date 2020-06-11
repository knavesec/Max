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
        "users" : {
            "query": "MATCH (n:User) RETURN n.name",
            "columns" : ["UserName"]
            },
        "comps" : {
            "query": "MATCH (n:Computer) RETURN n.name",
            "columns" : ["ComputerName"]
            },
        "groups" : {
            "query": "MATCH (n:Group) RETURN n.name",
            "columns" : ["GroupName"]
            },
        "das" : {
            "query": "MATCH p =(n:User)-[r:MemberOf*1..]->(g:Group) WHERE g.name=~'DOMAIN ADMINS@.*' RETURN n.name",
            "columns" : ["UserName"]
            },
        "unconstrained" : {
            "query": "MATCH (n) WHERE n.unconstraineddelegation=TRUE RETURN n.name",
            "columns" : ["ObjectName"]
            },
        "nopreauth" : {
            "query": "MATCH (n:User) WHERE n.dontreqpreauth=TRUE RETURN n.name",
            "columns" : ["UserName"]
            },
        "localadmin" : {
            "query": "MATCH p=shortestPath((m:User {{name:\"{uname}\"}})-[r:AdminTo|MemberOf*1..]->(n:Computer)) RETURN n.name",
            "columns" : ["ComputerName"]
            },
        "adminsof" : {
            "query": "MATCH p=shortestPath((m:Computer {{name:\"{comp}\"}})<-[r:AdminTo|MemberOf*1..]-(n:User)) RETURN n.name",
            "columns" : ["UserName"]
            },
        "owned" : {
            "query": "MATCH (n) WHERE n.owned=true RETURN n.name",
            "columns" : ["ObjectName"]
            },
        "hvt" : {
            "query": "MATCH (n) WHERE n.highvalue=true RETURN n.name",
            "columns" : ["ObjectName"]
            },
        "desc" : {
            "query": "MATCH (n:User) WHERE n.description IS NOT NULL RETURN n.name,n.description",
            "columns" : ["UserName","Description"]
            },
        "admincomps" : {
            "query": "MATCH (n:Computer),(m:Computer) MATCH (n)-[r:MemberOf|AdminTo*1..]->(m) return n.name,m.name",
            "columns" : ["AdminCompName","CompName"]
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
    elif (args.das):
        query = queries["das"]["query"]
        cols = queries["das"]["columns"]
    elif (args.unconstrained):
        query = queries["unconstrained"]["query"]
        cols = queries["unconstrained"]["columns"]
    elif (args.nopreauth):
        query = queries["nopreauth"]["query"]
        cols = queries["nopreauth"]["columns"]
    elif (args.owned):
        query = queries["owned"]["query"]
        cols = queries["owned"]["columns"]
    elif (args.hvt):
        query = queries["hvt"]["query"]
        cols = queries["hvt"]["columns"]
    elif (args.desc):
        query = queries["desc"]["query"]
        cols = queries["desc"]["columns"]
    elif (args.admincomps):
        query = queries["admincomps"]["query"]
        cols = queries["admincomps"]["columns"]
    elif (args.uname != ""):
        query = queries["localadmin"]["query"].format(uname=args.uname.upper().strip())
        cols = queries["localadmin"]["columns"]
    elif (args.comp != ""):
        query = queries["adminsof"]["query"].format(comp=args.comp.upper().strip())
        cols = queries["adminsof"]["columns"]

    r = do_query(args, query)
    x = json.loads(r.text)
    entry_list = x["results"][0]["data"]

    if not args.quiet:
        print(" - ".join(cols))
    for value in entry_list:
        try:
            print(" - ".join(value["row"]))
        except:
            pass


def mark_owned(args):

    if (args.clear):

        query = 'MATCH (n) WHERE n.owned=true SET n.owned=false'
        r = do_query(args,query)
        print("'Owned' attribute removed from all objects.")

    else:

        note_string = ""
        if args.notes != "":
            note_string = "SET n.notes=\"" + args.notes + "\""

        f = open(args.filename).readlines()

        for line in f:

            query = 'MATCH (n) WHERE n.name="{uname}" SET n.owned=true {notes} RETURN n'.format(uname=line.upper().strip(),notes=note_string)
            r = do_query(args, query)

            fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
            if not args.quiet:
                if r.text == fail_resp:
                    print("[-] AD Object: " + line.upper().strip() + " could not be marked as owned")
                else:
                    print("[+] AD Object: " + line.upper().strip() + " marked as owned successfully")


def mark_hvt(args):


    note_string = ""
    if args.notes != "":
        note_string = "SET n.notes=\"" + args.notes + "\""

    f = open(args.filename).readlines()

    for line in f:

        query = 'MATCH (n) WHERE n.name="{uname}" SET n.highvalue=true {notes} RETURN n'.format(uname=line.upper().strip(),notes=note_string)
        r = do_query(args, query)

        fail_resp = '{"results":[{"columns":["n"],"data":[]}],"errors":[]}'
        if not args.quiet:
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
    markowned = switch.add_parser("mark-owned",help="Mark objects as Owned")
    markhvt = switch.add_parser("mark-hvt",help="Mark items as High Value Targets (HVTs)")

    # GETINFO function parameters
    getinfo_switch = getinfo.add_mutually_exclusive_group(required=True)
    getinfo_switch.add_argument("--users",dest="users",default=False,action="store_true",help="Return a list of all domain users")
    getinfo_switch.add_argument("--comps",dest="comps",default=False,action="store_true",help="Return a list of all domain computers")
    getinfo_switch.add_argument("--groups",dest="groups",default=False,action="store_true",help="Return a list of all domain groups")
    getinfo_switch.add_argument("--das",dest="das",default=False,action="store_true",help="Return a list of all Domain Admins")
    getinfo_switch.add_argument("--unconst",dest="unconstrained",default=False,action="store_true",help="Return a list of all objects configured with Unconstrained Delegation")
    getinfo_switch.add_argument("--npusers",dest="nopreauth",default=False,action="store_true",help="Return a list of all users that don't require Kerberos Pre-Auth (AS-REP roastable)")
    getinfo_switch.add_argument("--adminto",dest="uname",default="",help="Return a list of computers that UNAME is a local administrator to")
    getinfo_switch.add_argument("--adminsof",dest="comp",default="",help="Return a list of users that are administrators to COMP")
    getinfo_switch.add_argument("--owned",dest="owned",default=False,action="store_true",help="Return all objects that are marked as owned")
    getinfo_switch.add_argument("--hvt",dest="hvt",default=False,action="store_true",help="Return all objects that are marked as High Value Targets")
    getinfo_switch.add_argument("--desc",dest="desc",default=False,action="store_true",help="Return all users with the description field populated (also returns description)")
    getinfo_switch.add_argument("--admincomps",dest="admincomps",default=False,action="store_true",help="Return all computers with admin privileges to another computer [Comp1-AdminTo->Comp2]")

    getinfo.add_argument("--get-note",dest="getnote",default=False,action="store_true",help="Return the \"notes\" attribute for whatever objects are returned")
    getinfo.add_argument("-q",dest="quiet",action="store_true",default=False,help="Quiet mode, suppress column headers from output")

    # MARKOWNED function paramters
    markowned.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markowned.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (method of compromise)")
    markowned.add_argument("--clear",dest="clear",action="store_true",help="Removed owned marker from all objects")

    # MARKHVT function parameters
    markhvt.add_argument("-f","--file",dest="filename",default="",required=False,help="Filename containing AD objects (must have FQDN attached)")
    markhvt.add_argument("--add-note",dest="notes",default="",help="Notes to add to all marked objects (reason for HVT status)")

    args = parser.parse_args()


    if args.command == "get-info":
        get_info(args)
    elif args.command == "mark-owned":
        mark_owned(args)
    elif args.command == "mark-hvt":
        mark_hvt(args)
    else:
        print("Error: use a module or use -h/--help to see help")



if __name__ == "__main__":
    main()
