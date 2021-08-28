#!/usr/bin/python3
# https://docs.hetzner.cloud/#firewalls-get-all-firewalls
import sys
import requests
import getopt
import time
import json

APIKEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
api_url = "https://api.hetzner.cloud/v1/firewalls"
ports=['224','8080']
serverIds=['xxxxxx','xxxxxxx']
firewallName="KNOCKD"
rules=[]
servers=[]


def main(argv):
    global APIKEY
    global api_url
    global ports
    global serverIds
    global firewallName
    global rules
    global servers

    try:
        options, args = getopt.getopt(sys.argv[1:], "a:i:",["action=", "ip="])
    except getopt.GetoptError as err:
        print(err)
        sys.exit(2)
    action=None
    ip=None
    for name, value in options:
        if name in ('-a', '--action'):
            action = value
        elif name in ('-i', '--ip'):
            ip = value

    print("Action:"+action)
    print("IP:"+ip)

    headersObj = {"Content-Type":"application/json","Authorization":"Bearer "+APIKEY}

    if action == "add":
        ip = ip+"/32"
        print("Allowing IP:"+ip)
        for port in ports:
            rules.append({"description":"Allow port "+port,"direction":"in","port":port,"protocol":"tcp","source_ips":[ip]})
        for serverId in serverIds:
            servers.append({"server":{"id":serverId},"type":"server"})

        #First check if rules already defined
        response = requests.get(api_url+"?name="+firewallName,headers=headersObj)
        if response.status_code != 200:
            print("Error in API request. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
        if response.json()['meta']['pagination']['total_entries'] > 0:
            print("Firewall rule already defined. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)

        dataObj = {"apply_to":servers,"labels":{"env":"dev"},"name":firewallName,"rules":rules}
        dataJson = json.dumps(dataObj)
        response = requests.post(api_url,data=dataJson,headers=headersObj)
        if response.status_code != 201:
            print("Error in API request. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
        if response.json()['actions'][0]['error'] != None:
            print("Error in API request. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
        for action in response.json()['actions']:
            if action['error'] != None:
                print("Error deploying firewall:"+action['error'])
                print(action)

    elif action == "del":

        response = requests.get(api_url+"?name="+firewallName,headers=headersObj)
        if response.status_code != 200:
            print("Error in API request. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
        if response.json()['meta']['pagination']['total_entries'] == 0:
            print("No firewall found. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
        elif response.json()['meta']['pagination']['total_entries'] >1:
            print("Multiple firewall found by name. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
        id = str(response.json()['firewalls'][0]['id'])
        print("ID:"+id)

        for serverId in serverIds:
            servers.append({"server":{"id":serverId},"type":"server"})

        dataObj = {"remove_from":servers}
        dataJson = json.dumps(dataObj)
        response = requests.post(api_url+"/"+id+"/actions/remove_from_resources",headers=headersObj,data=dataJson)
        if response.status_code != 201:
            print("Error in API request. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)

        time.sleep(5)

        response = requests.delete(api_url+"/"+id,headers=headersObj)
        if response.status_code != 204:
            print("Error in API request. Returncode:"+str(response.status_code))
            print(response.json())
            exit(2)
    else:
        print("Wrong parameter supplied. Allowed only add|del")
        exit(1)



if __name__ == "__main__":
   main(sys.argv[1:])
