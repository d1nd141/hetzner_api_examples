#!/usr/bin/python3
# https://docs.hetzner.cloud/#firewalls-get-all-firewalls
import sys
import requests
import getopt
import time
import json
import smtplib, ssl

APIKEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
api_url = "https://api.hetzner.cloud/v1/firewalls"
ports=['224','8080']
serverIds=['xxxxxx','xxxxxx']
firewallName="KNOCKD"
rules=[]
servers=[]
email_sender = 'xxx@xxx.com'
email_receiver = 'xxx@xxx.com'
email_username = 'xxxx'
email_password = 'xxxxx'
email_smtp = 'xxx.xxx.xxx'
email_port = 465
email_message = """\
Subject: Report from update_firewall.sh
"""

def sendMail(email_message):
    global email_sender
    global email_receiver
    global email_username
    global email_password
    global email_smtp
    global email_port

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(email_smtp,email_port,context=context) as server:
            server.login(email_username,email_password)
            server.sendmail(email_sender, email_receiver, email_message)
    except SMTPException:
        print ("Error: unable to send email")


def main(argv):
    global APIKEY
    global api_url
    global ports
    global serverIds
    global firewallName
    global rules
    global servers
    global email_message

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
            msg="Error in API request. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)
        if response.json()['meta']['pagination']['total_entries'] > 0:
            msg="Firewall rule already defined. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)

        dataObj = {"apply_to":servers,"labels":{"env":"dev"},"name":firewallName,"rules":rules}
        dataJson = json.dumps(dataObj)
        response = requests.post(api_url,data=dataJson,headers=headersObj)
        if response.status_code != 201:
            msg="Error in API request. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)
        if response.json()['actions'][0]['error'] != None:
            msg="Error in API request. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)
        for action in response.json()['actions']:
            if action['error'] != None:
                msg="Error deploying firewall:"+action['error']
                email_message = email_message + msg
                sendMail(email_message)
                print(msg)
                print(action)
        msg="Firewall opened for IP: "+ip
        email_message = email_message + msg
        sendMail(email_message)

    elif action == "del":

        response = requests.get(api_url+"?name="+firewallName,headers=headersObj)
        if response.status_code != 200:
            msg="Error in API request. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)
        if response.json()['meta']['pagination']['total_entries'] == 0:
            msg="No firewall found. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)
        elif response.json()['meta']['pagination']['total_entries'] >1:
            msg="Multiple firewall found by name. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
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
            msg="Error in API request. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)

        time.sleep(5)

        response = requests.delete(api_url+"/"+id,headers=headersObj)
        if response.status_code != 204:
            msg="Error in API request. Returncode:"+str(response.status_code)
            email_message = email_message + msg
            sendMail(email_message)
            print(msg)
            print(response.json())
            exit(2)
        email_message = email_message + "Firewall deleted for IP: "+ip
        sendMail(email_message)
    else:
        msg="Wrong parameter supplied. Allowed only add|del"
        email_message = email_message + msg
        sendMail(email_message)
        print(msg)
        exit(1)



if __name__ == "__main__":
   main(sys.argv[1:])
