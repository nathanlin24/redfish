#
# Author        : Vikram Fernandes
# Purpose       : The purpose of this script is to scan a range of subnets and discover HPE iLO's 
#                 and print this in a tabulated list
# Prerequisites : nmap binary needs to be installed and pip install python-nmap
# Usage         : python hpescan.py -s 192.168.2.0/24 
#

import requests
import nmap
import argparse
import os
import json
from tabulate import tabulate

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scanSubnet(subnet):
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet,arguments='-n -sP -PE -PA17988')

    print("Hosts discovered %d" % len(nm.all_hosts()))
    
    return nm.all_hosts()

def requestCredentials(iLO):

    UserName = os.environ.get('REDFISH_USER')
    password = os.environ.get('REDFISH_PASSWORD')
    
    if UserName is None or "":
        print ('ERROR: REDFISH_USER environment variable not set')
        return None    

    if password is None or "":
        print ('ERROR: REDFISH_PASSWORD environment variable not set')
        return None

    # Replace the " from the above command   
    UserName = UserName.replace('"','')
    password = password.replace('"','')

    payload = {
        "UserName": UserName, 
        "Password": password
    }    

    return payload

# Connect to iLO with user and password
def connect_iLO(ilo_in, payload):
    print ("Login to iLO")
    auth_token = None
    url = "https://" + ilo_in + "/redfish/v1/SessionService/Sessions/"

    headers = {"Content-Type": "application/json"}

    auth = requests.post(url,
                             data=json.dumps(payload),
                             headers=headers,
                             verify=False)

    if auth.status_code != 201:
        try:
            answer = auth.json()
        except ValueError:
            answer = ""        

    auth_token = auth.headers.get("x-auth-token")
    print("X-Auth-Token : " + auth_token)

    return auth_token

def ilo_get(ilo_in, auth_in, resource):    
    url = "https://" + ilo_in + resource

    header = {"Content-Type": "application/json","X-Auth-Token": auth_in }

    retObj = requests.get(url, headers=header, verify=False)

    return retObj.json()

def buildArguments():

    ap = None
    ap = argparse.ArgumentParser(description='This script scans the network for HPE iLOs and discovers them')
    ap.add_argument("-s", "--subnet",   dest="subnet", help="subnet", required=True)
    ap.add_argument("-i", "--ip",   dest="ip", help="subnet")

    return ap

def discoveriLO(iLO):    
    resource = "/redfish/v1"
    url = "https://" + iLO + resource

    header = {"Content-Type": "application/json","Accept": "application/json" }

    retObj = None
    try:    
        retObj = requests.get(url, headers=header, verify=False)    
    except Exception as e:    
        print("error with call to : %s" % iLO)                
    
    if retObj is not None and retObj.status_code == 200:        
        return retObj.json()
    else:
        return None

def buildOutput(responseObj):    
    retDict = {
        "Vendor" : responseObj['Vendor'], 
        "Product" : responseObj['Product'],
        "Hostname" : responseObj['Oem']['Hpe']['Manager'][0]['HostName'],
        "FQDN" : responseObj['Oem']['Hpe']['Manager'][0]['FQDN'],         
        "Type" : responseObj['Oem']['Hpe']['Manager'][0]['ManagerType'],
        "FW" : responseObj['Oem']['Hpe']['Manager'][0]['ManagerFirmwareVersion']
    }

    return retDict

def main():
    # Review arguments
    args = buildArguments().parse_args()
    
    iLOs = []

    if args.subnet:
        iLOs = scanSubnet(args.subnet)

    outDict = []

    for iLO in iLOs:
        print("iLO : %s" % iLO)
        retObj = discoveriLO(iLO)
        if retObj is not None:
            retDict = buildOutput(retObj)
            retDict['iLO'] = iLO
            outDict.append(retDict)
        
    print(tabulate(outDict,headers='keys',showindex=True))                  
  
if __name__ == "__main__":
	import sys
	sys.exit(main())  