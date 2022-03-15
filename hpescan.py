#
# Author        : Vikram Fernandes
# Purpose       : The purpose of this script is to scan a range of subnets and discover HPE iLO's 
#                 and print this in a tabulated list
# Prerequisites : nmap binary needs to be installed and pip install python-nmap
# Usage         : python hpescan.py -s 192.168.2.0/24 
#               : python hpescan.py -s 192.168.2.0/24 -x 
#

import requests

import argparse
import os
import json
from tabulate import tabulate
#import xmltodict

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scanSubnet(subnet):
    import ipaddress
    import socket
    import threading
    port = 17988
    ip_network = ipaddress.ip_network(subnet)
    for host in ip_network.hosts():
        host = str(host)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_connector:
            socket_connector.settimeout(2)  
            result = socket_connector.connect_ex((host, port))
            print(host)
            if result == 0:
                print(f'iLO at : {host}')
                yield host

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
    ap.add_argument("-i", "--ip",   dest="ip", help="IP pool")
    ap.add_argument("-x", "--xml",  dest="xml", action='store_true', help="xmldata")

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

def parseXMLDict(xmlDict):
    retDict = {
        "SerialNumber" : xmlDict['RIMP']['HSI']['SBSN'],
        "Product" : xmlDict['RIMP']['HSI']['SPN'],
        "Hostname" : xmlDict['RIMP']['MP']['SN'],
        "Type" : xmlDict['RIMP']['MP']['PN'],
        "FW" : xmlDict['RIMP']['MP']['FWRI']
    }

    if 'NICS' in xmlDict.keys():
        retDict['NICS'] = xmlDict['RIMP']['HSI']['NICS']
    
    return retDict


def discoveriLOXML(iLO):    
    resource = "/xmldata?item=all"
    url = "http://" + iLO + resource

    response = requests.get(url)

    #xmlDict = xmltodict.parse(response.content)
    xmlDict = xml2dict(response.content)

    retDict = parseXMLDict(xmlDict)

    return retDict

def xml2dict(t):
    from collections import defaultdict
    from xml.etree import cElementTree as ET
    d = {t.tag: {} if t.attrib else None}
    children = list(t)
    if children:
        dd = defaultdict(list)
        for dc in map(etree_to_dict, children):
            for k, v in dc.items():
                dd[k].append(v)
        d = {t.tag: {k: v[0] if len(v) == 1 else v
                     for k, v in dd.items()}}
    if t.attrib:
        d[t.tag].update(('@' + k, v)
                        for k, v in t.attrib.items())
    if t.text:
        text = t.text.strip()
        if children or t.attrib:
            if text:
              d[t.tag]['#text'] = text
        else:
            d[t.tag] = text
    return d
    
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

# Main function
def main():
    # Review arguments
    args = buildArguments().parse_args()
    
    iLOs = []

    if args.subnet:
        for ip in scanSubnet(args.subnet):
            iLOs.append(ip)
    print(iLOs)
    outDict = []

    if args.xml:
        for iLO in iLOs:
            print("iLO : %s" % iLO)
            retObj = discoveriLOXML(iLO)
            if retObj is not None:                
                retObj['iLO'] = iLO
                outDict.append(retObj)            
    else:
        for iLO in iLOs:
            print("iLO : %s" % iLO)
            retObj = discoveriLO(iLO)
            if retObj is not None:
                retDict = buildOutput(retObj)
                retDict['iLO'] = iLO
                outDict.append(retDict)
        
    print(tabulate(outDict,headers='keys',showindex=True))                  

# Startup
if __name__ == "__main__":
	import sys
	sys.exit(main())  
