
# Author : Vikram Fernandes

import requests
import os
import json
import argparse
import socket
import pprint
from tabulate import tabulate
from operator import itemgetter
from collections import Counter

REDFISH_IP = ''
REDFISH_USER = ''
REDFISH_PASS = ''

# Suppress warning - InsecureRequestWarning: Unverified HTTPS request is being made
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


##################################################################
# Function to build arguments
#
##################################################################
def buildArguments():

    ap = None
    ap = argparse.ArgumentParser(
        description='This script creates a boot LUN on a HPE iLO Gen10 server. Please verify environment variables REDFISH_USER and REDFISH_PASS are set')
    ap.add_argument("-pd", "--physical-drives", action='store_true',
                    dest="physical_drives", help="List physical drives ")
    ap.add_argument("-ld", "--logical-drives", action='store_true', dest="logical_drives",
                    help="List configured logical drives ")        
    ap.add_argument("-c", "--create-lun", action='store_true', dest="create_lun",
                    help="Create a LUN ")        
    ap.add_argument("-lz", "--list-drive-sizes", action='store_true',  dest="list_drive_sizes",  help="List drive sizes")
    ap.add_argument("-lc", "--list-controllers", action='store_true',  dest="list_controllers",  help="List controllers")
    ap.add_argument("-d", "--delete-lun",   dest="delete_lun",  help="Delete a LUN")
    ap.add_argument("-p", "--power-state",   dest="power_state", help="Power state")    
    ap.add_argument("-i", "--iLO",   dest="iLO", help="iLO address", required=True)

    return ap

##################################################################
# Function to validate ip
#
##################################################################
def validate_iLO(ip_in):
    """
     Validate IPv4 address
    :param ip: IPv4 Address
    :return: IP Address    
    """
    try:  
        ip_out = socket.gethostbyname(ip_in) 
        socket.inet_aton(ip_out)
        return 1
    except socket.error:
        # not legal
        print ("ERROR: Appliance {} NOT reachable".format(ip_in))
        return 0

##################################################################
# Function to retrieve user credentials and build dict
#
##################################################################
def requestCredentials(iLO):

    UserName = os.environ.get('REDFISH_USER')
    password = os.environ.get('REDFISH_PASSWORD')

    UserName = REDFISH_USER
    password = REDFISH_PASS

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

##################################################################
# Function to connect to the iLO
#
##################################################################
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


def ilo_post():
    print("perform http post requests")
    return 0


def ilo_patch():
    print("perform http patch requests")
    return 0

def getPhysicalDrives(ilo_in, auth_in):
    physicalDrives = ilo_get(ilo_in,auth_in,"/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives/")
    
    drives = physicalDrives['Members@odata.count']
    print()
    print("Physical drives found : " + str(drives))

    driveArray = []
    
    # iterate through the members of the request object
    for drive in physicalDrives['Members']:
        driveValue = drive['@odata.id']        
        driveDetails = ilo_get(ilo_in, auth_in,driveValue)

        drive = {
            "Model" : driveDetails['Model'],
            "MediaType" : driveDetails['MediaType'],
            "Location" : driveDetails['Location'],
            "Capacity" : driveDetails['CapacityGB'],
            "InterfaceType" : driveDetails['InterfaceType'],
            "Health" : driveDetails['Status']['Health'],
            "SerialNumber" : driveDetails['SerialNumber'],        
            "FirmwareVersion" : driveDetails['FirmwareVersion']['Current']['VersionString']
        }        
        driveArray.append(drive)

    return driveArray

def getLogicalDrives(ilo_in, auth_in):
    luns = ilo_get(ilo_in,auth_in,"/redfish/v1/Systems/1/smartstorageconfig/")

    lunArray = []
    print()

    if len(luns['LogicalDrives']) > 0:
        print("Logical drives found : {}".format(len(luns['LogicalDrives'])))
        for lun in luns['LogicalDrives']:
            lunrec = {
                "LogicalDriveName" : lun['LogicalDriveName'],
                "LogicalDriveNumber" : lun['LogicalDriveNumber'],
                "RAID" : lun['Raid'],
                "CapacityGB" : lun['CapacityGiB'],
                "VolumeUniqueIdentifier" : lun['VolumeUniqueIdentifier'],
                "DataDrives" : lun['DataDrives']
            }
            lunArray.append(lunrec)
    else:
        print("No Logical drives found")    
    
    return lunArray

def getUniqueDriveSize(drives):
    capacityList = []
    for drive in drives:
        capacityList.append(drive['Capacity'])

    retList = None
    if len(capacityList) > 0:
        uniqList = set(capacityList)
        retList = sorted(uniqList)

    countDrives = Counter(sorted(capacityList))    
    sortedDrives = []
    for key, value in countDrives.items():
        driveDict = {
            "DriveSize" : key,
            "Count" : value
        }
        sortedDrives.append(driveDict)
        
    print(tabulate(sortedDrives,headers='keys',showindex=True))
    print("Drives sizes available : {}".format(retList))
    return retList

def checkPowerState(ilo_in, auth_in):
    print("Checking PowerState")

def resetServer(ilo_in, auth_in, option_in):
    print("Resetting Serve with {}".format(option_in))

def createLogicalVolume(ilo_in, auth_in, physicalDrives, driveSize):
    



    if checkPowerState(ilo_in, auth_in):
        resetServer(ilo_in, auth_in, "ForceRestart") 
    else:
        resetServer(ilo_in, auth_in, "On") 

    
            
def createLUN(ilo_in, auth_in):
    # Get physical drives first
    physicalDrives = getPhysicalDrives(ilo_in, auth_in)
    uniq = getUniqueDriveSize(physicalDrives)
   
    driveSize = input("Drive size for RAID 1: ")
    print("Drive size selected : {}".format(driveSize))

    createLogicalVolume(ilo_in, auth_in, physicalDrives, driveSize)



    
    
    #driveSizes = sorted(physicalDrives,key=itemgetter('Capacity'))
    #mylist = list(set(val for dic in physicalDrives for val in dic.values()))

    #print(mylist)

def getControllers(ilo_in, auth_in):
    arrayControllers = ilo_get(ilo_in,auth_in,"/redfish/v1/Systems/1/SmartStorage/ArrayControllers/")

    controllerCount = arrayControllers['Members@odata.count']
    print()
    print("Controllers found : " + str(controllerCount))

    controllers = []
    
    # iterate through the members of the request object
    for controller in arrayControllers['Members']:
        cntrl = controller['@odata.id']        
        smartArray = ilo_get(ilo_in, auth_in,cntrl)

        arrayController = {
            "Location" : smartArray['Location'],
            "Model" : smartArray['Model'],
            "PartNumber" : smartArray['ControllerPartNumber'],
            "SerialNumber" : smartArray['SerialNumber'],
            "LocationFormat" : smartArray['LocationFormat'],
            "Health" : smartArray['Status']['Health'],            
            "FirmwareVersion" : smartArray['FirmwareVersion']['Current']['VersionString']
        }        
        controllers.append(arrayController)

    return controllers

  

##################################################################
# Main module
#
##################################################################
def main():
    # Review arguments
    args = buildArguments().parse_args()
    
    if args.iLO:
        if  not validate_iLO(args.iLO):
            exit(1)    
  
    # connect to iLO
    config_out = requestCredentials(args.iLO)

    if config_out is None:
        print ("ERROR: Environment variables REDFISH_USER and/or REDFISH_PASSWORD not set")
        exit(1)

    auth_token = connect_iLO(args.iLO, config_out)

    if auth_token is None: 
        print ("ERROR: login error")
        exit(1)

    if args.physical_drives:
        physicalDrives = getPhysicalDrives(args.iLO,auth_token)
        print(tabulate(physicalDrives,headers='keys',showindex=True))
    
    if args.logical_drives:
        logicalDrives = getLogicalDrives(args.iLO,auth_token)
        if len(logicalDrives) > 0:
            print(tabulate(logicalDrives,headers='keys',showindex=True))
        else:
            print("No logical drives found")

    if args.list_drive_sizes:
        physicalDrives = getPhysicalDrives(args.iLO,auth_token)
        getUniqueDriveSize(physicalDrives)

    if args.create_lun:
        # create a new logical drive
        createLUN(args.iLO,auth_token)
    
    if args.list_controllers:
        controllers = getControllers(args.iLO,auth_token)
        print(tabulate(controllers,headers='keys',showindex=True))

        



    print()
    
    exit(0)


##################################################################
# Start module
#
##################################################################
if __name__ == "__main__":
	import sys
	sys.exit(main())    
