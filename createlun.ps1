<#
.SYNOPSIS
    This script will help with initial provisioning of an HPE server using the Redfish API
.DESCRIPTION
    This script will list out physical, logical drives and help create or delete them
.PARAMETER physicalDrives
    Lists out the physical drives on the system
.PARAMETER logicalDrives
    Lists out the logical drives configured on the system
.PARAMETER createLogicalVol
    Creates a logical volume based on the drive sizes
.PARAMETER deleteLogicalVol
    Deletes all configured logical volumes
.PARAMETER powerState
    Display current power state of the system
.PARAMETER lastOperationState
    Display last RAID controller operation status
.Example
    .\createlun.ps1 -physicalDrives
.NOTES
    Author: Vikram Fernandes
    Date:   January 10, 2020
#>
 param (
        # List out physical drives 
        [switch]$physicalDrives = $false, 
        # List out physical drives 
        [switch]$logicalDrives = $false, 
        # Create a logical volume 
        [switch]$createLogicalVol = $false, 
        # Delete a logical volume 
        [switch]$deleteLogicalVol = $false,
        # Current power state
        [switch]$powerState = $false,
        # Status on the last RAID controller operation
        [switch]$lastOperationState = $false
        )
    
$Address = [System.Environment]::GetEnvironmentVariable('REDFISH_IP')
$user = [System.Environment]::GetEnvironmentVariable('REDFISH_USER') 
$passwd = [System.Environment]::GetEnvironmentVariable('REDFISH_PASS') 

Disable-HPERedfishCertificateAuthentication

function checkPowerState($session){
    $system = Get-HPERedfishDataRaw -Odataid '/redfish/v1/Systems/1/' -Session $session

    Write-Host
    Write-Host "Current PowerState : " $system.PowerState

    if ($system.PowerState -eq "On")
    {
        return $true
    }
    else {
        return $false
    }
}

function checkLastSmartArrayStatus($session)
{
    $lastStatus = Get-HPERedfishDataRaw -Odataid '/redfish/v1/Systems/1/smartstorageconfig/' -Session $session 

    $messageId = ""
    foreach($msg in $lastStatus.'@Redfish.Settings'.Messages)
    {
        $messageId = $msg.MessageId
    }
    Write-Host 
    Write-Host "Message : " $messageId ' Last executed at : ' $lastStatus.'@Redfish.Settings'.Time
}

function getPhysicalDrives($session) 
{    
    $localDrives = @()
    # Get a list of Physical drives    
    $physicalDrives = Get-HPERedfishDataRaw -Odataid '/redfish/v1/Systems/1/SmartStorage/ArrayControllers/0/DiskDrives/' -Session $session    
    
    foreach ($drive in $physicalDrives.Members.'@odata.id') {        
        $driveDet = Get-HPERedfishDataRaw -Odataid $drive -Session $session
        $driveObj = [PSCustomObject]@{
            Location     = $driveDet.Location;
            MediaType    = $driveDet.MediaType;
            Capacity     = $driveDet.CapacityGB;
            IntefaceType = $driveDet.InterfaceType
        }
        $localDrives += $driveObj        
    }

    if (!$localDrives.Count)
    {
        Write-Host 
        Write-Host "No physical drives on system"
    }
    else
    {
        Write-Host 
        Write-Host "Physical drives found"        
        $localDrives 
    }
}

function getLogicalDrives($session) 
{    
    $logicalDrvs = @()
    # Get a list of Physical drives    
    $LUNS = Get-HPERedfishDataRaw -Odataid '/redfish/v1/Systems/1/smartstorageconfig/' -Session $session    

    foreach($lun in $LUNS.LogicalDrives)    
    {        
        $lunObj = [PSCustomObject]@{
            LogicalDriveName     = $lun.LogicalDriveName;            
        }
    }    

    if (!$LUNS.LogicalDrives.Count)
    {
        Write-Host 
        Write-Host "No Logical Volumes on system"
    }
    else
    {
        Write-Host 
        Write-Host "Logical volumes found"
        
        foreach ($lun in $LUNS.LogicalDrives)
        {
            $lunObj = [PSCustomObject]@{
                LogicalDriveNumber     = $lun.LogicalDriveNumber;
                LogicalDriveName       = $lun.LogicalDriveName;
                Raid                   = $lun.Raid;
                CapacityGiB            = $lun.CapacityGiB
                VolumeUniqueIdentifier = $lun.VolumeUniqueIdentifier
            }
            $logicalDrvs += $lunObj            
        }
        $logicalDrvs | Format-Table -AutoSize
    }
}

function createLogicalVolume($driveSize, $drives, $session) 
{
     $logicalVol = Get-HPERedfishDataRaw -Odataid '/redfish/v1/Systems/1/smartstorageconfig/settings/' -Session $session  

     #Select Drives based on size
     $driveLocation = @()
     $driveLocations = @()
     foreach($drive in $($drives | Where-Object { $_.Capacity -eq $drivesize}) ) {

        $driveLocation += $drive
        $driveLocations += $drive.Location
     }

     Write-Host 
     Write-Host "Found Drives " $driveLocation.Count

     $logicalVol.DataGuard = "Disabled"
     $logicalDrivesArray = @()

     # Create a logicalDriveObject

     $logicalDrive = [PSCustomObject]@{        
        LogicalDriveName = $driveLocation[0].MediaType;
        Raid = 'Raid1';        
        DataDrives = $driveLocations;                
    }
    $logicalDrivesArray += $logicalDrive

    $logicalVol.LogicalDrives = $logicalDrivesArray
<#
    $logicalDrive = [PSCustomObject]@{
        CapacityGiB = '186';
        LogicalDriveName = $driveLocation[0].MediaType;
        Raid = 'Raid1';
        Accelerator = 'IOBypass';
        DataDrives = $driveLocations;
        StripSizeBytes = '262144'
        #CapacityGib = $driveLocation[0].Capacity;         
    }
#>
     $jsonStr = $logicalVol | ConvertTo-Json -Depth 99 
     #update the structure to create the drives
     
     $ret = Edit-HPERedfishData -Odataid '/redfish/v1/Systems/1/smartstorageconfig/settings/' -Setting $jsonStr -Session $session

     # processing message obtained by executing Set- cmdlet
     if($ret.error.'@Message.ExtendedInfo'.Count -gt 0)
     {
         foreach($msgID in $ret.error.'@Message.ExtendedInfo')
         {
             $status = Get-HPERedfishMessage -MessageID $msgID.MessageID -MessageArg $msgID.MessageArgs -Session $session
             $status
         }
     }

     # Verify the change
     $logicalVolAfter = Get-HPERedfishDataRaw -Odataid '/redfish/v1/Systems/1/smartstorageconfig/settings/' -Session $session  

     $logicalVolAfter.LogicalDrives
     # Reset the server for the change to commit
}

function deleteLogicalVolume($session) 
{    
    $emptyArray = @()    
    
    $logicalVol = [PSCustomObject]@{    
     DataGuard = "Disabled"
     LogicalDrives = $emptyArray
    }       

    $jsonStr = $logicalVol | ConvertTo-Json -Depth 99 
    #update the structure to create the drives
    
    $ret = Edit-HPERedfishData -Odataid '/redfish/v1/Systems/1/SmartStorageConfig/Settings/' -Setting $jsonStr -Session $session

    # processing message obtained by executing Set- cmdlet
    if($ret.error.'@Message.ExtendedInfo'.Count -gt 0)
    {
        foreach($msgID in $ret.error.'@Message.ExtendedInfo')
        {
            $status = Get-HPERedfishMessage -MessageID $msgID.MessageID -MessageArg $msgID.MessageArgs -Session $session
            $status
        }
    }    
}

function resetServer($session, $RestartType)
{
    $systems = Get-HPERedfishDataRaw -odataid '/redfish/v1/systems/' -Session $session

    foreach($sys in $systems.members.'@odata.id') # /redfish/v1/systems/1/, /redfish/v1/system/2/
    {
        $sysData = Get-HPERedfishDataRaw -odataid $sys -Session $session

        # creating setting object to invoke reset action. 
        # Details of invoking reset (or other possible actions) is present in 'Actions' of system data  
        $dataToPost = @{}
        $dataToPost.Add('ResetType', $RestartType)
        
        # Sending reset request to system using 'POST' in Invoke-HPERedfishAction
        $ret = Invoke-HPERedfishAction -odataid $sysData.Actions.'#ComputerSystem.Reset'.target -Data $dataToPost -Session $session

        # processing message obtained by executing Set- cmdlet
        if($ret.error.'@Message.ExtendedInfo'.Count -gt 0)
        {
            foreach($msgID in $ret.error.'@Message.ExtendedInfo')
            {
                $status = Get-HPERedfishMessage -MessageID $msgID.MessageID -MessageArg $msgID.MessageArgs -Session $session
                $status
            }
        }
    }
}

function deleteLogicalVolumes($session) {
    deleteLogicalVolume $session
    if (checkPowerState $session)
    {
        resetServer $session "ForceRestart"
    }
    else {
        resetServer $session "On"        
    }
}

function createLogicalVolumes($session){
    $drives = getPhysicalDrives $session
    
    Write-Host "Drive Capacities available : " $($drives.Capacity | Sort-Object -Unique)
    $driveSize = Read-Host "Drive size "

    if (!$driveSize)
    {
        Write-Host "No drive size selected"
        return
    }

    createLogicalVolume $driveSize $drives $session
    if (checkPowerState $session)
    {
        resetServer $session "ForceRestart"
    }
    else {
        resetServer $session "On"
    }    
}

# Main
# Connect to the iLO
Write-Host "Connect to iLO..." -NoNewline
$session = Connect-HPERedfish -Address $Address -Username $user -Password $passwd 
Write-Host "Connected"

if ($physicalDrives) {
    getPhysicalDrives $session
} elseif ($logicalDrives) {
    getLogicalDrives $session
} elseif  ($createLogicalVol) {
    createLogicalVolumes $session
} elseif ($deleteLogicalVol) {
    deleteLogicalVolumes $session
} elseif ($powerState) {
    $ret = checkPowerState $session
} elseif ($lastOperationState) {
    checkLastSmartArrayStatus $session
}else {
    Write-Host "No option selected"    
}

# Disconnect from the iLO
Disconnect-HPERedfish -Session $session
