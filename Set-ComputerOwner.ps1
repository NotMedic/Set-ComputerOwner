<#
.SYNOPSIS
    Updates the owner of a specified computer object in Active Directory.

.DESCRIPTION
    This function updates the owner of a specified computer object in Active Directory to a new owner.
    It requires the computer name and the new owner as parameters. The function includes error handling
    to manage cases where the computer object or the new owner cannot be found, or if there are permission issues.

.PARAMETER ComputerName
    The name of the computer object in Active Directory.

.PARAMETER NewOwner
    The new owner to be set for the computer object. This should be a valid user or group in Active Directory.

.EXAMPLE
    Set-ComputerOwner -ComputerName "YourComputerName" -NewOwner "Domain Admins"
    This example updates the owner of the computer object "YourComputerName" to "Domain Admins".

#>
function Set-ComputerOwner {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
    
        [Parameter(Mandatory=$true)]
        [string]$NewOwner
    )

    try {
        # Get the computer object
        $computer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
    } catch {
        Write-Error "Failed to find the computer object with the name $ComputerName"
        return
    }

    $computerDN = $computer.DistinguishedName
    $sd = Get-ACL "AD:$computerDN"

    try {
        # Get the SID of the new owner
        $newOwnerSid = (New-Object System.Security.Principal.NTAccount($NewOwner)).Translate([System.Security.Principal.SecurityIdentifier]) -ErrorAction Stop
    } catch {
        Write-Error "Failed to find the new owner $NewOwner"
        return
    }

    # Set the owner
    $sd.SetOwner($newOwnerSid)

    try {
        # Apply the updated security descriptor to the computer object
        Set-ACL -Path "AD:$computerDN" -AclObject $sd -ErrorAction Stop
        Write-Host "Owner of $ComputerName has been updated to $NewOwner"
    } catch {
        Write-Error "Failed to set the ACL for $ComputerName. Permission denied or other error."
    }
}

# Example usage:
# Set-ComputerOwner -ComputerName "YourComputerName" -NewOwner "Domain Admins"
