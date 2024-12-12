  <#
.SYNOPSIS
    Updates the owner of a specified object in Active Directory.

.DESCRIPTION
    This function updates the owner of a specified object in Active Directory to a new owner.
    It requires the object name and the new owner as parameters. The function includes error handling
    to manage cases where the object or the new owner cannot be found, or if there are permission issues.

.PARAMETER ObjectName
    The name of the object in Active Directory.

.PARAMETER NewOwner
    The new owner to be set for the object. This should be a valid user or group in Active Directory.

.EXAMPLE
    Set-ADObjectOwner -ObjectName "YourObjectName" -NewOwner "Domain Admins"
    This example updates the owner of the object "YourObjectName" to "Domain Admins".

#>
function Set-ADObjectOwner {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ObjectName,
    
        [Parameter(Mandatory=$true)]
        [string]$NewOwner
    )

    try {
        # Get the AD objects with the specified name and filter by objectClass
        $adObject = Get-ADObject -Filter { (Name -eq $ObjectName -or SamAccountName -eq $ObjectName ) -and (objectClass -eq 'user' -or objectClass -eq 'computer' -or objectClass -eq 'group') } -ErrorAction Stop
        if (-not $adObject) {
            Write-Error "No object found with the name $ObjectName"
            return
        }
    } catch {
        Write-Error "Failed to find the object with the name $ObjectName"
        return
    }


    $objectDN = $adObject.DistinguishedName
    $sd = Get-ACL "AD:$objectDN"

    write-host $ObjectDN
    write-host $sd

    try {
        # Get the SID of the new owner
        $newOwnerSid = (New-Object System.Security.Principal.NTAccount($NewOwner)).Translate([System.Security.Principal.SecurityIdentifier])
    } catch {
        Write-Error "Failed to find the new owner $NewOwner"
        return
    }

    # Set the owner
    $sd.SetOwner($newOwnerSid)

    try {
        # Apply the updated security descriptor to the AD object
        Set-ACL -Path "AD:$objectDN" -AclObject $sd -ErrorAction Stop
        Write-Host "Owner of $ObjectName has been updated to $NewOwner"
    } catch {
        Write-Error "Failed to set the ACL for $ObjectName. Permission denied or other error."
    }
}

# Example usage:
# Set-ADObjectOwner -ObjectName "YourObjectName" -NewOwner "Domain Admins" 
 
