  function Get-ADObjectsOwnedByUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Username
    )

    Import-Module ActiveDirectory

    $user = Get-ADUser -Identity $Username

    ForEach ($obj in Get-ADObject -Filter { (Name -eq $ObjectName -or SamAccountName -eq $ObjectName ) -and (objectClass -eq 'user' -or objectClass -eq 'computer' -or objectClass -eq 'group') } -Properties Owner) {
        $acl = Get-ACL -Path ("AD:\" + $obj.DistinguishedName) -ErrorAction SilentlyContinue

        if ($user.sid.value -eq ($acl.Sddl -replace 'o:(.+?)G:.+','$1')) {
            write-host $obj.Name is owned by $acl.Owner
        }
    }
} 
