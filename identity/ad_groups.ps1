# Common AD group queries. Needs the ActiveDirectory module (RSAT).
# These are one-liners to paste, not a script to run top to bottom.
# Swap 'HR' and the OU path for whatever you're actually looking at.

# every group in the domain
Get-ADGroup -Filter *

# does a group exist
Get-ADGroup -Identity 'HR'

# local admins on this box (local, not AD)
Get-LocalGroupMember -Identity 'Administrators'

# members of HR including anything nested inside it
Get-ADGroupMember -Identity 'HR' -Recursive

# same thing across a few groups
$groupNames = 'HR', 'Accounting', 'IT'
foreach ($group in $groupNames) {
    Get-ADGroupMember -Identity $group
}

# run the lookup as a different account
Get-ADGroup -Identity 'HR' -Credential (Get-Credential)

# HR members with their mail attribute
Get-ADGroupMember 'HR' | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object {
    $user = Get-ADUser $_.SamAccountName -Properties EmailAddress
    [PSCustomObject]@{
        Name  = $user.Name
        Email = $user.EmailAddress
    }
}

# security groups only (skips distribution lists)
Get-ADGroup -Filter { GroupCategory -eq 'Security' }

# groups under one OU
Get-ADGroup -Filter * -SearchBase 'OU=NYC,OU=Locations,DC=company,DC=pri'

# ...and dump them to csv
Get-ADGroup -Filter * -SearchBase 'OU=NYC,OU=Locations,DC=company,DC=pri' -SearchScope Subtree |
    Export-Csv -Path 'nyc.csv' -NoTypeInformation
