#Import AD Module
Import-Module ActiveDirectory

#Gets the previous date
$lastdate= (Get-Date).AddDays(-180)

#Get-ADUser -Properties LastLogonDate -Filter {LastLogonDate -lt $lastdate } | Remove-ADUser –WhatIF
$name = Read-Host -Prompt "Insert Name"
$identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName | Disable-ADAccount
echo "$name disabled"  