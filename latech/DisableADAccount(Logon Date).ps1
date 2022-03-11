#Import AD Module
Import-Module ActiveDirectory

#Gets the previous date
$lastdate= (Get-Date).AddDays(-180)

#Disable the account if the last logon date was over 6 months ago
$identity = Get-ADUser -Properties LastLogonDate -Filter {LastLogonDate -lt $lastdate } | Disable-ADAccount

#print results
$name = $identity.Name
echo "$name disabled"  