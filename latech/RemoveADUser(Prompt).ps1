#Import AD Module
Import-Module ActiveDirectory

#prompt user for CSV file path
$firstname =Read-Host -Prompt "Please enter the first name of the user: "
$lastname =Read-Host -Prompt "Please enter the last name of the user: "

#Sets the full name
$name = "$firstname $lastname"

#Grabs the Distinguished Name that Remove-ADUser needs to work 
$identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

Remove-ADUser -Identity $identity -Confirm:$false
echo "$name deleted" 
