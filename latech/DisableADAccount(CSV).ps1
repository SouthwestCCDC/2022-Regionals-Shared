#Import AD Module
Import-Module ActiveDirectory

#Import AD Module
Import-Module ActiveDirectory

#prompt user for CSV file path
$filepath =Read-Host -Prompt "Please enter the path to your CSV file"

#import the file into a variable
$users = Import-Csv $filepath

ForEach ($user in $users){
$firstname = $user."first_name" 
$lastname = $user."last_name"
$name = "$firstname $lastname"

#Grabs the Distinguished Name that Disable-ADAccount needs to work 
$identity = (Get-ADUser -Filter "Name -eq '$name'").DistinguishedName

Disable-ADAccount -Identity $identity
echo "$identity disabled" 
}