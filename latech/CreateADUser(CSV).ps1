#Import AD Module
Import-Module ActiveDirectory

#Notes
#(thing next to the one) allows you yo continue script on the next line/ NOTE NEEDED AFTER EVERY LINE. WILL NOT WORK IF A SPACE FOLLOWS IT
#-Name = Full Name (First, Last)
#-GivenName = First Name
#-Surname = Last Name
#-UserPrincipalName = User Name
#-AccountPassword (ConvertTo-SecureString [string] -AsPlainText -Force) = Password
#-Path = Path (In AD with view Advanced features on -> right click on the folder -> properties -> attribute editor -> distinguished name)
#-ChangePasswordAtLogon 1 = Make new user change password at log on. (0 = False, 1 = True)
#-Enabled 1 = Determines if the account is disabled by default

#prompt user for CSV file path
$filepath = Read-Host -Prompt "Please enter the path to you CSV file"

#import the file into a variable
$users = Import-Csv $filepath

ForEach ($user in $users){
#Use the column name after $user
$firstname = $user."first_name"
$lastname = $user."last_name"
$department = $user."Department"
$jobtitle = $user."jobtitle"
$username = $user."username"
$password = $user."password"

echo "$username, $firstname, $lastname, $jobtitle, $department"

#Create AD user
New-ADUser `
    -Name "$firstname $lastname" `
    -GivenName $firstname `
    -Surname $lastname `
    -UserPrincipalName $username `
    -Department $department `
    -Title $jobtitle `
    -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
    -Path "OU=Testing Grounds,DC=test,DC=local" `
    -ChangePasswordAtLogon 1 `
    -Enabled 1 
}