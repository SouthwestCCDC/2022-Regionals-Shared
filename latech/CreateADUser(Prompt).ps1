﻿#Import AD Module
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

#Grab Variables from User
$firstname = Read-Host -Prompt "Please enter your first name"
$lastname = Read-Host -Prompt "Please enter your last name"
$password = Read-Host -Prompt "Password: "


#Create AD user
New-ADUser `
    -Name "$firstname $lastname" `
    -GivenName $firstname `
    -Surname $lastname `
    -UserPrincipalName "$firstname.$lastname" `
    -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
    -Path "OU=Testing Grounds,DC=test,DC=local" `
    -ChangePasswordAtLogon 1 `
    -Enabled 1 