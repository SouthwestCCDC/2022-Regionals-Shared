$pass = Get-Content .\passwords.txt
#Each line corresponds to the password for the given user
$word = $pass.split([Environment]::NewLine)
$count = 0
foreach ($User in Get-Content .\users.txt)  #Opens a users.txt file to get all users to be added. Format: FName, LName, Username         
{            
    $lister = $User.split(" ")
    $Displayname = $lister[2]        
    $UserFirstname = $lister[0]          
    $UserLastname = $lister[1]            
    $OU = "OU=<OU-INNER>,OU=<OU-OUTER>,DC=<DOMAIN>,DC=COM" #Replace parameters. For a nested OU start with most specific and go out.                               
    $Password = $word[$count]            
    New-ADUser -Name "$Displayname" -DisplayName "$Displayname" -GivenName "$UserFirstname" -Surname "$UserLastname" -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $true -Path "$OU" -ChangePasswordAtLogon $true -PasswordNeverExpires $false        
 
    $count = $count + 1
}