Get-ADUser -Filter * -Properties * | Select-Object name | export-csv -path c:\export\allusers.scv