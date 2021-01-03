#Part 1 Exercises
##################
#Exercise 1
#Get all services where the display name begins with ‘Windows’.

Get-Service | where {$_.displayname -like 'windows*'}

#Exercise 2
#Get a list of all classic event logs on your computer.

Get-EventLog -List

#Exercise 3
#Find and display all of the commands on your computer 
#that start with ‘Remove’.

Get-Command -Name remove-* | measure
Get-Command -Verb remove   | measure


#Exercise 4
#What PowerShell command would you use to reboot one or more 
#remote computers?

Restart-Computer -ComputerName a, b

#Exercise 5
#How would you display all available modules installed on your computer?

Get-Module -ListAvailable

#Exercise 6
#How would you restart the BITS service on your computer and see the result?

Get-Service -Name BITS | Restart-Service

#Exercise 7
#List all the files in the %TEMP% directory and all subdirectories.

get-childitem -path  $env:TEMP  | `
Where-Object {$_.Attributes -EQ 'directory'}  


#Exercise 8
#Display the access control list (ACL) for Notepad.exe.

Get-Acl Notepad.exe | fl


#Exercise 9
#How could you learn more about regular expressions in PowerShell?

help about_Regular_Expressions

#Exercise 10
#Get the last 10 error entries from the System event log on your computer.

Get-EventLog -LogName System | Select-Object -Last 10

Get-WinEvent -LogName System | Select-Object -Last 10


#Exercise 11
#Show all of the ‘get’ commands in the PSReadline module.

Get-Command -Module PSReadline -Verb get

#Exercise 12
#Display the installed version of PowerShell.

$PSVersionTable

#Exercise 13
#How would you start a new instance of Windows 
#PowerShell without loading any profile scripts?

%windir%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe -noprofile

#Exercise 14
#How many aliases are defined in your current PowerShell session?
# 170 individual alias
# 136 unique  alias

Get-Alias -Name *   | Group-Object Definition | measure

#Exercise 15
#List all processes on your computer that have a working set 
#size greater than or equal to 50MB and
#sort by working set size in descending order.


Get-Process | Where-Object {$_.WorkingSet -ge 50mb}

#Exercise 16
#List all files in %TEMP% that were modified in the last 24 hours and 
#display the full file name, its size
#and the time it was last modified. Write a PowerShell expression that 
#doesn’t rely on hard coded
#values.

get-childitem -path  $env:TEMP -file -Recurse| `
Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} `
| Select-Object  @{name = "KB"; Expression = {[math]::round($_.length /1kb)}}, fullname


#Exercise 17
#Get all files in your Documents folder that are at least 1MB 
#in size and older than 90 days. Export
#the full file name, size, creation date and last modified date 
#to a CSV file. You may have to adjust
#the exercise based on files you have available.

Get-ChildItem -path 'C:\Users\LocalAdmin\Documents' -file -Recurse| `
Where-Object {$_.Length -gt 1mb -and $_.LastWriteTime -lt (Get-Date).AddDays(-90)} `
| Select-Object  @{name = "mb"; Expression = {[math]::round($_.length /1mb)}}, LastWriteTime, fullname | Export-Csv C:\Exercise17.csv


#Exercise 18
#Using files in your %TEMP% folder display the total number of each files 
#by their extension in
#descending order.

$ex = Get-ChildItem -Path $env:TEMP -file -Recurse | Group-Object extension  
$ex | ForEach-Object {$_}
$ex | measure


#Exercise 19
#Create an XML file of all processes running under your credentials.

Get-Process -IncludeUserName | where-object {$_.username -eq "$env:USERDOMAIN\$env:USERNAME"} 


Get-Process -IncludeUserName | where-object {$_.username -like '*localadmin*'} `
| Export-Clixml c:\powershell\ProcCred1.xml


(Get-Process -IncludeUserName | where-object {$_.username -like '*localadmin*'} | `
convertto-xml -NoTypeInformation).Save('c:\powershell\ProcCred2.xml')


#Exercise 20
#Using the XML file you created in the previous question, import the XML data into your
#PowerShell session and produce a formatted table report with processes grouped by the 
#associated company name.


$x = Import-Clixml c:\powershell\ProcCred1.xml ` 
$x | Sort-Object -Property company | ft -GroupBy  company 

$x  | Group-Object -Property company -NoElement 


#Exercise 21
#Get 10 random numbers between 1 and 50 and multiply each number by itself.

1..10 | ForEach-Object{($X = Get-Random -Minimum 1 -Maximum 50) * $X}


#Exercise 22
#Get a list of event logs on the local computer and create an HTML file that includes ‘Computername’
#as a heading. You can decide if you want to rename other headings to match the original cmdlet
#output once you have a solution working.


$X = Get-WinEvent -FilterHashtable @{logname = 'security'; id = 4625 } -ComputerName localhost `
| ConvertTo-Html -Property logname, id, machinename -Title "Security events for $env:computername" > c:\powershell\event.html


#Exercise 23
#Get modules in the PowerShell Gallery that are related to teaching.

Find-Module -name '*Teaching*'
Find-Module  | Where-Object {$_.description -like '*Teaching*' }
Find-Module -Tag teaching 

#Exercise 24
#Get all running services on the local machine and export the data to a json file. 
#Omit the required and dependent services. Verify by re-importing the json file.


Get-Service | Where-Object {$_.Status -eq 'running'} | Select-Object * -ExcludeProperty '*services*'| ConvertTo-Json | Out-File c:\powershell\services.json

Get-Content c:\powershell\services.json |  ConvertFrom-Json


#Exercise 25
#Test the local computer to see if port 80 is open.

Test-NetConnection google.com -CommonTCPPort http

Test-NetConnection google.com -Port 80

#Part 2 Exercises
##################

#Exercise 1
#Assuming you haven’t modified your PowerShell session with a profile script, what are the default
#PSDrives for the Registry provider?

HKCU                                   Registry      HKEY_CURRENT_USER         
HKLM                                   Registry      HKEY_LOCAL_MACHINE 


#Exercise 2
#How many certificates are installed in the root certificate store for the local machine?

    Set-Location -Path LocalMachine\Root
    Get-ChildItem | Measure-Object
    
    Get-ChildItem Cert:\LocalMachine\Root | Measure-Object
    

#Exercise 3
#Query the local registry to display the registered owner and organization.


Get-ItemPropertyValue -Path  'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' `
-Name registeredowner, registeredorganization  

#Exercise 4
#How many functions are defined in your current PowerShell session?

Get-ChildItem function: | measure

#Exercise 5
#List all applications installed under the Uninstall section of the registry. Give yourself a challenge
#and filter out those with a GUID for a name.

$install = Get-childitem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' -Recurse 

Get-childitem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' -Recurse `
 | ForEach-Object {Get-ItemProperty $_.pspath | Select-Object displayname}    
 
Get-childitem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' -Recurse `
 | ForEach-Object {Get-ItemProperty $_.pspath | Where-Object {$_.pschildname -notmatch "^{"} } | Select-object -property PSChildName  

 
#Exercise 6
#Modify the registered organization value in the registry. Verify the change. Then go ahead and
#change it back to the original value.


Get-ItemPropertyValue -Path  'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name registeredorganization  

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name registeredorganization -Value ""


#Exercise 7
#What PSProvider supports transactions?


get-psprovider | where {$_.Capabilities -like "*transactions*"}

Get-PSProvider | Select name, Capabilities

#Exercise 8
#How would you find code signing certificates installed on your computer?

Get-ChildItem -Path Cert:  -CodeSigningCert -Recurse


#Exercise 9
#Turn %PATH% into a list of directories.

$env:path -split ";"


#Exercise 10
#Create a new registry key under HKEY_CURRENT_USER called ‘PowerShell Training’. Then create
#values under it for your name, computername, the current date and PowerShell version. You should
#be able to get all of these values from PowerShell.

New-Item -Path HKCU: -Name 'PowerShell Training'
Set-ItemProperty -Path 'HKCU:\PowerShell Training' -Name Name -Value $env:USERNAME
Set-ItemProperty -Path 'HKCU:\PowerShell Training' -Name Computername -Value $env:COMPUTERNAME
Set-ItemProperty -Path 'HKCU:\PowerShell Training' -Name Date -Value (Get-Date).ToShortDateString()
Get-item 'HKCU:\PowerShell Training'

#Exercise 11
#Using PowerShell, delete the PowerShell Training registry setting you created in the previous
#exercise.

Remove-Item -Path 'HKCU:\PowerShell Training'

#Exercise 12
#Create a PSDrive called Download for the Downloads directory under your user directory.

New-PSDrive -Name Download -PSProvider FileSystem -Root "C:\users\LocalAdmin\Downloads"
 
#Exercise 13
#Get all functions that don’t support cmdletbinding.

Get-Command -CommandType Function |  Where-Object {$_.CmdletBinding -eq  $false}

#Exercise 14
#Get the default WSMan port values.

Get-ChildItem WSMan:\localhost\Service\DefaultPorts

#Exercise 15
#Set the Digest Authentication setting for WSMan to $False. If it is already False then set it to True.
#Revert the change if you need to.

Get-ChildItem WSMan:\localhost\Client\Auth
Set-Item -Path WSMan:\localhost\Client\Auth\Digest -Value $false

#Exercise 16
#Create a new environmental variable in PowerShell called Pictures that points to your Pictures
#folder. Does this setting persist?

New-Item -Path env: -Name Pictures -Value $env:userprofile\pictures

#Exercise 17
#Make a persistent environmental variable called Pictures that points to your Pictures folder. Verify
#it in PowerShell

New-ItemProperty -Path HKCU:\Environment -Name Pictures -Value `
$env:userprofile\pictures

#Exercise 18
#Create a backup copy of your user environmental variables found in the registry to EnvBackup.

Copy-Item HKCU:\Environment -Destination HKCU:\EnvBackup -PassThru

#Exercise 19
#Delete the persistent Pictures environmental variable you created earlier and recreate it using
#%USERPROFILE% as an expandable variable.

Remove-Item -Path env:pictures

#Exercise 20
#Export your user specific persistent environment settings to a CSV file that you can use outside of
#PowerShell.


Get-ChildItem env: | Export-Csv -Path C:\powershell\env.csv


#Exercise 21
#List all certificates that have expired showing the certificate’s friendly name, when it expired, the
#issuer and path.

Get-ChildItem Cert: -Recurse -ExpiringInDays 0  | Select-Object FriendlyName, NotAfter,  @{name='path'; expression= {Join-Path -Path cert: -ChildPath (Convert-Path $_.pspath)}}, Issuer

#Exercise 22
#Get a unique list of commands run from your command history. Bonus points if you can filter out
#any help commands.

Get-History | Where-Object {$_.commandline -notmatch "help"} | Sort-Object commandline `
| Get-Unique 
 

#Exercise 23
#Using the DNSClientCache cmdlet, export all records other than AAAA to a CSV file. Your export
#should include the computername, the entry, its type, the time to live, and its data. Instead of a
#comma, use a semicolon as the separator.

 
Get-DnsClientCache -type A, CNAME, PTR


#Exercise 24
#Using your birthday, write an object to the pipeline that shows your birthday (and time if you know
#or want to guess something), your current age in years as a round number, the timespan you’ve been
#alive, the day of the week you were born, and what day you can retire at age 65. Other than your
#birthday, you should be able to calculate everything.

$properties = @{

                 'DOB'        = $DOB      = 1
                 'Age'        = $Age      = 2                   
                 'TimeSpan'   = $TimeSpan = 3
                 'Retire'     = $Retire   = 4 

                        }

$Exercise24 = New-Object -TypeName psobject -Property $Properties   

 
#Exercise 25
#Assuming you have a few third party applications or utilities running, prepare a formatted report
#of all processes that are not from Microsoft and copy to the clipboard. Paste into Notepad to verify.


Get-Process | Where-Object {$_.Company -notlike '*Microsoft*'}    


#Part 3 Exercises
##################

#Exercise 1
Create an array of the numbers 1 to 20 and then get the 5th element of the array


$array = 1 .. 20
$array[4]


#Exercise 2
#Initialize an empty array. Add 10 random numbers between 10 and 100. Finally, get the sum total of
#all numbers in the array.

$array = @()
1..10 | ForEach-Object {$array +=(Get-Random -Minimum 1 -Maximum 100)}
$array  | measure-object -sum
 

#Exercise 3
#Create a hashtable with keys for your computername, PowerShell version and the current date
#(without the time). Don’t use any hardcoded values.

$Exercise3 = @{
                'Computername' = $env:computername
                'version' = ($PSVersionTable).psversion
                'Date' = (Get-Date).ToShortDateString()             
              }
$Exercise3

 
#Exercise 4
#Using the hashtable from the previous exercise, add a key for Name using the values of Bits and
#WinRM. Remove the Date and PowerShell version keys. Finally, splat the hashtable to Get-Service.

$Exercise3.Add( 'name', ("bits", "WINRM"))
$Exercise3.Remove('version')
$Exercise3.Remove('Date')
Get-Service @exercise3 

#Exercise 5
#Create an ordered hashtable with keys for your computername, all the running processes, the top 5
#processes using the most working set and the total size of your %TEMP% folder in bytes. Complete
#the exercise by creating a custom object from the hashtable.





#Exercise 6
#Recreate the hashtable from the previous exercise, but this time create a custom object at the same
#time.





#Exercise 7
#Get all event logs on your computer that have entries and show the log name, maximum size, the
#total number of entries, and a property called Computername to reflect the computer name.



#Exercise 8
#Recursively go through all file in %TEMP%, or a directory of your choice. The result of your
#PowerShell expression should show the number of files per file extension and their total size in
#bytes.



#Exercise 9
#Create an array of letters A through E. Get a random item from the array and assign it to $X. Then
#create a PowerShell construct that displays “alpha”,”bravo”,”charlie”,”delta”,”echo” based on the value
#of X.




#Exercise 10
#Take the string “PowerShell Forever” and display it reversed.




#Exercise 11
#Create a hashtable of services based on their startup type.



#Exercise 12
#Using the hashtable you created in the previous exercise, get the display name of the last disabled
#service.




#Exercise 13
#Get all the even numbers between 1 and 50.




#Exercise 14
#Starting with $i equal to 0, loop 5 times, each time incrementing $i by 5. At the end, does $i equal
#25?




#Exercise 15
#Display the top 25 processes that have been running the longest. Include the process ID, process
#name, start time, how long it has been running and path.



#Exercise 16
#Get 25 random numbers between 10 and 100. Multiply each one by 3 then get the total sum of these
#numbers, their average, the largest number and the smallest.




#Exercise 17
#Create these aliases:
#• np (notepad.exe)
#• tx (tzutil.exe)
#• ct (control.exe)
#Export them to a json file. Delete the new aliases you just created and recreate them from the json
#file.



#Exercise 18
#Find all files in %TEMP%, or a folder of your choice, that are either less than 100 bytes or greater than
#1 megabyte.





#Exercise 19
#Take the output from the previous exercise and save it as a standard XML file in UTF-8 format. The
#filename should be in %TEMP%, and include a datetime like YearMonthDay and the computername.




#Exercise 20
#Using Invoke-RestMethod, get the latest RSS entries from https://jdhitsolutions.com/blog/feed and
#display the title, link, and when it was published, as a date time value, in a grid view. For bonus
#points, see if you can include a comma separated list of category names.



#Exercise 21
#Using the previous solution as a starting point, select a single entry from Out-Gridview and open
#the link in your web browser.




#Exercise 22
#Get a unique list of commands run from your command history. Bonus points if you can filter out
#any help commands.





#Exercise 23
#Using the DNSClientCache cmdlet, export all records other than AAAA to a CSV file. Your export
#should include the computername, the entry, its type, the time to live, and its data. Instead of a
#comma, use a semicolon as the separator.




#Exercise 24
#Using your birthday, write an object to the pipeline that shows your birthday (and time if you know
#or want to guess something), your current age in years as a round number, the timespan you’ve been
#alive, the day of the week you were born, and what day you can retire at age 65. Other than your
#birthday, you should be able to calculate everything.




#Exercise 25
#Assuming you have a few third party applications or utilities running, prepare a formatted report
#of all processes that are not from Microsoft and copy to the clipboard. Paste into Notepad to verify.




