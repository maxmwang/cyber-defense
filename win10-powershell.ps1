$date = Get-Date

# making directory desktop
$directory_letter = Read-Host -Prompt 'directory letter'
$cd = $directory_letter + ':\Users\' + $env:USERNAME + '\desktop'
Write-Host $cd
pause
cd $cd

# output folder created in same directory as script location
New-Item -Path .\script-output -ItemType directory

# shows hidden files
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced Hidden 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced HideFileExt 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced ShowSuperHidden 1
kill -n explorer

Write-Host 'hidden files are now showing in file explorer' 
pause
cls

# disable default guest/admin
net user Guest /active:no
net user Administrator /active:no
net user DefaultAccount /active:no

Write-Host default guest/admin disabled


#-----users/admins

# delete unauthorized users/admins
# user passwords
New-Item -Path .\script-output\deleted-users.txt -ItemType file
Out-File -FilePath .\script-output\deleted-users.txt -Append -InputObject $date
New-Item -Path .\script-output\user-passwords.txt -ItemType file
Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject $date

$user_list = New-Object System.Collections.ArrayList
$admin_list = New-Object System.Collections.ArrayList

while($TRUE) {
    $username_temp = Read-Host -Prompt "give 1 username"
    if ($username_temp -eq 'none' -or $username_temp -eq '') {
        break
    }
    $user_list.add($username_temp) > $null
}
while($TRUE) {
    $adminname_temp = Read-Host -Prompt "give 1 adminname"
    if ($adminname_temp -eq 'none' -or $adminname_temp -eq '') {
        break
    }
    $admin_list.add($adminname_temp) > $null
}
Out-File -FilePath .\script-output\deleted-users.txt -Append -InputObject $user_list
Out-File -FilePath .\script-output\deleted-users.txt -Append -InputObject $admin_list

foreach ($i in Get-WmiObject -class Win32_UserAccount -filter "status='ok'" | Select name) {
    $avoid = $env:USERNAME,"Administrator","Guest"
    If (-NOT ($i.name -in $avoid)) {
        If (-NOT ($i.name -in $user_list -or $i.name -in $admin_list)) {
            net localgroup users $i.name /delete
            net user $i.name /active:no
            $fileOutput = "deleted user: " + $i.name
            Out-File -FilePath .\script-output\deleted-users.txt -Append -InputObject $fileOutput
        }
        If (-NOT ($i.name -in $admin_list)) {
            net localgroup administrators $i.name /delete
            $fileOutput = "deleted admin: " + $i.name
            Out-File -FilePath .\script-output\deleted-users.txt -Append -InputObject $fileOutput
        }
        $password = 'qwQW12!@' + $i.name
        net user $i.name $password 
        $fileOutput = $i.name + ': ' + $password
        Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject $fileOutput
        If ($i.name -in $admin_list) {
            $prompt = "new password for " + $i.name
            $password = Read-Host -Prompt $prompt
            If (-NOT ($password -eq 'none' -or $password -eq '')) {
                net user $i.name $Password
                $fileOutput = $i.name + " (admin): " + $password
                Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject $fileOutput
            }
        }
    }
}
Write-Host "deleted unauthorized users, changed user passwords"
Write-Host "check deleted-users.txt and user-passwords.txt"
pause
cls

# add new users/recruits
New-Item -Path .\script-output\recruits.txt -ItemType file
Out-File -FilePath .\script-output\recruits.txt -Append -InputObject $date

while ($TRUE) {
    net users

    $recruit_username = Read-Host -Prompt "recruit's username (none)"
    if ($recruit_username -eq 'none' -or $recruit_username -eq '') {
        break
    }
    $recruit_password = Read-Host -Prompt "recruit's password (none)"
    if ($recruit_username -eq 'none' -or $recruit_username -eq '') {
        break
    }
    net user $recruit_username $recruit_password /logonpasswordchg:yes /add

    $file_output = $recruit_username + ': ' + $recruit_password
    Out-File -FilePath .\script-output\recruits.txt -Append -InputObject $file_output
}

Write-Host 'added recruits; check recruits.txt for log'
pause
cls

# special admin passwords
Out-File -FilePath .\script-output\recruits.txt -Append -InputObject 'special admin passwords:'

while($TRUE) {
    
}

