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

# user passwords
New-Item -Path .\script-output\user-passwords.txt -ItemType file
Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject $date

foreach ($i in Get-WmiObject -class Win32_UserAccount -filter "status='ok'" | Select name) {
    $avoid = $env:USERNAME,"Administrator","Guest"
    If (-NOT ($i.name -in $avoid)) {
        $password = 'qwQW12!@' + $i.name
        net user $i.name $password 
        $fileOutput = $i.name + ': ' + $password
        Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject $fileOutput
    }
}

Write-Host 'user passwords changed; check user-passwords.txt for log'
pause
cls

# special admin passwords
Out-File -FilePath .\script-output\recruits.txt -Append -InputObject 'special admin passwords:'

while(1 -eq 1) {
    
}

# add new users/recruits
New-Item -Path .\script-output\recruits.txt -ItemType file
Out-File -FilePath .\script-output\recruits.txt -Append -InputObject $date

while (1 -eq 1) {
    net user
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