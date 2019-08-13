# output folder created in same directory as script location
New-Item -Path .\script-output -ItemType directory

# shows hidden files
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced Hidden 1
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced HideFileExt 0
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced ShowSuperHidden 1
kill -n explorer

Write-Host hidden files are now showing in file explorer 
pause
cls

# disable default guest/admin
net user Guest /active:no
net user Administrator /active:no
net user DefaultAccount /active:no

Write-Host default guest/admin disabled

# user passwords
New-Item -Path .\script-output\user-passwords.txt -ItemType file

foreach ($i in Get-WmiObject -class Win32_UserAccount -filter "status='ok'" | Select name) {
    $avoid = $env:USERNAME,"Administrator","Guest"
    If (-NOT ($i.name -in $avoid)) {
        $password = 'qwQW12!@' + $i.name
        Write-Host $password
        $fileOutput = $i.name + ': ' + $password
        Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject $fileOutput
    }
}
Out-File -FilePath .\script-output\user-passwords.txt -Append -InputObject '-----'

pause
cls
