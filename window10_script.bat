@echo off

:: currently includes
:: files made after script completed: deletedmediafiles.txt, oldgroups.txt, passwords.txt; all made in same folder as script
setlocal EnableExtensions
net stop TrustedInstaller

set /P cd=What is your computer's directory:
set /P your_username=What is your username:

echo Script Starting...
echo //--------------------------------//--------------------------------//

:: folder-view options
echo Showing hidden/operating system files
call :folder_view

call :chat_clear

:: users
call :default_adminandguest
call :user_passwords
call :special_passwords

call :chat_clear

:: groups
call :group_deladmin
call :group_addadmin
call :group_delusers
call :group_addusers
call :group_newrecruits
call :group_delremoteusers

call :chat_clear

:: media
echo Deleting mp3, mp4, m4v, mov, and avi files
call :delete_media

call :chat_clear

:: features
echo Windows Features
call :windows_features

call :chat_clear

:: windows services
call :services_configure

call :chat_clear

:: control panel
echo Control Panel Settings
call :reg_uac
call :reg_windowsupdate
call :reg_remoteservices
call :reg_windowsfirewall

call :chat_clear

pause

EXIT /B %ERRORLEVEL%

//--------------------//--------------------//
:: ask for chat clear

:chat_clear
set /P chatclear_choice=Clear the chat [Y/N]:
if /I %chatclear_choice% == Y (
	cls
)
EXIT /B 0

//--------------------//--------------------//
:: folder-view options

:folder_view
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V Hidden /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V ShowSuperHidden /T REG_DWORD /D 1 /F >> nul 2>&1
reg import %cd%:\scriptResources\TaskManager.reg >> nul 2>&1
taskkill /IM explorer.exe /F >> nul 2>&1
start explorer.exe
echo //--------------------------------//
EXIT /B 0

//--------------------//--------------------//
:: users settings

:default_adminandguest
echo Disabling default admin and guest
net user Guest /active:no
net user Administrator /active:no
echo //--------------------------------//
EXIT /B 0

:user_passwords
echo Changing passwords to qwerQWER1234!@#$
echo BEG of user's passwords list:>> passwords.txt
for /f "tokens=2* delims==" %%G in ('
	wmic USERACCOUNT where "status='OK'" get name/value  2^>NUL
     ') DO for %%g in (%%~G) do (
		if /I %%~g NEQ %your_username% if /I %%~g NEQ Administrator if /I %%~g NEQ Guest (
		echo User: %%~g
		net user %%~g qwerQWER1234!@#$
		echo %%~g Password set to qwerQWER1234!@#$>> passwords.txt
		)
)
echo //--------------------------------//
echo END of user's passwords list>> passwords.txt
echo //--------------------------------//>> passwords.txt
EXIT /B 0

:special_passwords
echo BEG of admin's passwords list:>> passwords.txt
set /P special_admin=Special Admin's Name [username/none]:
if /I %special_admin% == none (
	echo //--------------------------------//
	echo END of admin's passwords list>> passwords.txt
	echo //--------------------------------//>> passwords.txt
	EXIT /B 0
)
set /P special_password=Special Admin's Password [one]:
net user %special_admin% %special_password%
goto special_passwords

//--------------------//--------------------//
:: groups settings

:: admins
:group_deladmin
echo Editing ADMIN group
echo BEG of OLD admins list:>> oldgroups.txt
for /f "tokens=2* delims==" %%G in ('
	wmic USERACCOUNT where "status='OK'" get name/value  2^>NUL
     ') DO for %%g in (%%~G) do (
		if /I %%~g NEQ %your_username% if /I %%~g NEQ Administrator (
		echo OLD admin: %%~g
		net localgroup Administrators %%~g /delete
		echo %%~g removed from Admin group
		echo OLD ADMIN %%~g removed>> oldgroups.txt
		)
)
echo //--------------------------------//
echo END of OLD admins list>> oldgroups.txt
echo //--------------------------------//>> oldgroups.txt
EXIT /B 0

:group_addadmin
net user
set /P new_admin=Add admin [one username/none]:
if /I %new_admin% == none (
	echo //--------------------------------//
	EXIT /B 0
)
net localgroup Administrators %new_admin% /add
echo %new_admin% added to admins group
goto group_addadmin

:: users
:group_delusers
echo Editing USER group
echo BEG of OLD users list:>> oldgroups.txt
for /f "tokens=2* delims==" %%G in ('
	wmic USERACCOUNT where "status='OK'" get name/value  2^>NUL
     ') DO for %%g in (%%~G) do (
		if /I %%~g NEQ %your_username% if /I %%~g NEQ Administrator if /I %%~g NEQ Guest (
		echo OLD user: %%~g
		net localgroup Users %%~g /delete
		echo %%~g removed from Users group
		echo OLD USER %%~g removed>> oldgroups.txt
		)
)
echo //--------------------------------//
echo END of OLD users list>> oldgroups.txt
echo //--------------------------------//>> oldgroups.txt
EXIT /B 0

:group_addusers
net user
set /P new_user=Add user [one username/none]:
if /I %new_user% == none (
	echo //--------------------------------//
	EXIT /B 0
)
net localgroup Users %new_user% /add
echo %new_user% added to users groups
goto group_addusers

:: new recruits - change password on next logon = enabled
:group_newrecruits
echo Adding new recruits
:loop_group_newrecruits
set /P new_recruit=Any new recruits [one username/none]:
if /I %new_recruit% == none (
	echo //--------------------------------//
	EXIT /B 0
)
net user %new_recruit% qwerQWER1234 /add
echo You must MANUALLY turn on Change password on next logon
set /P check_admin=Admin or user [admin/user]:
if /I %check_admin% == admin (
	net localgroup Administrators %new_recruit% /add
	net localgroup Users %new_recruit% /add
)
if /I %check_admin% == user (
	net localgroup Users %new_recruit% /add
)
goto loop_group_newrecruits

:: remove users from remote desktop users group
:group_delremoteusers
for /f "tokens=2* delims==" %%G in ('
	wmic USERACCOUNT where "status='OK'" get name/value  2^>NUL
     ') DO for %%g in (%%~G) do (
		net localgroup "Remote Desktop Users" %%~g /delete
		net localgrouyp "Remote Management Users" %%~g /delete
)
echo //--------------------------------//
EXIT /B 0
//--------------------//--------------------//
:: media files
:: finished 2/1

:delete_media
for %%e in (mp3,mp4,m4v,mov,avi) do (
	attrib -s -h -a -r /s /d %cd%:\*%%e
	del /s %cd%:\*%%e >> deletedmediafiles.txt
	echo %%e files searched
)
echo //--------------------------------//
EXIT /B 0

//--------------------//--------------------//
:: windows features

:windows_features
DISM /online /disable-feature /featurename:TelnetClient
DISM /online /enable-feature /featurename:Internet-Explorer-Optional-amd64
set /P server=Are you on a server [Y/N]?
if /I %server% == N (
	net stop WAS
	iisreset /stop
	DISM /online /disable-feature /featurename:TFTP
	DISM /online /disable-feature /featurename:SmbDirect
	DISM /online /disable-feature /featurename:SimpleTCP
	)
EXIT /B 0

//--------------------//--------------------//
:: windows services

:services_configure
echo Configuring Windows Services
:: disabled
for %%S in (tapisrv,bthserv,mcx2svc,remoteregistry,seclogon,telnet,tlntsvr,p2pimsvc,simptcp,fax,msftpsvc,nettcpportsharing,iphlpsvc,lfsvc,bthhfsrv,irmon,sharedaccess,xblauthmanager,xblgamesave,xboxnetapisvc) do (
	sc config %%S start= disabled >> nul 2>&1
	sc stop %%S >> nul 2>&1
)
:: enabled - automatic start
for %%S in (eventlog,mpssvc,windefend) do (
	sc config %%S start= auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)
:: enabled - delayed start
for %%S in (sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto >> nul 2>&1
	sc start %%S >> nul 2>&1
)

:: off - manual start
for %%S in (wersvc,wecsvc) do (
	sc config %%S start= demand >> nul 2>&1
)
echo //--------------------------------//
EXIT /B 0

//--------------------//--------------------//
:: windows shares

:shares_del
echo Deleting shares
echo BEG of deleted shares list:>> deletedshares.txt
set /P share_keep_YN=Any shares to keep [Y/N]:
if /I %share_keep_YN% == N (
	echo Deleting all shares except default IPC$, C$, ADMIN$
	for /f "tokens=2* delims==" %%G in ('
		wmic SHARE where "status='OK'" get name/value  2^>NUL
	     ') DO for %%g in (%%~G) do (
			if /I %%~g NEQ IPC$ if /I %%~g NEQ C$ if /I %%~g NEQ ADMIN$ (
				net share %%~g /delete
				echo %%~g deleted>> deletedshares.txt
			)
	)
)

if /I %share_keep_YN% == Y (
	for /f "tokens=2* delims==" %%G in ('
		wmic SHARE where "status='OK'" get name/value  2^>NUL
	     ') DO for %%g in (%%~G) do (
			if /I %%~g NEQ IPC$ if /I %%~g NEQ C$ if /I %%~g NEQ ADMIN$ (
				echo IPC$, C$, ADMIN$ shares ignored
				echo %%~g
				set /P share_specific_YN=Keep this share [Y/N]:
				if /I %share_specific_YN% == N (
					net share %%~g /delete
					echo %%~g deleted>> deletedshares.txt
				)
			)
	)
)
echo Add new shares manually at fsmgmt.msc
echo END of deleted shares list>> deletedshares.txt
echo //--------------------------------//
EXIT /B 0

//--------------------//--------------------//
:: windows registry edit

:reg_windowsupdate
echo Configuring Windows Update
echo. & echo Configuring Windows Update
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V AUOptions /T REG_DWORD /D 4 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ElevateNonAdmins /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F >> nul 2>&1
echo //--------------------------------//
EXIT /B 0

:reg_uac
echo Configuring UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V PromptOnSecureDesktop /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableInstallerDetection /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableLUA /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableVirtualization /T REG_DWORD /D 1 /F >> nul 2>&1
echo //--------------------------------//
EXIT /B 0

:reg_remoteservices
echo Configuring Remote Control Service
set /P remote_choice=Disabled Remote Services [Y/N]:
if /I %choice% == Y (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V fDenyTSConnections /T REG_DWORD /D 1 /F >> nul 2>&1
	sc config iphlpsvc start= disabled >> nul 2>&1
	sc stop iphlpsvc >> nul 2>&1
	sc config umrdpservice start= disabled >> nul 2>&1
	sc stop umrdpservice >> nul 2>&1
	sc config termservice start= disabled >> nul 2>&1
	sc stop termservice >> nul 2>&1
) else (
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V fDenyTSConnections /T REG_DWORD /D 0 /F >> nul 2>&1
    reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V UserAuthentication /T REG_DWORD /D 1 /F >> nul 2>&1
)
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F >> nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F >> nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F >> nul 2>&1
echo //--------------------------------//
EXIT /B 0

:reg_windowsfirewall
echo Configuring Windows Firewall
netsh advfirewall set allprofiles state on >> nul 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >> nul 2>&1
netsh advfirewall firewall add rule name="Block135tout" protocol=TCP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135uout" protocol=UDP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135tin" protocol=TCP dir=in localport=135 action=block
netsh advfirewall firewall add rule name="Block135tout" protocol=UDP dir=in localport=135 action=block
netsh advfirewall firewall add rule name="Block137tout" protocol=TCP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137uout" protocol=UDP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137tin" protocol=TCP dir=in localport=137 action=block
netsh advfirewall firewall add rule name="Block137tout" protocol=UDP dir=in localport=137 action=block
netsh advfirewall firewall add rule name="Block138tout" protocol=TCP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138uout" protocol=UDP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138tin" protocol=TCP dir=in localport=138 action=block
netsh advfirewall firewall add rule name="Block138tout" protocol=UDP dir=in localport=138 action=block
netsh advfirewall firewall add rule name="Block139tout" protocol=TCP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139uout" protocol=UDP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139tin" protocol=TCP dir=in localport=139 action=block
netsh advfirewall firewall add rule name="Block139tout" protocol=UDP dir=in localport=139 action=block
echo //--------------------------------//
EXIT /B 0
