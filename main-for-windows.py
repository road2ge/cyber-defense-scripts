# This script is actually for Cyber Security on Windows 7.  Should mostly work
# for Windows 8 and 10 too.  I just absolutely hate using Windows 8 and refuse
# to test it on any Windows 8 machine.
from subprocess import call
from subprocess import check_output
import os
import sys
import admin
if not admin.isUserAdmin():
		admin.runAsAdmin()
username = os.getenv('username')
# The firewall needs to be enabled.  This is here because I hate Control Panel.
os.system('netsh advfirewall set allprofiles state on')
#Turn on UAC
os.system('C:\\Windows\\System32\\cmd.exe /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f')
os.system('secedit /import /db secedit.sdb /cfg cyber.inf /overwrite /log MyLog.txt')

users = []
alpha = 'abcdefghijklmnopqrstuvwxyz'
numbers = '1234567890'
alpha_numeric = alpha + alpha.upper() + numbers
incoming_user = ''
temp_users = check_output('net user')
times_through = 1
# " / \ [ ] : ; | = , + * ? < > are the characters not allowed in usernames
for character in temp_users:
	if character in alpha_numeric or character in "-#\'.!@$%^&()}{":
		incoming_user += character
	elif len(incoming_user) > 0:
		if times_through > 5 and incoming_user != 'Administrator' and incoming_user != 'Guest':
		   users.append(incoming_user)
		incoming_user = ''
		times_through += 1
users = users[0:len(users)-4]

allowed_users = input('What users are allowed? You don\'t have to include yourself. ')
allowed_users = allowed_users.split(',')
allowed_users.append(username)
for user in users:
	if user not in allowed_users:
		cmd_remove = check_output('net user ' + user + ' /delete')
		cmd_remove
	if user not in users:
		os.system('net user ' + user +  'p@55w0rd /add')
allowed_admins = input('What admins are allowed? Don\'t include yourself again. ')
allowed_admins = allowed_admins.split(',')
allowed_admins.append(username)
for user in allowed_admins:
	os.system('net localgroup Administrators ' + user + ' p@55w0rd /add')
for user in allowed_users:
	if user not in allowed_admins:
		cmd_remove_admin = os.system('net localgroup Administrators ' + user + ' /remove')
		cmd_remove_admin
# A whole bunch of registry lines.  I don't care if some of these are in the cyber.inf secpol import, sometimes
# When I'm testing that, things don't go write... Oh well, I'd rather have a bunch of os.system calls and duplicate entries
# Than have me think something happened when it didn't.
# Password policy automagic
os.system('net accounts /FORCELOGOFF:30 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:10UNIQUEPW:5')
# Automagic updates
os.system('reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f')
os.system('reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f')
# Let's turn off that awkward thing called RDP
os.system('reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f')
os.system('reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f')
# Clean DNS cache, cause why not
os.system('ipconfig /flushdns')
# Disable leh autorun
os.system('reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f')
# Disable built-in accounts
os.system('net user Guest /active:NO')
os.system('net user Administrator /active:NO')
# Clear page file on shutdown
os.system('reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f')
# Does not reboot if logged on after update installed
os.system('reg ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f')
# No CTRL+ALT+DELETE on logon
os.system('reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 1 /f')