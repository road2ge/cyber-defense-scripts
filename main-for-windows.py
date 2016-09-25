# This script is actually for Cyber Security on Windows 7.  Should mostly work
# for Windows 8 and 10 too.  I just absolutely hate using Windows 8 and refuse
# to test it on any Windows 8 machine.
from subprocess import call
from subprocess import check_output
import os
import sys
username = os.getenv('username')
# The firewall needs to be enabled.  This is here because I hate Control Panel.
os.system('netsh advfirewall set allprofiles state on')
#Turn on UAC
os.system('C:\\Windows\\System32\\cmd.exe /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f')
# There is a lot of whitespace in this.  I need to find a way to remove it, but I'm on Ubuntu right now
os.system('secedit /import /db secedit.sdb /cfg asdf.inf /overwrite /log MyLog.txt')

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


allowed_users = input('What users are allowed? ')
allowed_users = allowed_users.split(',')
allowed_users.append(username)
for user in users:
    if user not in allowed_users:
        cmd_remove = check_output('net user ' + user + ' /delete')
        cmd_remove
    if user not in users:
        os.system('net user ' + user +  'p@55w0rd /add')
allowed_admins = input('What admins are allowed? ')
allowed_admins = allowed_admins.split(',')
allowed_admins.append(username)
for user in allowed_admins:
    os.system('net localgroup Administrators ' + user + ' p@55w0rd /add')
for user in allowed_users:
    if user not in allowed_admins:
        cmd_remove_admin = os.system('net localgroup Administrators ' + user + ' /remove')
        cmd_remove_admin
        
