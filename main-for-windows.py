# This script is actually for Cyber Security on Windows 7.  Should mostly work
# for Windows 8 and 10 too.  I just absolutely hate using Windows 8 and refuse
# to test it on any Windows 8 machine.
from __future__ import print_function
from subprocess import call
from subprocess import check_output
import os
############################# User Management #############################
username = os.getenv('username')
users = []
alpha = 'abcdefghijklmnopqrstuvwxyz'
numbers = '1234567890'
alpha_numeric = alpha + alpha.upper() + numbers
incoming_user = ''
temp_users = str(check_output('net user'))
times_through = 1
for not_allowed_characters in '"/\[]:;|=,+*?<>':
    temp_users.replace(not_allowed_characters, '')
temp_users.replace("\r\n","")
temp_users.replace("\r","")
temp_users.replace("\n","")

# " / \ [ ] : ; | = , + * ? < > are the characters not allowed in usernames
# Get a list of all users on the system
for character in temp_users:
    if character in alpha_numeric or character in "-#\'.!@$%^&()}{":
        incoming_user += character
    elif len(incoming_user) > 0:
        if times_through > 5:
           users.append(incoming_user)
        incoming_user = ''
        times_through += 1
users = users[0:len(users)-4]
print('All the users currently on this computer are ' + users)
do_user_management = input("Shall we manage users? 'y' or 'n' ")
def user_management(users):
    def should_be_admin(user)
        should_be_admin = input(user + "is an administrator. Should they be? 'y' or 'n' ")
        if should_be_admin == 'y':
            return True
        if should_be_admin == 'n':
            return False
    def should_be_user(user):
        should_be_user = input(user + "is a user. Should they be? 'y' or 'n' ")
        if should_be_user == 'y':
            return True
        if should_be_user == 'n':
            return False
    for user in users:
        # Iterate through user list
        if user in check_output('net localgroup Administrators'):
            # If user is in the Administrators localgroup
            if not should_be_admin(user):
                print('Removing ' + user + ' from the Administrators group')
                os.system('net localgroup Administrators ' + user + ' /delete')
        else:
            if not should_be_user(user):
                print('Removing ' + user)
                os.system('net user ' + user + ' /delete')
            if should_be_user(user):
                if user not in check_output('net localgroup Administrators'):
                    if should_be_admin(user):
                        print('Adding ' + user + 'to the Administrators group')
                        os.system('net localgroup Administrators ' + user + ' /add')
if do_user_management == 'y':
    user_management(users):

############################# Registry keys and such #############################
# Password policy automagic
print('Chaning password policies and such...')
os.system('net accounts /FORCELOGOFF:30 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:10 /UNIQUEPW:5')
# Automagic updates
print('Automagic updates are now actualy automagic')
os.system('reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 3 /f')
os.system('reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f')
# Let's turn off that awkward thing called RDP
print('nice, RDP is now gone')
os.system('reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f')
os.system('reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f')
# Clean DNS cache, cause why not
print('Bro, I cleaned your DNS cache. Deal with it.')
os.system('ipconfig /flushdns')
# Disable leh autorun
print('RIP autorun')
os.system('reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f')
# Disable built-in accounts
print('I really hope you weren\'t the default Administrator account')
os.system('net user Guest /active:NO')
os.system('net user Administrator /active:NO')
# Clear page file on shutdown
print('Pagefile clears on shutdown. GG')
os.system('reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f')
# Does not reboot if logged on after update installed
print('Will no longer reboot when logged on, after update is installed')
os.system('reg ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f')
# No CTRL+ALT+DELETE on logon
print('No CTRL+ALT+DEL on logon')
os.system('reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 1 /f')
# Make auditing great again.
print('Auditing now on! Yay!!!!')
os.system('auditpol /set /category:* /success:enable')
os.system('auditpol /set /category:* /failure:enable')
# Enable firewall
print('The firewall torch has been passed on to you')
os.system('netsh advfirewall set allprofiles state on')
# Turn on UAC
print('UAC = triggered')
os.system('reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f')
os.system('echo You\'re going to have to type exit')
os.system('secedit /import /db secedit.sdb /cfg cyber.inf /overwrite /log MyLog.txt')
reg_dir = '"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" '
for command in (('FilterAdministratorToken','1'),('ConsentPromptBehaviorAdmin','1'),('ConsentPromptBehaviorUser','1'),('EnableInstallerDetection','1'),('ValidateAdminCodeSignatures','1'),('EnableLUA','1'),('PromptOnSecureDesktop','1'),('EnableVirtualization','1'),('EnableVirtualization','1')):
    os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f')
reg_dir = "KEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
for command in (('AUOptions', '4'),('ElevateNonAdmins', '1'),('IncludeRecommendedUpdates', '1'),('ScheduledInstallTime', '22')):
    os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f')
reg_dir = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
for command in (('fDenyTSConnections', '1'),('AllowRemoteRPC', '0')):
    os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f') 
reg_dir = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance'
for command in (('fAllowFullControl','0'),('fAllowToGetHelp','0')):
    os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f')
reg_dir = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
command = ('UserAuthentication','1')
os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f')
reg_dir = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance'
command = ('CreateEncryptedOnlyTickets','1')
os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f')
reg_dir = 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 
command = ('fDisableEncryption','0')
os.system('reg add ' + reg_dir + command[0] + '/v ' + command[1] + ' /t REG_DWORD /f')
############################# Search for media files #############################
file_list = []
directory_to_scan = input('What directory would you like to scan for media files? Remember to enclose your directory in \'s or "s, and use two \s if your directory ends in a \. ')
for root, dirs, files in os.walk(directory_to_scan):
    for f_name in files:
        file_path = os.path.join(root, f_name)
        for extension in ('.mp3','.wav','.png','wmv','.jpg','.jpeg','.mp4','.avi','.mov','.aif','.iff','.m3u','.m4a','.wma','.m4v','.mpg','.bmp','.gif'):
            if file_path.endswith(extension):
                file_list.append(file_path)
text_file = open('media_files.txt','w')
for file in file_list:
    text_file.write(file + "\n")
text_file.close()
