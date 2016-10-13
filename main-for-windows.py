# This script is actually for Cyber Security on Windows 7.  Should mostly work
# for Windows 8 and 10 too.  I just absolutely hate using Windows 8 and refuse
# to test it on any Windows 8 machine.
############################# Check for proper priveleges #############################
import sys
import ctypes

'''def run_as_admin(argv=None, debug=False):
    shell32 = ctypes.windll.shell32
    if argv is None and shell32.IsUserAnAdmin():
        return True

    if argv is None:
        argv = sys.argv
    if hasattr(sys, '_MEIPASS'):
        # Support pyinstaller wrapped program.
        arguments = map(unicode, argv[1:])
    else:
        arguments = map(unicode, argv)
    argument_line = u' '.join(arguments)
    executable = unicode(sys.executable)
    if debug:
        print('Command line: ', executable, argument_line)
    ret = shell32.ShellExecuteW(None, u"runas", executable, argument_line, None, 1)
    if int(ret) <= 32:
        return False
    return None
if __name__ == '__main__':
    ret = run_as_admin()
    if ret is True:
        print('I have admin privilege.')
        raw_input('Press ENTER to exit.')
    elif ret is None:
        print('I am elevating to admin privilege.')
        raw_input('Press ENTER to exit.')
    else:
        print('Error(ret=%d): cannot elevate privilege.')'''

from subprocess import call
from subprocess import check_output
import os

username = os.getenv('username')
users = []
alpha = 'abcdefghijklmnopqrstuvwxyz'
numbers = '1234567890'
alpha_numeric = alpha + alpha.upper() + numbers
incoming_user = ''
temp_users = str(check_output('net user'))
times_through = 1
# " / \ [ ] : ; | = , + * ? < > are the characters not allowed in usernames
# Get a list of all users on the system
for character in temp_users:
    if character in alpha_numeric or character in "-#\'.!@$%^&()}{":
        incoming_user += character
    elif len(incoming_user) > 0:
        if times_through > 5 and incoming_user != 'Administrator' and incoming_user != 'Guest':
           users.append(incoming_user)
        incoming_user = ''
        times_through += 1
users = users[0:len(users)-4]

############################# User Management #############################
# Get list of allowed users
allowed_users = input('What users are allowed? You don\'t have to include yourself. Enclose in \'s. ')
allowed_users = allowed_users.split(',')
allowed_users.append(username)
# Remove unauthorized users
for user in users:
    if user not in allowed_users:
        print('Removing ' + user)
        os.system('net user ' + user + ' /delete')
    if user not in users:
        print('Adding user with 1337 p@55w0rd')
        os.system('net user ' + user +  'p@55w0rd /add')
# Get list of allowed Administrators
allowed_admins = input('What admins are allowed? Don\'t include yourself again. Enclose in \'s. ')
allowed_admins = allowed_admins.split(',')
allowed_admins.append(username)
# Add allowed Administrators to Administrator group
for user in allowed_admins:
    print('Adding ' + user + ' to Administrators group')
    os.system('net localgroup Administrators ' + user + ' /add')
# Remove unauthorized Administrators from Administrator group
for user in allowed_users:
    if user not in allowed_admins:
        cmd_remove_admin = os.system('net localgroup Administrators ' + user + ' /delete')
        cmd_remove_admin

############################# Registry keys and such #############################
# Password policy automagic
print('Chaning password policies and such...')
os.system('net accounts /FORCELOGOFF:30 /MINPWLEN:8 /MAXPWAGE:30 /MINPWAGE:10 UNIQUEPW:5')
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
os.system('C:\\Windows\\System32\\cmd.exe /k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f')
os.system('echo You\'re going to have to type exit')
os.system('secedit /import /db secedit.sdb /cfg cyber.inf /overwrite /log MyLog.txt')

############################# Search for media files #############################
file_list = []
directory_to_scan = input('What directory would you like to scan for media files? Remember to enclose your directory in \'s or \"s, and use two \\s for every \\ in your directory. ')
for root, dirs, files in os.walk('C:\\'):
    for f_name in files:
        file_path = os.path.join(root, f_name)
        for extension in ('.mp3','.wav','.png','wmv','.jpg','.jpeg','.mp4','.avi','.mov','.aif','.iff','.m3u','.m4a','.wma','.m4v','.mpg','.bmp','.gif'):
            if file_path.endswith(extension):
                file_list.append(file_path)
text_file = open('media_files.txt','w')
for file in file_list:
    text_file.write(file + "\n")
text_file.close()
