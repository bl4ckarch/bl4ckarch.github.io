---
layout: post
title: "NTLM Relay on Windows Server 2025, I spent 20 minutes convinced my lab was broken"
date: 2026-02-27
categories: blogPost
tags: NTLM relay active-directory windows-server-2025 msv1_0 ldaps coercion

---

I thought I had skilled issued again.
Reread my commands. I checked the registry. Restarted ntlmrelayx. Went through the entire checklist. It turned out it wasn't me this time.

When the victim DC is using Windows Server 2025, the classic cross-DC coerce and relay to LDAPS attack, which exploits a misconfigured 'LmCompatibilityLevel' to get NTLMv1+ESS out and remove the MIC, no longer works. No matter what the registry says. The attack has just died.

NTLM relay is gradually becoming dark.

---

## How this started

I was working on **PrintSpoofer-ng**, my from-scratch implementation I wrote up [here](https://bl4ckarch.github.io/posts/PrintSpoofer_from_scratch/). Once it was running cleanly I wanted to push it further  test my coercion techniques against a more recent environment and see what still holds. Guess what, it doesn't anymore. But that's not the subject of this blog post.

I had `BL4CKARCH-DC02` (Windows Server 2019) sitting around with `LmCompatibilityLevel` intentionally degraded, the kind of misconfiguration you run into constantly on internal engagements. So I just dropped `BL4CKARCH-DC01` (Windows Server 2025) next to it to see what happens.

30 second setup: :-)

No i actually spent time modifying the configurations because i did take into considerations the forest and domain fonctional levels. 

```bash
ntlmrelayx.py -t ldaps://BL4CKARCH-DC01 -smb2support --shadow-credentials --remove-mic
```

```bash
DFSCoerce.py -u vagrant -p 'Password123.' -d bl4ckarch.local BL4CKARCH-DC02 192.168.56.1
```

I was expecting my usual NTLMv1+ESS. The auth came in. But it was NTLMv2.

`--remove-mic` useless. Relay dead.

---

## What I checked first (spoiler: everything was fine)

Before going deeper I did the full round:

- `LmCompatibilityLevel` on `BL4CKARCH-DC02` → **1**. Correctly degraded.
- ntlmrelayx → same command I've been running on engagements for months.
- Responder → auth is arriving, NTLMv2 coming out of `BL4CKARCH-DC02`.


![Responder — NTLMv2 from BL4CKARCH-DC02 despite LmCompatLevel=1](/assets/blog/NTLM-RELAY-IS-DEAD/responder-ntlmv2-dc02.png)


*NTLMv2 arriving from BL4CKARCH-DC02  registry says 1, NTLMv2 comes out anyway*

So I changed one variable: same `BL4CKARCH-DC02` as victim, relay target switched to another 2019 DC.

NTLMv1+ESS. Relay goes through. Shadow Credentials written.

So `BL4CKARCH-DC02` isn't the problem. **`BL4CKARCH-DC01` (2025) is changing what `BL4CKARCH-DC02` generates.**

That's where it gets interesting.

---

## Why BL4CKARCH-DC01 (2025) affects what BL4CKARCH-DC02 (2019) sends

Quick detour for context.

When `BL4CKARCH-DC02` authenticates to our machine over NTLM, the response type it generates  NTLMv1 or NTLMv2 depends on its own `LmCompatibilityLevel`. Not the target's. So in theory, if `BL4CKARCH-DC02` has `LmCompatibilityLevel=1`, it should always send NTLMv1 regardless of who it is authenticating to.

Except no. That's what got me.

I pulled out Ghidra and pulledthe two `msv1_0.dll` binaries from Windows 2019 and Windows 2025

---

## What changed in msv1_0.dll

The function we care about is `MspLm20GetChallengeResponse`. That's the one that decides what kind of authentication response to generate.

**On Server 2022** it reads `NtLmGlobalLmProtocolSupported` from the registry at runtime and uses it directly. Set `LmCompatibilityLevel=1`, the variable is 1, you get NTLMv1.

**On Server 2025** there's an extra check in that same function. Before using the registry value, the code verifies it's above a hardcoded minimum. If it's too low  it gets silently replaced by that minimum. And that minimum is high enough to force NTLMv2.


![MspLm20GetChallengeResponse — msv1_0.dll Server 2025](/assets/blog/NTLM-RELAY-IS-DEAD/msv1_0-mspLm20-diff.png)
*The hardcoded value inside MspLm20GetChallengeResponse  Server 2025 overrides NtLmGlobalLmProtocolSupported before generating the response*

NtLmGlobalLmProtocolSupported is the global variable that reflects LmCompatibilityLevel from the registry. On Server 2022, that value is read and used directly  registry says 1, variable is 1, the rest of the function generates NTLMv1.
On Server 2025, these three lines change everything. The registry value is read into v24, but immediately after there's a check: if it's less than or equal to 4, it gets replaced by 4. Value 4 maps to Send NTLMv2 response only  the absolute minimum this function will ever agree to produce.
v24 is then the variable used throughout the rest of the function to decide what response type to generate. Since v24 can never go below 4 on Server 2025, NTLMv1 is structurally impossible  regardless of what is written in HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel.
The registry isn't ignored  it's read, checked, and silently overridden if it's too low. Subtle, but intentional.

Practical result: whatever you put in the registry on a Server 2025 box, NTLMv1 will never come out. The registry value is read, and silently ignored if it's too low.

Worth noting: the **default** value of `NtLmGlobalLmProtocolSupported` also shifted from 3 on Server 2022 to 4 on Server 2025. But the hardcoded floor is the real change, not just the default.

---

## The proof — side by side

Here's `LmCompatibilityLevel=1` set on `BL4CKARCH-DC01` (Server 2025):


![LmCompatibilityLevel=1 on BL4CKARCH-DC01](/assets/blog/NTLM-RELAY-IS-DEAD/registry-lmcompat-dc01.png)
*Registry on BL4CKARCH-DC01  LmCompatibilityLevel=1. Means nothing.*

And here's Responder with both DCs coerced at the same time, `--disable-ess` active:


![Responder — NTLMv1 vs NTLMv2 side by side](/assets/blog/NTLM-RELAY-IS-DEAD/responder-contrast.png)
*BL4CKARCH-DC02 (2019) → NTLMv1. BL4CKARCH-DC01 (2025) → NTLMv2. Same LmCompatibilityLevel=1 on both.*

That's the proof. Same registry value. Different OS. Different output.

---

## Why NTLMv1+ESS was the piece that made MIC stripping work

NTLMv1 responses are **exactly 24 bytes**. Fixed structure, predictable layout. With ESS the client challenge is derived from both nonces, but the blob stays compact. That compactness is what made `--remove-mic` reliable  the MIC field in the AUTHENTICATE message could be zeroed out without breaking anything downstream on the LDAPS side.

NTLMv2 is variable-length. Full blob with target info, timestamp, and integrity bindings that hold the MIC in place. Strip the MIC and the auth invalidates. That's it.

---

## Quick breakdown for engagements

| Coerced victim | Relay target | Victim LmCompatLevel | Result |
|---|---|---|---|
| ≤ 2022 | ≤ 2022 | 0, 1 or 2 |  NTLMv1+ESS → relay works |
| ≤ 2022 | 2025 | 0, 1 or 2 |  NTLMv1+ESS → relay works |
| **2025** | **anything** | **anything** | **NTLMv2 → relay dead** |

The variable that matters is **the OS of the coerced machine**. Not the target.

---

## Blue team note

If you're not full Server 2025 yet, enforce `LmCompatibilityLevel = 5` via GPO on all DCs:

```
Computer Configuration → Windows Settings → Security Settings
→ Local Policies → Security Options
→ "Network security: LAN Manager authentication level"
→ Send NTLMv2 response only. Refuse LM & NTLM
```

Also enable LDAPS channel binding and LDAP signing separately  different surface but both need to be in place.

---

## What this actually says about Microsoft

What struck me isn't the change itself, it's *how* they did it.

They could have just updated the default registry value. That would've covered 95% of cases. Instead they hardcoded a limit value into the binary, which means even an admin who *intentionally* wants to downgrade can't do it on Server 2025.

That's an admission. It says Microsoft no longer trusts that `LmCompatibilityLevel` will be correctly configured in production environments. So they stopped relying on it and compiled the answer directly into the binary.

This behavior has been there since **KB5043080** (September 2024 Cumulative Update, Windows 11 24H2 arm64) and is consistent across all Server 2025 builds I've tested.

NTLM is on its way out anyway. But given how slow enterprise migrations actually move, mixed 2019/2022/2025 environments are going to stick around for a long time. Always check DC OS versions before building your relay chain.



