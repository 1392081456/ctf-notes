---
type: source
created: 2026-05-19
updated: 2026-05-19
related: [[sources/0x401ctf2025_flag_syndicate]]
---

# 0x401 CTF 2025 FlagSyndicate (Xianji #328 / #329) — English Writeup

DFIR challenge — 18 questions total. One 16 GB VMDK chains together: openKylin desktop triage → custom TCP server ELF reverse engineering (AES-128-CBC with key/IV appended to ciphertext) → reconstruction of a transmitted ZIP from base64-text payload → offline revival of MySQL 8 InnoDB to expose a black-market "Flag Market" trading stolen CTF flags.

Concepts used: [[concepts/vmdk-nbd-readonly-mount]], [[concepts/yescrypt-john-cracking]], [[concepts/aes-cbc-key-iv-appended]], [[concepts/mysql-innodb-offline-revive]]

## Story

Teams in a CTF were submitting flags suspiciously fast. A disk image seized from an organizer's machine should reveal how the flags leaked.

Attachments:
- `FlagSyndicate.vmdk` — 16 GB monolithicSparse VMware disk
- `dict.txt` — 3001 weak-password wordlist (used for yescrypt + salted MD5 cracking)
- 7z extraction password: `asfdif8yvwefvyewaryuvuwerwersadf4waert`

## Part 1 — Disk + Protocol Reversing (8 questions)

### 1. Mount VMDK read-only

```bash
sudo apt install -y qemu-utils
sudo modprobe nbd max_part=16
sudo qemu-nbd --read-only --connect=/dev/nbd0 FlagSyndicate.vmdk
sudo fdisk -l /dev/nbd0
# nbd0p1=1G /boot, nbd0p5=23G /
sudo mount -o ro,noload /dev/nbd0p5 /mnt/forensics/root
sudo mount -o ro,noload /dev/nbd0p1 /mnt/forensics/boot
```

`/etc/os-release` → **openKylin 2.0 SP1** (Chinese open-source Kylin desktop Linux). **Q1 OS = `openkylin`**.

### 2. yescrypt password cracking (Q2)

Admin hash in `/etc/shadow` starts with `$y$j9T$...` — the `$y$` prefix means **yescrypt** (the modern default on recent glibc). Hashcat support for yescrypt is poor; john's `--format=crypt` defers to the system `crypt(3)` and works directly.

```bash
john --format=crypt --wordlist=dict.txt admin.hash
# → sadrtdchampions
```

**Q2 = `sadrtdchampions`**

### 3. Browser history (Q3)

```bash
sqlite3 .mozilla/firefox/*.default-release/places.sqlite \
  "SELECT url FROM moz_places ORDER BY last_visit_date DESC;"
# Last visits include: http://127.0.0.1:5000/  Flag Market
#                     https://umdctf.io/  ← the CTF site
```

**Q3 = `umdctf`**

### 4. Communication tool ID (Q4–Q5)

`Desktop/commu_server` — ELF 64-bit, not stripped. **Q4 = `commu_server`**.

Disassembly of `main`:
```
mov edi, 0x112e   ; 0x112e = 4398
call htons
...
call bind / listen
```

**Q5 port = `4398`**.

### 5. Protocol reverse — the trick (Q6–Q8)

Reconstructed `handle_client` pseudocode:

```c
while ((n = read(fd, buf, 0x10000)) > 0) {
    RAND_bytes(key, 16);          // per-message random key
    RAND_bytes(iv,  16);          // per-message random IV
    ct = aes_encrypt(buf, n, key, iv, &out_len);
    blob = malloc(out_len + 32);
    memcpy(blob,                ct,  out_len);
    memcpy(blob + out_len,      key, 16);   // ★ key appended to ciphertext
    memcpy(blob + out_len + 16, iv,  16);   // ★ IV  appended to ciphertext
    log_line = base64(blob);                // base64(ct||key||iv)
    write_log_line(log_line);
}
```

**The trick: random key & IV look secure, but they are concatenated to the ciphertext in the log**. So every entry can be decrypted offline:

```python
raw = base64.b64decode(line_data)
ct, key, iv = raw[:-32], raw[-32:-16], raw[-16:]
pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
```

Decrypted log (timezone = Asia/Shanghai = UTC+8):

| # | Time (UTC+8) | Content |
|---|---|---|
| 1 | 14:55:25 | `Hello, I'm your boss.` |
| 2 | 14:55:40 | `It's time to work.` |
| 3 | 14:55:57 | `I will give you the source code of the market system.` |
| 4 | 14:57:37 | `Now,you will receive a file called market.zip from the server.` |
| **5** | **14:57:42** | **base64-text payload, 7612 B (a second base64 decode yields a ZIP, PK\x03\x04)** |
| 6 | 14:58:06 | `All done! Please construct the website.` |

**Q6 message count = `5`** (5 text messages; the file is counted separately).
**Q7 file receive time = `2025-10-29_14:57:42`**.

Entry #5 decrypts to ASCII text starting `UEsDBBQA...` = base64 of `PK\x03\x04`. One more base64 decode →

```python
zipbytes = base64.b64decode(msg5_payload)
# size 5708, MD5 = fe1829167aa8ed4f28d4651a7876a2e7
# Contains: app.py, requirements.txt, templates/{admin,base,login,myflags,register,shop}.html
```

**Q8 MD5 = `fe1829167aa8ed4f28d4651a7876a2e7`** (the decoded market.zip; the on-wire base64-text MD5 `e56a5578253275e80cdb4e0b84387411` is a fallback answer).

## Part 2 — Flask Source Audit + MySQL Forensics (10 questions)

market.zip is a tiny Flask + SQLAlchemy + flask_login shop.

### 6. Static source audit (Q1–Q3)

`app.py:12` → `mysql+pymysql://root:Aura123@127.0.0.1:3306/flagshop`. **Q1 DB = `flagshop`**.

`init_db()` ships 3 hardcoded samples:
```python
samples = [
    ('Starter Flag',  'CTF{starter_flag}',  100),
    ('Advanced Flag', 'CTF{advanced_flag}', 300),
    ('Secret Vault',  'CTF{vault_secret}',  1000),
]
```
**Q2 default flag count = `3`**.

`templates/base.html:16` → `<div class="font-bold text-2xl">Flag Vault</div>`. **Q3 = `Flag Vault`**.

### 7. Reviving MySQL InnoDB offline (Q4–Q10)

Disk's `/var/lib/mysql/` is MySQL **8.0.36** (`mysql.ibd` strings → `server_version=80036`). Kali has no local MySQL; cleanest revival is via Docker:

```bash
sudo cp -r /mnt/forensics/root/var/lib/mysql /tmp/forensics_work/mysql_data
sudo chmod -R u+rw /tmp/forensics_work/mysql_data
docker pull mysql:8.0.36
docker run -d --name flagshop_forensic \
  -v /tmp/forensics_work/mysql_data:/var/lib/mysql \
  -e MYSQL_ROOT_PASSWORD=Aura123 \
  mysql:8.0.36 --skip-grant-tables
```

**Critical**: the MySQL version must match — InnoDB redo-log layout changes across majors and MySQL 5.7 refuses to mount an 8.x datadir. `--skip-grant-tables` bypasses the original root password. Once the version aligns, InnoDB recovery succeeds.

Queries for Q4–Q10:

```sql
-- Q4 second-to-last flag on home page
-- (shop.html iterates `Item.query.all()` with no pagination, default PK ASC)
SELECT title FROM item ORDER BY id DESC LIMIT 2;
-- Flag_bd1bc642 / Flag_fbd25fe8

-- Q5 admin password hash
SELECT password_hash, salt FROM user WHERE username='admin';
-- 0e4f2c69b500d86249736944b5f6296d / 30e2c98eec4a61e9

-- Q6 the flag value of Flag_de4f665c
SELECT flag FROM item WHERE title='Flag_de4f665c';
-- flag{99fb23e3b49811f08030000c29ab8140}

-- Q7 flag bought by user 123123 at 2025-10-29 07:47:58 UTC
SELECT i.flag FROM purchase p
JOIN user u ON u.id=p.user_id
JOIN item i ON i.id=p.item_id
WHERE u.username='123123' AND p.timestamp='2025-10-29 07:47:58';
-- flag{9a5bf3aab49811f08030000c29ab8140}  (Flag_c5836a83)

-- Q8 total users
SELECT COUNT(*) FROM user;  -- 46215

-- Q9 number of admin users
SELECT COUNT(*) FROM user WHERE is_admin=1;  -- 18921
-- Unusually high. Many `user_xxxxxxxxx` rows have is_admin=1, evidently
-- a quirk of however the dataset was seeded. The literal field-count is 18921.

-- Q10 xianyu hash
SELECT password_hash, salt FROM user WHERE username='xianyu';
-- 141926946b25cfdaf31aeef42d5ead5d / c53548da31201cbe
```

The site stores `md5(password + salt)`. Hashcat mode 10 = `md5($pass.$salt)`:

```bash
echo '141926946b25cfdaf31aeef42d5ead5d:c53548da31201cbe' > xianyu.hash
hashcat -a 0 -m 10 xianyu.hash dict.txt
# → woshishei
```

**Q10 = `woshishei`** ("我是谁" = "who am I" in pinyin).

## All Answers

| Part | Q | Answer |
|---|---|---|
| P1 | Q1 OS | `openkylin` |
| P1 | Q2 Admin password | `sadrtdchampions` |
| P1 | Q3 CTF site | `umdctf` |
| P1 | Q4 Communication tool | `commu_server` |
| P1 | Q5 Listen port | `4398` |
| P1 | Q6 Messages received | `5` |
| P1 | Q7 File receive time | `2025-10-29_14:57:42` |
| P1 | Q8 File MD5 | `fe1829167aa8ed4f28d4651a7876a2e7` |
| P2 | Q1 DB name | `flagshop` |
| P2 | Q2 Default flags | `3` |
| P2 | Q3 Top-left banner | `Flag Vault` |
| P2 | Q4 Second-to-last flag | `Flag_fbd25fe8` |
| P2 | Q5 admin hash | `0e4f2c69b500d86249736944b5f6296d` |
| P2 | Q6 Flag_de4f665c value | `flag{99fb23e3b49811f08030000c29ab8140}` |
| P2 | Q7 123123's purchase | `flag{9a5bf3aab49811f08030000c29ab8140}` |
| P2 | Q8 Total users | `46215` |
| P2 | Q9 Admin users | `18921` |
| P2 | Q10 xianyu password | `woshishei` |

## Full Storyline

1. The victim ran `commu_server` (listening on 0.0.0.0:4398, encrypting each received message with AES + a random key, writing to `/tmp/commu_log.txt`).
2. Between 14:55 and 14:58 (UTC+8) the syndicate boss pushed 6 messages over TCP: greeting, work order, market source code (as base64-text payload), confirmation.
3. The victim deployed Flag Market on 127.0.0.1:5000 and pre-loaded the DB with 2000+ `Flag_xxxxxxxx` items (the leaked CTF flags).
4. Black-market members (`user1`, `xianyu`, `123123`, and `admin` themselves) logged in and "bought" flags they already had the answers to.
5. Forensics: read-only VMDK → reverse the ELF → decrypt logs → reconstruct the ZIP → revive MySQL → tie the whole supply chain together.

## Pitfalls

- **You cannot `mount` a VMDK directly.** Kali ships without qemu-utils; install it first. `vmware-mount` is deprecated.
- **Entry #5 decrypts to ASCII**, not raw bytes — my first attempt to `unzip` it failed. It's base64 in base64 (a protective double-encoding or just text-mode transmission).
- **MySQL datadirs are not portable across major versions.** MySQL 8 uses `mysql.ibd` (system tablespace) and `#ib_16384_*.dblwr` doublewrite files — MySQL 5.7 cannot open them. Always pull the exact version (here `8.0.36`, derived from `server_version=80036` strings in `mysql.ibd`).
- **`--skip-grant-tables` disables networking by default on MySQL 8** (a safety guard). Just `docker exec` over the unix socket — no need to fight with `--skip-networking=0`.
- **yescrypt is poorly supported in hashcat.** Use `john --format=crypt` so it goes through libcrypt → system crypt(3). Even at ~100 H/s, a 3 000-entry dictionary finishes in 30 seconds.
- **`Item.query.all()` without `order_by` returns rows in PK-ascending order** in SQLAlchemy. So "second-to-last on the home page" is strictly `id DESC LIMIT 1 OFFSET 1` (= id 2002).

## Cleanup

```bash
docker rm -f flagshop_forensic
sudo umount /mnt/forensics/boot /mnt/forensics/root
sudo qemu-nbd --disconnect /dev/nbd0
```

Chinese version: [[sources/0x401ctf2025_flag_syndicate]]
