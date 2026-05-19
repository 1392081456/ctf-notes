# Lab Writeup Template

> 每次打完靶场/CTF/授权项目，复制此模板填写。
> 路径: `/root/Security/labs/<漏洞名或靶场名>/writeup.md`

---

# Lab Writeup: [漏洞名/CVE编号]

**日期**: YYYY-MM-DD
**靶场**: [vulhub/HTB/TryHackMe/自建/授权项目]
**难度**: ★☆☆☆☆ ~ ★★★★★
**耗时**: X 分钟
**标签**: [反序列化/SQLi/SSRF/文件上传/提权/...]

---

## 1. 目标信息

| 项 | 值 |
|---|---|
| IP:Port | |
| OS | |
| 中间件/框架 | |
| 应用版本 | |
| 初始权限 | |
| 最终权限 | |

## 2. 攻击链（一句话）

```
[入口] → [漏洞利用] → [权限获取] → [后渗透/提权]
```

## 3. 详细步骤

### 3.1 信息收集

```bash
# 端口扫描 / 指纹识别 / 目录爆破
```

### 3.2 漏洞发现

- 发现过程
- 漏洞原理（2-3 句）

### 3.3 漏洞利用

```bash
# 关键命令 / payload
```

### 3.4 权限获取

```bash
# 拿 shell 的方式
```

### 3.5 后渗透 / 提权（如有）

```bash
# 提权路径
```

## 4. 踩坑记录

| 问题 | 原因 | 解决 |
|---|---|---|
| | | |

## 5. 收获 / 新学到的

- [ ] 新技术点
- [ ] 可复用的 payload
- [ ] 需要加入知识库的内容

## 6. 工具清单

| 工具 | 用途 | 备注 |
|---|---|---|
| | | |

## 7. Defense（必填 — labs 章节强制项）

Labs writeup 的攻防双视角承诺在此兑现。每个 lab 需要从三个维度补全防御：**Hardening**（缩小攻击面）、**Detection**（实时捕获）、**Threat Hunting**（事后取证）。每节至少 3 条，含 1 个具体的规则/IOC/查询示例。

### 7.1 Hardening — 缩小攻击面

| 措施 | 实施方式 | 阻断哪一步 |
|---|---|---|
|  |  |  |
|  |  |  |
|  |  |  |

- [ ] 厂商补丁路径（CVE 编号 → 修复版本）
- [ ] 配置加固（默认凭据/默认 key/默认路径）
- [ ] 依赖瘦身（移除 gadget chain 入口库）
- [ ] 运行时最小权限（non-root / read-only FS / drop capabilities）
- [ ] 网络层（egress filter / 入口 WAF）

### 7.2 Detection — 实时捕获

- [ ] **流量特征**：长度异常 / 熵异常 / 关键字（含示例 WAF/Suricata 规则）
- [ ] **日志特征**：异常 stack trace / 高频错误（含 SIEM 关联规则）
- [ ] **行为特征**：进程派生 / 文件落地 / 网络外联（含 Falco/Sysmon 规则）

```
# 示例规则（替换为实际 payload）
```

### 7.3 Threat Hunting — 事后取证

- [ ] **文件系统 IOC**：典型落地路径（`find` 一行）
- [ ] **内存证据**：JVM heap dump / process memory 提取关键对象
- [ ] **日志回溯**：access log / audit log 怎么搜
- [ ] **网络流量回查**：NetFlow / pcap 怎么过滤

```bash
# 示例查询命令
```

## 8. 关联

- 方法论: `knowledge_base/techniques/xxx.md`
- CVE: `cve_lookup CVE-XXXX-XXXXX`
- 同类漏洞: 
