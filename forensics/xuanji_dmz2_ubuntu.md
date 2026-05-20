---
type: source
created: 2026-05-10
updated: 2026-05-10
related: []
---

# 玄机 — 仿真 DMZ 应急响应（DMZ2 Ubuntu）

涉及概念：[[concepts/nacos-cve-2021-29442-ua-bypass]]、[[concepts/linux-uid-zero-hidden-user]]
涉及实体：[[entities/app_nacos]]、[[entities/ctf_xuanji]]、[[entities/cve_2021-29442]]

## 题目

https://xj.edisec.net/challenges/380 — DMZ2 Ubuntu 22.04，攻击者从 DMZ1 横移至此并做权限维持。SSH `root/Solarsec521`。

## 答案

| 步骤 | 答案 |
|---|---|
| Step1 web 新增账号 | `flag{system}` |
| Step2 隐藏系统用户 | `flag{sys-update}` |
| Step3 /var/flag/1 | `flag{ad31ea22e324ee6effd454decf7477c9}` |
| Step4 /var/flag/2 | `flag{85fdb55f08925b3ae7149e869124f2c4}` |
| Step5 /var/flag/3 | `flag{163e32607debcc6091e993929afe8064}` |
| Step6 /var/flag/4 | `flag{2d1848c8560becac27d30a5d4daf6da3}` |

## 关键发现

1. 8848 端口跑 Nacos 1.4.0 — User-Agent `Nacos-Server` 鉴权绕过 (CVE-2021-29442)
2. `/etc/passwd` 里 `sys-update:x:0:0::/var/tmp/.sys:/bin/bash` — UID=0 隐藏后门
3. `/var/tmp/.sys/.ssh/authorized_keys` — 攻击者 SSH 公钥维持
4. `/usr/sbin/sys-kernel-opt` (systemd service `sys-kernel-opt.service`) 是题目检查器，每 ~10s 轮询：
   - Nacos 用户列表无 system → 写 `/var/flag/1`
   - passwd/shadow 无 sys-update → 写 `/var/flag/2`
   - nacos service inactive → 写 `/var/flag/3`
   - root 密码改了 → 写 `/var/flag/4`

`strings` 直接能看到检查逻辑和 flag。

## 处置流程

```bash
# Step3
curl -H 'User-Agent: Nacos-Server' -X DELETE \
  "http://127.0.0.1:8848/nacos/v1/auth/users?username=system"

# Step4 —— userdel 拒绝删 UID=0 用户("user used by process 1")，必须 sed
sed -i '/^sys-update:/d' /etc/passwd
sed -i '/^sys-update:/d' /etc/shadow
rm -rf /var/tmp/.sys

# Step5
systemctl stop nacos && systemctl disable nacos

# Step6
echo 'root:NewSecurePass2026!' | chpasswd
```

每步后 `sleep 12` 等检查器轮询。

## 踩坑

1. **`userdel` 对 UID=0 隐藏用户失败**：报 "user used by process 1"，因为 PID 1 systemd 以 UID=0 运行，被认作是"该 UID=0 用户"。绕法是直接 sed 改 passwd/shadow。
2. **`/var/flag/` 一开始空**：必须真做处置动作才会被检查器写入；不要试图直接 cat 没生成的文件。
3. **检查间隔 ~10s**：不等待会误以为没生效。
4. **`strings` 出 flag**：本题可直接逆 binary 拿全部 flag，但应急响应价值在于"识别后门 → 安全处置 → 验证修复"流程。
