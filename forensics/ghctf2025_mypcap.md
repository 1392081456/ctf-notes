---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# GHCTF2025 mypcap (NSSCTF)

Tomcat Manager WAR 部署冰蝎 webshell → AES-ECB 解密通信还原命令 → 读取密码文件 → MySQL 协议提取数据 → 三答案拼接 BLAKE2b 解密 flag。

涉及概念：[[concepts/behinder-webshell-aes-decrypt]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

给定 pcapng + flag 解密脚本，需回答三个问题：
1. 受害者开放端口
2. 数据库密码（mrl64 放在桌面）
3. 数据库中的重要数据

答案经 BLAKE2b → AES-GCM 解密 flag。

## 解法

1. SYN-ACK 判断开放端口：22, 3306, 8080
2. 攻击者通过 Tomcat Manager 上传 `t3st.war`（冰蝎 webshell，AES key = `8a1e94c07e3fb7d5`）
3. 解密 webshell POST（Base64 → AES-ECB → Java class bytecode → 提取命令字符串）
4. 命令 `cat p4ssw0rd` 响应：`mysql password is n1cep4Ss`
5. MySQL 协议 `SELECT * FROM data` 响应：`Th1s_1s_Imp0Rt4Nt_D4Ta`

## Flag

```
NSSCTF{703663c4-1ff1-4c51-83b8-0f4303e82659}
```

## 踩坑

- webshell 响应是 JSON 格式 `{"msg":"<base64>","status":"<base64>"}`，msg 字段再 base64 解码得明文
- POST body 解密后是 Java class 字节码，不是明文命令；需从 class 常量池提取命令字符串
