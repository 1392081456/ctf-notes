---
type: source
created: 2026-05-13
updated: 2026-05-13
related: []
---

# CISCN2019 总决赛 Day2 Web1 Easyweb

SQL 注入（`\0` 吃引号）+ Cookie XOR 伪造 admin + Client-IP 控制日志文件名 + `<?=` 短标签日志写 Shell。

涉及概念：[[concepts/php-log-poisoning]]

## 环境

- PHP 5.5.9 + Apache + MySQL
- Cookie 加密：XOR with key `!*(fp60zoy` + base64
- 日志路径：`logs/upload.{md5(get_real_ip())}.log.php`
- `short_open_tag = Off`（但 `<?=` 在 PHP 5.4+ 始终可用）

## 攻击路径

1. 源码泄露（GitHub + robots.txt 提示 .bak）
2. 分析 Cookie 加密逻辑，XOR 伪造 admin 身份
3. image.php `\0` 吃引号 SQL 注入（UNION 读文件/信息）
4. upload.php 日志文件名基于 `md5(get_real_ip())`，通过 `Client-IP` 头获取全新日志
5. 上传文件名 `<?=`$_GET[c]`;?>` 写入日志（绕过 `/php/i` 过滤）
6. 访问日志文件 RCE → `cat /flag`

## `\0` 吃引号原理

```
输入: id=\0
→ addslashes: \\0 (转义反斜杠)
→ str_replace 移除 \0: 剩余 \
→ SQL: where id='\' or path='...'
→ \' 转义引号，id 字符串吞掉后续内容
→ path 参数进入 SQL 上下文
```

## 关键细节

- `str_replace` 移除 `\0`/`%00`/`\'`/`'`，使得 SQL 注入中无法使用任何引号
- INTO OUTFILE 需要引号包裹路径，因此不可行
- 日志文件一旦写入语法错误的 PHP 就永久损坏（PHP 解析整个文件）
- 必须通过 `Client-IP` 伪造获取全新日志文件

## 教训

- 日志文件以 .php 结尾是严重安全隐患
- `get_real_ip()` 信任客户端头是常见漏洞
- `<?=` 短标签绕过 "php" 关键字过滤是经典技巧
- curl 的 `-F` 选项中 `;` 是分隔符，含 `;` 的文件名需要用编程语言发送
