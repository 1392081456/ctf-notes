---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# GHCTF2025 SQL (NSSCTF)

数字型 UNION 注入 + 严格 WAF 绕过。WAF 封锁了所有函数调用、information_schema、跨库点号访问、字符串函数，但 UNION SELECT 和 FROM 当前库表名未拦截。通过直接猜测 `flag` 表 + `flag` 列获取 flag。

涉及概念：[[concepts/sql-waf-bypass-guessing]]、[[concepts/sql-urlencode-keyword-bypass]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

页面回显 SQL 语句和 Error，数字型注入，5 列（位置 2/3/4/5 有回显）。

## WAF 规则

- 所有函数调用被拦（`database()`, `version()`, `concat()`, `substr()` 等）
- 跨库点号访问被拦（`information_schema.xxx`, `mysql.xxx`, `sys.xxx`）
- 大小写/注释绕过无效
- 单引号被拦
- 但 `union select`、`from <table>`、子查询 `(select ...)` 不被拦

## 解法

WAF 封死了所有元数据查询路径，无法获取表名/列名。直接猜测：

```
?id=-1 union select 1,flag,3,4,5 from flag
```

## Flag

```
NSSCTF{Funny_Sq11111111ite!!!}
```

## 踩坑

- 花时间尝试各种 WAF 绕过（注释、大小写、编码）全部失败
- 正确思路是：当所有元数据路径被封时，直接猜表名/列名
- `flags`、`secret`、`admin` 等表名也被 WAF 拦截，只有 `flag` 没被拦
