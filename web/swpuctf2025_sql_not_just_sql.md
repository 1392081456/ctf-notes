---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# SWPUCTF 2025 秋季新生赛 - sql仅仅只是sql吗？ (NSSCTF)

数字型 UNION 注入 + multi_query 堆叠查询 + UDF 提权 RCE。flag 藏在非标准路径 `/fffffllllllaaaaagggg`。

涉及概念：[[concepts/mysql-udf-rce]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

PHP 7.3 + MariaDB 10.6 用户查询系统，`?id=` 数字型注入，`multi_query()` 启用堆叠查询。secrets 表只有 FAKE_FLAG。真 flag 在文件系统中。

## 解法

1. UNION 注入确认 3 列，`database()` = ctf，`version()` = 10.6.14-MariaDB
2. `load_file('/var/www/html/index.php')` 读源码，发现 `multi_query()` + root 权限
3. Webroot 不可写（INTO OUTFILE / general_log_file 均失败）
4. 发现 plugin 目录 `/usr/lib/mariadb/plugin/` 可写
5. 分块上传 `lib_mysqludf_sys_64.so`（8040 bytes）到表中转，再 `INTO DUMPFILE` 写入 plugin 目录
6. `CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.so'`
7. `sys_eval('ls /')` 发现 `/fffffllllllaaaaagggg`
8. `sys_eval('cat /fffffllllllaaaaagggg')` 获取 flag

## Flag

```
NSSCTF{d11a1ca0-7761-4a4e-8e4d-21b27b6a4451}
```

## 踩坑

- Webroot 无写权限，general_log 写 webshell 路线不通
- UDF 二进制通过 GET URL 一次性上传会因长度截断，需用表做中转分块上传
- Flag 文件名故意混淆（`fffffllllllaaaaagggg`），需 `ls /` 才能发现
