---
type: source
created: 2026-05-13
updated: 2026-05-13
related: []
---

# 羊城杯 2020 Break The Wall

PHP `eval($_GET['c'])` 后门，但自定义"墙"（函数名黑名单）移除了几乎所有危险函数。Flag 藏在环境变量 `FLAG` 中。

涉及概念：[[concepts/php-env-flag-harvesting]]

## 环境

- PHP 7.4.8 + Apache (apache2handler)
- 大量函数被黑名单移除（system, exec, passthru, fopen, file_put_contents, scandir, glob...）
- 文件系统极简（仅 /var/www/html 和 /tmp）
- Docker 容器（Kubernetes 环境变量可见）

## 攻击路径

1. `?c=phpinfo();` → 确认可执行 PHP 代码
2. 测试发现 system/exec/scandir 等被封禁
3. 通过 `get_extension_funcs('standard')` 枚举可用函数（535 个函数在扩展定义中，但大量被过滤移除）
4. 发现 `getenv()` 和 `$_ENV` 可用
5. `?c=var_dump(getenv('FLAG'));` → 获取 flag

## 函数过滤分析

过滤方式：自定义 PHP 扩展在运行时按函数名从函数表移除危险函数。同名内部函数的不同别名可能一个被移除另一个保留（如 fwrite 移除但 fputs 保留）。

| 状态 | 函数示例 |
|------|---------|
| 可用 | file_get_contents, readfile, tmpfile, fputs, fread, getenv, posix_*, apache_note |
| 不可用 | system, exec, passthru, popen, proc_open, shell_exec, fopen, fwrite, file_put_contents, scandir, opendir, glob, fsockopen, stream_socket_client, curl_exec, putenv, mail, error_log, ini_set |

## 教训

- 环境变量是常被忽视的 flag 存储位置
- `$_ENV` / `getenv()` / `phpinfo()` 可泄露环境变量
- 函数名黑名单可能遗漏别名函数
- 即使封禁了几乎所有危险操作，信息泄露途径仍存在
