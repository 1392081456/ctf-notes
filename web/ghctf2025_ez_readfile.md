---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# GHCTF2025 ez_readfile (NSSCTF)

PHP MD5 强碰撞（`===` + `is_string` 约束）解锁 `file_get_contents` 任意文件读取。flag 藏在超长随机文件名中，通过读 `/docker-entrypoint.sh` 获取路径。

涉及概念：[[concepts/php-md5-collision]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

```php
if (md5($_POST['a']) === md5($_POST['b'])) {
    if ($_POST['a'] != $_POST['b']) {
        if (is_string($_POST['a']) && is_string($_POST['b'])) {
            echo file_get_contents($_GET['file']);
        }
    }
}
```

## 解法

1. 使用 Marc Stevens 经典 MD5 碰撞对（128 字节二进制，URL-encode 后 POST）
2. `/flag` 不存在 → 读 `/docker-entrypoint.sh` 发现 flag 写入超长文件名
3. 读取该文件获得 flag

## Flag

```
NSSCTF{1c32175e-19f2-45bf-828d-9ba55cc49fd0}
```

## 踩坑

- `is_string` 排除了数组绕过 `a[]=1&b[]=2`
- flag 不在 `/flag`，需要信息收集找到真实路径
