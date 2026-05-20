---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# 玄武杯2025 ez_fastapi (NSSCTF)

FastAPI 自定义 Jinja2 单花括号分隔符盲 SSTI → `app.router.add_route()` 内存马注入绕过 `add_api_route` 禁用 → sudo chmod 提权读 flag。

涉及概念：[[concepts/fastapi-memory-shell]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

FastAPI 应用，`/shellMe?username=` 参数拼入 Jinja2 模板渲染，但 render 结果被丢弃（盲 SSTI）。`app.add_api_route` 和 `app.add_middleware` 被禁用。flag 在 `/flag`，root 只读。

## 解法

1. 识别自定义分隔符 `{` / `}`（非标准 `{{` / `}}`）
2. 盲 SSTI 确认：`{7*7}` 返回 200，`{{7*7}}` 返回 500
3. 通过 `lipsum.__globals__['__builtins__']['eval']()` 执行 Python 代码
4. 用 `sys.modules['app'].app.router.add_route()` 注入新路由（绕过 `add_api_route` 禁用）
5. 新路由 `/shell?cmd=` 实现回显 RCE
6. `sudo -l` 发现 `(ALL) NOPASSWD: /usr/bin/chmod`
7. `sudo chmod 644 /flag && cat /flag`

## Flag

```
NSSCTF{0ec5e0bc-3188-47da-857b-be3fb21180cb}
```

## 踩坑

- 误用 `{{}}` 双花括号导致 500，浪费时间做 time-based blind 提取
- 盲 SSTI 应优先注入内存马获得回显，而非逐字符提取
- uvicorn 启动时 `__main__` 不是 app 模块，需用 `sys.modules['app']`
