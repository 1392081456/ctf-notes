---
type: source
created: 2026-05-13
updated: 2026-05-13
related: []
---

# NewStarCTF 最后的流量分析

布尔盲注流量还原。通过 HTTP 响应长度差异（712 vs 705）区分 True/False，逐字符提取 flag。

## 环境

- pcap 文件，127.0.0.1 本地回环 HTTP 流量
- 攻击目标：`/comments.php?name=if((substr((select(text)from(wfy_comments)where(id=100)),pos,1)="char"),100,0)`
- 每个字符猜测使用独立 TCP 连接

## 解题方法

1. 按 TCP 源端口配对请求和响应
2. 从 URI 提取位置和猜测字符
3. 响应长度 ≥ 710 为 True（含数据），< 710 为 False（空）
4. 每个位置取 True 响应对应的字符拼接

## 关键细节

- `if(condition, 100, 0)`：True 返回 id=100 的记录（响应更大），False 返回 id=0（不存在，响应更小）
- 响应使用 chunked + gzip 编码，但总长度差异仍可区分
- 攻击者字符集按键盘顺序遍历：qwertyuioplkjhgfdsazxcvbnm + 特殊字符

## 教训

- 布尔盲注流量分析的核心：找到 True/False 响应的区分特征（长度/内容/状态码）
- 每个请求独立 TCP 连接时，用源端口关联请求-响应对
