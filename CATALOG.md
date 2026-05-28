# Challenge Catalog

> Comprehensive index of CTF challenges and fundamental notes I have worked through. The **English deep writeups** for representative problems are in the `pwn/`, `reverse/`, `crypto/`, `web/`, and `forensics/` directories of this repository — see the main [README.md](README.md) for the curated list.
>
> This catalog records the full breadth of practice (~300 entries). Most were originally documented as personal study notes in Chinese (archived locally). They are listed here to show training history. Entries marked as fundamentals are knowledge-base notes (stack frame, glibc internals, PLT/GOT) rather than per-challenge writeups.

---

## Pwn — Binary Exploitation (75 entries)

- **32位程序与64位程序运行时栈帧分布区别** — `Pwn/32位程序与64位程序运行时栈帧分布区别.md` (162 lines)
- **Linux系统调用号表** — `Pwn/Linux系统调用号表.md` (739 lines)
- **PWN的基础知识** — `Pwn/PLT表与GOT表.md` (181 lines)
- **二进制的保护机制** — `Pwn/二进制的保护机制：.md` (161 lines)
- **堆题目的一些基础函数** — `Pwn/堆题目的一些基础函数.md` (340 lines)
- **栈（Stack）的工作原理：** — `Pwn/栈（Stack）的工作原理：.md` (96 lines)
- **格式化字符串原理介绍** — `Pwn/格式化字符串原理介绍.md` (989 lines)
- **格式化字符串漏洞** — `Pwn/格式化字符串漏洞.md` (227 lines)
- **格式化字符串漏洞基础** — `Pwn/格式化字符串漏洞基础.md` (338 lines)
- **常见的ubuntu中的ld与libc收集** — `Pwn/ubuntu_libc_ld-master/readme.md` (41 lines)
- **writeup** — `Pwn/actf_2019_babystack/writeup.md` (91 lines)
- **writeup** — `Pwn/babyheap_actf_2019/writeup.md` (92 lines)
- **Search libc function offset** — `Pwn/LibcSearcher/README.md` (38 lines)
- **main_arena_offset** — `Pwn/main_arena_offset-master/README.md` (42 lines)
- **writeup** — `Pwn/suctf_2018_stack/writeup.md` (56 lines)
- **axb_2019_brop64 — 解题笔记** — `Pwn/BUUCTF/axb_2019_brop64/notes.md` (230 lines)
- **axb_2019_brop64 — 分析 & 调试复盘** — `Pwn/BUUCTF/axb_2019_brop64/writeup.md` (210 lines)
- **axb_2019_heap 解题过程复盘** — `Pwn/BUUCTF/axb_2019_heap/axb_2019_heap_writeup.md` (271 lines)
- **babyheap_0ctf_2017** — `Pwn/BUUCTF/babyheap_0ctf_2017/babyheap_0ctf_2017.md` (689 lines)
- **babyheap_0ctf_2017** — `Pwn/BUUCTF/babyheap_0ctf_2017/babyheap_0ctf_2017_重新整理.md` (670 lines)
- **jarvisoj_tell_me_something** — `Pwn/BUUCTF/jarvisoj_tell_me_something/jarvisoj_tell_me_something.md` (54 lines)
- **jarvisoj_test_your_memory** — `Pwn/BUUCTF/jarvisoj_test_your_memory/jarvisoj_test_your_memory.md` (79 lines)
- **[mrctf2020_shellcode](D:\Security\Pwn\BUUCTF\mrctf2020_shellcode\mrctf2020_shellcode) ** — `Pwn/BUUCTF/mrctf2020_shellcode/mrctf2020_shellcode.md` (305 lines)
- **not_the_same_3dsctf_2016** — `Pwn/BUUCTF/not_the_same_3dsctf_2016/not_the_same_3dsctf_2016.md` (161 lines)
- **npuctf_2020_easyheap — 解题笔记** — `Pwn/BUUCTF/npuctf_2020_easyheap/notes.md` (294 lines)
- **npuctf_2020_easyheap — 分析 & 调试复盘** — `Pwn/BUUCTF/npuctf_2020_easyheap/writeup.md` (229 lines)
- **others_shellcode** — `Pwn/BUUCTF/others_shellcode/others_shellcode.md` (68 lines)
- **picoctf_2018_buffer overflow 1** — `Pwn/BUUCTF/picoctf_2018_buffer overflow 1/picoctf_2018_buffer overflow 1.md` (55 lines)
- **picoctf_2018_rop chain** — `Pwn/BUUCTF/picoctf_2018_rop chain/picoctf_2018_rop chain.md` (68 lines)
- **bjdctf_2020_babyrop** — `Pwn/BUUCTF/bjdctf_2020_babyrop/bjdctf_2020_babyrop.md` (174 lines)
- **bjdctf_2020_babyrop2** — `Pwn/BUUCTF/bjdctf_2020_babyrop2/bjdctf_2020_babyrop2.md` (245 lines)
- **bjdctf_2020_babystack** — `Pwn/BUUCTF/bjdctf_2020_babystack/bjdctf_2020_babystack.md` (36 lines)
- **bjdctf_2020_babystack2** — `Pwn/BUUCTF/bjdctf_2020_babystack2/bjdctf_2020_babystack2.md` (70 lines)
- **bjdctf_2020_router** — `Pwn/BUUCTF/bjdctf_2020_router/bjdctf_2020_router.md` (55 lines)
- **ciscn_2019_c_1** — `Pwn/BUUCTF/ciscn_2019_c_1/ciscn_2019_c_1.md` (206 lines)
- **ciscn_2019_en_2** — `Pwn/BUUCTF/ciscn_2019_en_2/ciscn_2019_en_2.md` (88 lines)
- **ciscn_2019_es_2** — `Pwn/BUUCTF/ciscn_2019_es_2/ciscn_2019_es_2.md` (496 lines)
- **inndy_rop** — `Pwn/BUUCTF/inndy_rop/inndy_rop.md` (429 lines)
- **jarvisoj_fm** — `Pwn/BUUCTF/jarvisoj_fm/jarvisoj_fm.md` (84 lines)
- **jarvisoj_level0** — `Pwn/BUUCTF/jarvisoj_level0/jarvisoj_level0.md` (50 lines)
- **jarvisoj_level2** — `Pwn/BUUCTF/jarvisoj_level2/jarvisoj_level2.md` (55 lines)
- **jarvisoj_level2_x64** — `Pwn/BUUCTF/jarvisoj_level2_x64/jarvisoj_level2_x64.md` (53 lines)
- **jarvisoj_level3** — `Pwn/BUUCTF/jarvisoj_level3/jarvisoj_level3.md` (138 lines)
- **jarvisoj_level3_x64** — `Pwn/BUUCTF/jarvisoj_level3_x64/jarvisoj_level3_x64.md` (278 lines)
- **jarvisoj_level4** — `Pwn/BUUCTF/jarvisoj_level4/jarvisoj_level4.md` (105 lines)
- **ciscn_2019_ne_5** — `Pwn/BUUCTF/ciscn_2019_ne_5/ciscn_2019_ne_5.md` (79 lines)
- **ciscn_2019_n_1** — `Pwn/BUUCTF/ciscn_2019_n_1/ciscn_2019_n_1.md` (111 lines)
- **ciscn_2019_n_3 — Writeup** — `Pwn/BUUCTF/ciscn_2019_n_3/writeup.md` (133 lines)
- **ciscn_2019_n_5** — `Pwn/BUUCTF/ciscn_2019_n_5/ciscn_2019_n_5.md` (176 lines)
- **ciscn_2019_n_8** — `Pwn/BUUCTF/ciscn_2019_n_8/ciscn_2019_n_8.md` (44 lines)
- **ciscn_2019_s_3** — `Pwn/BUUCTF/ciscn_2019_s_3/ciscn_2019_s_3.md` (401 lines)
- **ez_pz_hackover_2016** — `Pwn/BUUCTF/ez_pz_hackover_2016/ez_pz_hackover_2016.md` (181 lines)
- **get_started_3dsctf_2016** — `Pwn/BUUCTF/get_started_3dsctf_2016/get_started_3dsctf_2016.md` (210 lines)
- **[HarekazeCTF2019]baby_rop2** — `Pwn/BUUCTF/[HarekazeCTF2019]baby_rop2/[HarekazeCTF2019]baby_rop2.md` (243 lines)
- **[OGeek2019]babyrop** — `Pwn/BUUCTF/[OGeek2019]babyrop/[OGeek2019]babyrop.md` (183 lines)
- **[ZJCTF 2019]EasyHeap** — `Pwn/BUUCTF/[ZJCTF 2019]EasyHeap/[ZJCTF 2019]EasyHeap.md` (378 lines)
- **[第五空间2019 决赛]PWN5** — `Pwn/BUUCTF/[第五空间2019 决赛]PWN5/[第五空间2019 决赛]PWN5.md` (115 lines)
- **铁人三项(第五赛区)_2018_rop** — `Pwn/BUUCTF/铁人三项(第五赛区)_2018_rop/铁人三项(第五赛区)_2018_rop.md` (65 lines)
- **README** — `Pwn/LibcSearcher/libc-database/README.md` (42 lines)
- **[pwn1_sctf_2016](D:\Security\Pwn\BUUCTF\pwn1_sctf_2016\pwn1_sctf_2016) ** — `Pwn/BUUCTF/pwn1_sctf_2016/pwn1_sctf_2016.md` (55 lines)
- **pwn2_sctf_2016** — `Pwn/BUUCTF/pwn2_sctf_2016/pwn2_sctf_2016.md` (173 lines)
- **rip 1** — `Pwn/BUUCTF/rip/rip 1.md` (136 lines)
- **warmup_csaw_2016** — `Pwn/BUUCTF/warmup_csaw_2016/warmup_csaw_2016.md` (69 lines)
- **wustctf2020_getshell** — `Pwn/BUUCTF/wustctf2020_getshell/wustctf2020_getshell.md` (64 lines)
- **[HarekazeCTF2019]baby_rop** — `Pwn/BUUCTF/[HarekazeCTF2019]baby_rop/[HarekazeCTF2019]baby_rop.md` (51 lines)
- **[actf_2019_babyheap]** — `pwn/actf_2019_babyheap.md` (~50 lines) — BUUCTF / glibc 2.27 UAF + tcache reuse + printf %s GOT leak + system@PLT
- **[actf_2019_babystack]** — `pwn/actf_2019_babystack.md` (~32 lines) — BUUCTF / 栈迁移 ret2libc, 16 字节溢出 + 栈地址泄露 + leave;ret pivot
- **[ciscn_2019_n_3]** — `pwn/ciscn_2019_n_3.md` (~71 lines) — BUUCTF / 32-bit tcache UAF, strbuf 覆盖旧 record 函数指针 → system("sh;#")
- **[ciscn_2019_final_2]** — `pwn/ciscn_2019_final_2.md` (~120 lines) — BUUCTF / 64-bit glibc 2.27 type-switch UAF + tcache poison → 改 `stdin->_fileno = 666` 让 scanf 读 flag
- **[ciscn_2019_c_3]** — `pwn/ciscn_2019_c_3.md` (~110 lines) — BUUCTF / 64-bit glibc 2.27 / 9-slot UAF + selfloop 填 tcache（同 chunk free 7 次自指）+ 第 8 次进 unsorted bin leak libc + backdoor 累加器伪造 fd → `__free_hook = one_gadget`
- **[ciscn_2019_c_5]** — `pwn/ciscn_2019_c_5.md` (~110 lines) — BUUCTF / 64-bit glibc 2.27 Full RELRO + FORTIFY / `__printf_chk(1, user_buf)` 格式串 leak（第 7 个 %p = `_IO_2_1_stderr_`）+ tcache double-free (libc 2.27 无 key 检查) → `__free_hook = system` + `free("/bin/sh")`
- **[wustctf2020_babyfmt]** — `pwn/wustctf2020_babyfmt.md` (~180 lines) — BUUCTF / 64-bit glibc 2.23 fmt 漏洞 4 步链：%hhn reset single-shot bool + %p leak PIE/libc + %s 读 secret + 改 `stdout->_fileno=2` 突破 close(1)+open(/flag) 陷阱
- **[npuctf_2020_easyheap]** — `pwn/npuctf_2020_easyheap.md` (~50 lines) — BUUCTF / off-by-one overlapping ×2 (leak + write) + __free_hook
- **[suctf_2018_stack]** — `pwn/suctf_2018_stack.md` (~27 lines) — BUUCTF / 经典 ret2win 后门 system("/bin/sh") + +1 栈对齐
- **[hwb_2019_mergeheap]** — `pwn/hwb_2019_mergeheap.md` (~115 lines) — BUUCTF / 2019 强网杯 / glibc 2.27 / size ≤ 0x400 强制 "fill 7 tcache then unsorted" 套路 / `merge` 不清原指针 → overlapping chunks / tcache poison → `__free_hook = one_gadget` getshell

## Reverse Engineering (57 entries)

- **[长城杯三 2025] vvvmmm** — `reverse/changcheng3_vvvmmm.md` (~270 lines) — UPX-packed + Unicorn-embedded RISC-V VM; hardcoded-key polynomial hash drives 12 stream words XOR'd with the 48-byte user input; the trap is `UC_RISCV_REG_X10 = 11 = a0` (not `a1`). Detailed Chinese debug-log version at `Reverse/第三届"长城杯"初赛-vvvmmm/WRITEUP_CN.md`
- **[2019红帽杯]easyRE** — `Reverse/BUUCTF/[2019红帽杯]easyRE.md` (107 lines)
- **解题过程** — `Reverse/BUUCTF/helloword/helloworld.md` (27 lines)
- **crackMe** — `Reverse/BUUCTF/crackMe/crackMe.md` (18 lines)
- **解题过程** — `Reverse/BUUCTF/CrackRTF/CrackRTF.md` (111 lines)
- **解题过程** — `Reverse/BUUCTF/findit/findit.md` (52 lines)
- **解题过程** — `Reverse/BUUCTF/[ACTF新生赛2020]easyre/[ACTF新生赛2020]easyre.md` (46 lines)
- **[ACTF新生赛2020]Oruga** — `Reverse/BUUCTF/[ACTF新生赛2020]Oruga/[ACTF新生赛2020]Oruga.md` (111 lines)
- **解题过程** — `Reverse/BUUCTF/[ACTF新生赛2020]rome/[ACTF新生赛2020]rome.md` (60 lines)
- **[ACTF新生赛2020]Universe_final_answer** — `Reverse/BUUCTF/[ACTF新生赛2020]Universe_final_answer/[ACTF新生赛2020]Universe_final_answer.md` (84 lines)
- **[ACTF新生赛2020]usualCrypt** — `Reverse/BUUCTF/[ACTF新生赛2020]usualCrypt/[ACTF新生赛2020]usualCrypt.md` (88 lines)
- **解题过程** — `Reverse/BUUCTF/[BJDCTF2020]JustRE/[BJDCTF2020]JustRE.md` (54 lines)
- **[UTCTF2020]basic-re** — `Reverse/BUUCTF/[UTCTF2020]basic-re/[UTCTF2020]basic-re.md` (14 lines)
- **[WMCTF 2020] easy_re 逆向分析 writeup** — `Reverse/BUUCTF/[WMCTF2020]easy_re/writeup.md` (412 lines)
- **[WUSTCTF2020]Cr0ssfun** — `Reverse/BUUCTF/[WUSTCTF2020]Cr0ssfun/[WUSTCTF2020]Cr0ssfun.md` (67 lines)
- **解题过程** — `Reverse/BUUCTF/[WUSTCTF2020]level1/[WUSTCTF2020]level1.md` (33 lines)
- **[WUSTCTF2020]level2** — `Reverse/BUUCTF/[WUSTCTF2020]level2/[WUSTCTF2020]level2.md` (20 lines)
- **[WUSTCTF2020]level3** — `Reverse/BUUCTF/[WUSTCTF2020]level3/[WUSTCTF2020]level3.md` (84 lines)
- **[WUSTCTF2020]level4** — `Reverse/BUUCTF/[WUSTCTF2020]level4/[WUSTCTF2020]level4.md` (110 lines)
- **[FlareOn3]Challenge1** — `Reverse/BUUCTF/[FlareOn3]Challenge1/[FlareOn3]Challenge1.md` (38 lines)
- **[FlareOn4]IgniteMe** — `Reverse/BUUCTF/[FlareOn4]IgniteMe/[FlareOn4]IgniteMe.md` (62 lines)
- **解题过程** — `Reverse/BUUCTF/[FlareOn4]login/[FlareOn4]login.md` (34 lines)
- **[FlareOn6]Overlong** — `Reverse/BUUCTF/[FlareOn6]Overlong/[FlareOn6]Overlong.md` (192 lines)
- **[GUET-CTF2019] encrypt 逆向分析 writeup** — `Reverse/BUUCTF/[GUET-CTF2019]encrypt/writeup.md` (260 lines)
- **[GUET-CTF2019]number_game** — `Reverse/BUUCTF/[GUET-CTF2019]number_game/[GUET-CTF2019]number_game.md` (184 lines)
- **解题过程** — `Reverse/BUUCTF/[GUET-CTF2019]re/[GUET-CTF2019]re.md` (162 lines)
- **解题过程** — `Reverse/BUUCTF/[GWCTF 2019]pyre/[GWCTF 2019]pyre.md` (101 lines)
- **[Zer0pts2020]easy strcmp** — `Reverse/BUUCTF/[Zer0pts2020]easy strcmp/[Zer0pts2020]easy strcmp.md` (59 lines)
- **[网鼎杯 2020 青龙组]bang** — `Reverse/BUUCTF/[网鼎杯 2020 青龙组]bang/[网鼎杯 2020 青龙组]bang.md` (58 lines)
- **[网鼎杯 2020 青龙组]boom** — `Reverse/BUUCTF/[网鼎杯 2020 青龙组]boom/[网鼎杯 2020 青龙组]boom.md` (78 lines)
- **[网鼎杯 2020 青龙组]jocker  re** — `Reverse/BUUCTF/[网鼎杯 2020 青龙组]jocker/[网鼎杯 2020 青龙组]jocker  re.md` (320 lines)
- **[网鼎杯 2020 青龙组]singal 解法2** — `Reverse/BUUCTF/[网鼎杯 2020 青龙组]singal/[网鼎杯 2020 青龙组]singal 解法2.md` (311 lines)
- **[网鼎杯 2020 青龙组]singal** — `Reverse/BUUCTF/[网鼎杯 2020 青龙组]singal/[网鼎杯 2020 青龙组]singal.md` (162 lines)
- **[羊城杯 2020]easyre** — `Reverse/BUUCTF/[羊城杯 2020]easyre/[羊城杯 2020]easyre.md` (68 lines)
- **解题过程** — `Reverse/BUUCTF/不一样的flag/不一样的flag.md` (33 lines)
- **[GWCTF 2019]re3** — `Reverse/BUUCTF/[GWCTF 2019]re3/[GWCTF 2019]re3.md` (178 lines)
- **[GWCTF 2019]xxor** — `Reverse/BUUCTF/[GWCTF 2019]xxor/[GWCTF 2019]xxor.md` (135 lines)
- **解题过程** — `Reverse/BUUCTF/[GXYCTF2019]luck_guy/[GXYCTF2019]luck_guy.md` (75 lines)
- **[MRCTF2020]hello_world_go** — `Reverse/BUUCTF/[MRCTF2020]hello_world_go/[MRCTF2020]hello_world_go.md` (34 lines)
- **[MRCTF2020]Transform** — `Reverse/BUUCTF/[MRCTF2020]Transform/[MRCTF2020]Transform.md` (86 lines)
- **[MRCTF2020]Xor** — `Reverse/BUUCTF/[MRCTF2020]Xor/[MRCTF2020]Xor.md` (103 lines)
- **[SCTF2019] creakme — Writeup** — `Reverse/BUUCTF/[SCTF2019]creakme/writeup.md` (426 lines)
- **[SUCTF2019]SignIn** — `Reverse/BUUCTF/[SUCTF2019]SignIn/[SUCTF2019]SignIn.md` (60 lines)
- **解题过程** — `Reverse/BUUCTF/Java逆向解密/Java逆向解密.md` (55 lines)
- **解题过程** — `Reverse/BUUCTF/reverse1/reverse1.md` (58 lines)
- **解题过程** — `Reverse/BUUCTF/reverse2/reverse2.md` (36 lines)
- **解题过程：** — `Reverse/BUUCTF/reverse2/内涵的软件.md` (29 lines)
- **解题过程** — `Reverse/BUUCTF/reverse3/reverse3.md` (62 lines)
- **解题过程** — `Reverse/BUUCTF/rsa/rsa.md` (87 lines)
- **解题过程** — `Reverse/BUUCTF/SimpleRev/SimpleRev.md` (90 lines)
- **解题过程：** — `Reverse/BUUCTF/xor/xor.md` (66 lines)
- **Youngter-drive** — `Reverse/BUUCTF/Youngter-drive/Youngter-drive.md` (53 lines)
- **解题过程** — `Reverse/BUUCTF/刮开有奖/刮开有奖.md` (137 lines)
- **解题过程** — `Reverse/BUUCTF/新年快乐/新年快乐.md` (29 lines)
- **特殊的 BASE64** — `Reverse/BUUCTF/特殊的 BASE64/特殊的 BASE64.md` (30 lines)
- **相册** — `Reverse/BUUCTF/相册/相册.md` (42 lines)
- **解题过程** — `Reverse/BUUCTF/简单注册器/简单注册器.md` (47 lines)

## Web Exploitation (185 entries)

- **babyweb** — `Web/BUUCTF/babyweb.md` (32 lines)
- **SSRF Me** — `Web/BUUCTF/SSRF Me.md` (184 lines)
- **warmup** — `Web/BUUCTF/warmup.md` (306 lines)
- **[BJDCTF2020]Cookie is so stable** — `Web/BUUCTF/[BJDCTF2020]Cookie is so stable.md` (94 lines)
- **[BJDCTF2020]EzPHP** — `Web/BUUCTF/[BJDCTF2020]EzPHP.md` (321 lines)
- **[BJDCTF2020]Mark loves cat** — `Web/BUUCTF/[BJDCTF2020]Mark loves cat.md` (199 lines)
- **[BJDCTF2020]The mystery of ip** — `Web/BUUCTF/[BJDCTF2020]The mystery of ip.md` (68 lines)
- **[BJDCTF2020]ZJCTF，不过如此** — `Web/BUUCTF/[BJDCTF2020]ZJCTF，不过如此.md` (124 lines)
- **[BUUCTF 2018]Online Tool** — `Web/BUUCTF/[BUUCTF 2018]Online.md` (85 lines)
- **[De1CTF 2019]SSRF Me** — `Web/BUUCTF/[De1CTF 2019]SSRF Me.md` (366 lines)
- **[GWCTF 2019]我有一个数据库** — `Web/BUUCTF/[GWCTF 2019]我有一个数据库.md` (41 lines)
- **[GXYCTF2019]禁止套娃** — `Web/BUUCTF/[GXYCTF2019]禁止套娃.md` (145 lines)
- **[GYCTF2020]EasyThinking** — `Web/BUUCTF/[GYCTF2020]EasyThinking.md` (162 lines)
- **[ISITDTU 2019]EasyPHP** — `Web/BUUCTF/[ISITDTU 2019]EasyPHP.md` (246 lines)
- **[MRCTF2020]Ezpop** — `Web/BUUCTF/[MRCTF2020]Ezpop.md` (219 lines)
- **[NCTF2019]Fake XML cookbook** — `Web/BUUCTF/[NCTF2019]Fake XML cookbook.md` (210 lines)
- **[NPUCTF2020]ReadlezPHP** — `Web/BUUCTF/[NPUCTF2020]ReadlezPHP.md` (75 lines)
- **[SWPUCTF 2018]SimplePHP** — `Web/BUUCTF/[SWPUCTF 2018]SimplePHP.md` (339 lines)
- **[WUSTCTF2020]朴实无华** — `Web/BUUCTF/[WUSTCTF2020]朴实无华.md` (116 lines)
- **[安洵杯 2019]easy_serialize_php** — `Web/BUUCTF/[安洵杯 2019]easy_serialize_php.md` (244 lines)
- **[安洵杯 2019]easy_web** — `Web/BUUCTF/[安洵杯 2019]easy_web.md` (94 lines)
- **[强网杯 2019]高明的黑客** — `Web/BUUCTF/[强网杯 2019]高明的黑客.md` (152 lines)
- **解题过程** — `Web/BUUCTF/[极客大挑战 2019]Http.md` (47 lines)
- **[网鼎杯 2018]Comment** — `Web/BUUCTF/[网鼎杯 2018]Comment.md` (286 lines)
- **[网鼎杯 2018]Fakebook** — `Web/BUUCTF/[网鼎杯 2018]Fakebook.md` (188 lines)
- **[网鼎杯 2020 半决赛]AliceWebsite** — `Web/BUUCTF/[网鼎杯 2020 半决赛]AliceWebsite.md` (93 lines)
- **[网鼎杯 2020 朱雀组]Nmap** — `Web/BUUCTF/[网鼎杯 2020 朱雀组]Nmap.md` (203 lines)
- **[网鼎杯 2020 朱雀组]phpweb** — `Web/BUUCTF/[网鼎杯 2020 朱雀组]phpweb.md` (107 lines)
- **[网鼎杯 2020 白虎组]PicDown** — `Web/BUUCTF/[网鼎杯 2020 白虎组]PicDown.md` (219 lines)
- **[网鼎杯 2020 青龙组]AreUSerialz** — `Web/BUUCTF/[网鼎杯 2020 青龙组]AreUSerialz.md` (209 lines)
- **浅谈PHP代码执行中出现过滤限制的绕过执行方法** — `Web/BUUCTF/浅谈PHP代码执行中出现过滤限制的绕过执行方法.md` (603 lines)
- **ctf** — `Web/ctf-master/README.md` (2 lines)
- **SQL-inject** — `Web/SQL/SQL-inject.md` (128 lines)
- **[CISCN2019 华北赛区 Day2 Web1]Hack World** — `Web/SQL/[CISCN2019 华北赛区 Day2 Web1]Hack World.md` (58 lines)
- **[GXYCTF2019]BabySQli** — `Web/SQL/[GXYCTF2019]BabySQli.md` (136 lines)
- **[GYCTF2020]Blacklist** — `Web/SQL/[GYCTF2020]Blacklist.md` (90 lines)
- **[极客大挑战 2019]HardSQL** — `Web/SQL/[极客大挑战 2019]HardSQL.md` (98 lines)
- **[玄武杯 2025] ez_fastapi Writeup** — `Web/NSSCTF/[玄武杯 2025]ez_fastapi/writeup.md` (98 lines)
- **[玄武杯 2025] 锦家有什么 — Writeup** — `Web/NSSCTF/[玄武杯 2025]锦家有什么/writeup.md` (61 lines)
- **[羊城杯 2020] Break The Wall** — `Web/BUUCTF/[羊城杯 2020]Break The Wall/writeup.md` (108 lines)
- **解题过程** — `Web/BUUCTF/代码审计/[ACTF2020 新生赛]Include.md` (28 lines)
- **解题过程** — `Web/BUUCTF/代码审计/[BJDCTF2020]Easy MD5].md` (101 lines)
- **解题过程** — `Web/BUUCTF/代码审计/[极客大挑战 2019]PHP.md` (81 lines)
- **解题过程：** — `Web/BUUCTF/代码审计/[极客大挑战 2019]Secret File.md` (41 lines)
- **[BSidesCF 2020]Had a bad day** — `Web/BUUCTF/伪协议/[BSidesCF 2020]Had a bad day.md` (70 lines)
- **解题过程** — `Web/BUUCTF/命令执行/[ACTF2020 新生赛]Exec.md` (29 lines)
- **解题过程** — `Web/BUUCTF/命令执行/[GXYCTF2019]Ping Ping Ping.md` (101 lines)
- **解题过程** — `Web/BUUCTF/文件上传/[ACTF2020 新生赛]Upload.md` (39 lines)
- **解题过程** — `Web/BUUCTF/文件上传/[极客大挑战 2019]Upload.md` (65 lines)
- **解题过程** — `Web/BUUCTF/路径构造/[HCTF 2018]WarmUp.md` (142 lines)
- **[DASCTF 2023 & 0X401七月暑期挑战赛] EzFlask** — `Web/BUUCTF/[DASCTF 2023 & 0X401七月暑期挑战赛]EzFlask/writeup.md` (109 lines)
- **[NewStarCTF 2023 公开赛道]medium_sql** — `Web/BUUCTF/[NewStarCTF 2023 公开赛道]medium_sql/writeup.md` (119 lines)
- **[NPUCTF2020]验证🐎** — `Web/BUUCTF/[NPUCTF2020]验证码/writeup.md` (157 lines)
- **[网鼎杯 2020 玄武组]SSRFMe** — `Web/BUUCTF/[网鼎杯 2020 玄武组]SSRFMe/writeup.md` (158 lines)
- **[网鼎杯 2020 白虎组] PicDown** — `Web/BUUCTF/[网鼎杯 2020 白虎组]PicDown/writeup.md` (109 lines)
- **[GHCTF 2025] ez_readfile — Writeup** — `Web/NSSCTF/[GHCTF 2025]ez_readfile/writeup.md` (85 lines)
- **[GHCTF 2025] SQL — Writeup** — `Web/NSSCTF/[GHCTF 2025]SQL/writeup.md` (97 lines)
- **[LitCTF 2025] easy_file — Writeup** — `Web/NSSCTF/[LitCTF 2025]easy_file/writeup.md` (173 lines)
- **[LitCTF 2025] nest_js — Writeup** — `Web/NSSCTF/[LitCTF 2025]nest_js/writeup.md` (83 lines)
- **[LitCTF 2025] 多重宇宙日记 — Writeup** — `Web/NSSCTF/[LitCTF 2025]多重宇宙日记/writeup.md` (78 lines)
- **[LitCTF 2025] 星愿信箱 — Writeup** — `Web/NSSCTF/[LitCTF 2025]星愿信箱/writeup.md` (83 lines)
- **[SWPUCTF 2025 秋季新生赛] sql仅仅只是sql吗？** — `Web/NSSCTF/[SWPUCTF 2025 秋季新生赛]sql仅仅只是sql吗？/writeup.md` (166 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/README.md` (52 lines)
- **解题过程** — `Web/BUUCTF/SQL/[SUCTF 2019]EasySQL.md` (72 lines)
- **做题过程** — `Web/BUUCTF/SQL/[强网杯 2019]随便注.md` (133 lines)
- **解题过程** — `Web/BUUCTF/SQL/[极客大挑战 2019]BabySQL.md` (74 lines)
- **知识点：MySQL中单引号、双引号的区别** — `Web/BUUCTF/SQL/[极客大挑战 2019]EasySQL1.md` (101 lines)
- **解题过程** — `Web/BUUCTF/SQL/[极客大挑战 2019]LoveSQL2.md` (75 lines)
- **[CISCN2019 华东南赛区] Double Secret** — `Web/BUUCTF/[CISCN2019 华东南赛区]Double Secret/writeup.md` (154 lines)
- **[CISCN2019 华北赛区 Day1 Web1] Dropbox** — `Web/BUUCTF/[CISCN2019 华北赛区 Day1 Web1]Dropbox/writeup.md` (156 lines)
- **[CISCN2019 总决赛 Day2 Web1] Easyweb** — `Web/BUUCTF/[CISCN2019 总决赛 Day2 Web1]Easyweb/writeup.md` (125 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/view/README.md` (0 lines)
- **think-trace** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/think-trace/README.md` (14 lines)
- **think-view** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/think-view/README.md` (35 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/symfony/polyfill-mbstring/README.md` (13 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/symfony/polyfill-php72/README.md` (27 lines)
- **CHANGELOG** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/symfony/var-dumper/CHANGELOG.md` (53 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/symfony/var-dumper/README.md` (15 lines)
- **CONTRIBUTING** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/CONTRIBUTING.md` (119 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/README.md` (86 lines)
- **thinkphp6 常用的一些扩展类库** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/think-helper/README.md` (32 lines)
- **think-multi-app** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/think-multi-app/README.md` (14 lines)
- **ThinkORM** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/think-orm/README.md` (27 lines)
- **ThinkTemplate** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/think-template/README.md` (69 lines)
- **Deprecations** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/league/flysystem/deprecations.md` (19 lines)
- **Security Policy** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/league/flysystem/SECURITY.md` (16 lines)
- **Flysystem Cached CachedAdapter** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/league/flysystem-cached-adapter/readme.md` (20 lines)
- **CHANGELOG** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/opis/closure/CHANGELOG.md` (220 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/opis/closure/README.md` (97 lines)
- **Changelog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/psr/cache/CHANGELOG.md` (16 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/psr/cache/README.md` (9 lines)
- **PSR Container** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/psr/container/README.md` (5 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/psr/log/README.md` (58 lines)
- **The MIT License (MIT)** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/psr/simple-cache/LICENSE.md` (21 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/psr/simple-cache/README.md` (8 lines)
- **ThinkORM** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/topthink/think-orm/README.md` (27 lines)
- **CHANGELOG** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/webmozart/assert/CHANGELOG.md` (131 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/webmozart/assert/README.md` (276 lines)
- **Changes in php-code-coverage 6.1** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-code-coverage/ChangeLog-6.1.md` (41 lines)
- **SebastianBergmann\CodeCoverage** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-code-coverage/README.md` (40 lines)
- **Change Log** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-file-iterator/ChangeLog.md` (70 lines)
- **php-file-iterator** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-file-iterator/README.md` (14 lines)
- **Text_Template** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-text-template/README.md` (14 lines)
- **ChangeLog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-timer/ChangeLog.md` (36 lines)
- **phpunit/php-timer** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-timer/README.md` (49 lines)
- **Change Log** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-token-stream/ChangeLog.md` (57 lines)
- **php-token-stream** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-token-stream/README.md` (14 lines)
- **Changes in PHPUnit 7.5** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/phpunit/ChangeLog-7.5.md` (195 lines)
- **PHPUnit** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/phpunit/README.md` (40 lines)
- **Changelog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/psr/cache/CHANGELOG.md` (16 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/psr/cache/README.md` (9 lines)
- **PSR Container** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/psr/container/README.md` (5 lines)
- **Change Log** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/object-enumerator/ChangeLog.md` (53 lines)
- **Object Enumerator** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/object-enumerator/README.md` (14 lines)
- **Change Log** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/object-reflector/ChangeLog.md` (20 lines)
- **Object Reflector** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/object-reflector/README.md` (14 lines)
- **Recursion Context** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/recursion-context/README.md` (14 lines)
- **ChangeLog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/resource-operations/ChangeLog.md` (26 lines)
- **Resource Operations** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/resource-operations/README.md` (14 lines)
- **Version** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/version/README.md` (43 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/symfony/polyfill-ctype/README.md` (12 lines)
- **Changelog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/theseer/tokenizer/CHANGELOG.md` (32 lines)
- **Tokenizer** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/theseer/tokenizer/README.md` (49 lines)
- **thinkphp6 常用的一些扩展类库** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/topthink/think-helper/README.md` (32 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/psr/log/README.md` (58 lines)
- **The MIT License (MIT)** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/psr/simple-cache/LICENSE.md` (21 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/psr/simple-cache/README.md` (8 lines)
- **Change Log** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/code-unit-reverse-lookup/ChangeLog.md` (10 lines)
- **code-unit-reverse-lookup** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/code-unit-reverse-lookup/README.md` (14 lines)
- **ChangeLog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/comparator/ChangeLog.md` (59 lines)
- **Comparator** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/comparator/README.md` (37 lines)
- **ChangeLog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/diff/ChangeLog.md` (53 lines)
- **sebastian/diff** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/diff/README.md` (195 lines)
- **Changes in sebastianbergmann/environment** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/environment/ChangeLog.md` (120 lines)
- **sebastian/environment** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/environment/README.md` (17 lines)
- **ChangeLog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/exporter/ChangeLog.md` (15 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/exporter/README.md` (171 lines)
- **GlobalState** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/sebastian/global-state/README.md` (16 lines)
- **CONTRIBUTING** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-code-coverage/.github/CONTRIBUTING.md` (1 lines)
- **ISSUE_TEMPLATE** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/php-code-coverage/.github/ISSUE_TEMPLATE.md` (18 lines)
- **Contributing** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/doctrine/instantiator/CONTRIBUTING.md` (35 lines)
- **Instantiator** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/doctrine/instantiator/README.md` (39 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/hamcrest/hamcrest-php/README.md` (53 lines)
- **Deprecations** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/league/flysystem/deprecations.md` (19 lines)
- **Security Policy** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/league/flysystem/SECURITY.md` (16 lines)
- **Flysystem Cached CachedAdapter** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/league/flysystem-cached-adapter/readme.md` (20 lines)
- **CHANGELOG** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/mikey179/vfsstream/CHANGELOG.md` (247 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/mikey179/vfsstream/README.md` (8 lines)
- **Change Log** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/mockery/mockery/CHANGELOG.md` (135 lines)
- **Contributing** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/mockery/mockery/CONTRIBUTING.md` (88 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/mockery/mockery/README.md` (284 lines)
- **DeepCopy** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/myclabs/deep-copy/README.md` (375 lines)
- **CHANGELOG** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/opis/closure/CHANGELOG.md` (220 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/opis/closure/README.md` (97 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/src/think/console/bin/README.md` (1 lines)
- **Manifest** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phar-io/manifest/README.md` (30 lines)
- **Changelog** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phar-io/version/CHANGELOG.md` (44 lines)
- **Version** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phar-io/version/README.md` (61 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpdocumentor/reflection-common/README.md` (12 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpdocumentor/reflection-docblock/README.md` (67 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpdocumentor/type-resolver/README.md` (179 lines)
- **CHANGES** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpspec/prophecy/CHANGES.md` (243 lines)
- **Prophecy** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpspec/prophecy/README.md` (402 lines)
- **Contributor Code of Conduct** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/phpunit/.github/CODE_OF_CONDUCT.md` (28 lines)
- **Contributing to PHPUnit** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/phpunit/.github/CONTRIBUTING.md` (68 lines)
- **ISSUE_TEMPLATE** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/phpunit/phpunit/.github/ISSUE_TEMPLATE.md` (15 lines)
- **README** — `Web/BUUCTF/[GYCTF2020]EasyThinking/web/vendor/topthink/framework/vendor/mockery/mockery/docs/README.md` (3 lines)
- **[ciscn2019_double_secret]** — `web/ciscn2019_double_secret.md` (~47 lines) — CISCN 2019 华东南 / Flask RC4 解密 + Jinja2 SSTI RCE
- **[ciscn2019_easyweb]** — `web/ciscn2019_easyweb.md` (~53 lines) — CISCN 2019 总决赛 / \0 吃引号 SQLi + Cookie XOR 伪造 + Client-IP 日志写 Shell
- **[ghctf2025_ez_readfile]** — `web/ghctf2025_ez_readfile.md` (~42 lines) — GHCTF 2025 / MD5 强碰撞 + 文件读取 + docker-entrypoint 信息收集
- **[ghctf2025_sql]** — `web/ghctf2025_sql.md` (~45 lines) — GHCTF 2025 / SQL 注入 + WAF 绕过 / 直接猜 flag 表/列
- **[litctf2025_easy_file]** — `web/litctf2025_easy_file.md` (~95 lines) — LitCTF 2025 / PHP LFI + 上传 / 黑名单静默 + <?= 短标签绕过
- **[litctf2025_multiverse_diary]** — `web/litctf2025_multiverse_diary.md` (~72 lines) — LitCTF 2025 / Express 原型污染 isAdmin 提权
- **[litctf2025_nest_js]** — `web/litctf2025_nest_js.md` (~49 lines) — LitCTF 2025 / Next.js 弱口令 + JS bundle flag 泄露
- **[litctf2025_star_wish]** — `web/litctf2025_star_wish.md` (~46 lines) — LitCTF 2025 / Jinja2 SSTI {% %} 标签绕过 + 命令拼接
- **[newstarctf2023_medium_sql]** — `web/newstarctf2023_medium_sql.md` (~48 lines) — NewStarCTF 2023 / 布尔盲注 + %53ELECT 绕过 + innodb_table_stats 替代
- **[npuctf2020_yanzhengma]** — `web/npuctf2020_yanzhengma.md` (~62 lines) — NPUCTF 2020 / saferEval 正则白名单 + 箭头函数参数遮蔽 + 原型链 String→Function RCE
- **[swpuctf2025_sql_not_just_sql]** — `web/swpuctf2025_sql_not_just_sql.md` (~40 lines) — SWPUCTF 2025 / 数字型注入 + multi_query 堆叠 + UDF 提权 RCE
- **[wangdingbei2020_picdown]** — `web/wangdingbei2020_picdown.md` (~51 lines) — 网鼎杯 2020 白虎 / 任意文件读取 + /proc/fd 恢复 secret + 隐藏路由 RCE
- **[xuanwu2025_ez_fastapi]** — `web/xuanwu2025_ez_fastapi.md` (~39 lines) — 玄武杯 2025 / FastAPI 盲 SSTI 内存马 + sudo chmod 提权
- **[xuanwu2025_jinja]** — `web/xuanwu2025_jinja.md` (~39 lines) — 玄武杯 2025 / Jinja2 SSTI 无过滤入门题
- **[yangchengbei2020_break_the_wall]** — `web/yangchengbei2020_break_the_wall.md` (~43 lines) — 羊城杯 2020 / eval 后门 + 函数名黑名单, flag 在环境变量
- **[portswigger_ai_destructive_actions]** — `web/portswigger_ai_destructive_actions.md` (~95 lines) — PortSwigger / 间接 prompt 注入 / blog 评论骗带 carlos 认证态的 LLM scanner 删号 / 攻击词汇反而被识破，纯口语自助请求才中 / LLM01+LLM06
- **[portswigger_ai_exfil_apikey]** — `web/portswigger_ai_exfil_apikey.md` (~85 lines) — PortSwigger / 间接 prompt 注入数据外泄变体 / 无结果页(404)→ scanner 把 carlos API key 发成评论回显 / owner framing 第一轮即中 / LLM01+LLM06+LLM02
- **[portswigger_ai_secondary_ssrf]** — `web/portswigger_ai_secondary_ssrf.md` (~110 lines) — PortSwigger Practitioner / 间接 prompt 注入驱动 routing-based SSRF / 伪造 Host=192.168.0.5:8080 经路由层达 loopback-only admin 裸 GET /admin/delete?username=carlos / URL-based(stockApi)绕不过 loopback, Host 值是 admin IP 非 localhost / LLM01+LLM06+SSRF

## Cryptography (15 entries)

- **[GHCTF 2025] baby_signin Writeup** — `CRYPTO/[GHCTF 2025]baby_signin/writeup.md` (97 lines)
- **[GHCTF 2025] EZ_Fermat Writeup** — `CRYPTO/[GHCTF 2025]EZ_Fermat/writeup.md` (79 lines)
- **[GHCTF 2025] MIMT_RSA Writeup** — `CRYPTO/[GHCTF 2025]MIMT_RSA/writeup.md` (89 lines)
- **[GKCTF 2021]XOR** — `CRYPTO/[GKCTF 2021]XOR/writeup.md` (90 lines)
- **[MRCTF2020]Easy_RSA** — `CRYPTO/[MRCTF2020]Easy_RSA/writeup.md` (65 lines)
- **writeup** — `CRYPTO/[UTCTF2020]basic-crypto/writeup.md` (77 lines)
- **[央企杯 2025] big_e_rsa Writeup** — `CRYPTO/[央企杯 2025]big_e_rsa/writeup.md` (99 lines)
- **[网鼎杯 2020 青龙组]you_raise_me_up** — `CRYPTO/[网鼎杯 2020 青龙组]you_raise_me_up/[网鼎杯 2020 青龙组]you_raise_me_up.md` (65 lines)
- **[LitCTF 2025] math** — `crypto/litctf2025_math.md` (~180 lines) — RSA `hint=(p+noise)(q+noise)` leak: Pollard rho on `hint-n` → 40-bit noise → Vieta → (p,q) → flag
- **[XCTF 9th Finals 2025] Tch3s** — `crypto/xctf2025_tch3s.md` (~190 lines) — predictable `srand(time())`; brute Unix-timestamp seed from Test 1 plaintext (~95M seconds, ~1 min), regenerate the key, inject it into the running binary via gdb-python, then `call` the binary's own decrypt. Detailed Chinese debug-log version at `CRYPTO/第九届 XCTF 国际网络攻防联赛总决赛-Tch3s/WRITEUP_CN.md`
- **[ghctf2025_baby_signin]** — `crypto/ghctf2025_baby_signin.md` (~32 lines) — GHCTF 2025 / e=4 不互素 AMM 开根签到
- **[ghctf2025_ez_fermat]** — `crypto/ghctf2025_ez_fermat.md` (~35 lines) — GHCTF 2025 / 费马小定理 + 多项式 GCD 分解 RSA
- **[ghctf2025_mimt_rsa]** — `crypto/ghctf2025_mimt_rsa.md` (~40 lines) — GHCTF 2025 / RSA 乘法同态 MITM 恢复 36-bit 合数 KEY
- **[utctf2020_basic_crypto]** — `crypto/utctf2020_basic_crypto.md` (~34 lines) — UTCTF 2020 / 四层编码洋葱 Binary→Base64→ROT10→Substitution
- **[yangqibei2025_big_e_rsa]** — `crypto/yangqibei2025_big_e_rsa.md` (~44 lines) — 央企杯 2025 / Eisenstein RSA + 浮点精度 d 恢复

## Miscellaneous & Forensics (19 entries)

- **easycap** — `Misc/easycap.md` (2 lines)
- **Misc 环境清单（2026-05-06 实装版）** — `Misc/setup.md` (232 lines)
- **Wireshark的常用** — `Misc/Wireshark的常用.md` (219 lines)
- **内存取证** — `Misc/内存取证.md` (369 lines)
- **压缩包和图片修复** — `Misc/压缩包和图片修复.md` (4 lines)
- **数据包中的线索** — `Misc/数据包中的线索.md` (14 lines)
- **被嗅探的流量** — `Misc/被嗅探的流量.md` (2 lines)
- **[GHCTF 2025] mybrave Writeup** — `Misc/[GHCTF 2025]mybrave/writeup.md` (66 lines)
- **[GHCTF 2025] mypcap Writeup** — `Misc/[GHCTF 2025]mypcap/writeup.md` (134 lines)
- **[NewStarCTF 公开赛赛道]最后的流量分析** — `Misc/[NewStarCTF 公开赛赛道]最后的流量分析/writeup.md` (89 lines)
- **[OtterCTF 2018] Name Game — Writeup** — `Misc/[OtterCTF 2018]Name Game/writeup.md` (142 lines)
- **[鹤城杯 2021] 流量分析 — Writeup** — `Misc/[鹤城杯 2021]流量分析/writeup.md` (140 lines)

- **[0x401 CTF 2025] FlagSyndicate (玄机 #328 + #329, 18-question IR)** — `forensics/0x401ctf2025_flag_syndicate.md` (~280 lines) — VMDK read-only NBD mount / yescrypt password cracking / ELF reversing of an AES+random-key TCP server (key+IV appended to ciphertext) / base64-in-base64 ZIP payload / MySQL 8.0.36 InnoDB datadir offline revival via Docker. Chinese debug-log version at `Misc/0x401-FlagSyndicate-1/WRITEUP_CN.md` (同步到 -2)
- **[振兴杯 2025] 钓鱼佬的疏忽 (EML 取证)** — `forensics/zhenxing2025_phishing_oversight.md` (~110 lines) — `X-HAS-ATTACH: no` 假头 / 正文 base64 冷鱼 `Y3RmX2lzX2dvb2RfYm95` 后来是 docx XOR key / 从 XOR-加密 ZIP 恢复 Office 文档. Chinese version at `Misc/2025振兴杯-应急处置-钓鱼佬的疏忽/WRITEUP_CN.md`
- **[振兴杯 2025] ICS C2 (OPC UA 流量)** — `forensics/zhenxing2025_ics_c2.md` (~130 lines) — OPC UA Node 9/10 值被滥用为双向 C2 (下行 REACTOR-001-SEG## 指令 / 上行 RESULT-SEG## 响应) / 分段 base64 重组后是 JSON / 工控协议无加密是核心盲点. Chinese version at `Misc/2025振兴杯-应急处置-ics_c2/WRITEUP_CN.md`

### Deep IR writeups added 2026-05-18

These are full English incident-response walkthroughs published under `forensics/` in this repository (not the private `Misc/` study notes above):

- **[长城杯 2024] SnakeBackdoor** — `forensics/changcheng2024_snake_backdoor.md` (~580 lines) — 6-question chain: HTTP brute → Flask SSTI → 33-layer nested loader → RC4 memory shell + binary-trojan dynamic AES key
- **[0x401 CTF 2025] TECI** — `forensics/0x401_2025_teci.md` (~210 lines) — 8-question chain: .NET NativeAOT trojan + RC4/XOR two-cipher key-swap trap
- **[Xuanji] Supply-Chain Part 2** — `forensics/xuanji_sc_supply_chain_part2.md` (~150 lines) — multi-stage supply-chain poisoning + reverse-shell backdoor IR
- **[Xuanji] Supply-Chain Part 3** — `forensics/xuanji_sc_supply_chain_part3.md` (~170 lines) — Jenkins+Gitea CI/CD: webhook hijack, command injection, credential exfil
- **[铁人三项决赛 2024] APK + Tomcat + PAM** — `forensics/tieren_2024_apk_pam_incident.md` (~280 lines) — 18-question full chain: APK JWT forgery, Behinder per-session AES JSP shell, `/etc/passwd` direct hash injection, PAM `ssh_back_pwd` magic password + `/tmp/.sshlog` credential logger
- **[玄机 2025] CobaltStrike 流量分析** — `forensics/xuanji_2025_cs_traffic_analysis.md` (~280 lines) — 11-question CS 4.4 IR: stager extraction → 1768.py profile parse → Docker 2375 unauth → `.cobaltstrike.beacon_keys` Java keystore → RSA-1024 priv → metadata raw_aes_key → AES-256-CBC per-session traffic decrypt
- **[ghctf2025_mybrave]** — `forensics/ghctf2025_mybrave.md` (~35 lines) — GHCTF 2025 / bkcrack ZipCrypto 已知明文攻击 + PNG 隐写
- **[ghctf2025_mypcap]** — `forensics/ghctf2025_mypcap.md` (~41 lines) — GHCTF 2025 / Tomcat 冰蝎 webshell AES 流量解密 + MySQL 数据提取
- **[newstarctf2023_last_traffic]** — `forensics/newstarctf2023_last_traffic.md` (~34 lines) — NewStarCTF 2023 / 布尔盲注流量还原 (HTTP 响应长度区分 True/False)
- **[xuanji_dmz2_ubuntu]** — `forensics/xuanji_dmz2_ubuntu.md` (~67 lines) — 玄机 DMZ2 应急响应 / Nacos CVE-2021-29442 + UID=0 隐藏后门 sys-update
- **[dasctf2025h1_webshell_plus]** — `forensics/dasctf2025h1_webshell_plus.md` (~186 lines) — DASCTF 2025 H1 / Bluetooth OBEX file reassembly (tshark hex stitching, `--export-objects` unsupported) + JPEG trailer ZIP + Windows ZIP password GBK encoding for `の` (`a4 ce` ≠ UTF-8 `e3 81 ae`) + grayscale PNG R-channel as UTF-8 text. Chinese version at `Misc/DASCTF2025上半年赛-Webshell_Plus/WRITEUP_CN.md`
- **[zhujian2025_dimensionality_reduction]** — `forensics/zhujian2025_dimensionality_reduction.md` (~168 lines) — 2025 ZhuJian Cup / 729×729 PNG trailer carving (1200×120 RGBA inner) → 3-px subpixel phase separation (3 frames + WASD path) → 3-adic Peano L-System 6-iter pixel reorder → QR code → flag. Contest 0-solve, 44th-rank reproduction. Chinese version at `Misc/2025铸剑杯-降维打击/WRITEUP_CN.md`

---

## Labs — Vulnerability Reproduction (23 entries)

Attacker-perspective writeups for published CVEs reproduced in local Docker labs (vulhub). Each writeup includes a three-part Defense chapter (Hardening / Detection / Threat Hunting). See `labs/README.md` for chapter overview.

- **Apache Shiro 1.2.4 RememberMe Deserialization RCE** — `labs/shiro_550/writeup_en.md` (~270 lines) — CVE-2016-4437: hardcoded AES key + CommonsBeanutils1 gadget + `TemplatesImpl` bytecode loading + Java 9+ module reflection workaround + full Defense chapter
- **Apache ActiveMQ OpenWire Deserialization RCE** — `labs/activemq_2023_46604/writeup_en.md` (~180 lines) — CVE-2023-46604: Spring `ClassPathXmlApplicationContext` gadget over OpenWire TCP/61616; HelloKitty ransomware in-the-wild reference; cgroup v2 JVM workaround documented
- **Jenkins CLI `expandAtFiles` File Read → RCE** — `labs/jenkins_2024_23897/writeup_en.md` (~200 lines) — CVE-2024-23897: args4j anonymous CLI file read → `secret.key`/`master.key` exfil → Script Console Groovy RCE as root
- **Grafana DuckDB SQL Injection → RCE** — `labs/grafana_2024_9264/writeup_en.md` (~180 lines) — CVE-2024-9264: SQL Expressions API + DuckDB `read_blob()` file read + `shellfs` extension pipe-to-shell RCE
- **TeamCity Authentication Bypass → Admin RCE** — `labs/teamcity_2024_27198/writeup_en.md` (~190 lines) — CVE-2024-27198: Servlet `;.jsp` path-parameter trick bypasses auth → unauthenticated REST API → SYSTEM_ADMIN account creation
- **Metabase Pre-Auth JDBC RCE** — `labs/metabase_2023_38646/writeup_en.md` (~180 lines) — CVE-2023-38646: Leaked setup-token + H2 JDBC URL `INIT` parameter injection → `CSVWRITE` arbitrary file write / JavaScript trigger RCE
- **GeoServer XPath Property Name RCE** — `labs/geoserver_2024_36401/writeup_en.md` (~170 lines) — CVE-2024-36401: OGC `GetPropertyValue` evaluates `valueReference` as XPath/EL → single GET request `Runtime.exec()` as root
- **JimuReport FreeMarker SSTI RCE** — `labs/jimureport_2023_4450/writeup_en.md` (~170 lines) — CVE-2023-4450: `/jmreport/queryFieldBySql` endpoint renders SQL through FreeMarker → `Execute` class instantiation → command output in response
- **Nexus Repository Path Traversal** — `labs/nexus_2024_4956/writeup_en.md` (~160 lines) — CVE-2024-4956: Jetty `URIUtil.canonicalPath()` treats empty segments as root → `%2F%2F..%2F` traversal reads arbitrary files (admin.password, configs)
- **Next.js Middleware Auth Bypass** — `labs/nextjs_2025_29927/writeup_en.md` (~160 lines) — CVE-2025-29927: `x-middleware-subrequest` header with 5× middleware name repetition triggers recursion limit → middleware skipped entirely → auth bypass
- **Langflow Pre-Auth RCE** — `labs/langflow_2025_3248/writeup_en.md` (~170 lines) — CVE-2025-3248: `/api/v1/validate/code` uses `exec()` on user Python → `@exec()` decorator evaluated at definition time → pre-auth RCE with output in response
- **Apache Log4Shell JNDI Injection RCE** — `labs/log4j_2021_44228/writeup_en.md` (~298 lines) — CVE-2021-44228: `${jndi:ldap://...}` substitution in log message triggers JNDI lookup → remote class load → arbitrary code execution; the canonical 2021 advisory
- **Spring4Shell — Spring Framework RCE via Data Binding** — `labs/spring_2022_22965/writeup_en.md` (~277 lines) — CVE-2022-22965: `class.module.classLoader.resources.context.parent.pipeline.first.*` data binding chain → write JSP webshell to Tomcat ROOT
- **Fastjson 1.2.24 AutoType Deserialization RCE** — `labs/fastjson_1224_rce/writeup_en.md` (~254 lines) — CVE-2017-18349: `@type` AutoType + `JdbcRowSetImpl` JNDI → LDAP referral → CommonsBeanutils gadget chain
- **Redis Unauthorized Access — Arbitrary File Write / SSH Key Injection** — `labs/redis_4_unacc/writeup_en.md` (~285 lines) — `CONFIG SET dir/dbfilename` + `SAVE` writes attacker-controlled RDB to `~/.ssh/authorized_keys`; the classical no-auth Redis takeover
- **Apache Tomcat Tribes EncryptInterceptor Bypass RCE** — `labs/tomcat_2026_34486/writeup_en.md` (~275 lines) — CVE-2026-34486: missing receiver-side encryption enforcement → cluster RPC deserialization → cross-node code execution
- **DataEase JWT Authentication Bypass** — `labs/dataease_2025_49001/writeup_en.md` (~305 lines) — CVE-2025-49001: hardcoded JWT signing key + flawed token issuance flow → admin impersonation → BI platform takeover
- **ComfyUI-Manager CRLF Injection in Configuration Handler** — `labs/comfyui_2026_22777/writeup_en.md` (~292 lines) — CVE-2026-22777: insufficient header sanitization in plugin/configuration endpoint → CRLF smuggling → cache poisoning / response splitting
- **OpenClaw Cross-Site WebSocket Hijacking → RCE** — `labs/openclaw_2026_25253/writeup_en.md` (~246 lines) — CVE-2026-25253: WebSocket origin check missing + HMAC challenge-response bypassed via leaked token → unauthenticated RCE via Node.js plugin runtime
- **ZeroShell kerbynet Pre-Auth Command Injection → root** — `labs/zeroshell_2019_12725/writeup_en.md` (~417 lines) — CVE-2019-12725: `%0A` newline injection in `NoAuthREQ` `x509type` → apache RCE → `sudo tar --checkpoint-action` GTFOBins → root. Vendor project unmaintained (no patch exists) — defense is detection-only: Sigma + 3× Suricata + Splunk SPL ×2 + Sentinel KQL ×2 + IOC table. Paired with vulhub-style Docker reproducer and ELF IOC-extraction tooling. Defense section occupies ~48% of the writeup.
- **Apache ActiveMQ Jolokia addNetworkConnector RCE** — `labs/activemq_2026_34197/writeup_en.md` (~178 lines) — CVE-2026-34197: Jolokia JMX-HTTP bridge → `static:(vm://?brokerConfig=xbean:http://...)` 异步 fetch 远程 Spring XML → `MethodInvokingFactoryBean` 触发 `Runtime.exec()`，CVSS 8.8 认证后 RCE (默认 admin:admin)，含 Sigma/Suricata/Splunk/Sentinel 全套 SOC artifact
- **GNU InetUtils telnetd USER 参数注入** — `labs/inetutils_2026_24061/writeup_en.md` (~160 lines) — CVE-2026-24061: telnetd 未净化 NEW-ENVIRON 发来的 `USER` 环境变量直接传给 `/bin/login -f`，`USER="-f root"` → 零交互 root shell，CVSS 9.8 unauth，CWE-88 argument injection 经典
- **Chartbrew MongoDB Query → Node.js `Function()` RCE** — `labs/chartbrew_2026_25887/writeup_en.md` (~179 lines) — CVE-2026-25887: `runMongo` 把用户 query 直接给 `new Function('MongoClient','collection', query)` → `global.process.mainModule.require('child_process').execSync()`，首位注册即 admin = 实际 pre-auth，CVSS 8.8

---

## Notes on this catalog

- Lines counts indicate note depth (a 300+ line entry is a full writeup; a 50 line entry is often a quick reference).
- Paths are relative to my private local study directory; they remain valid references for cross-checking.
- This index is updated whenever a new batch of challenges is added; entries are not removed even if writeups are later refactored or deleted.
