/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_util：格式化/字节序/内存/字符串底座 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"

/* ---- 极简格式化：只做十进制/定宽十六进制/字符串，不依赖 snprintf ---- */

void se_o_c(struct se_out *o, char c)
{
    if (o->n + 1u < o->cap)
        o->buf[o->n++] = c;
}

void se_o_s(struct se_out *o, const char *s)
{
    while (*s)
        se_o_c(o, *s++);
}

void se_o_dec(struct se_out *o, se_u32 v)
{
    char t[12];
    int i = 0;

    if (!v) {
        se_o_c(o, '0');
        return;
    }
    while (v && i < 12) {
        t[i++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (i)
        se_o_c(o, t[--i]);
}

void se_o_hex(struct se_out *o, se_u64 v, se_u32 width)
{
    char t[24];
    int i = 0;

    if (!v)
        t[i++] = '0';
    while (v && i < 24) {
        se_u32 d = (se_u32)(v & 0xfu);

        t[i++] = (char)(d < 10u ? ('0' + d) : ('a' + d - 10u));
        v >>= 4;
    }
    while ((se_u32)i < width)
        t[i++] = '0';
    while (i)
        se_o_c(o, t[--i]);
}

void se_o_pad(struct se_out *o, const char *s, se_u32 width)
{
    se_u32 k = 0;

    while (*s) {
        se_o_c(o, *s++);
        k++;
    }
    while (k++ < width)
        se_o_c(o, ' ');
}

/* ---------------- 字节序读写（KPM 无 asm/unaligned.h） ---------------- */

se_u32 se_rd32(const se_u8 *p)
{
    return (se_u32)p[0] | ((se_u32)p[1] << 8) | ((se_u32)p[2] << 16) | ((se_u32)p[3] << 24);
}

se_u64 se_rd64(const se_u8 *p)
{
    return (se_u64)se_rd32(p) | ((se_u64)se_rd32(p + 4) << 32);
}

void se_wr32(se_u8 *p, se_u32 v)
{
    p[0] = (se_u8)v; p[1] = (se_u8)(v >> 8); p[2] = (se_u8)(v >> 16); p[3] = (se_u8)(v >> 24);
}

void se_wr64(se_u8 *p, se_u64 v)
{
    se_wr32(p, (se_u32)v);
    se_wr32(p + 4, (se_u32)(v >> 32));
}

/*
 * 只分配 KB 级缓冲（策略本体由 security_read_policy 自己 vmalloc）。
 * __kmalloc + kfree 在 4.19~6.18 的 kallsyms 里都稳定存在；
 * kvzalloc 在 6.1 上被 LTO 内联掉了，不能用（已用设备 kallsyms 快照核对）。
 */
void *se_alloc(se_ulong size)
{
    if (!p_kvzalloc)
        return 0;
    /* GFP_KERNEL = 0xcc0 */
    return ((void *(*)(se_ulong, se_u32))p_kvzalloc)(size, 0xcc0u);
}

void se_free(void *p)
{
    if (p && p_kvfree)
        ((void (*)(const void *))p_kvfree)(p);
}

int se_kread(void *dst, const void *src, se_ulong n)
{
    if (!p_kread)
        return -1;
    if (kver >= VERSION(5, 8, 0))
        return ((long (*)(void *, const void *, se_ulong))p_kread)(dst, src, n) == 0 ? 0 : -1;
    return ((int (*)(void *, const void *, se_ulong))p_kread)(dst, src, n) == 0 ? 0 : -1;
}

/*
 * 内核指针判定。定义放前面：se_copy_attrs（副本属性表遍历）要用，
 * 上一版它声明在文件后段、使用在前面 —— 使用先于声明编译不过，
 * 这正是审计立誓要防的那类错位。
 */
int se_kptr_ok(se_u64 v)
{
    return (v >> 48) == 0xffffull && v != 0xffffffffffffffffull;
}

/* ---------------- 结构推导：symtab 与 te_avtab ---------------- */

int se_streq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

int se_memeq(const void *a, const void *b, se_u32 n)
{
    const se_u8 *x = (const se_u8 *)a;
    const se_u8 *y = (const se_u8 *)b;
    se_u32 i;

    for (i = 0; i < n; i++) {
        if (x[i] != y[i])
            return 0;
    }
    return 1;
}

int se_parse3(char *buf, char **a, char **b, char **c)
{
    char *p = buf;
    char **out[3];
    int i;

    out[0] = a; out[1] = b; out[2] = c;
    for (i = 0; i < 3; i++) {
        while (*p == ' ' || *p == '\n' || *p == '\t' || *p == '\r')
            p++;
        if (!*p)
            return -1;
        *out[i] = p;
        while (*p && *p != ' ' && *p != '\n' && *p != '\t' && *p != '\r')
            p++;
        if (*p) {
            *p = 0;
            p++;
        }
    }
    return 0;
}
