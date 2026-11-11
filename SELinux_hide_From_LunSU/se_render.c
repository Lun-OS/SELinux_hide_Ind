/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_render：渲染三路 + 自检 */
#include "sehide.h"

/* ---------------- 渲染器（自建三路） ---------------- */

/*
 * 一路：上下文串 -> SID（自实现 se_parse_ctx，不经内核直调）
 *   （历史注：string_to_context_struct 的参数个数不能按主版本号判——
 *   主线 v4.19.157 services.c:1366-1370 是六参（多一个 scontext_len），
 *   但 Android/vendor 分支早已 backport 掉它 —— 本机 elish 4.19.113 树
 *   services.c:1376-1380 就是五参，v5.4 起主线也统一五参
 *   （v5.4 :1375-1378 / v5.10 :1424-1427 / v6.1 :1437-1440 /
 *     v6.6 :1416-1419 / v6.12 :1426-1429 / v6.18 :1475-1478）。
 *   4.19.157 实机按六参调用时内核把 x3（我们传的 len=9）
 *   当成 ctx，context_init() 里 memset(0x9, 0, 0x50) 直接 Oops。
 *   装机期解析统一改 secctx 委托（不直调 stc），
 *   见 se_layout.c se_ctx_type。）
 *
 * 二路：SID -> 上下文串
 *   sidtab_search_entry(sidtab, sid) -> struct sidtab_entry *（5.10+）
 *     struct sidtab_entry { u32 sid; u32 hash; struct context context; ... } -> context 在 +8
 *   sidtab_search(sidtab, sid) -> struct context *（4.19/5.4）
 *   context_struct_to_string(pol, ctx, &str, &len)
 *
 * 三路：权限判定
 *   entry x2 -> context_struct_compute_av(pol, sctx, tctx, tclass, avd, NULL)
 *
 * avd 前五个 u32 是 allowed / auditallow / auditdeny / seqno / flags，
 * 4.19~6.18 顺序一致；这里给 64 字节零缓冲，只读前 20 字节。
 */

/*
 * 渲染三路为副本侧自实现，不绑定/调用内核 static 函数
 * string_to_context_struct —— 它在主线 4.19 是六参、vendor 4.19 与
 * 5.10+ 是五参（四树源码实证），参数个数无法在 KPM 环境安全判别，
 * 写死五参在主线 4.19 上 context_init 对空指针 memset 直接 Oops。
 *
 * 自实现依赖的全部原语：
 *   - 按名查 datum：se_sym_search()（se_policydb.c:71，规则注入实机在用，
 *     4.x hashtab 指针 / 5.9+ symtab_search 双形态已处理）
 *   - datum->value@0：type/role/user_datum 四树逐字一致（value 均在 +0）
 *   - value 反查 name：hashtab 桶遍历（node{key@0,datum@8,next@16} 四树
 *     逐字一致，se_copy_attrs 同款模式实机在用）；不用 sym_name()——
 *     4.19 是 flex_array（policydb.h:371）、6.x 是连续指针数组
 *     （policydb.h:382），跨版本布局不同，遍历法绕开该分叉
 *   - struct context 布局：user@0 role@4 type@8 len@12 range@16..55
 *     str@56，四树逐字一致（context.h 实证）
 *
 * 崩溃面收敛：全程只读副本内存（容错读 se_kread + se_kptr_ok）与
 * 自有栈缓冲；失败返回错误码，由门回落内核原版 handler。
 * 非特权观测面：零内核接口调用、零日志、零分配（与既有审计一致）。
 */

/* symtab[idx] 的 hashtab 句柄（4.x table 是指针 / 5.9+ 内嵌），同 se_copy_attrs */
static int sym_ht(void *pdb, se_u32 idx, se_u64 *ht_out, se_u32 *size_out)
{
    se_u64 sym = (se_u64)(se_ulong)pdb + L.symtab_off + (se_u64)idx * L.symtab_stride;
    se_u64 tbl = 0, ht = 0;
    se_u32 size = 0;

    if (!L.symtab_off || !L.symtab_stride)
        return -1;

    if (L.symtab_stride == 16u) {
        /* 4.x：symtab.table 是 struct hashtab *，先解引用 */
        if (se_kread(&tbl, (void *)(se_ulong)sym, 8) || !se_kptr_ok(tbl))
            return -2;
        if (se_kread(&ht, (void *)(se_ulong)tbl, 8) ||
            se_kread(&size, (se_u8 *)(se_ulong)tbl + 8u, 4))
            return -2;
    } else {
        /* 5.9+：hashtab 内嵌在 symtab 里，{htable, size, ...} */
        if (se_kread(&ht, (void *)(se_ulong)sym, 8) ||
            se_kread(&size, (se_u8 *)(se_ulong)sym + 8u, 4))
            return -2;
    }
    if (!se_kptr_ok(ht) || !size || size > (1u << 20))
        return -3;

    *ht_out = ht;
    *size_out = size;
    return 0;
}

/* value -> name：遍历 symtab[idx] 的 hashtab，命中 datum->value 后读 key 字符串 */
static int sym_name_by_val(void *pdb, se_u32 idx, se_u32 value, char *out, se_u32 cap)
{
    se_u64 ht = 0, node = 0, datum = 0, next = 0, key = 0;
    se_u32 size = 0, i, guard;
    int rc;

    if (!value || !cap)
        return -1;

    rc = sym_ht(pdb, idx, &ht, &size);
    if (rc)
        return rc;

    for (i = 0; i < size; i++) {
        if (se_kread(&node, (se_u8 *)(se_ulong)ht + (se_u64)i * 8u, 8))
            return -4;
        guard = 0;
        while (node && se_kptr_ok(node) && ++guard < 64u) {
            se_u32 v = 0;

            if (se_kread(&datum, (se_u8 *)(se_ulong)node + 8u, 8) ||
                !se_kptr_ok(datum) ||
                se_kread(&v, (void *)(se_ulong)datum, 4))
                return -5;
            if (v == value) {
                if (se_kread(&key, (void *)(se_ulong)node, 8) ||
                    !se_kptr_ok(key))
                    return -6;
                memset(out, 0, cap);
                if (se_kread(out, (void *)(se_ulong)key, cap - 1u))
                    return -7;
                return 0;
            }
            if (se_kread(&next, (se_u8 *)(se_ulong)node + 16u, 8))
                return -5;
            node = next;
        }
        if (guard >= 64u)
            return -8;      /* 链长异常：链表被读歪了 */
    }
    return -9;              /* value 不在表内 */
}

/* 单段查 value：symtab 基址 + 段名 -> datum->value */
static int seg_val(void *pdb, se_u32 idx, const char *seg, se_u32 *out)
{
    void *sym = (se_u8 *)pdb + L.symtab_off + (se_u64)idx * L.symtab_stride;
    void *d;
    se_u32 v = 0;

    d = se_sym_search(sym, seg);
    if (!d || ((se_ulong)d >> 48) != 0xffffull)
        return -2;
    if (se_kread(&v, d, 4))
        return -3;
    if (!v || v > 0xffffu)
        return -4;
    *out = v;
    return 0;
}

#define SE_SYM_USER 4u   /* policydb.h:220 SYM_USERS=4（4.19/6.1 同）；
                            （曾误写 0=SYM_COMMONS），su 段永远查空 → rc=-2 */
#define SE_SYM_ROLE 2u
#define SE_SYM_TYPE 3u
#define SE_STR_MLS  -95    /* MLS 段：自实现不支持（mls 关闭路径自证） */

/*
 * 一路（自实现）：上下文串 -> struct context（副本）。
 *
 * 按 ':' 切段。SELinux 串恒为 user:role:type[:mls]：第 4 段是 MLS 敏感度，
 * mls 关闭的内核解析它时直接跳过（4.19 mls.c:250 *scontext += strlen 分支）
 * ——所以 "u:r:su:s0" 是 4 段且必须接受、忽略第 4 段（曾在此误拒，
 * selftest rc=-95、su sid 兜底解析失败）。≥5 段才是真正异常。
 * 原地改写 buf 与内核原版契约一致。
 */
int se_parse_ctx(char *buf, void *ctxbuf)
{
    static const se_u32 symidx[3] = { SE_SYM_USER, SE_SYM_ROLE, SE_SYM_TYPE };
    char *seg[5];
    se_u8 *ctx = ctxbuf;
    int i, n = 1;

    if (!buf || !ctxbuf || !L.copy || !L.symtab_off)
        return -1;

    memset(ctxbuf, 0, SE_CTX_BUF);   /* range/str 区域清零，防栈残留进 compute_av */

    seg[0] = buf;
    for (i = 0; buf[i]; i++) {
        if (buf[i] == ':') {
            buf[i] = 0;
            if (n < 5)
                seg[n] = &buf[i + 1];
            n++;
        }
    }
    if (n < 3)
        return -2;
    /*
     * 5 段 = MLS 形态 "u:r:type:sens:cats"（真实 app 域全部带
     * 类别，如 u:r:platform_app:s0:c512,c768）。此前一律拒绝（-SE_STR_MLS）
     * 导致带类别的特权查询恒 -22（SystemUI 等 attach 循环崩的直接机制，
     * 实测 T2 wr=1 / T3 无 MLS 版 wr=0 复现）。MLS 段跳过：range 置零
     * （parse 开头已 memset），求值走 type（Android app 边几乎不含
     * mlsconstrain，实测 T3 副本答案 allow 与出厂一致）；MLS 精确
     * 填充（sens symtab + cat ebitmap）留待实测需要时再做。
     */
    if (n > 5)
        return SE_STR_MLS;   /* 6 段以上：结构异常 */

    for (i = 0; i < 3; i++) {
        se_u32 v = 0;
        int rc = seg_val(L.copy, symidx[i], seg[i], &v);

        if (rc)
            return rc;
        se_wr32(ctx + (se_u32)i * 4u, v);
    }
    se_wr32(ctx + 12, 0u);      /* len=0：无串缓存标记 */
    return 0;
}

/*
 * 串 -> sid（自实现解析 + 既有 sidtab 绑定）。
 * sidtab_context_to_sid(sidtab, context, sid*) 三参四树一致（sidtab.c
 * 4.19:191 / 5.10:264 / 6.1:264 / 6.6:265），保留绑定。
 */
int se_ctx_to_sid(const char *s, se_u32 *sid_out)
{
    char buf[64];
    se_u8 ctx[SE_CTX_BUF];
    se_ulong n = strlen(s);
    se_u32 sid = 0;
    int rc;

    if (!p_sidtab_to_sid || n >= sizeof(buf))
        return -1;

    memcpy(buf, s, n + 1);
    memset(ctx, 0, sizeof(ctx));

    rc = se_parse_ctx(buf, ctx);
    if (rc)
        return rc;

    rc = ((int (*)(void *, void *, se_u32 *))p_sidtab_to_sid)(L.sidtab, ctx, &sid);
    if (rc)
        return rc;

    *sid_out = sid;
    return 0;
}

/*
 * 二路（自实现为主）：struct context -> 规范串（副本）。
 *
 * 只对"自产 ctx"（len==0 且 range 全零，即本文件 se_parse_ctx 的输出）
 * 自行拼装 user:role:type；其他来源（sidtab 转来的、带串缓存的）回落
 * 内核原版 context_struct_to_string —— 它的 str 缓存分支与 MLS 序列化
 * 不在自实现覆盖范围内，回落路径保持既有行为。
 * 内核拼装语义（6.1 services.c context_struct_to_string）：
 *   sym_name(p, SYM_USERS, user-1) 等 —— value 直接作下标；
 *   自实现用 hashtab 遍历反查，避开 4.19 flex_array 分叉。
 */
int se_ctx_to_str(void *ctx, char *out, se_u32 outlen)
{
    static const se_u32 symidx[3] = { SE_SYM_USER, SE_SYM_ROLE, SE_SYM_TYPE };
    se_u32 off, i;
    se_u32 o = 0;
    int rc;

    if (!ctx || !out || !outlen)
        return -1;

    /* 非自产 ctx（有串缓存或带 MLS range）：回落内核原版 */
    if (se_rd32((se_u8 *)ctx + 12) != 0u)
        goto fallback;
    for (off = 16u; off < 56u; off += 4u)
        if (se_rd32((se_u8 *)ctx + off) != 0u)
            goto fallback;

    memset(out, 0, outlen);
    for (i = 0; i < 3u; i++) {
        char name[64];
        se_u32 nl;

        rc = sym_name_by_val(L.copy, symidx[i],
                             se_rd32((se_u8 *)ctx + i * 4u),
                             name, sizeof(name));
        if (rc)
            return rc;
        nl = strlen(name);
        if (!nl || o + 1u + nl >= outlen)
            return -3;
        if (i)
            out[o++] = ':';
        memcpy(out + o, name, nl);
        o += nl;
    }
    out[o] = 0;
    return 0;

fallback:
{
    se_u64 str = 0;
    se_u32 len = 0;
    int r;

    if (!p_ctx_to_str || !L.copy)
        return -1;

    r = ((int (*)(void *, void *, se_u64 *, se_u32 *))p_ctx_to_str)
        (L.copy, ctx, &str, &len);
    if (r)
        return r;
    if (!str || len == 0 || len >= outlen)
        return -3;

    memset(out, 0, outlen);
    if (se_kread(out, (void *)(se_ulong)str, len))
        return -4;

    if (p_kfree)
        ((void (*)(const void *))p_kfree)((void *)(se_ulong)str);
    return 0;
}
}

se_u32 g_avd[8];

/*
 * 权限判定：两个 struct context 直接算，不再经过 sid。
 *
 * context_struct_compute_av 自己填 allowed/auditallow/auditdeny
 * （6.1 services.c:627-629，其余版本同样那三行）；permissive 位是调用方的
 * 事（4.19 :1137、6.1 :1144），这里补上 —— 否则 /access 的 flags 永远不带
 * PERMISSIVE，用户态会认为 su 域是 enforcing。
 *
 * seqno 给 0：它是"策略第几次重载"的计数器，用户态拿它判缓存是否失效。
 * 副本是开机时拷的，之后不再变，恒 0 与"策略没有再次加载"是同一语义。
 */
int se_compute_av(void *sctx, void *tctx, se_u32 tclass,
                         se_u32 *allowed, se_u32 *flags, se_u32 *avd5)
{
    se_u8 avd[SE_AVD_BUF];
    se_u32 sctype;
    void *pdb = L.copy;   /* 特权查询答副本（对齐 LKM ksu_se_compute_av） */

    if (!p_compute_av || !pdb)
        return -1;

    memset(avd, 0, sizeof(avd));
    se_wr32(avd + 8, 0xffffffffu);   /* auditdeny */
    se_wr32(avd + 12, 0u);           /* seqno     */

    sctype = se_rd32((se_u8 *)sctx + 8);   /* context{user,role,type,len} */
    if (p_get_bit && L.perm &&
        ((int (*)(void *, se_ulong))p_get_bit)((se_u8 *)pdb + L.perm, sctype))
        se_wr32(avd + 16, se_rd32(avd + 16) | 0x1u);   /* AVD_FLAGS_PERMISSIVE */

    /*
     * v6.17 起（不是 6.18）在 permissive_map 和 len 之间多了
     * neveraudit_map（v6.17/v6.18 policydb.h:303，v6.12 无），两位都命中
     * 时直接全通（services.c:1158-1161）。
     * 这里用的是 se_calibrate() 实测的数据布局间距，不是函数形状分派：
     * 静态版本表只管调用 ABI，数据布局仍以实测为准，
     * 避免厂商回移版本号骗过判据。间距 32 = 中间多一个 ebitmap(16B)。
     */
    if (p_get_bit && L.perm && L.lenoff == L.perm + 32u &&
        ((int (*)(void *, se_ulong))p_get_bit)
            ((se_u8 *)pdb + L.perm + 16u, sctype)) {
        se_u32 both = se_rd32(avd + 16) | 0x2u;   /* AVD_FLAGS_NEVERAUDIT */
        se_u32 bits;

        se_wr32(avd + 16, both);
        bits = se_rd32(avd + 16);
        if (bits == 0x3u) {
            g_avd[0] = 0xffffffffu;   /* allowed 全通 */
            g_avd[1] = 0;             /* auditallow */
            g_avd[2] = 0xffffffffu;   /* auditdeny  */
            g_avd[3] = 0;             /* seqno      */
            g_avd[4] = bits;          /* flags      */
            if (allowed)
                *allowed = g_avd[0];
            if (flags)
                *flags = g_avd[4];
            if (avd5) {   /* 栈上出参（门并发防 g_avd 竞态） */
                avd5[0] = g_avd[0];
                avd5[1] = g_avd[1];
                avd5[2] = g_avd[2];
                avd5[3] = g_avd[3];
                avd5[4] = g_avd[4];
            }
            return 0;
        }
    }

    ((void (*)(void *, void *, void *, se_u32, void *, void *))p_compute_av)
        (pdb, sctx, tctx, tclass, avd, 0);

    g_avd[0] = se_rd32(avd);        /* allowed    */
    g_avd[1] = se_rd32(avd + 4);    /* auditallow */
    g_avd[2] = se_rd32(avd + 8);    /* auditdeny  */
    g_avd[3] = se_rd32(avd + 12);   /* seqno      */
    g_avd[4] = se_rd32(avd + 16);   /* flags      */

    if (allowed)
        *allowed = g_avd[0];
    if (flags)
        *flags = g_avd[4];
    if (avd5) {   /* 栈上出参（门并发防 g_avd 竞态） */
        avd5[0] = g_avd[0];
        avd5[1] = g_avd[1];
        avd5[2] = g_avd[2];
        avd5[3] = g_avd[3];
        avd5[4] = g_avd[4];
    }
    return 0;
}

/* 自检：把 su 自己的三路都跑一遍，结果写日志，不碰 live */
void se_selftest(void)
{
    se_u32 cls = 0, allowed = 0, flags = 0;
    se_u8 sctx[SE_CTX_BUF], tctx[SE_CTX_BUF];
    char buf[64];
    char out[128];
    int rc;

    memcpy(buf, "u:r:su:s0", sizeof("u:r:su:s0"));
    rc = se_parse_ctx(buf, sctx);
    pr_info("sehide: test parse rc=%d\n", rc);
    if (rc)
        return;

    memcpy(buf, "u:r:su:s0", sizeof("u:r:su:s0"));
    rc = se_parse_ctx(buf, tctx);
    if (rc) {
        pr_info("sehide: test parse2 rc=%d\n", rc);
        return;
    }

    rc = se_ctx_to_str(sctx, out, sizeof(out));
    pr_info("sehide: test ctx->str rc=%d '%s'\n", rc, out);

    if (se_class_val("process", &cls))
        return;

    rc = se_compute_av(sctx, tctx, cls, &allowed, &flags, (void *)0);
    pr_info("sehide: test av rc=%d allowed=%08x flags=%08x\n", rc, allowed, flags);
}
