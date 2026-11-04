/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_layout：标定与结构推导 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"

/* 标定结果实例（struct 定义在 sehide.h） */
struct se_calib L;

/* ---------------- 取策略二进制 ---------------- */

int se_read_policy(void **out, se_ulong *out_len)
{
    void *state;
    int rc;

    if (!p_read_policy)
        return -2;

    /*
     * 签名分界（v-fix 复审 20261104：v6.3~v6.7 tag 原始行+文件指纹校验）：
     *   4.19~v6.3（含 stable 4.19.325 / 5.10.245 / 6.1.191 / mainline v6.3）
     *     security_read_policy(state, data, len)          —— 三参
     *   v6.4 起（mainline v6.4 tag :3948 原始行实测，state 全局单例化
     *     `struct selinux_state *state = &selinux_state;`）
     *     security_read_policy(data, len)                 —— 两参
     * 旧判据 6.6 错误：当时实测了 4.19.325/5.10.245/6.1.191/6.6.161 四点
     * （全对）但漏测 6.4/6.5，从四点线性推断分界 6.6。6.4/6.5 上若按三参
     * 调两参函数，state 指针会被函数当作 data 出参 → `*len` 写坏
     * selinux_state 头 8B → Oops（内存破坏级）。
     */
    if (kver >= VERSION(6, 4, 0)) {
        rc = ((int (*)(void **, se_ulong *))p_read_policy)(out, out_len);
    } else {
        state = (void *)p_selinux_state;
        if (!state)
            return -3;
        rc = ((int (*)(void *, void **, se_ulong *))p_read_policy)(state, out, out_len);
    }

    if (rc) {
        /* v84：一次性失败诊断 —— container 活性与 slot10 现值。
         * c0=container 首 8B（5.10+ 为 sidtab*）；sN=state 第 slot 字段现值，
         * 与 calib 时的 container 对照可判定 state->policy 是否被换代/清空。 */
        se_u64 c0 = 0, s10 = 0;
        static int rp_diag;

        if (L.container && se_kptr_ok((se_u64)(se_ulong)L.container))
            se_kread(&c0, L.container, 8);
        if (L.slot < 32u)
            se_kread(&s10, (se_u8 *)state + (se_u64)L.slot * 8u, 8);
        if (rp_diag < 3) {
            rp_diag++;
            pr_info("sehide: rp fail rc=%d cont=%016llx c0=%016llx s%u=%016llx pdb=%016llx\n",
                    rc, (se_u64)(se_ulong)L.container, c0, L.slot, s10,
                    (se_u64)(se_ulong)L.pdb);
        }
        return rc;
    }
    if (!*out || !*out_len || *out_len > SE_MAX_BIN)
        return -4;
    return 0;
}

int se_ebitmap_seg(const se_u8 *p, se_u32 avail, se_u32 *out)
{
    se_u32 unit, count;
    se_u64 total;

    if (avail < 12)
        return -1;
    unit = se_rd32(p);
    count = se_rd32(p + 8);
    if (unit != 64)
        return -1;
    if (count > avail / 12)
        return -1;
    total = 12ull + (se_u64)count * 12ull;
    if (total > avail)
        return -1;
    *out = (se_u32)total;
    return 0;
}

int se_parse_hdr(const se_u8 *b, se_u32 blen, struct bin_hdr *h)
{
    se_u32 slen, off, seg;

    if (blen < 24)
        return -1;
    if (se_rd32(b) != SE_MAGIC)
        return -2;

    slen = se_rd32(b + 4);
    if (slen == 0 || slen > 64 || 8u + slen + 16u > blen)
        return -3;
    off = 8u + slen;

    h->vers = se_rd32(b + off);
    off += 16u;                       /* policyvers/config/sym_num/ocon_num */

    if (se_ebitmap_seg(b + off, blen - off, &seg))   /* policycaps */
        return -4;
    off += seg;

    h->perm_off = off;
    if (se_ebitmap_seg(b + off, blen - off, &h->perm_len))
        return -5;
    off += h->perm_len;

    /*
     * 紧跟 permissive_map 之后就是 sym_num 个 symtab 的 nprim（u32）。
     * 依据 policydb_write：写完 permissive_map 后先写 num_syms 个 nprim，
     * 再逐个写各表内容。这 8 个数在内存里必须与 symtab[i].nprim 相等，
     * 所以可以当指纹用。
     */
    h->np_off = off;
    h->sym_num = se_rd32(b + 8u + slen + 8u);
    if (h->sym_num == 0 || h->sym_num > 8u)
        return -6;
    if (off + h->sym_num * 4u > blen)
        return -7;
    return 0;
}

/* 找一段里有没有置位的 bit；返回第一个未置位的低位 type */
se_u32 se_pick_type(const se_u8 *b, const struct bin_hdr *h)
{
    const se_u8 *p = b + h->perm_off;
    se_u32 count = se_rd32(p + 8);
    se_u32 t, i;

    for (t = 1; t < 1024; t++) {
        int set = 0;

        for (i = 0; i < count; i++) {
            const se_u8 *e = p + 12u + i * 12u;
            se_u32 sb = se_rd32(e);
            se_u64 m = se_rd64(e + 4);

            if (t >= sb && t < sb + 64) {
                set = ((m >> (t - sb)) & 1ull) != 0;
                break;
            }
        }
        if (!set)
            return t;
    }
    return 0;
}

/* 构造 B'：把 permissive 段写成"空"（B 非空时）或"单 bit"（B 为空时） */
se_u8 *se_make_bprime(const se_u8 *b, se_u32 blen, const struct bin_hdr *h,
                             se_u32 type, int empty, se_u32 *out_len)
{
    se_u32 seg = empty ? 12u : 24u;
    se_u32 tail_off = h->perm_off + h->perm_len;
    se_u32 newlen, tail;
    se_u8 *nb;

    if (h->perm_len == 0 || tail_off > blen)
        return 0;
    tail = blen - tail_off;
    newlen = h->perm_off + seg + tail;

    nb = se_alloc(newlen);
    if (!nb)
        return 0;

    memcpy(nb, b, h->perm_off);
    se_wr32(nb + h->perm_off, 64);
    if (empty) {
        se_wr32(nb + h->perm_off + 4, 0);
        se_wr32(nb + h->perm_off + 8, 0);
    } else {
        se_wr32(nb + h->perm_off + 4, (type + 63u) & ~63u);
        se_wr32(nb + h->perm_off + 8, 1u);
        se_wr32(nb + h->perm_off + 12, type & ~63u);
        se_wr64(nb + h->perm_off + 16, 1ull << (type & 63u));
    }
    if (tail)
        memcpy(nb + h->perm_off + seg, b + tail_off, tail);

    *out_len = newlen;
    return nb;
}

/* 一次 policydb_read，结果拷到 out */
int se_pdb_read_copy(const se_u8 *bin, se_u32 blen, se_u8 *out, void *scratch)
{
    se_u8 pf[16];   /* struct policy_file { char *data; size_t len; } —— 4.19~6.18 一致 */
    int rc;

    if (!p_pdb_read)
        return -1;

    memset(scratch, 0, SE_PDB_BUF);
    se_wr64(pf, (se_u64)(se_ulong)bin);
    se_wr64(pf + 8, blen);

    rc = ((int (*)(void *, void *))p_pdb_read)(scratch, pf);
    if (rc)
        return rc;

    memcpy(out, scratch, SE_PDB_BUF);

    /*
     * policydb_read 内部建了一整套子分配：8 个 symtab 的 hashtab、avtab 的
     * flex_array 和每个规则节点（这台机器 66242 条，光节点就 ~1.6MB）、
     * ocontext、genfs…… 只把外层 scratch free 掉等于每次标定漏掉好几 MB。
     * early-init 阶段内存本来就紧，这里必须按内核自己的析构走一遍。
     */
    if (p_pdb_destroy)
        ((void (*)(void *))p_pdb_destroy)(scratch);
    return 0;
}

/*
 * 差分定位 permissive_map：找相邻两块 8 字节，两块都变了，且
 *   A 一侧为 0、另一侧是内核指针（ebitmap.node）
 *   B 高 32 位为 0（ebitmap.highbit）
 */
int se_probe(const se_u8 *b, se_u32 blen, const se_u8 *bp, se_u32 bplen, se_u32 *off_out)
{
    se_u8 *m1 = 0, *m3 = 0, *c1 = 0, *c3 = 0;
    se_u32 hits = 0, hit_off = 0, off;
    int rc = -1;

    m1 = se_alloc(SE_PDB_BUF);
    m3 = se_alloc(SE_PDB_BUF);
    c1 = se_alloc(SE_PDB_BUF);
    c3 = se_alloc(SE_PDB_BUF);
    if (!m1 || !m3 || !c1 || !c3)
        goto out;

    rc = se_pdb_read_copy(b, blen, c1, m1);
    if (rc)
        goto out;
    rc = se_pdb_read_copy(bp, bplen, c3, m3);
    if (rc)
        goto out;

    for (off = 0; off + 16u <= SE_PDB_BUF; off += 8u) {
        se_u64 n1 = se_rd64(c1 + off), n3 = se_rd64(c3 + off);
        se_u64 h1 = se_rd64(c1 + off + 8), h3 = se_rd64(c3 + off + 8);
        se_u64 node, hb;

        if (n1 == n3 || h1 == h3)
            continue;
        if (n1 && n3)
            continue;
        node = n1 ? n1 : n3;
        if ((node >> 48) != 0xffffull)
            continue;
        hb = h1 ? h1 : h3;
        if ((hb >> 32) != 0)
            continue;

        hits++;
        hit_off = off;
    }

    L.probe_hits = hits;

    if (hits != 1) {
        rc = -1;
        goto out;
    }
    *off_out = hit_off;
    rc = 0;
out:
    se_free(m1); se_free(m3); se_free(c1); se_free(c3);
    return rc;
}

/* ---------------- 锚点定位 live policydb ---------------- */

/*
 * policydb 尾部固定：policycaps(16) -> permissive_map(16) -> len -> policyvers
 * （4.19 policydb.h:299-306，6.1 同序；6.18 中间多 neveraudit_map，故间距 16 或 32）
 * 于是 x + perm + gap 处必然是 len，+8 处必然是 policyvers。
 * policyvers 与二进制头同源（policydb_read 直接读入），必然相等。
 */
int se_anchor(const se_u8 *p, se_u32 vers, se_u32 *gap_out, se_u64 *len_out)
{
    se_u64 node = se_rd64(p);
    se_u32 hb = se_rd32(p + 8);
    se_u32 gap;

    for (gap = 16u; gap <= 32u; gap += 16u) {
        se_u64 len = se_rd64(p + gap);
        se_u32 pv = se_rd32(p + gap + 8u);

        if (pv != vers)
            continue;
        if (len < (1ull << 16) || len > (se_u64)SE_MAX_BIN)
            continue;
        if (node == 0) {
            if (hb != 0)
                continue;
        } else if ((node >> 48) != 0xffffull || hb == 0) {
            continue;
        }
        *gap_out = gap;
        *len_out = len;
        return 1;
    }
    return 0;
}

void *se_scan_pdb(void *base, se_u32 range, se_u32 blen, se_u32 *off_out, se_u32 *gap_out)
{
    se_u32 off, n = 0, n_blen = 0, off_b = 0, gap_b = 0, off_o = 0, gap_o = 0;
    se_u8 tmp[48];

    for (off = 0; off + 8u <= range; off += 8u) {
        se_u32 gap;
        se_u64 len;

        if (se_kread(tmp, (se_u8 *)base + off + L.perm, sizeof(tmp)))
            continue;
        if (!se_anchor(tmp, L.vers, &gap, &len))
            continue;

        n++;
        off_o = off;
        gap_o = gap;
        if (blen && len == (se_u64)blen) {
            n_blen++;
            off_b = off;
            gap_b = gap;
        }
    }

    if (n_blen == 1) {
        *off_out = off_b;
        *gap_out = gap_b;
        return (se_u8 *)base + off_b;
    }
    if (!n_blen && n == 1) {
        *off_out = off_o;
        *gap_out = gap_o;
        return (se_u8 *)base + off_o;
    }
    return 0;
}

int se_locate(void)
{
    void *state = (void *)p_selinux_state;
    se_u32 i;

    if (!state)
        return -1;

    for (i = 0; i < 32; i++) {
        se_u64 v;
        se_u32 off = 0, gap = 0;
        void *pdb;

        if (se_kread(&v, (se_u8 *)state + i * 8u, 8))
            break;
        if ((v >> 48) != 0xffffull || v == 0xffffffffffffffffull)
            continue;

        pdb = se_scan_pdb((void *)(se_ulong)v, 2048u, L.bin_len, &off, &gap);
        if (!pdb)
            continue;

        L.slot = i;
        L.pdb_off = off;
        L.container = (void *)(se_ulong)v;
        L.pdb = pdb;
        L.lenoff = L.perm + gap;

        /*
         * sidtab 在哪：
         *   5.10+ : struct selinux_policy { struct sidtab *sidtab; struct policydb; ... }
         *           policydb 紧跟指针之后（pdb_off == 8），sidtab 是解引用得到。
         *   4.19/5.4 : struct selinux_ss { struct sidtab sidtab; struct policydb; ... }
         *           sidtab 内嵌在容器开头。
         */
        if (L.pdb_off == sizeof(void *)) {
            se_u64 sp = 0;

            if (se_kread(&sp, L.container, 8))
                return -3;
            if ((sp >> 48) != 0xffffull)
                return -4;
            L.sidtab = (void *)(se_ulong)sp;
        } else {
            L.sidtab = L.container;
        }
        return 0;
    }
    return -2;
}

/* ---------------- su 的 type ---------------- */

/*
 * string_to_context_struct 会原地把 ':' 改成 '\0'，所以必须传可写副本。
 * 它把结果填进 struct context，前四个 u32 是 user/role/type/len（4.19~6.18 同）。
 */
/* su 的完整 context，探针拿它当 compute_av 的入参，避免用零填充的假 context */
se_u8 g_su_ctx[SE_CTX_BUF];
int g_su_ctx_ok;

int se_ctx_type(const char *s, se_u32 *type_out)
{
    char buf[64];
    se_u8 ctx[SE_CTX_BUF];
    se_ulong n = strlen(s);
    int rc;

    if (!p_str_to_ctx || n >= sizeof(buf))
        return -1;

    memcpy(buf, s, n + 1);
    memset(ctx, 0, sizeof(ctx));

    /*
     * (pol, sidtab, scontext, ctx, def_sid) —— 全版本五参，理由见渲染器那段注释。
     * 这里就是 4.19 上把 x3(len=9) 当 ctx 崩掉 memset(0x9,0,0x50) 的地方。
     */
    rc = ((int (*)(void *, void *, char *, void *, se_u32))p_str_to_ctx)
        (L.pdb, L.sidtab, buf, ctx, SECSID_NULL);

    if (rc)
        return rc;

    *type_out = se_rd32(ctx + 8);   /* struct context { u32 user, role, type, len; ... } */
    memcpy(g_su_ctx, ctx, SE_CTX_BUF);
    g_su_ctx_ok = 1;
    return 0;
}

/*
 * 从 policydb_read 的机器码里直接读出 te_avtab 的偏移。
 *
 * policydb_read 里一定有一句 avtab_read(&p->te_avtab, fp, p)
 * （4.19 policydb.c:2449，6.1 :2542），编译出来是
 *     add  x0, xN, #imm      ; x0 = &p->te_avtab
 *     mov  x1, ...           ; fp
 *     mov  x2, ...           ; p
 *     bl   avtab_read
 * imm 是编译期常量，等于 offsetof(struct policydb, te_avtab)，跟结构体定义
 * 一一对应，不用猜、也不受 vendor 改结构影响 —— 比扫内存稳。
 *
 * AArch64 编码：BL = 0x94000000 | imm26；ADD(imm, 64bit) = 0x91000000，
 * imm12 在 bit21:10，shift 标志在 bit22。
 */
/*
 * 让内核自己把 &policydb->te_avtab 交出来。
 *
 * context_struct_compute_av 内部一定会执行
 *     avtab_search_node(&policydb->te_avtab, &avkey)
 * （4.19 services.c:667，6.1 services.c:1067 同一句）。把这个调用临时
 * inline hook 掉，然后主动跑一次 compute_av，第一个参数就是 te_avtab 的
 * 地址 —— 是内核按自己的结构体定义算出来的，没有任何推导。
 * 测完立刻 unhook，运行期不留钩子。
 *
 * hook/unhook 是 KernelPatch 自己的 API（base/hook.c:612/638，
 * KP_EXPORT_SYMBOL(hook)）。这里不直接引用符号，而是用 KP 导出的
 * symbol_lookup_name 运行期查 —— 万一这版 KP 没导出，只是探针不可用，
 * 不会让整个模块装载失败。
 */

void *volatile g_seen_avtab;
void *g_avnode_orig;

void *se_avnode_probe(void *h, const void *key)
{
    void *orig = g_avnode_orig;

    if (!g_seen_avtab)
        g_seen_avtab = h;

    /*
     * hook() 返回之前 g_avnode_orig 还是空，这段窗口里别的 CPU 也可能进来。
     * 宁可不转发（等于"没查到规则"，最坏是这一次判定少给权限），
     * 也不能拿空指针去调用。
     */
    if (!orig)
        return 0;

    return ((void *(*)(void *, const void *))orig)(h, key);
}

int se_probe_avtab(void)
{
    se_u8 sctx[SE_CTX_BUF], tctx[SE_CTX_BUF], avd[64];
    void *bak = 0;
    se_u32 type = L.su_type ? L.su_type : 1u;
    se_ulong off;

    if (!p_avtab_node_search || !p_compute_av || !p_kp_hook || !p_kp_unhook)
        return -1;

    memset(sctx, 0, sizeof(sctx));
    memset(tctx, 0, sizeof(tctx));
    memset(avd, 0, sizeof(avd));
    if (g_su_ctx_ok) {
        memcpy(sctx, g_su_ctx, SE_CTX_BUF);
        memcpy(tctx, g_su_ctx, SE_CTX_BUF);
    } else {
        se_wr32(sctx + 8u, type);      /* struct context { user, role, type, len } */
        se_wr32(tctx + 8u, type);
    }

    g_seen_avtab = 0;
    g_avnode_orig = 0;
    if (((int (*)(void *, void *, void **))p_kp_hook)
            ((void *)p_avtab_node_search, (void *)se_avnode_probe, &bak) != 0)
        return -2;
    g_avnode_orig = bak;

    /* class 1 一定存在（4.19 的 class 值是 1..nprim 连续），只为把调用走进去 */
    ((void (*)(void *, void *, void *, se_u32, void *, void *))p_compute_av)
        (L.pdb, sctx, tctx, 1u, avd, 0);

    ((void (*)(void *))p_kp_unhook)((void *)p_avtab_node_search);

    if (!g_seen_avtab)
        return -3;

    off = (se_ulong)g_seen_avtab - (se_ulong)L.pdb;
    if (off < 16u || off > SE_PDB_BUF)
        return -4;

    L.avtab_off = (se_u32)off;
    return 0;
}

/*
 * 在 caller 的机器码里找指向 callee 的 BL，再回溯最多 16 条指令找
 *   add x0, xN, #imm
 * 这里的 imm 就是 struct 里那个成员的编译期偏移。命中即写回 L.avtab_off。
 */
int se_off_from_caller(se_ulong caller, se_ulong callee, se_u32 max_bytes)
{
    se_u8 buf[256];
    se_u32 base, n;
    se_ulong bl_at = 0;
    int found = 0;

    for (base = 0; base < max_bytes && !found; base += sizeof(buf)) {
        if (se_kread(buf, (se_u8 *)caller + base, sizeof(buf)))
            break;
        for (n = 0; n + 4u <= sizeof(buf); n += 4u) {
            se_u32 insn = se_rd32(buf + n);
            se_s32 imm26;
            se_ulong tgt;

            if ((insn & 0xFC000000u) != 0x94000000u)
                continue;
            imm26 = (se_s32)(insn & 0x03FFFFFFu);
            if (imm26 & 0x02000000)
                imm26 -= 0x04000000;
            tgt = caller + base + n + (se_ulong)((se_s64)imm26 * 4);
            if (tgt == callee) {
                bl_at = caller + base + n;
                found = 1;
                break;
            }
        }
    }
    if (!found)
        return -1;

    for (n = 1; n <= 16u && n * 4u <= bl_at - caller; n++) {
        se_u32 insn = 0;
        se_u32 imm12, rn, rd, sh;

        if (se_kread(&insn, (se_u8 *)(bl_at - n * 4u), 4))
            return -2;
        if ((insn & 0xFF800000u) != 0x91000000u)
            continue;
        rd = insn & 0x1Fu;
        rn = (insn >> 5) & 0x1Fu;
        imm12 = (insn >> 10) & 0xFFFu;
        sh = (insn >> 22) & 1u;
        if (rd != 0u || rn == 31u)
            continue;
        if (sh)
            imm12 <<= 12;
        if (imm12 < 16u || imm12 > 8192u)
            continue;
        L.avtab_off = imm12;
        return 0;
    }
    return -3;
}

int se_te_avtab_from_code(void)
{
    /*
     * 三处交叉验证，谁先给出合格值就用谁：
     *   A. policydb_read 里 avtab_read(&p->te_avtab, ...)
     *   B. context_struct_compute_av 里 avtab_search_node(&policydb->te_avtab, ...)
     *   C. 同上但用 avtab_search（4.19 的 compute_av 用的是它）
     * imm 都是编译期常量，不随 vendor 改结构而失真。
     */
    if (p_pdb_read && p_avtab_read &&
        !se_off_from_caller(p_pdb_read, p_avtab_read, 16384u))
        return 0;
    if (p_compute_av && p_avtab_node_search &&
        !se_off_from_caller(p_compute_av, p_avtab_node_search, 16384u))
        return 0;
    if (p_compute_av && p_avtab_search &&
        !se_off_from_caller(p_compute_av, p_avtab_search, 16384u))
        return 0;
    return -1;
}

/*
 * 兜底：扫 avtab 的形态。
 *
 * avtab_alloc 保证的不变式（4.19 avtab.c:311-330，6.1 :322-323）：
 *   nslot 是 2 的幂，mask == nslot - 1
 * 加上 htable 必须是内核指针、nel 在合理范围，四个条件同时命中的位置就是 avtab。
 */
int se_scan_avtab(const se_u8 *copy)
{
    se_u32 off;

    for (off = 8u; off + 24u <= SE_PDB_BUF && off < 1024u; off += 8u) {
        se_u64 ht = se_rd64(copy + off);
        se_u32 nel = se_rd32(copy + off + 8u);
        se_u32 nslot = se_rd32(copy + off + 12u);
        se_u32 mask = se_rd32(copy + off + 16u);

        if ((ht >> 48) != 0xffffull || ht == 0xffffffffffffffffull)
            continue;
        if (nel == 0 || nel > (1u << 22))
            continue;
        if (nslot < 8u || nslot > (1u << 24) || (nslot & (nslot - 1u)))
            continue;
        if (mask != nslot - 1u)
            continue;

        L.avtab_off = off;
        L.avtab_nel = nel;
        return 0;
    }
    return -1;
}

/*
 * 由 te_avtab 反推 symtab[0]：
 *   symtab[SYM_NUM] -> sym_val_to_name[SYM_NUM]（8 个指针）
 *   -> class/role/user/type_val_to_struct（4 个指针）-> te_avtab
 * 合计 12 个 8 字节 = 96，顺序在 4.19~6.18 一致（4.19 policydb.h:239-264）。
 * 所以 base = avtab_off - 96 - sym_num*stride，stride 由 hashtab 形态决定：
 *   4.x  : symtab{ struct hashtab *table; u32 nprim; }   nprim@+8 , stride 16
 *   5.4+ : symtab{ struct hashtab  table; u32 nprim; }   nprim@+16, stride 24
 * 判据只要求"每个 symtab 的首字段是内核指针、nprim 合理"，不再比对二进制。
 */
int se_symtab_from_avtab(const se_u8 *copy)
{
    static const se_u32 strides[] = { 16u, 24u, 32u, 40u, 48u };
    se_u32 si;

    for (si = 0; si < sizeof(strides) / sizeof(strides[0]); si++) {
        se_u32 stride = strides[si];
        se_u32 need = 96u + L.sym_num * stride;
        se_u32 base;
        se_u32 i;
        int ok = 1;

        if (L.avtab_off < need)
            continue;
        base = L.avtab_off - need;

        for (i = 0; i < L.sym_num; i++) {
            se_u64 tbl = se_rd64(copy + base + i * stride);
            se_u32 nprim = se_rd32(copy + base + i * stride + stride - 8u);

            /*
             * v83：htable 允许 NULL。6.1 GKI 实证（fp_br21 dump）：
             * levels 表 htable=NULL（空表）位于 stride=24 网格中间，
             * 旧判据"每表首字段必须 0xffff 指针"在它身上 break，
             * 把正确的 stride=24/base=16 整个否掉 -> derive miss ->
             * 引擎半残（symtab 未标定 -> inbound skip=27 -> su_sid=0）。
             * 空表（htable=NULL）与满表（0xffff 指针）皆为合法形态；
             * 0xffffffffffffffff 仍为非法（全 F 是垃圾特征）。
             */
            if (tbl && (tbl >> 48) != 0xffffull) {
                ok = 0;
                break;
            }
            if (tbl == 0xffffffffffffffffull) {
                ok = 0;
                break;
            }
            /*
             * nprim 允许为 0：bools 表（SYM_BOOLS）在没开任何布尔时就是空的。
             * 4.19 实测 nprim = 5/103/4/3359/1/0/1/1024；
             * 6.1 GKI 实测（fp_br21 dump）：5/107/4/5118/1/0/1/1024
             * （SYM_TYPES=3，Android 重排，types 表 nprim=5118 >= su_type+1）。
             */
            if (nprim > 0x100000u) {
                ok = 0;
                break;
            }
        }
        if (!ok)
            continue;

        L.symtab_off = base;
        L.symtab_stride = stride;
        return 0;
    }
    return -1;
}

/* derive 失败时把副本前 256 字节打出来，便于对结构 —— 只在失败时用 */
void se_dump_pdb(const se_u8 *p)
{
    se_u32 i;

    for (i = 0; i < 256u; i += 16u)
        pr_info("sehide: pdb+%03x %016llx %016llx\n", i,
                (unsigned long long)se_rd64(p + i),
                (unsigned long long)se_rd64(p + i + 8u));
}

/* 在副本上验证 L.avtab_off 确实是 avtab（avtab_alloc 的四条不变式） */
int se_check_avtab(const se_u8 *copy)
{
    se_u32 off = L.avtab_off;
    se_u32 nel, nslot, mask;

    if (off < 16u || off + 24u > SE_PDB_BUF)
        return -1;
    nel = se_rd32(copy + off + 8u);
    nslot = se_rd32(copy + off + 12u);
    mask = se_rd32(copy + off + 16u);

    if (nel == 0 || nel > (1u << 22))
        return -2;
    if (nslot < 8u || nslot > (1u << 24) || (nslot & (nslot - 1u)))
        return -3;
    if (mask != nslot - 1u)
        return -4;

    L.avtab_nel = nel;
    return 0;
}

/* 拿一份 policydb 副本，做上面两步推导，然后销毁副本 */
int se_derive_layout(void)
{
    void *b = 0;
    se_ulong blen = 0;
    se_u8 *scratch = 0;
    int rc;

    rc = se_read_policy(&b, &blen);
    if (rc)
        return rc;

    scratch = se_alloc(SE_PDB_BUF);
    if (!scratch) {
        se_free(b);
        return -1;
    }

    memset(scratch, 0, SE_PDB_BUF);
    {
        se_u8 pf[16];

        se_wr64(pf, (se_u64)(se_ulong)b);
        se_wr64(pf + 8, (se_u32)blen);
        rc = ((int (*)(void *, void *))p_pdb_read)(scratch, pf);
    }
    se_free(b);
    if (rc) {
        se_free(scratch);
        return rc;
    }

    /*
     * 推导顺序（v56 恢复 v53 实测全绿顺序）：
     * 1) inline hook 探针（内核自己交出 avtab 地址，最可靠——v53 在 4.19
     *    实测全绿的路径）。代价是装机早期写一次 .text：MKP/写保护机型
     *    当场死（v12 实证）——v55 的 pstore 崩溃证明下游 role_bits/inbound
     *    消费扫描值的风险远高于探针：错位值骗过不变式校验后写坏 live。
     *    非 MKP 机型（4.19 vendor 全系）走此路径；MKP 机的安全探针另案。
     * 2) 反解（纯读）：探针不可用时。
     * 3) 形态扫描（纯读）：最后兜底。
     */
    rc = se_probe_avtab();
    if (!rc) {
        rc = se_check_avtab(scratch);
        if (!rc)
            pr_info("sehide: avtab by probe off=%u nel=%u\n", L.avtab_off, L.avtab_nel);
        else
            pr_info("sehide: probe off=%u rejected rc=%d\n", L.avtab_off, rc);
    } else {
        pr_info("sehide: probe unavailable rc=%d\n", rc);
    }

    if (rc) {
        L.avtab_off = 0;
        rc = se_te_avtab_from_code();
        if (!rc) {
            rc = se_check_avtab(scratch);
            if (!rc)
                pr_info("sehide: avtab by code off=%u nel=%u\n", L.avtab_off, L.avtab_nel);
            else
                pr_info("sehide: code off=%u rejected rc=%d\n", L.avtab_off, rc);
        }
    }

    /* 3) 兜底：扫 avtab 的形态（avtab_alloc 四条不变式，纯读） */
    if (rc) {
        L.avtab_off = 0;
        rc = se_scan_avtab(scratch);
        if (!rc)
            pr_info("sehide: avtab by scan off=%u nel=%u\n", L.avtab_off, L.avtab_nel);
    }

    if (!rc)
        rc = se_symtab_from_avtab(scratch);
    if (rc)
        pr_info("sehide: derive miss rc=%d avtab_off=%u nel=%u\n",
                rc, L.avtab_off, L.avtab_nel);
    if (rc)
        se_dump_pdb(scratch);

    /* 同上：这份 scratch 也是 policydb_read 建出来的，内部子分配要一起释放 */
    if (p_pdb_destroy)
        ((void (*)(void *))p_pdb_destroy)(scratch);
    se_free(scratch);
    return rc;
}

/* ---------------- 入口 ---------------- */

int se_calibrate(void)
{
    void *b = 0;
    se_ulong blen = 0;
    se_u8 *bp = 0;
    se_u32 bplen = 0, perm = 0, type = 0;
    struct bin_hdr h;
    int rc;

    memset(&L, 0, sizeof(L));

    L.kver_major = kver >> 16;
    L.kver_minor = (kver >> 8) & 0xff;

    rc = se_read_policy(&b, &blen);
    if (rc) {
        pr_info("sehide: read_policy rc=%d\n", rc);
        return rc;
    }
    L.bin_len = (se_u32)blen;

    rc = se_parse_hdr((se_u8 *)b, (se_u32)blen, &h);
    if (rc) {
        pr_info("sehide: header rc=%d\n", rc);
        se_free(b);
        return rc;
    }
    L.vers = h.vers;
    L.sym_num = h.sym_num;
    /*
     * 注意：这里不再读二进制里的 nprim 当指纹。二进制格式是
     * {nprim, nel} 交错 + nel 个变长条目（4.19 policydb.c:2420-2432），
     * 连续读 8 个 u32 得到的是 [nprim0, nel0, nprim1, nel1 ...]，
     * 不是 8 个 nprim。symtab/avtab 的定位改由 se_scan_avtab 反推。
     */

    type = se_pick_type((se_u8 *)b, &h);
    if (!type) {
        pr_info("sehide: no free type bit\n");
        se_free(b);
        return -5;
    }

    bp = se_make_bprime((se_u8 *)b, (se_u32)blen, &h, type, h.perm_len != 12u, &bplen);
    if (!bp) {
        pr_info("sehide: bprime failed\n");
        se_free(b);
        return -6;
    }

    rc = se_probe((se_u8 *)b, (se_u32)blen, bp, bplen, &perm);
    se_free(bp);
    se_free(b);
    if (rc) {
        pr_info("sehide: probe rc=%d hits=%u\n", rc, L.probe_hits);
        return -7;
    }
    L.perm = perm;

    rc = se_locate();
    if (rc) {
        pr_info("sehide: locate rc=%d\n", rc);
        return rc;
    }

    L.ok = 1;
    pr_info("sehide: calib ok vers=%u len=%u perm=%u lenoff=%u slot=%u pdboff=%u\n",
            L.vers, L.bin_len, L.perm, L.lenoff, L.slot, L.pdb_off);
    return 0;
}
