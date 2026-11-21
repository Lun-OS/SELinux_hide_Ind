/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_policydb：规则原语与副本生命周期 */
#include "sehide.h"

/* ---------------- 写 live 的 permissive 位 ---------------- */


int se_set_permissive(void *policydb, se_u32 perm_off, se_u32 type)
{
    if (!p_ebitmap_set)
        return -1;

    /* ebitmap_set_bit(struct ebitmap *, unsigned long / u32, int) */
    return ((int (*)(void *, se_ulong, int))p_ebitmap_set)
        ((se_u8 *)policydb + perm_off, (se_ulong)type, 1);
}

/* ---------------- live len 维护 ----------------
 *
 * 6.1 起 put_entry 带溢出检查（policydb.h:377：len > fp->len 返回
 * -EINVAL）；4.19 无检查。apd 的 PostFsData 经 sel_open_policy →
 * security_read_policy → policydb_write 重序列化 live，输出缓冲上限 =
 * policydb.len（加载时的原始 blob 长度）。我们往 live 加的每条 avtab
 * 规则（重序列化 12B）与首次置位的 permissive 位（+12B）都让重序列化
 * 变长 —— 超过 len 即 -EINVAL，apd 的 SePolicy::from_file 失败、
 * on_post_data_fs 静默退出。4.19 无检查所以不易暴露。
 *
 * 修复：live 侧每次有效写入同步把 policydb.len 增加对应增量，保证
 * policydb_write 的缓冲恒够；L.bin_len 同步（否则 len 指纹失配引发
 * recal 风暴）。apd 注入触发的真重载整体换代 live（len 由内核
 * policydb_read 重设），随后的 recal 再次维护 len——良性循环。副本由
 * 内核 policydb_read 构建、无人对副本 policydb_write，len 无需维护。
 */

/* avtab = {htable 8B, nel 4B, nslot 4B, mask 4B}（4.19/6.1 同构），
 * nel 在 avtab+8。 */
static se_u32 se_avtab_nel(void *pdb)
{
    se_u32 nel = 0;

    if (!pdb || !L.avtab_off)
        return 0;
    se_kread(&nel, (se_u8 *)pdb + L.avtab_off + 8u, 4u);
    return nel;
}

static int se_len_grow(int bytes)
{
    se_u64 len = 0;

    if (!bytes || !L.pdb || !L.lenoff)
        return -1;
    if (se_kread(&len, (se_u8 *)L.pdb + L.lenoff, 8u))
        return -1;
    *(volatile se_u64 *)((se_u8 *)L.pdb + L.lenoff) =
        len + (se_u64)bytes;
    L.bin_len += (se_u32)bytes;
    return 0;
}

void *se_sym_search(void *sym, const char *name)
{
    /* 内核形态守卫：坏指针（如 build_copy 之前查未初始化的 L.copy）
     * 会让内核 symtab_search 解引用 NULL+offset 直接 Oops 死机。
     * 坏指针一律返回 0，调用方按 -2 fail-closed，绝不让坏指针进内核。 */
    if (!sym || ((se_ulong)sym >> 48) != 0xffffull)
        return 0;
    if (p_symtab_search)
        return (void *)((unsigned long (*)(void *, const char *))p_symtab_search)
            (sym, name);
    if (p_hashtab_search) {
        se_u64 tbl = 0;

        if (se_kread(&tbl, sym, 8) || !tbl || (tbl >> 48) != 0xffffull)
            return 0;
        return (void *)((unsigned long (*)(void *, const void *))p_hashtab_search)
            ((void *)(se_ulong)tbl, name);
    }
    return 0;
}

int se_type_val_at(void *pdb, const char *name, se_u32 *out)
{
    void *sym = (se_u8 *)pdb + L.symtab_off + 3u * L.symtab_stride;
    void *d;

    if (!L.symtab_off || !L.symtab_stride)
        return -1;
    d = se_sym_search(sym, name);
    if (!d || ((se_ulong)d >> 48) != 0xffffull)
        return -2;
    if (se_kread(out, d, 4))
        return -3;
    if (*out == 0 || *out > 0xffffu)
        return -4;
    return 0;
}

int se_class_val_at(void *pdb, const char *name, se_u32 *out)
{
    void *sym = (se_u8 *)pdb + L.symtab_off + 1u * L.symtab_stride;
    void *d;

    if (!L.symtab_off || !L.symtab_stride)
        return -1;
    d = se_sym_search(sym, name);
    if (!d || ((se_ulong)d >> 48) != 0xffffull)
        return -2;
    if (se_kread(out, d, 4))
        return -3;
    if (*out == 0 || *out > 0xffffu)
        return -4;
    return 0;
}

int se_type_val(const char *name, se_u32 *out)
{
    return se_type_val_at(L.pdb, name, out);
}

int se_class_val(const char *name, se_u32 *out)
{
    /* 查出厂副本而非 live——live 上 LSP 新增的类（快照没有）返回
     * -2，由门转成出厂同款 EINVAL；快照内类编号与快照 compute_av 自洽 */
    return se_class_val_at(L.copy, name, out);
}


/*
 * 类名 + 权限名 -> 位掩码。
 * 用内核自己的 security_get_permissions()：它把该类的权限名按 value-1 落进数组
 * （6.1 services.c:3455 起，*nperms = permissions.nprim），所以第 i 项就是 1<<i 位。
 * 这样完全不用碰 class_datum.permissions 的内部布局。
 */
/*
 * security_get_permissions 把权限名 kstrdup 出来放进数组
 * （6.1 services.c: get_permissions_callback 里 kstrdup），
 * 所以数组本身和每个字符串都要释放。
 */
void se_free_perms(char **perms, se_u32 n)
{
    se_u32 i;

    if (!perms)
        return;
    if (p_kfree) {
        for (i = 0; i < n && i < 256u; i++) {
            se_u64 p = 0;

            if (se_kread(&p, (se_u8 *)perms + i * 8u, 8))
                break;
            if (p && (p >> 48) == 0xffffull)
                ((void (*)(const void *))p_kfree)((void *)(se_ulong)p);
        }
        ((void (*)(const void *))p_kfree)(perms);
    }
}

int se_perm_mask(const char *cls, const struct se_rule *r, se_u32 *out)
{
    void *first = (kver >= SE_KVER_510) ? L.container : (void *)p_selinux_state;
    char **perms = 0;
    se_u32 n = 0, i, mask = 0;
    int rc;

    if (!p_get_perms)
        return -1;

    rc = ((int (*)(void *, char *, char ***, se_u32 *))p_get_perms)
        (first, (char *)cls, &perms, &n);
    if (rc || !perms)
        return -2;

    if (!r->p0) {
        mask = (n >= 32u) ? 0xffffffffu : ((1u << n) - 1u);
    } else {
        const char *want[5];

        want[0] = r->p0; want[1] = r->p1; want[2] = r->p2;
        want[3] = r->p3; want[4] = r->p4;

        for (i = 0; i < n && i < 32u; i++) {
            se_u64 nm = 0;
            char nb[64];
            se_u32 k;

            if (se_kread(&nm, (se_u8 *)perms + i * 8u, 8) || !nm)
                continue;
            memset(nb, 0, sizeof(nb));
            if (se_kread(nb, (void *)(se_ulong)nm, sizeof(nb) - 1))
                continue;
            for (k = 0; k < 5u; k++) {
                if (want[k] && se_streq(nb, want[k]))
                    mask |= 1u << i;
            }
        }
        if (!mask) {
            se_free_perms(perms, n);
            return -3;
        }
    }

    se_free_perms(perms, n);
    *out = mask;
    return 0;
}

/*
 * 单权限名版位掩码（改① 的 allow/deny 用）。与 se_perm_mask 共用
 * security_get_permissions 路径 —— 该路径查的是 live 的类/权限定义
 * （类权限集合与副本一致是常态；外部 blob 改类定义时该命令按失败处理）。
 */
static int se_perm_mask_shared(const char *cls, const char **want, se_u32 nwant, se_u32 *out)
{
    void *first = (kver >= SE_KVER_510) ? L.container : (void *)p_selinux_state;
    char **perms = 0;
    se_u32 n = 0, i, mask = 0;

    if (!p_get_perms)
        return -1;

    {
        int rc = ((int (*)(void *, char *, char ***, se_u32 *))p_get_perms)
            (first, (char *)cls, &perms, &n);

        if (rc || !perms)
            return -2;
    }

    if (!nwant) {
        mask = (n >= 32u) ? 0xffffffffu : ((1u << n) - 1u);
    } else {
        for (i = 0; i < n && i < 32u; i++) {
            se_u64 nm = 0;
            char nb[64];
            se_u32 k;

            if (se_kread(&nm, (se_u8 *)perms + i * 8u, 8) || !nm)
                continue;
            memset(nb, 0, sizeof(nb));
            if (se_kread(nb, (void *)(se_ulong)nm, sizeof(nb) - 1))
                continue;
            for (k = 0; k < nwant; k++) {
                if (want[k] && se_streq(nb, want[k]))
                    mask |= 1u << i;
            }
        }
        if (!mask) {
            se_free_perms(perms, n);
            return -3;
        }
    }

    se_free_perms(perms, n);
    *out = mask;
    return 0;
}

int se_perm_mask_name(void *pdb, const char *cls, const char *perm, se_u32 *out)
{
    (void)pdb;
    return se_perm_mask_shared(cls, &perm, perm ? 1u : 0u, out);
}



/* ---------------- 副本 ---------------- */

/* 把 pdb 的某条 allow 规则写进去（pdb 可以是 live，也可以是副本） */
int se_add_allow_at(void *pdb, se_u32 src, se_u32 tgt, se_u32 cls, se_u32 bits)
{
    void *avtab = (se_u8 *)pdb + L.avtab_off;
    se_u8 key[8];
    se_u8 dat[8];
    void *node;

    key[0] = (se_u8)src;  key[1] = (se_u8)(src >> 8);
    key[2] = (se_u8)tgt;  key[3] = (se_u8)(tgt >> 8);
    key[4] = (se_u8)cls;  key[5] = (se_u8)(cls >> 8);
    key[6] = 0x01;        key[7] = 0x00;
    memset(dat, 0, sizeof(dat));
    se_wr32(dat, bits);

    if (p_avtab_node_search) {
        /*
         * avtab_search_node 从 4.19 到 6.18 都返回 struct avtab_node *
         * （4.19 avtab.h:113），node+8 就是 datum.u.data。
         */
        node = (void *)((unsigned long (*)(void *, void *))p_avtab_node_search)(avtab, key);
        if (node && ((se_ulong)node >> 48) == 0xffffull) {
            volatile se_u32 *p = (volatile se_u32 *)((se_u8 *)node + 8u);

            *p |= bits;
            return 0;
        }
    } else if (p_avtab_search) {
        /*
         * 退回 avtab_search 时返回值语义分叉：
         *   4.19/5.x 返回 struct avtab_datum *（key 在它前面 8 字节，4.19 avtab.h:96）
         *   6.x      返回 struct avtab_node *
         * 用"前 8 字节是否等于我们要的 key"来判定，不猜版本。
         */
        void *r = (void *)((unsigned long (*)(void *, void *))p_avtab_search)(avtab, key);

        if (r && ((se_ulong)r >> 48) == 0xffffull) {
            se_u8 k[8];

            if (!se_kread(k, (se_u8 *)r - 8u, 8) && se_memeq(k, key, 8)) {
                volatile se_u32 *p = (volatile se_u32 *)r;

                *p |= bits;
                return 0;
            }
            if (!se_kread(k, r, 8) && se_memeq(k, key, 8)) {
                volatile se_u32 *p = (volatile se_u32 *)((se_u8 *)r + 8u);

                *p |= bits;
                return 0;
            }
        }
    }
    if (!p_avtab_add)
        return -1;
    /*
     * avtab_insert_nonunique 返回的是 struct avtab_node *（4.19 avtab.c:153-181，
     * 6.1 同样），只有 NULL 才是失败。以前按 int 收，指针被当成错误码，
     * 于是"插入成功"也被判失败，inbound 规则全部 skip —— 这是规则写了却
     * 不生效的直接原因。
     */
    return ((void *(*)(void *, void *, void *))p_avtab_add)(avtab, key, dat) ? 0 : -1;
}

/*
 * se_add_allow_at 的对偶 —— deny 语义。已存在节点则把权限位清掉；
 * 不存在节点即无事可做（内核 deny 语义等价）。
 */
int se_clear_allow_at(void *pdb, se_u32 src, se_u32 tgt, se_u32 cls, se_u32 bits)
{
    void *avtab = (se_u8 *)pdb + L.avtab_off;
    se_u8 key[8];
    void *node;

    key[0] = (se_u8)src;  key[1] = (se_u8)(src >> 8);
    key[2] = (se_u8)tgt;  key[3] = (se_u8)(tgt >> 8);
    key[4] = (se_u8)cls;  key[5] = (se_u8)(cls >> 8);
    key[6] = 0x01;        key[7] = 0x00;      /* AVTAB_ALLOWED */

    if (p_avtab_node_search) {
        node = (void *)((unsigned long (*)(void *, void *))p_avtab_node_search)(avtab, key);
        if (node && ((se_ulong)node >> 48) == 0xffffull) {
            volatile se_u32 *p = (volatile se_u32 *)((se_u8 *)node + 8u);

            *p &= ~bits;
        }
        return 0;
    }
    if (p_avtab_search) {
        void *r = (void *)((unsigned long (*)(void *, void *))p_avtab_search)(avtab, key);

        if (r && ((se_ulong)r >> 48) == 0xffffull) {
            se_u8 k[8];

            if (!se_kread(k, (se_u8 *)r - 8u, 8) && se_memeq(k, key, 8)) {
                volatile se_u32 *p = (volatile se_u32 *)r;

                *p &= ~bits;
                return 0;
            }
            if (!se_kread(k, r, 8) && se_memeq(k, key, 8)) {
                volatile se_u32 *p = (volatile se_u32 *)((se_u8 *)r + 8u);

                *p &= ~bits;
                return 0;
            }
        }
    }
    return 0;
}


/* 副本里 symtab[idx].nprim（idx: 0 commons, 1 classes, 2 roles, 3 types ...） */
se_u32 se_sym_nprim(const se_u8 *pdb, se_u32 idx)
{
    se_u32 off = L.symtab_off + idx * L.symtab_stride + L.symtab_stride - 8u;

    if (off + 4u > SE_PDB_BUF)
        return 0;
    return se_rd32(pdb + off);
}

/*
 * 副本换代（对齐 LKM ksu_se_rebuild 的延迟一代释放）：
 * 门处理器无锁读 L.copy，拿指针和解引用之间副本可能被换掉 —— 立即
 * 析构上一份就是 UAF。规则：先把新副本挂上 L.copy，旧的挂到
 * g_copy_prev；析构 g_copy_prev（上上代），此刻最早读走旧指针的 CPU
 * 也已完成（门是极短临界区），上上代必然无人引用。
 */
void *g_copy_prev;


void *g_rp_mirror;                      /* 镜像缓冲（vmalloc_user 持久块） */
se_u32 g_rp_mirror_len;                 /* 镜像有效长度；0=无效 */

static void se_mirror_capture(void *pdb)
{
    se_u64 sz, left = 0;
    se_u8 pf[16];
    void *nd;
    long wrc;

    g_rp_mirror_len = 0;
    if (!pdb || !p_pdb_write || !p_vmalloc_user || !p_vfree)
        return;

    sz = (se_u64)L.bin_len * 2u + (1u << 20);
    nd = (void *)((void *(*)(se_u64))p_vmalloc_user)(sz);
    if (!nd)
        return;
    se_wr64(pf, (se_u64)(se_ulong)nd);
    se_wr64(pf + 8, sz);
    wrc = ((long (*)(void *, void *))p_pdb_write)(pdb, pf);
    if (wrc) {
        ((void (*)(void *))p_vfree)(nd);
        pr_info("sehide: mirror capture rc=%ld\n", wrc);
        return;
    }
    if (se_kread(&left, pf + 8, 8) || !left || left > sz) {
        ((void (*)(void *))p_vfree)(nd);
        pr_info("sehide: mirror cursor bad left=%llu\n", (se_u64)left);
        return;
    }
    /* 成功：作废旧镜像，发布新镜像 */
    if (g_rp_mirror)
        ((void (*)(void *))p_vfree)(g_rp_mirror);
    g_rp_mirror = nd;
    g_rp_mirror_len = (se_u32)(sz - left);
    pr_info("sehide: mirror captured (len=%u)\n", g_rp_mirror_len);
}

void se_retire_copy(void *fresh)
{
    void *old = L.copy;

    L.copy = fresh;
    if (g_copy_prev && p_pdb_destroy)
        ((void (*)(void *))p_pdb_destroy)(g_copy_prev);
    se_free(g_copy_prev);
    g_copy_prev = old;
}

se_u32 se_copy_attrs(void *pdb, se_u32 *out, se_u32 cap)
{
    se_u64 sym = (se_u64)(se_ulong)pdb + L.symtab_off + 3u * L.symtab_stride;
    se_u64 tbl = 0, ht = 0, node = 0, datum = 0, next = 0;
    se_u32 size = 0, i, cnt = 0, guard;
    se_u8 td[8];

    if (!L.symtab_stride)
        return 0;

    if (L.symtab_stride == 16u) {
        /* 4.x：symtab.table 是 struct hashtab *，先解引用 */
        if (se_kread(&tbl, (void *)(se_ulong)sym, 8) || !se_kptr_ok(tbl))
            return 0;
        if (se_kread(&ht, (void *)(se_ulong)tbl, 8) ||
            se_kread(&size, (se_u8 *)(se_ulong)tbl + 8u, 4))
            return 0;
    } else {
        /* 5.9+：hashtab 内嵌在 symtab 里，{htable, size, ...} */
        if (se_kread(&ht, (void *)(se_ulong)sym, 8) ||
            se_kread(&size, (se_u8 *)(se_ulong)sym + 8u, 4))
            return 0;
    }
    if (!se_kptr_ok(ht) || size == 0 || size > (1u << 20))
        return 0;

    for (i = 0; i < size; i++) {
        if (se_kread(&node, (se_u8 *)(se_ulong)ht + (se_u64)i * 8u, 8))
            return 0;
        guard = 0;
        while (node && se_kptr_ok(node) && ++guard < 64u) {
            if (se_kread(&datum, (se_u8 *)(se_ulong)node + 8u, 8) ||
                !se_kptr_ok(datum) ||
                se_kread(td, (void *)(se_ulong)datum, 8))
                return 0;
            if (td[4] > 1u || td[5] > 1u)
                return 0;           /* 不是 {u32,u32,u8,u8} 的形状，布局假设破了 */
            if (td[5] == 1u && cnt < cap)
                out[cnt++] = se_rd32(td);   /* value，policydb_read 按序赋值必非 0 */

            if (se_kread(&next, (se_u8 *)(se_ulong)node + 16u, 8))
                return 0;
            node = next;
        }
        if (guard >= 64u)
            return 0;               /* 链长异常：链表被读歪了 */
    }
    return cnt;
}

int se_stamp_rules(void *pdb)
{
    se_u32 comp_type = 0;
    se_u32 ncls, ntyp, t;
    se_u32 attrs[512];
    se_u32 n, c, i;

    if (!g_comp_tname || se_type_val_at(pdb, g_comp_tname, &comp_type))
        comp_type = 0;
    if (!comp_type && se_type_val_at(pdb, "su", &comp_type))
        return -1;
    if (!comp_type)
        return -1;
    if (!p_avtab_add)
        return -1;

    ncls = se_sym_nprim(pdb, 1u);
    ntyp = se_sym_nprim(pdb, 3u);
    if (ncls > 512u)
        ncls = 512u;
    if (ntyp > 4096u)
        ntyp = 4096u;

    n = se_copy_attrs(pdb, attrs, 512u);
    if (n && n < 512u) {
        /* 对齐 LKM：组件域 -> attribute × 所有 class */
        for (c = 1; c <= ncls; c++)
            for (i = 0; i < n; i++)
                se_add_allow_at(pdb, comp_type, attrs[i], c, 0xffffffffu);
    } else {
        /* 回退超集：组件域 -> 每个具体 type × 所有 class */
        for (c = 1; c <= ncls; c++)
            for (t = 1; t <= ntyp; t++)
                se_add_allow_at(pdb, comp_type, t, c, 0xffffffffu);
    }
    return 0;
}

static int role_pass(const se_u8 *pdb, se_u32 off, se_u32 nroles)
{
    se_u32 i;

    for (i = 0; i < nroles; i++) {
        se_u64 rp = 0;
        se_u32 v = 0;

        if (se_kread(&rp, pdb + off + (se_u64)i * 8u, 8) || !se_kptr_ok(rp))
            return -1;
        if (se_kread(&v, (void *)(se_ulong)rp, 4) || v != i + 1u)
            return -1;      /* role_datum.value 恒等于下标+1，错位即失配 */
    }
    return 0;
}

static void se_stamp_copy_extras(void *buf, se_u32 comp_type)
{
    /* inbound 半边盖章（特权 oracle 一致性）—— 与决策面 inbound 语义
     * 等价：domain(全源)→comp域×白名单六类×全权；文件类刻意不放
     * （mountinfo 泄露修复语义）。副本私有，非特权零接触。 */
    if (se_decision_ready()) {
        se_u32 dom = 0;
        static const char *const ibn[6] = {
            "process", "fd", "fifo_file", "unix_stream_socket",
            "memfd_file", "binder",
        };

        if (se_type_val_at(buf, "domain", &dom) == 0 && dom) {
            se_u32 i;

            for (i = 0; i < 6; i++) {
                se_u32 cv = 0;

                if (se_class_val_at(buf, ibn[i], &cv) == 0 && cv)
                    se_add_allow_at(buf, dom, comp_type, cv, 0xffffffffu);
            }
        }
    }

    /* permissive 位（对象 = 生态组件域；live 零写入） */
    if (comp_type && L.perm)
        se_set_permissive(buf, L.perm, comp_type);
    else if (L.su_type && L.perm)
        se_set_permissive(buf, L.perm, L.su_type);

    /* 对齐内核 security_load_policy 流程（services.c:3132
     * policydb_read 之后调 evaluate_cond_nodes）。幂等防御性重评估。 */
    if (p_eval_conds)
        ((void (*)(void *))p_eval_conds)(buf);
}

/*
 * 建副本：policydb_read 到自有内存，注入后换代。
 *
 * 每调一次产出一份新副本（对齐 LKM：rebuild 总是重 build，失败的旧副本保留）；
 * 旧副本经 se_retire_copy 延迟一代，绝不在还有 CPU 可能引用时释放。
 */
int se_build_copy(void)
{
    void *b = 0, *buf = 0;
    se_ulong blen = 0;
    se_u8 pf[16];
    int rc;

    rc = se_read_policy(&b, &blen);
    if (rc) {
        pr_info("sehide: bcopy rp rc=%d\n", rc);
        return rc;
    }

    buf = se_alloc(SE_PDB_BUF);
    if (!buf) {
        se_free(b);
        return -1;
    }
    memset(buf, 0, SE_PDB_BUF);
    se_wr64(pf, (se_u64)(se_ulong)b);
    se_wr64(pf + 8, (se_u32)blen);
    rc = ((int (*)(void *, void *))p_pdb_read)(buf, pf);
    se_free(b);
    if (rc) {
        static int bc_diag;

        if (bc_diag < 3) {
            bc_diag++;
            pr_info("sehide: bcopy pr rc=%d len=%u\n", rc, (se_u32)blen);
        }
        se_free(buf);
        return rc;
    }

    /*
     * 副本里给生态组件域开全类全权（g_comp_type：KP 生态=magisk，
     * 旧生态=su；回退 L.su_type）。全权域 = 生态组件域，对齐 LKM
     * apply_ksu_rules 的 ksu_allow(db, <comp>, ALL, ALL, ALL)。
     * 类号 1..classes.nprim 连续（policydb_read 按序赋值），不查
     * sym_val_to_name —— 4.19 那张表是 `struct flex_array *`，不是
     * 5.10+ 的 `char **`（4.19 policydb.h:255 vs 6.1 :254），按下标读
     * 会读到 flex_array 自己的头。
     *
     * permissive 位由这里显式写入副本：live 不先置位（live 零写入），
     * 副本是特权查询的答题主，permissive 语义保持不变。
     */
    /* 镜像捕获（盖章前——出厂纯净态） */
    se_mirror_capture(buf);

    if (L.su_type && p_avtab_add) {
        se_u32 comp_type = g_comp_type ? g_comp_type : L.su_type;
        se_u32 ncls = se_sym_nprim(buf, 1u);
        se_u32 ntyp = se_sym_nprim(buf, 3u);
        se_u32 attrs[512];
        se_u32 n, c, t, i;

        if (ncls > 512u)
            ncls = 512u;
        if (ntyp > 4096u)
            ntyp = 4096u;

        n = se_copy_attrs(buf, attrs, 512u);
        if (n && n < 512u) {
            /* 对齐 LKM：组件域 → attribute × 所有 class */
            for (c = 1; c <= ncls; c++)
                for (i = 0; i < n; i++)
                    se_add_allow_at(buf, comp_type, attrs[i], c,
                                    0xffffffffu);
        } else {
            /* 回退超集：组件域 → 每个具体 type × 所有 class */
            for (c = 1; c <= ncls; c++)
                for (t = 1; t <= ntyp; t++)
                    se_add_allow_at(buf, comp_type, t, c, 0xffffffffu);
        }

        /* inbound/permissive/cond 尾段抽为共用函数（与
         * se_absorb_blob 同款，去重）。 */
        se_stamp_copy_extras(buf, comp_type);
    }   /* if (L.su_type && p_avtab_add) —— outbound/inbound 盖章作用域闭合 */

    /* 注入完成后才发布指针（对齐 LKM：apply 之后 se_copy = pol），再换代 */
    se_retire_copy(buf);

    /* 副本换代后重建决策面翻译表（读新 L.copy 的 symtab——
     * install/recal 全走本函数；blob 吸收换代不改类定义，无需重建）。 */
    se_perm_tab_build();
    return 0;
}

int se_absorb_blob(const se_u8 *blob, se_u32 blen)
{
    se_u8 *buf;
    se_u8 pf[16];
    se_u32 magic = 0, ncls_blob = 0, ncls_live = 0;
    se_u32 comp_type;
    int rc;

    if (!blob || !blen || blen > SE_MAX_BIN || !L.ok || !L.copy ||
        !p_pdb_read)
        return 0;   /* 未就绪：丢弃，假成功（门语义不变） */
    if (blen < 16u)
        goto drop;
    magic = (se_u32)blob[0] | ((se_u32)blob[1] << 8u) |
            ((se_u32)blob[2] << 16u) | ((se_u32)blob[3] << 24u);
    if (magic != 0xf97cff8cu)   /* SELINUX_MAGIC（sepolicy_flags.h:13）；
                                 * 文本/未知格式：非本引擎处理面，丢弃 */
        goto drop;

    buf = se_alloc(SE_PDB_BUF);
    if (!buf)
        goto drop;
    memset(buf, 0, SE_PDB_BUF);
    se_wr64(pf, (se_u64)(se_ulong)blob);
    se_wr64(pf + 8, blen);
    rc = ((int (*)(void *, void *))p_pdb_read)(buf, pf);
    if (rc) {
        static int ab_diag;

        if (ab_diag < 3) {
            ab_diag++;
            pr_info("sehide: absorb pdb_read rc=%d len=%u\n", rc, blen);
        }
        se_free(buf);
        goto drop;
    }

    ncls_blob = se_sym_nprim(buf, 1u);
    /* 类数基准从 L.copy 取（自有内存，se_rd32 直接解引用安全；L.pdb 在
     * 重载窗口可能被内核重建而悬空）。副本基底=出厂 live → 类数等价。 */
    ncls_live = se_sym_nprim(L.copy, 1u);
    if (!ncls_blob || ncls_blob != ncls_live) {
        pr_info("sehide: absorb class mismatch blob=%u live=%u, dropped\n",
                ncls_blob, ncls_live);
        se_free(buf);
        goto drop;
    }

    /* 镜像长度倒退保护：正常写 = 最新镜像 + 新规则，magiskpolicy 幂等
     * 不缩 → 长度单调不减；严格倒退 ⇒ 旧读覆盖（writer 持旧读）会覆盖
     * 已累积规则 → 丢弃假成功（生态无感）。等于=合法幂等，不丢。 */
    if (g_rp_mirror_len && blen < g_rp_mirror_len) {
        pr_info("sehide: /load stale blob dropped (len=%u < mirror=%u)\n",
                blen, g_rp_mirror_len);
        se_free(buf);
        goto drop;
    }

    /* 镜像捕获（盖章前——出厂+本 blob 规则的累积态） */
    se_mirror_capture(buf);

    comp_type = g_comp_type ? g_comp_type : L.su_type;
    if (se_stamp_rules(buf)) {
        se_free(buf);
        goto drop;
    }
    se_stamp_copy_extras(buf, comp_type);

    se_retire_copy(buf);
    pr_info("sehide: /load absorbed into copy (len=%u classes=%u)\n",
            blen, ncls_blob);
    return 0;

drop:
    pr_info("sehide: /load blob dropped (len=%u magic=%08x)\n", blen, magic);
    return 0;
}
