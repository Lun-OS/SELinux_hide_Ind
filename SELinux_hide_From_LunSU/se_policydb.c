/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_policydb：规则原语与副本生命周期 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
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

/* ---------------- live len 维护（v88 根因修复） ----------------
 *
 * 6.1 起 put_entry 带溢出检查（policydb.h:377：len > fp->len 返回
 * -EINVAL）；4.19 无检查（memcpy 撞过、fp.len 无符号递减、恒返回 0）。
 * apd 的 PostFsData 经 sel_open_policy → security_read_policy →
 * policydb_write 重序列化 live，输出缓冲上限 = policydb.len（加载时的
 * 原始 blob 长度，policydb_read 设置）。我们往 live 加的每条 avtab
 * 规则（重序列化 12B：u16×4 key + u32 datum，avtab_write_item）与首次
 * 置位的 permissive 位（ebitmap_write 空 4B → 1 节点 16B，+12B）都让
 * 重序列化变长 —— 超过 len 即 -EINVAL，apd 的 SePolicy::from_file
 * 失败，on_post_data_fs 的 `?` 直接退出（fp_br30：before 上报后 18ms
 * 内静默退出、零 load、零 crash、零 tombstone）。4.19 无检查所以装机
 * 从未暴露。
 *
 * 修复：live 侧每次有效写入同步把 policydb.len 增加对应增量，保证
 * policydb_write 的缓冲恒够；L.bin_len 同步（否则 len 指纹失配引发
 * recal 风暴）。apd 注入触发的真重载整体换代 live（len 由内核
 * policydb_read 重设），随后的 recal 重写三件套并再次维护 len —— 良性
 * 循环。副本由内核 policydb_read 构建、无人对副本 policydb_write，
 * len 无需维护。
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

/* 幂等版 permissive：已置位不重写（ebitmap 无新节点、序列化不变长）。 */
int se_set_permissive_once(void *pdb, se_u32 type, int *grown)
{
    int already = 0;

    if (!pdb || !L.perm || !type || !p_ebitmap_set)
        return -1;
    if (p_get_bit)
        already = ((int (*)(void *, se_ulong))p_get_bit)
            ((se_u8 *)pdb + L.perm, (se_ulong)type);
    if (((int (*)(void *, se_ulong, int))p_ebitmap_set)
        ((se_u8 *)pdb + L.perm, (se_ulong)type, 1))
        return -1;
    if (grown && !already)
        *grown += 12;
    return 0;
}

/*
 * 内容与 selinux/rules.c 的 apply_inbound_rules() 一致：只写"别的域 -> su"
 * 这一半。su 作为源那一半由 live 的 permissive 位和副本负责，不写进 live。
 */
const struct se_rule se_rules[] = {
    /* init：init 域内的早期进程操控/注入类组件（通用，LunSU inbound 同款） */
    { "init", "process", 0, 0, 0, 0, 0 },
    { "init", "dir", 0, 0, 0, 0, 0 },
    { "init", "file", 0, 0, 0, 0, 0 },
    { "init", "fd", 0, 0, 0, 0, 0 },
    { "init", "fifo_file", 0, 0, 0, 0, 0 },
    { "init", "unix_stream_socket", 0, 0, 0, 0, 0 },
    { "init", "binder", 0, 0, 0, 0, 0 },
    { "init", "memfd_file", 0, 0, 0, 0, 0 },
    { "init", "chr_file", 0, 0, 0, 0, 0 },
    { "init", "sock_file", 0, 0, 0, 0, 0 },
    { "init", "lnk_file", 0, 0, 0, 0, 0 },
    { "init", "debugfs", 0, 0, 0, 0, 0 },

    { "servicemanager", "dir", "search", "read", 0, 0, 0 },
    { "servicemanager", "file", "open", "read", 0, 0, 0 },
    { "servicemanager", "process", "getattr", 0, 0, 0, 0 },

    { "domain", "process", "sigchld", 0, 0, 0, 0 },
    { "domain", "fd", "use", 0, 0, 0, 0 },
    { "domain", "fifo_file", "write", "read", "open", "getattr", 0 },
    { "domain", "unix_stream_socket", "read", "write", "connectto", "getopt", "getattr" },
    { "domain", "memfd_file", "execute", "getattr", "map", "read", "write" },
    { "domain", "binder", 0, 0, 0, 0, 0 },

    { "logd", "dir", "search", 0, 0, 0, 0 },
    { "logd", "file", "read", "open", "getattr", 0, 0 },

    { "hwservicemanager", "dir", "search", 0, 0, 0, 0 },
    { "hwservicemanager", "file", "read", "open", 0, 0, 0 },
    { "hwservicemanager", "process", "getattr", 0, 0, 0, 0 },

    { "system_server", "process", "getpgid", "sigkill", 0, 0, 0 },
};

#define NRULES (sizeof(se_rules) / sizeof(se_rules[0]))


/*
 * 新增：type/class 查询的参数化版本 —— 在"给定的"policydb 上查名字。
 * se_type_val/se_class_val 保持原签名转调（live）。改①/改② 在副本上
 * 注入规则时必须用副本自己的 symtab（外部 blob 的 type 值可能不同于 live）。
 */
/*
 * symtab 里按名字查 datum（原 L1296-1310 纯搬移，去 static）。
 *   5.9+   : symtab_search(&pdb->symtab[i], name)
 *   5.9 前 : hashtab_search(symtab[i].table, name)，4.x 的 table 是指针先解引用
 */
void *se_sym_search(void *sym, const char *name)
{
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
    /* v66：查出厂副本而非 live——live 上 LSP 新增的类（快照没有）返回
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
    void *first = (kver >= VERSION(5, 10, 0)) ? L.container : (void *)p_selinux_state;
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
 * 新增：单权限名版位掩码（改① 的 allow/deny 用）。与 se_perm_mask 共用
 * security_get_permissions 路径 —— 该路径查的是 live 的类/权限定义
 * （类权限集合与副本一致是常态；外部 blob 改类定义时该命令按失败处理）。
 */
static int se_perm_mask_shared(const char *cls, const char **want, se_u32 nwant, se_u32 *out)
{
    void *first = (kver >= VERSION(5, 10, 0)) ? L.container : (void *)p_selinux_state;
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
 * 新增：se_add_allow_at 的对偶 —— deny 语义。已存在节点则把权限位清掉；
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

void se_retire_copy(void *fresh)
{
    void *old = L.copy;

    L.copy = fresh;
    if (g_copy_prev && p_pdb_destroy)
        ((void (*)(void *))p_pdb_destroy)(g_copy_prev);
    se_free(g_copy_prev);
    g_copy_prev = old;
}

/*
 * 遍历副本 p_types（symtab[3]）收集 attribute 类型的 value。
 * 等价于 LKM add_rule_raw 的 tgt=NULL 分支：ksu_hashtab_for_each +
 * if (type->attribute)（sepolicy.c:322-341）—— LKM 的
 * ksu_allow(su, ALL, ALL, ALL) 只给属性类型写规则（~260×103 条而不是
 * 3359×103 条），具体类型靠内核判定时的目标侧属性展开命中
 * （6.1 services.c:1074-1078：tattr = &type_attr_map_array[t->type-1]，
 * 逐个属性值再查一次 avtab）。
 *
 * 布局八版本一致（4.19 policydb.h:113-118 / 6.18 :111-116 逐字相同；
 * hashtab_node{key,datum,next} 同样未变）：type_datum 的 attribute 在 +5。
 * 任何一步读不通或布局自检失败（attribute>1）都整体放弃返回 0，
 * 调用方回退到"具体类型全写"的语义超集 —— 慢，但正确性不依赖这里。
 */
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

/*
 * 新增（调整说明）：把 build_copy 的注入段抽成函数 —— 对给定副本重打
 * outbound 半边（su -> attribute × 全类全权，或回退超集）。se_build_copy
 * 与改② 的 /load 门共用：LunSU 的 outbound 恒在副本上，inbound 恒在 live。
 * su 的 type 值改为在"这一份"pdb 的 symtab 里解析（se_type_val_at），
 * 使外部 blob 成为副本基底时取值依然正确。
 */
int se_stamp_rules(void *pdb)
{
    se_u32 comp_type = 0;
    se_u32 ncls, ntyp, t;
    se_u32 attrs[512];
    se_u32 n, c, i;

    /*
     * v85：outbound 半边的盖章对象 = 生态组件域（g_comp_tname）。
     * KP 生态 = magisk（与切域/三件套同域，LunSU 语义逐条对齐——只是
     * 域对象随生态变）；查名失败回退 "su"（4.19 等旧生态，行为不变）。
     */
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

/*
 * 新增：live 的 role 条件位（LunSU 第三类 live 写，LKM ksu_se_role_bits 1:1）。
 *
 * 偏移推导（全部来自结构关系，非设备探测）：
 *   policydb 尾段字段顺序（6.1 内核树 security/selinux/ss/policydb.h:256-265
 *   逐字核对；4.19 同序）：
 *     sym_val_to_name[SYM_NUM](8 指针) -> class/role/user/type_val_to_struct
 *     (4 指针) -> te_avtab
 *   与 se_symtab_from_avtab 用的 96 字节关系同源。故
 *     role_val_to_struct = te_avtab 偏移 - 24
 *   role_datum = { u32 value; u32 bounds; ebitmap dominates; ebitmap types }
 *   （6.1 policydb.h:77-82，4.19 同）=> types 在 +24。
 *   role->types 索引 = type->value - 1（0 基数组）；permissive_map 索引 =
 *   type->value（1 基）—— 两个约定并存，LKM 注释里已用血泪钉死。
 *
 * 条件位语义：写前逐 role 查位，已置即跳过（live 已接受 = 不写）；
 * 任何一次 set_bit 失败立即中止上报，绝不吞掉（对齐 LKM 同款纪律）。
 */
/*
 * v56 根因修复（pstore 实证 20261101 elish Oops #1）：
 *
 * 旧实现 role_off = avtab_off - 24 直接消费 avtab 推导结果，自检仅查
 * "指针带内核前缀"。v54 改 2 后 avtab 由形态扫描给出（240，反解 248 被
 * 校验拒绝——两个推导器矛盾），role_off 指向错误位置，名字指针被当作
 * role_datum，rp+24 处垃圾被当作 ebitmap 传给内核 ebitmap_set_bit →
 * NULL deref Oops → init 崩 → 启动失败。
 *
 * 新定位：不依赖 avtab_off。独立扫描 policydb 头部区，寻找满足
 * "连续 nroles 个指针且第 i 个 datum->value == i+1" 的偏移 ——
 * role 数组由 policydb_read 按序赋值（value=下标+1），错位必然不满足。
 * 找到后逐项写入，写前再对每个 rp 做同样形态校验。
 */
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

int se_role_bits(int value)
{
    se_u32 i, nroles;
    se_u32 off, role_off = 0;
    se_u32 comp_type;
    int rc;

    if (!L.ok || !L.pdb || !L.su_type || !p_ebitmap_set)
        return -1;

    /* v85：位写对象 = 生态组件域（与三件套其余两类一致） */
    comp_type = g_comp_type ? g_comp_type : L.su_type;

    nroles = se_sym_nprim((const se_u8 *)L.pdb, 2u);
    if (!nroles || nroles > 1024u)
        return -1;

    /* 独立定位 role 指针数组：不消费 avtab_off */
    for (off = 16u; off + (se_u64)nroles * 8u <= SE_PDB_BUF; off += 8u) {
        se_u64 p0 = 0;

        if (se_kread(&p0, (se_u8 *)L.pdb + off, 8) || !se_kptr_ok(p0))
            continue;
        if (!role_pass((const se_u8 *)L.pdb, off, nroles))
            role_off = off;
    }
    if (!role_off)
        return -1;

    for (i = 0; i < nroles; i++) {
        se_u64 rp = 0;
        se_u32 cur = 0;

        if (se_kread(&rp, (se_u8 *)L.pdb + role_off + (se_u64)i * 8u, 8))
            return -1;
        if (!se_kptr_ok(rp))
            continue;
        /* 条件位：live 已接受（位已置）就不写，幂等且保持出厂态 */
        if (p_get_bit &&
            ((int (*)(void *, se_ulong))p_get_bit)
                ((void *)(se_ulong)(rp + 24u), (se_ulong)(comp_type - 1u)) == value)
            continue;
        rc = ((int (*)(void *, se_ulong, int))p_ebitmap_set)
            ((void *)(se_ulong)(rp + 24u), (se_ulong)(comp_type - 1u), value);
        if (rc) {
            pr_info("sehide: live role[%u] set_bit(%u) failed: %d\n",
                    i, comp_type - 1u, rc);
            return rc;
        }
        if (p_get_bit) {
            cur = ((int (*)(void *, se_ulong))p_get_bit)
                ((void *)(se_ulong)(rp + 24u), (se_ulong)(comp_type - 1u));
            if ((int)cur != value) {
                pr_info("sehide: live role[%u] self-check %u != %d\n",
                        i, cur, value);
                return -1;
            }
        }
    }
    pr_info("sehide: live role bit %d for comp type %u over %u roles\n",
            value, comp_type, nroles);
    return 0;
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
     * v85：副本里给生态组件域开全类全权（g_comp_type：KP 生态=magisk，
     * 旧生态=su；回退 L.su_type）。对齐 LunSU 语义——全权域 = 生态组件域，
     * 机制不变，域对象随生态。对齐 LKM apply_ksu_rules 的
     * ksu_allow(db, <comp>, ALL, ALL, ALL)。
     * 类号 1..classes.nprim 连续（policydb_read 按序赋值），不查
     * sym_val_to_name —— 4.19 那张表是 `struct flex_array *`，不是
     * 5.10+ 的 `char **`（4.19 policydb.h:255 vs 6.1 :254），按下标读
     * 会读到 flex_array 自己的头。
     *
     * permissive 位 v60 起由这里显式写入副本：live 不再先置位（live 零写入），
     * 副本自查行为与旧版（继承 live）一致——副本是特权查询的答题主，
     * permissive 语义保持不变。
     */
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
    }

    /* v60/v85：副本显式置 permissive（对象 = 生态组件域） */
    if (g_comp_type && L.perm)
        se_set_permissive(buf, L.perm, g_comp_type);
    else if (L.su_type && L.perm)
        se_set_permissive(buf, L.perm, L.su_type);

    /* 注入完成后才发布指针（对齐 LKM：apply 之后 se_copy = pol），再换代 */
    se_retire_copy(buf);
    return 0;
}

int se_apply_inbound_g(se_u32 su, int *grown)
{
    se_u32 i, ok = 0, bad = 0, nel0, nel1;

    nel0 = se_avtab_nel(L.pdb);

    for (i = 0; i < NRULES; i++) {
        const struct se_rule *r = &se_rules[i];
        se_u32 src = 0, cls = 0, mask = 0;

        if (se_type_val(r->src, &src))
            goto skip;
        if (se_class_val(r->cls, &cls))
            goto skip;
        if (se_perm_mask(r->cls, r, &mask))
            goto skip;
        if (se_add_allow_at(L.pdb, src, su, cls, mask))
            goto skip;

        ok++;
        continue;
skip:
        bad++;
    }

    nel1 = se_avtab_nel(L.pdb);
    /* 每条新增 avtab 节点重序列化 +12B（u16×4 key + u32 datum）；
     * 命中已有节点的 OR 更新不加节点、不计增量。 */
    if (grown)
        *grown += (int)((nel1 - nel0) & 0xffffffffu) * 12;

    L.rules_ok = ok;
    L.rules_fail = bad;
    pr_info("sehide: inbound ok=%u skip=%u nel=%u\n", ok, bad, L.avtab_nel);
    return ok;
}

/*
 * live 三件套（v90 恢复，LunSU 形态定稿）：
 * live = 出厂 + 三件套（inbound 24 条 + permissive comp 位 + role 条件位）。
 *
 * duck_detector 报告（fp_br31 同代）实证的失守点全部源于"生态注入落
 * live"：magisk/magisk_file/lsposed_file 类型可被 app_zygote 载体的
 * context oracle（EINVAL=不存在 / EACCES=存在）与 setprocattr oracle
 * 识别，policyload=5 可从 status 页读出，(untrusted_app→magisk:binder /
 * →lsposed_file:file read) access oracle = allowed —— 全部来自 /load
 * 放行后的真重载。恢复 /load 门（blob 全丢弃）后 live = 出厂 + 三件套，
 * 上述三项归零；su 是出厂类型，三件套的 flags/inbound 差异被 read_policy
 * 门挡在非特权可达面之外（LunSU selinuxfs.c:408/:470 注释同款论证）。
 *
 * v88 的 len 维护保留：6.1 的 put_entry 溢出检查要求 live 的每次有效
 * 写入同步扩 policydb.len，否则 apd 读 /sys/fs/selinux/policy 时
 * policydb_write 返回 -EINVAL（fp_br30 根因）。
 */
void se_apply_trio(se_u32 type)
{
    int grown = 0;
    int rc;

    if (!L.pdb || !type)
        return;

    se_apply_inbound_g(type, &grown);
    rc = se_set_permissive_once(L.pdb, type, &grown);
    if (rc)
        pr_info("sehide: permissive bit failed rc=%d\n", rc);

    if (grown > 0)
        se_len_grow(grown);
    pr_info("sehide: live trio type=%u ok=%u skip=%u len+%dB\n",
            type, L.rules_ok, L.rules_fail, grown > 0 ? grown : 0);
}

/*
 * exec 进 su 域那一下。
 *
 * LKM 版是挂 bprm 钩子把「内核拒绝 + 新身份是 su」翻成允许。KPM 这版不用钩子，
 * 改成往 live 写一条 process:transition 允许规则 —— 内核自己的判定直接放行，
 * 与钩子等效，且是纯数据写（不用碰 static_call 跳转，也不用读 bprm 结构）。
 *
 * 依据：内核在 exec 时查 process:transition（源 = 调用方域），permissive 位只看源，
 * 答不了这一问；所以必须有一条 (src -> su, process, transition) 的 allow。
 */
void se_allow_transition(se_u32 su)
{
    se_u32 cls = 0, mask = 0;
    static const struct se_rule tr = { "domain", "process", "transition", 0, 0, 0, 0 };

    if (se_class_val("process", &cls))
        return;
    if (se_perm_mask("process", &tr, &mask))
        return;

    /* 对 domain 属性本身写一条：(domain -> su, process, transition) */
    {
        se_u32 src = 0;

        if (se_type_val("domain", &src))
            return;
        se_add_allow_at(L.pdb, src, su, cls, mask);
        pr_info("sehide: transition rule domain->su mask=%08x\n", mask);
    }
}

/*
 * ---------------- v78：blob 吸收（终版：副本内核构建，live 零手工） ----------------
 *
 * v62-v77 七轮装机证据的最终收敛：
 *   - 全部事故（v68 attr map、v70 解引用、v72/73/75 定位器、v76 strlen
 *     panic、v77 v2s 定位）同源：往 live 的 policydb 手工注入类型并维护
 *     其派生表——在 KPM 约束下（无类型化符号，纯偏移考古）不可靠；
 *   - v77 实证「副本 = policydb_read(blob) + su 盖章」一次成功且无 panic；
 *   - live 类型注入自始多余：本机模块文件全部用 stock 标签（fp_br9
 *     ap_tree 实证 system_file/adb_data_file），LunSU 的 live 亦从不注入
 *     类型（borrowed names，type count 不变）。
 *
 * 终版语义（LunSU 对齐，问题树不存在）：
 *   live  = 出厂 + su 三件套（inbound + permissive + role 位，仅 install
 *           时写入）——零类型注入、零派生表手工操作；
 *   copy  = policydb_read(blob) + su 盖章 + 换代（内核自建全部派生表/
 *           索引/一致性，含 type_val_to_struct_array——type_attribute_
 *           bounds_av 对其 BUG_ON(!slot) 不可缺席）；
 *   规则  = 只在 copy（特权查询视图），live 无模块规则。
 *
 * 失败 fail-closed：解析/盖章失败返回错误让组件重试，未换代即整块释放。
 */

int se_absorb_blob(const se_u8 *blob, se_u32 blen)
{
    /*
     * v90：blob 全丢弃（假成功）。LunSU 形态 = live 与副本都保持
     * "出厂 + 三件套"——blob（apd 的 magisk blob / 模块 sepolicy.rule
     * 的编译产物）里的 magisk/lsp 类型与规则一旦进 live 或副本，就会被
     * app_zygote 载体的 context oracle（EINVAL/EACCES 判别）、
     * setprocattr oracle 与 access oracle 全部读出（duck_detector 实测
     * 三项失守）。生态组件的生存由 KP task_ext 兜底 + 三件套承担
     * （4.19 v84b /load 门在场全链实证），blob 内容无生存贡献，纯暴露。
     * 模块自身的 sepolicy 批（KPM 控制面）与 LunSU handle_sepolicy 对等，
     * 走 se_ctl 进副本，不经此路径。
     */
    (void)blob;
    (void)blen;
    pr_info("sehide: /load absorbed (blob dropped, live+copy untouched)\n");
    return 0;
}
