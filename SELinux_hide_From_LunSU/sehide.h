/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * sehide.h - SELinux_hide_From_LunSU KPM 共享内部头。
 *
 * 分层：se_util / se_symbol / se_layout / se_policydb / se_rules /
 *   se_render / se_gate / se_bprm / se_recal / sehide_main
 * 版本历史见 docs/selinux-hide/KPM-1.1.0-注释工作日志归档.md。
 */
#ifndef __SEHIDE_H
#define __SEHIDE_H

#include <compiler.h>
#include <kpmodule.h>
#include <kallsyms.h>
#include <kputils.h>
#include <common.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>

extern void *memcpy(void *dst, const void *src, unsigned long n);
extern void *memset(void *dst, int c, unsigned long n);
extern unsigned long strlen(const char *s);
extern int strncmp(const char *a, const char *b, unsigned long n);
extern char *strncpy(char *d, const char *s, unsigned long n);

typedef unsigned char se_u8;
typedef unsigned short se_u16;
typedef unsigned int se_u32;
typedef unsigned long long se_u64;
typedef unsigned long se_ulong;
typedef int se_s32;
typedef long long se_s64;

#define SE_PDB_BUF  2048u          /* 覆盖 4.19(488B) ~ 6.18(608B)，留余量 */
#define SE_MAX_BIN  (64u << 20)
#define SE_MAGIC    0xf97cff8cu
#define SE_CTX_BUF  256u           /* struct context 前缀够用，留足余量 */
#define SECSID_NULL 0u
#define SE_AVD_BUF  64u
#define NSYM 34   /* syms[] 条目数；定长供跨文件 sizeof */

/* ------------------------------------------------------------------
 * 静态形状表。
 *
 * 每条分界都是相邻两个主线 tag 的源码逐字比对结果，取证与行号见
 * docs/selinux-hide/KPM-按内核版本静态形状表-20261111.md。
 * 不再做运行期形状探测：下面每个函数只按 kver 返回固定形状。
 *
 *   v4.20  string_to_context_struct 6 参 -> 5 参（删第 4 位 scontext_len；
 *          现已委托内核，无直调）
 *   v5.6   sidtab_search 变 static inline；sidtab_search_entry 出现
 *          （按符号存在性分派，不走版本号）
 *   v5.8   probe_kernel_read -> copy_from_kernel_nofault；symtab 指针 -> 内嵌
 *   v5.9   hashtab_search 变 .h inline（3 参带 key_params）
 *   v5.10  selinux_policy 容器化；security_get_permissions 首参 state -> policy
 *   v6.4   state 全局单例化：avc_denied / avc_has_perm / avc_ss_reset /
 *          security_read_policy / security_compute_av_user /
 *          security_context_str_to_sid 同时去掉首参（同一个改动）
 *   v6.13  avc_denied 插入 base_perm（8 参 -> 9 参）
 *   v6.17  policydb 增加 neveraudit_map
 *
 * 版本族 -> 调用 ABI 形状一览（这就是各版本「走几参」）：
 *   4.19.x 官方 : avc_denied 9 参带 state；read_policy 3 参；
 *                 avc_has_perm 6 参；avc_ss_reset 2 参；
 *                 string_to_context_struct 6 参（已委托，不再直调）；
 *                 sidtab_search 真函数；
 *                 hashtab_search 2 参；get_permissions 首参 state。
 *   4.20 - 5.5  : 同上，仅 string_to_context_struct 变 5 参（同样已委托）。
 *   5.6 - 5.7   : 同上，sidtab_search 变 inline -> 改用 sidtab_search_entry。
 *   5.8         : 同上，symtab 内嵌、uaccess 改名（返回类型不变，无 ABI 差异）。
 *   5.9         : 同上，hashtab_search 变 inline 3 参 -> 改用 symtab_search。
 *   5.10 - 6.3  : get_permissions 首参改 policy(L.container)。
 *                 6.1 属此族：avc_denied 仍是 9 参带 state。
 *   6.4 - 6.12  : state 全局单例化，上述六个函数同去首参；
 *                 avc_denied 8 参，avd 落在第 8 个参数槽。
 *   6.13 - 6.16 : avc_denied 9 参（插入 base_perm），avd 回第 9 槽。
 *   6.17+       : 同上，policydb 多 neveraudit_map（由布局标定处理）。
 *
 * 「按版本号写死」只覆盖无法委托的调用 ABI 形状。KPM 原有的 policydb
 * 数据布局标定（se_calibrate / strides[]）与符号解析（按符号存在性选
 * symtab_search/hashtab_search、sidtab_search/sidtab_search_entry）保持
 * 原样：它们不是 ABI 形状，换成版本号反而会被厂商回移树骗过。
 *
 * string_to_context_struct 不再直调 —— 它是依赖面里唯一「同版本号
 * 两种形状」的函数（Android common 把 v4.20 的删参改动带进 4.19；
 * 官方 4.19 全族 6 参，4.19.157 实机按六参递参即 Oops）。装机期解析
 * 统一经 security_secctx_to_secid 委托内核用自己编译的形状调用
 * （3 参，4.19~6.18 函数体 md5 全同）。单一产物覆盖全部版本。
 * ------------------------------------------------------------------ */
#define SE_KVER_510   VERSION(5, 10, 0)
#define SE_KVER_64    VERSION(6, 4, 0)
#define SE_KVER_613   VERSION(6, 13, 0)

/* avc_denied 的三种参数形状（参数顺序逐字取自各 tag 的 avc.c） */
enum se_aden_shape {
    SE_ADEN_9S = 0,  /* <=6.3    (state, ssid, tsid, tclass, requested,
                                  driver, xperm, flags, avd) */
    SE_ADEN_8  = 1,  /* 6.4-6.12 (ssid, tsid, tclass, requested,
                                  driver, xperm, flags, avd) */
    SE_ADEN_9B = 2,  /* >=6.13   (ssid, tsid, tclass, requested, driver,
                                  base_perm, xperm, flags, avd) */
};

static inline enum se_aden_shape se_kver_aden(void)
{
    if (kver >= SE_KVER_613)
        return SE_ADEN_9B;
    if (kver >= SE_KVER_64)
        return SE_ADEN_8;
    return SE_ADEN_9S;
}

/* v6.4 前这一族函数都带 state 或 avc 指针首参；v6.4 起全局单例化后没有。 */
static inline int se_kver_has_state(void)
{
    return kver < SE_KVER_64;
}

/* fp_hook / strncpy_from_user 都走运行期解析，避免成为装载期的未定义符号 */
#define SE_FPHOOK(t, r, b) do { \
    if (p_fp_hook) \
        ((void (*)(void *, void *, void **))p_fp_hook)((t), (r), (b)); \
} while (0)

#define SE_STRNCPY_USER(d, s, n) \
    (p_strncpy_user ? ((long (*)(char *, const char *, long))p_strncpy_user)((d), (s), (n)) : -1L)

/* KernelPatch 私有符号表 API（base/hook.c、utils.c） */
extern unsigned long symbol_lookup_name(const char *name);

/* KSU sepol 批量命令码（userspace/ksud uapi/selinux.h，bindgen 取证 1:1） */
#define KSU_SEPOLICY_MAX_BATCH_SIZE (8U * 1024U * 1024U)
#define KSU_SEPOLICY_MAX_ARGS 5
#define KSU_SEPOLICY_CMD_NORMAL_PERM   1u
#define KSU_SEPOLICY_CMD_XPERM         2u
#define KSU_SEPOLICY_CMD_TYPE_STATE    3u
#define KSU_SEPOLICY_CMD_TYPE          4u
#define KSU_SEPOLICY_CMD_TYPE_ATTR     5u
#define KSU_SEPOLICY_CMD_ATTR          6u
#define KSU_SEPOLICY_CMD_TYPE_TRANSITION 7u
#define KSU_SEPOLICY_CMD_TYPE_CHANGE   8u
#define KSU_SEPOLICY_CMD_GENFSCON      9u
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW      1u
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY       2u
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_AUDITALLOW 3u
#define KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DONTAUDIT  4u
#define KSU_SEPOLICY_SUBCMD_XPERM_ALLOW      1u
#define KSU_SEPOLICY_SUBCMD_XPERM_AUDITALLOW 2u
#define KSU_SEPOLICY_SUBCMD_XPERM_DONTAUDIT  3u
#define KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE 1u
#define KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE    2u
#define KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_CHANGE 1u
#define KSU_SEPOLICY_SUBCMD_TYPE_CHANGE_MEMBER 2u

struct se_out {
    char *buf;
    se_u32 cap;
    se_u32 n;
};

struct sym_slot {
    const char *name;
    unsigned long addr;
    char matched[48];
};

struct walk_ctx {
    const char *base;
    se_ulong len;
    unsigned long addr;
};

struct bin_hdr {
    se_u32 vers;
    se_u32 perm_off;
    se_u32 perm_len;
    se_u32 sym_num;   /* 二进制头里的 sym_num */
    se_u32 np_off;    /* 8 个 nprim 值的起始偏移（紧跟 permissive_map 段之后） */
};

struct se_rule {
    const char *src;
    const char *cls;
    const char *p0, *p1, *p2, *p3, *p4;   /* p0 == 0 表示该类全部权限 */
};

/* 标定结果（原单文件 L365-392 匿名 struct，命名以供跨文件共享） */
struct se_calib {
    int ok;
    se_u32 kver_major, kver_minor;
    se_u32 vers;          /* 二进制头里的 policyvers */
    se_u32 perm;          /* permissive_map 在 policydb 内偏移 */
    se_u32 lenoff;        /* len 在 policydb 内偏移 */
    se_u32 bin_len;
    se_u32 slot;          /* selinux_state 里第几个 8 字节是容器指针 */
    se_u32 pdb_off;       /* policydb 在容器内偏移 */
    void *container;
    void *sidtab;
    void *copy;           /* 自建副本的 policydb */
    void *pdb;
    se_u32 su_type;
    se_u32 probe_hits;

    /* 结构推导 */
    se_u32 sym_num;
    se_u32 nprim[9];
    se_u32 symtab_off;    /* symtab[0] 在 policydb 内偏移 */
    se_u32 symtab_stride; /* 16 = 4.x 指针形态，24 = 5.9+ 内嵌形态 */
    se_u32 avtab_off;     /* te_avtab 在 policydb 内偏移 */
    se_u32 avtab_nel;
    se_u32 rules_ok;
    se_u32 rules_fail;
    se_u32 role_off;      /* 新增：role_val_to_struct 指针数组在 policydb 内偏移 */
};

extern struct se_calib L;

/* ---------------- 符号槽（定义 se_symbol.c） ---------------- */
extern unsigned long p_read_policy;
extern unsigned long p_pdb_read;
extern unsigned long p_eval_conds;   /* evaluate_cond_nodes（副本条件规则状态初始化） */
extern unsigned long p_kwrite;       /* copy_to_kernel_nofault（门输出写内核页） */
extern unsigned long p_adenied;      /* avc_denied 最终地址（经 patch_config 链解析） */
extern unsigned long p_adenied_l3;   /* L3 直查 avc_denied（互证备用） */
extern unsigned long p_patch_text;   /* 内核 aarch64_insn_patch_text（挂载/卸载执行原语） */
extern unsigned long p_ahp;          /* avc_has_perm（决策面活体自检用） */
extern unsigned long p_pdb_destroy;
extern unsigned long p_kread;
extern unsigned long p_kvzalloc;
extern unsigned long p_kvfree;
extern unsigned long p_ebitmap_set;
extern unsigned long p_hashtab_ins;
extern unsigned long p_kthread_create_on_node;
extern unsigned long p_wake_up_process;
extern unsigned long p_kthread_should_stop;
extern unsigned long p_msleep_interruptible;   /* blob 类型声明注入 live symtab */
extern unsigned long p_flex_prealloc; /* type_attr_map_array 扩容（policydb_write 序列化安全） */
extern unsigned long p_flex_get;      /* 新槽定位（导出真函数，4.19 kallsyms T） */
extern unsigned long p_ctx_to_str;
extern unsigned long p_compute_av;
extern unsigned long p_write_op;
extern unsigned long p_sel_write_access;
extern unsigned long p_sel_write_context;
extern unsigned long p_bprm_sym;
extern unsigned long p_hook_heads;
extern unsigned long p_scall_table;
extern unsigned long p_scall_update;
extern unsigned long p_blob_sizes;
extern unsigned long p_fp_hook;
extern unsigned long p_strncpy_user;
extern unsigned long p_sidtab_to_sid;
extern unsigned long p_sidtab_search;   /* 4.19 sidtab_search（直返 context*） */
extern unsigned long p_sidtab_entry;    /* 5.10+ sidtab_search_entry */
extern unsigned long p_secclass_map;    /* 源 A 备用（自证后使用） */
extern unsigned long p_ksym_each;       /* KP 全表按名遍历（D 段可靠） */
extern unsigned long p_str2cls;         /* 内核 string_to_security_class（T 段） */
extern unsigned long p_str2av;          /* 内核 string_to_av_perm（T 段） */
extern unsigned long p_pdb_write;       /* policydb_write（T 段） */
extern unsigned long p_vmalloc_user;    /* vmalloc_user（T 段） */
extern unsigned long p_vfree;           /* vfree（T 段） */
extern unsigned long p_sel_open_policy; /* sel_open_policy（调用点自证锚） */
extern void *g_rp_mirror;               /* 特权读镜像（盖章前序列化存档） */
extern se_u32 g_rp_mirror_len;          /* 镜像有效长度；0=无效 */
extern unsigned long p_get_bit;
extern unsigned long p_cred_getsecid;
extern unsigned long p_secctx_to_sid;
extern unsigned long p_selinux_state;
extern unsigned long p_avtab_search;
extern unsigned long p_avtab_node_search;
extern unsigned long p_avtab_add;
extern unsigned long p_avtab_read;
extern unsigned long p_symtab_search;
extern unsigned long p_hashtab_search;
extern unsigned long p_get_perms;
extern unsigned long p_kfree;
extern unsigned long p_avc_reset;
extern unsigned long p_avc_struct;
extern unsigned long p_kp_hook;
extern unsigned long p_kp_unhook;
extern unsigned long p_kuid;
extern unsigned long p_set_sec_override;   /* 内核 set_security_override（组件域切轨） */
/* 新增绑定（改①②）：写劫持与内核文件读取 */
extern unsigned long p_sel_write_load;
extern unsigned long p_copy_from_user;
extern unsigned long p_filp_open;
extern unsigned long p_filp_close;
extern unsigned long p_kernel_read;
/* 影子页/坐标系重建：KP 内部全局（page_shift/linear_voffset/pgd_va）不在
 * KP 符号表（仅 KP_EXPORT_SYMBOL 进表，symbol.h:23 + kpimg.lds:89），KPM 引用即
 * unknown symbol 拒载 —— 坐标系改由 kallsyms 可见符号 + TCR/TTBR1 重建（se_shadow.c） */
extern unsigned long p_sel_load_ops;    /* selinuxfs sel_load_ops（System.map d 段实证） */
extern unsigned long p_vmalloc;
extern unsigned long p_vfree;
extern unsigned long p_stop_machine;
extern unsigned long p_gfp;             /* __get_free_pages */
extern unsigned long p_memstart;        /* arm64 memstart_addr（PHYS_OFFSET，memory.h:204） */
extern unsigned long p_kimage_voff;     /* arm64 kimage_voffset（memory.h:210） */
extern unsigned long p_swapper;         /* swapper_pg_dir */
extern unsigned long p_text;            /* _text（自证锚） */

extern struct sym_slot syms[34];

/* ---------------- se_util.c ---------------- */
void se_o_c(struct se_out *o, char c);
void se_o_s(struct se_out *o, const char *s);
void se_o_dec(struct se_out *o, se_u32 v);
void se_o_hex(struct se_out *o, se_u64 v, se_u32 width);
void se_o_pad(struct se_out *o, const char *s, se_u32 width);
se_u32 se_rd32(const se_u8 *p);
se_u64 se_rd64(const se_u8 *p);
void se_wr32(se_u8 *p, se_u32 v);
void se_wr64(se_u8 *p, se_u64 v);
void *se_alloc(se_ulong size);
void se_free(void *p);
int se_kread(void *dst, const void *src, se_ulong n);
int se_kwrite(void *dst, const void *src, se_ulong n);
int se_kptr_ok(se_u64 v);
int se_streq(const char *a, const char *b);
int se_memeq(const void *a, const void *b, se_u32 n);
int se_parse3(char *buf, char **a, char **b, char **c);

/* ---------------- se_symbol.c ---------------- */
unsigned long se_sym(const char *name);
void se_sym_fill(struct sym_slot *s);
void se_bind_symbols(void);

/* ---------------- se_layout.c ---------------- */
int se_read_policy(void **out, se_ulong *out_len);
int se_ebitmap_seg(const se_u8 *p, se_u32 avail, se_u32 *out);
int se_parse_hdr(const se_u8 *b, se_u32 blen, struct bin_hdr *h);
se_u32 se_pick_type(const se_u8 *b, const struct bin_hdr *h);
se_u8 *se_make_bprime(const se_u8 *b, se_u32 blen, const struct bin_hdr *h,
                      se_u32 type, int empty, se_u32 *out_len);
int se_pdb_read_copy(const se_u8 *bin, se_u32 blen, se_u8 *out, void *scratch);
int se_probe(const se_u8 *b, se_u32 blen, const se_u8 *bp, se_u32 bplen, se_u32 *off_out);
int se_anchor(const se_u8 *p, se_u32 vers, se_u32 *gap_out, se_u64 *len_out);
void *se_scan_pdb(void *base, se_u32 range, se_u32 blen, se_u32 *off_out, se_u32 *gap_out);
int se_locate(void);
int se_ctx_type(const char *s, se_u32 *type_out);
void *se_avnode_probe(void *h, const void *key);
int se_probe_avtab(void);
int se_off_from_caller(se_ulong caller, se_ulong callee, se_u32 max_bytes);
int se_te_avtab_from_code(void);
int se_scan_avtab(const se_u8 *copy);
int se_symtab_from_avtab(const se_u8 *copy);
void se_dump_pdb(const se_u8 *p);
int se_check_avtab(const se_u8 *copy);
int se_derive_layout(void);
int se_calibrate(void);
extern se_u8 g_su_ctx[SE_CTX_BUF];
extern int g_su_ctx_ok;
extern void *volatile g_seen_avtab;
extern void *g_avnode_orig;

extern void *g_copy_prev;   /* 副本换代：上代指针（se_policydb.c 定义） */

/* ---------------- se_policydb.c ---------------- */
int se_set_permissive(void *policydb, se_u32 perm_off, se_u32 type);
void *se_sym_search(void *sym, const char *name);
int se_type_val(const char *name, se_u32 *out);
int se_type_val_at(void *pdb, const char *name, se_u32 *out);
int se_class_val(const char *name, se_u32 *out);
int se_class_val_at(void *pdb, const char *name, se_u32 *out);
void se_free_perms(char **perms, se_u32 n);
int se_perm_mask(const char *cls, const struct se_rule *r, se_u32 *out);
int se_perm_mask_name(void *pdb, const char *cls, const char *perm, se_u32 *out);
int se_add_allow_at(void *pdb, se_u32 src, se_u32 tgt, se_u32 cls, se_u32 bits);
int se_clear_allow_at(void *pdb, se_u32 src, se_u32 tgt, se_u32 cls, se_u32 bits);
/* se_apply_inbound_g / se_apply_trio 已随三件套删除：live 恒出厂，
 * 三件套的放行职责由决策面唯一承担，见 se_decision.c 头注释。 */

/* ---------------- se_decision.c（决策面翻转） ----------------
 * live 归零后的 su/组件域放行通道：唯一 hook = avc_denied 收口的
 * 自建叠加（patch_config 双源互证 + 内核 aarch64_insn_patch_text 写
 * KP replace 入口 + 活体自检，不调用 KP hook()，KP 引擎内部行为零依赖）。
 * replace 语义：非特权（uid≥10000）零干预直通原生；特权 outbound
 * （源=su/comp）全类 / inbound 白名单六类 → 改 avd + return 0，不写缓存。
 * 原理与撤销理由见 se_decision.c 头注释（全 verbatim）。 */
int se_decision_install(void);   /* install 期调用；g_su_sid/g_comp_sid 标定之后 */
void se_decision_uninstall(void); /* 模块卸载：patch_text 恢复 KP replace 前缀 */
void se_decision_recalibrate(void); /* policy 重载后刷新 inbound 白名单 */
int se_perm_tab_build(void);     /* secclass_map 预建翻译表（build_copy 尾） */
int se_perm_tab_ready(void);     /* 表就绪查询 */
int se_copy_query_allow(se_u32 ssid, se_u32 tsid, se_u32 tclass,
                        se_u32 requested);   /* 副本收口查询（钩子层语义入参） */
int se_decision_ready(void);     /* 挂载 + 活体自检都通过才为 1 */
int se_decision_enabled(void);   /* status 面板用 */
se_u32 se_sym_nprim(const se_u8 *pdb, se_u32 idx);
void se_retire_copy(void *fresh);
se_u32 se_copy_attrs(void *pdb, se_u32 *out, se_u32 cap);
int se_build_copy(void);
int se_stamp_rules(void *pdb);   /* 新增：在给定副本上重打引擎规则（build_copy / load 门共用） */
int se_role_bits(int value);     /* 新增：live 的 role 条件位（LunSU 第三类 live 写） */
int se_absorb_blob(const se_u8 *blob, se_u32 blen);
int se_load_worker_start(void);  /* blob 新增类型声明注入 live */
/* se_allow_transition（早期死代码，全工程无调用点）已删 —— transition 放行
 * 由 se_decision.c 的决策面翻转覆盖（hooks.c binder 检查的 avc_has_perm
 * denied 落入 avc_denied 收口，tsid==su 翻转放行）。 */
/* se_rules[] / se_role_bits 已随三件套删除。 */

/* ---------------- se_render.c ---------------- */
int se_ctx_to_sid(const char *s, se_u32 *sid_out);
int se_parse_ctx(char *buf, void *ctxbuf);
int se_ctx_to_str(void *ctx, char *out, se_u32 outlen);
int se_compute_av(void *sctx, void *tctx, se_u32 tclass,
                  se_u32 *allowed, se_u32 *flags, se_u32 *avd5);
void se_selftest(void);
extern se_u32 g_avd[8];
const char *se_ctx_str(se_u32 sid, char *buf, se_u32 len);

/* ---------------- se_gate.c ---------------- */
int se_gate_privileged(void);
long se_access_write(void *file, char *ubuf, se_ulong size);
int se_install_gate(void);
long se_context_write(void *file, char *ubuf, se_ulong size);
int se_install_gate_ctx(void);
long se_load_write(void *file, char *ubuf, se_ulong size);   /* 新增：/load 写门 */
int se_install_load_gate(void);                              /* 新增 */
void se_uninstall_gates(void);                               /* 卸载还原门槽位 */
void se_uninstall_hook(void);                                /* 卸载还原 bprm 钩子槽位 */

/* ---------------- se_status.c（status 页冻结） ---------------- */
extern unsigned long p_sel_read_status;
extern unsigned long p_status_ops;
int se_status_install(void);
int se_install_read_gate(void);  /* /policy 读门——特权读策略答副本序列化 */
unsigned long se_sym_via_enum(const char *name);  /* KP 全表枚举解析（D 段可靠） */
int se_insn_pc_related(se_u32 inst);              /* PC 相关指令判定（决策面/读门共用） */
void se_status_restore(void);
extern void *g_orig_access_write;
extern void *g_orig_context_write;
extern void *g_orig_load_write;

/* ---------------- se_bprm.c ---------------- */
int se_cred_is_su(se_u64 cred);
int se_off_is_cred(void *bprm, se_u32 off);
se_u32 se_derive_cred_off(void *bprm);
int se_bprm_wrap(void *bprm);
int se_find_fn_field(se_u64 base, se_u64 target, se_u32 *off_out);
int se_install_hook_early(void);   /* event 期原子安装（原 se_install_hook，scall 分支删） */
extern int (*g_orig_bprm)(void *bprm);
extern se_u32 g_cred_off;
extern se_u32 g_lbs_cred;
extern se_u32 g_su_sid;
extern int g_hook_done;
extern int g_install_fails;

/*
 * 组件域参数化（三件套/切域/副本盖章作用于"生态组件域"，而不是
 * 硬编码 su）。KP 生态组件域 = magisk（KP handle_before_execve 实证），
 * 硬编码 su 会覆盖 KP 的域设置、断掉 KP package_config 通道（zygisk
 * 全灭）。
 *
 * 标定（se_install_engine，一次性）：
 *   live 有 "u:r:magisk:s0" 类型 → comp = magisk（KP 生态）
 *   否则                         → comp = su（4.19 等旧生态，装机验证路径）
 * 重载自愈（se_recalibrate_light/full）随 su_type 一起重解析 comp_type/sid。
 */
extern se_u32 g_comp_type;      /* 组件域 type 值（live policydb symtab） */
extern se_u32 g_comp_sid;       /* 组件域 sid（secctx_to_sid 标定，切域写入值） */
extern const char *g_comp_ctx;  /* "u:r:magisk:s0" | "u:r:su:s0" */
extern const char *g_comp_tname;/* "magisk" | "su"（symtab 查名用） */

/* ---------------- se_shadow.c（mkpms 式页分裂影子页） ---------------- */
int se_shadow_init(void);
int se_shadow_ready(void);
int se_shadow_hook(void *target, void *replace, void **backup);
void se_shadow_remove_all(void);
extern int g_shadow_installed;
extern int g_mm_ok;
extern int g_mm_page_shift;

/* ---------------- se_recal.c ---------------- */
int se_live_ok(void);
int se_comp_upgrade(void);   /* 生态域（magisk）出现时升级 g_comp_*，幂等 */
int se_cas32(volatile int *p, int oldv, int newv);
int se_recalibrate_light(void);
int se_recalibrate_full(void);
void se_avc_flush_after_recal(void);
void se_recalibrate(void);
extern int g_degraded;
extern volatile int g_recal_busy;
/* 决策面（avc_denied，RCU 读临界区，禁睡眠）只置旗，
 * 由门/bprm（进程上下文）代跑，自愈/探测晚一个周期。 */
extern volatile int g_recal_pending;   /* 1 = live 指纹失配，待 se_recalibrate */
extern volatile int g_comp_pending;    /* 1 = 组件域探测待办，待 se_comp_upgrade */
extern se_u32 g_recal_total;
extern int g_eco_loaded;   /* 生态重载已发生 */

/* ---------------- se_rules.c（新增，LunSU rules.c 1:1） ---------------- */
long se_handle_sepolicy(const se_u8 *payload, se_u32 len);

/* ---------------- sehide_main.c ---------------- */
int se_install_engine(void);   /* 由 se_bprm_wrap 首触（进程上下文）调用 */

#endif /* __SEHIDE_H */
