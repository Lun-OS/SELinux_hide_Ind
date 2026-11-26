/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <ksyms.h>
#include "sehide.h"

/* av_decision 偏移（4.19 security.h:190-196 与 6.1 security.h:256-262
 * verbatim 同构）：allowed@0, auditallow@4, auditdeny@8, seqno@12, flags@16 */
#define SE_AVD_OFF_ALLOWED    0
#define SE_AVD_OFF_AUDITALLOW 4
#define SE_AVD_OFF_AUDITDENY  8

/* patch_config.avc_denied 偏移（preset.h:121-141 字段序，第 12 个 u64）。
 * 偏移错误由 install 的双源互证兜底（安全失败，不错挂）。 */
#define SE_PC_AVDENIED_OFF    88u

/* 入口补丁条数上限：绝对跳转 4 条（LDR X17/BR X17/addr64），BTI 落点
 * 保留形态再加 1 条 BTI JC 前缀（KP hook_prepare:561-567 同款），共 5。
 * 与 KP branch_absolute（base/hook.c:309-317）同构。 */
#define SE_ADEN_PATCH_N       5u
/* backup trampoline 条数 = 复制（≤5）+ 绝对跳回（4）。 */
#define SE_ADEN_TRAMP_N       12u

static int se_decision_on;
static int se_aden_patched;   /* 入口已改写（install 中途失败/卸载恢复的依据） */

int se_decision_ready(void)
{
    return se_decision_on;
}

/* backup trampoline：位于本模块 .text（KPM 代码段可执行）。内容运行期
 * 由内核 patch_text 写入（对 KPM VA 走内核原生 fixmap/alias 路径）。
 * [0..bak_n-1] = 落点函数入口前缀复制；[bak_n..+3] = 绝对跳回
 * target + bak_n*4（函数主体）。跳回为 BR 间接落点 —— 本机 KP 自身
 * backup 链（relo + BR 回内核函数中部）自开机持续运行无恙，同模式
 * 活体证明。 */
static se_u32 se_aden_tramp[SE_ADEN_TRAMP_N] __attribute__((section(".text"), aligned(4)));
/* 卸载恢复用：落点函数入口前缀的原始内容（纯数据，无需可执行）。 */
static se_u32 se_aden_saved[SE_ADEN_PATCH_N];
/* 挂载状态：
 *   se_aden_target  补丁落点（direct=avc_denied / coexist=kp replace）
 *   se_aden_bak_n   备份/补丁条数（direct 带 BTI 前缀 5 / 否则 4；coexist 4）
 *   se_aden_mode    1=direct 内核入口接管（主形态）2=coexist KP replace 叠挂（回退） */
static unsigned long se_aden_target;
static int se_aden_bak_n;
/* r17 诊断：入口补丁快照（install 成功后复制），供 recal 巡检比对
 * 入口是否仍被我们接管——被还原 = 决策面失明（su 无兜底全灭）。 */
static se_u32 se_aden_live[SE_ADEN_PATCH_N];
/* 第二接管点：security_secctx_to_secid（域翻译，仅特权路径——su
 * setcon 链的翻译步骤；非特权不发起 setcon，不受影响）。生态注入域
 * （magisk 等）不在 live sidtab，KP setcon 的 secctx→sid 查找失败 →
 * 切域失败（6.1 上表现为 context=shell:s0）。别名规则：live 查找失败但副本有效
 * 的上下文 → 返回 comp_sid（su:s0，live 有效 sid）→ 会话进入决策面
 * 覆盖集。调用者仅 KP setcon + netfilter/netlabel 配置态（cred.c:796
 * 唯一常态调用者），零热路径。live 命中 → 原样透传（出厂语义）。 */
static unsigned long se_sec_target;
static int se_sec_bak_n, se_sec_patched, se_sec_on;
static se_u32 se_sec_saved[SE_ADEN_PATCH_N];
static se_u32 se_sec_live[SE_ADEN_PATCH_N];
static se_u32 se_sec_tramp[SE_ADEN_TRAMP_N]
    __attribute__((section(".text"), aligned(4)));
typedef int (*se_sec_fn)(const char *, se_u32, se_u32 *);
static int se_aden_mode;
/* coexist 回退形态下的 KP replace 地址（日志/诊断用）。 */
static unsigned long se_kp_replace_addr;
/* bypass 形态（KP unhook + direct）的回滚状态：
 *   se_kp_avc_unhooked   我们对 avc_denied 调过 p_kp_unhook（卸载/失败
 *                        路径必须 p_kp_hook 装回，否则 KP root 放行丢失）
 *   se_kp_slow_unhooked  同上，slow_avc_audit
 *   se_kp_slow_replace   slow_avc_audit 的 KP replace 地址（重装参数） */
static int se_kp_avc_unhooked;
static int se_kp_slow_unhooked;
static unsigned long se_kp_slow_replace;
static se_u32 se_rdiag_n;       /* 决策面透传打印限流计数 */

/* KP hook 重装（p_kp_hook 语义与 boot 期一致：重读当前入口为
 * origin_insts——调用前提：入口已恢复原始指令）。 */
static void se_kp_rehook_avc(void)
{
    void *bak = 0;

    if (!se_kp_avc_unhooked)
        return;
    se_kp_avc_unhooked = 0;
    if (p_kp_hook && se_kp_replace_addr &&
        !((int (*)(void *, void *, void **))p_kp_hook)
            ((void *)(se_ulong)p_adenied, (void *)se_kp_replace_addr, &bak))
        return;
    /* 重装失败 = 入口保持原始态（stock 语义，无翻转无 KP 放行）。
     * 系统稳定 fail-closed，仅功能缺失——概率极低（unhook 刚成功）。 */
    pr_info("sehide: kp re-hook FAILED, entry left stock (su grant down)\n");
}

static void se_kp_rehook_slow(void)
{
    void *bak = 0;

    if (!se_kp_slow_unhooked)
        return;
    se_kp_slow_unhooked = 0;
    if (p_kp_hook && se_kp_slow_replace) {
        ((int (*)(void *, void *, void **))p_kp_hook)
            ((void *)(se_ulong)p_slow_audit, (void *)se_kp_slow_replace, &bak);
        return;
    }
    pr_info("sehide: kp slow re-hook skipped (sym missing)\n");
}

/* backup trampoline 的调用原型：与 avc_denied 完全同签名（9 参），参数
 * 寄存器/栈透传。 */
typedef int (*se_aden_orig_t)(void *, void *, void *, void *, void *,
                              void *, void *, void *, void *);

/* 入口指令的 PC 相关判定（与 KP base/hook.c 的 masks/types 同一指令族，
 * 精简为本场景需要的"能否原样复制"判定）。命中 PC 相关族返回 1。 */
int se_insn_pc_related(se_u32 inst)
{
    se_u32 op = inst >> 26u;          /* B/BL 族高 6 位 */
    se_u32 top = inst >> 24u;         /* 粗分族 */

    if (op == 0x05u || op == 0x25u)           /* B / BL */
        return 1;
    if ((inst & 0xFF000010u) == 0x54000000u)  /* B.cond */
        return 1;
    if (top == 0x10u || top == 0x90u)         /* ADR / ADRP */
        return 1;
    if (top == 0x18u || top == 0x58u || top == 0x98u ||
        top == 0xD8u || top == 0x1Cu || top == 0x5Cu || top == 0x9Cu)
        return 1;                              /* LDR/PRFM/SIMD 字面量族 */
    if (top == 0x34u || top == 0x35u || top == 0x36u || top == 0x37u)
        return 1;                              /* CBZ/CBNZ/TBZ/TBNZ */
    return 0;                                  /* HINT(NOP/BTI)/序言/通用指令原样复制 */
}

static int se_insn_is_b(se_u32 inst)
{
    return (inst & 0xFC000000u) == 0x14000000u;
}


/* KSU 规则集掩码（钩子层静态序 perm 位；0 = 未覆盖/未解析）。 */
static se_u32 g_ksu_m_binder;        /* binder ALL（:153，任意源） */
static se_u32 g_ksu_m_fd;            /* fd use（:128） */
static se_u32 g_ksu_m_fifo;          /* fifo_file w/r/open/getattr（:129-132） */
static se_u32 g_ksu_m_uss;           /* uss r/w/connectto/getopt/getattr（:133-137） */
static se_u32 g_ksu_m_memfd;         /* memfd_file 5perm（:140-144；6.1 恒 0） */
static se_u16 g_ksu_c_binder, g_ksu_c_fd, g_ksu_c_fifo, g_ksu_c_uss,
              g_ksu_c_proc, g_ksu_c_dir, g_ksu_c_file, g_ksu_c_memfd;
/* 源域限定组的原子 perm 掩码（process/dir/file 按源域组合）。 */
static se_u32 g_ksu_p_sigchld, g_ksu_p_getpgid, g_ksu_p_sigkill,
              g_ksu_p_getattr, g_ksu_p_search, g_ksu_p_dir_read,
              g_ksu_p_file_open, g_ksu_p_file_read;
/* KSU 源域 sid（context 经 sidtab 解析；0 = 未解析 → 该源域规则失效）。 */
static se_u32 g_ksu_sid_init, g_ksu_sid_sm, g_ksu_sid_logd,
              g_ksu_sid_hws, g_ksu_sid_ss;
static int g_ksu_tab_ready;

void se_ksu_recal(void);  /* 前向声明：g_scm_addr 就绪即建 KSU 规则表
                           * （install 期 g_scm_addr 尚未就绪，首次建表
                           * deferred——se_perm_tab_build 尾部补建，幂等）。
                           * 定义在本文件 KSU 段。 */

#define SE_CLS_MAX   96u    /* 翻译表覆盖上限（钩子层类号安全界） */
#define SE_SCM_SZ    272u   /* sizeof(struct security_class_mapping)
                             * = 8 + (4*8+1)*8，4.19/6.1 avc_ss.h 逐字同构 */
#define SE_PERM_MAX  32u

static se_u16 g_cls_pol[SE_CLS_MAX];                /* tclass → policy 类值 */
static se_u32 g_perm_bit[SE_CLS_MAX][SE_PERM_MAX];  /* tclass → 位 i 的 policy 位掩码 */
static se_u32 g_nperm_tab[SE_CLS_MAX];              /* 每类钩子层权限数 */
static int g_tab_ready;
static unsigned long g_scm_addr;                     /* 自证通过的 secclass_map 地址 */
static se_u32 g_ksvc_cls;                            /* kernel_service 钩子层类号
                                                      * （setcon 翻转判据，安装期解析） */

int se_perm_tab_ready(void)
{
    return g_tab_ready;
}

/* secclass_map 地址自证：[0]="security"、[1]="process"（avc_ss.h 数组序，
 * SELinux 架构规范不变量）。返回 0=通过；非 0=错地址/不可读。 */
static int se_scm_verify(unsigned long addr)
{
    se_u64 np0 = 0, np1 = 0;
    char nb[16];

    if (!addr || (addr >> 48) != 0xffffull)
        return -2;
    if (se_kread(&np0, (void *)addr, 8) ||
        se_kread(&np1, (void *)(addr + SE_SCM_SZ), 8) ||
        !se_kptr_ok(np0) || !se_kptr_ok(np1))
        return -3;   /* name_ptr 非内核地址：L1 错地址形态 */
    memset(nb, 0, sizeof(nb));
    if (se_kread(nb, (void *)(se_ulong)np0, sizeof(nb) - 1u) ||
        !se_streq(nb, "security"))
        return -4;
    memset(nb, 0, sizeof(nb));
    if (se_kread(nb, (void *)(se_ulong)np1, sizeof(nb) - 1u) ||
        !se_streq(nb, "process"))
        return -5;
    return 0;
}

/* KP kallsyms_on_each_match_symbol 回调：首命中记录地址并停止遍历。 */
static int se_scm_enum_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 1;   /* 非 0 = 停止 */
}

/* secclass_map 地址解析：
 * 通道 1 = L1（kp symbol_lookup_name 首路径，p_secclass_map）——D 段
 *          错地址前科，先自证把关；
 * 通道 2 = KP 导出 kallsyms_on_each_match_symbol 精确名遍历。 */
static int se_scm_resolve(void)
{
    unsigned long addr;
    int rc;

    addr = p_secclass_map;
    rc = se_scm_verify(addr);
    if (!rc) {
        g_scm_addr = addr;
        return 0;
    }
    pr_info("sehide: scm L1 addr=%016lx verify rc=%d, retry via kp enum\n",
            (se_u64)addr, rc);

    if (!p_ksym_each)
        return -6;
    addr = 0;
    ((int (*)(int (*)(void *, unsigned long), const char *, void *))
         p_ksym_each)(se_scm_enum_cb, "secclass_map", &addr);
    rc = se_scm_verify(addr);
    if (rc) {
        pr_info("sehide: scm kp-enum addr=%016lx verify rc=%d\n",
                (se_u64)addr, rc);
        return -7;
    }
    g_scm_addr = addr;
    pr_info("sehide: secclass_map via kp enum %016lx\n", (se_u64)addr);
    return 0;
}

/* 建表：与内核 selinux_set_mapping 逐句等价（services.c:133/151 verbatim），
 * pol=副本 L.copy。零布局知识（272B 为源码结构定义）、零扫描（O(类数×
 * 权限数) 次内核函数调用）、零提取数据（类名/权限名全部来自内核自身
 * secclass_map 与副本 symtab）。 */
int se_perm_tab_build(void)
{
    se_u32 tclass, ncls_ok = 0;
    int rc;

    g_tab_ready = 0;
    if (!L.ok || !L.copy)
        return -1;
    if (!p_str2cls || !p_str2av)
        return -2;

    rc = se_scm_resolve();
    if (rc)
        return rc;

    memset(g_cls_pol, 0, sizeof(g_cls_pol));
    memset(g_perm_bit, 0, sizeof(g_perm_bit));
    memset(g_nperm_tab, 0, sizeof(g_nperm_tab));

    for (tclass = 1; tclass < SE_CLS_MAX; tclass++) {
        se_u64 name_ptr = 0;
        char name[48];
        se_u32 cn = 0, i;
        unsigned long cls_pol;

        if (se_kread(&name_ptr, (void *)(g_scm_addr +
                     (unsigned long)(tclass - 1u) * SE_SCM_SZ), 8))
            break;                      /* 读失败=表尾 */
        if (!se_kptr_ok(name_ptr))
            break;

        memset(name, 0, sizeof(name));
        if (se_kread(name, (void *)name_ptr, sizeof(name) - 1u))
            break;
        while (cn < sizeof(name) - 1u && name[cn])
            cn++;
        if (!cn)
            break;

        /* 内核函数：类名 → 副本 policy 类值（=cladatum->value）。 */
        cls_pol = ((se_u16 (*)(void *, const char *))p_str2cls)(L.copy, name);
        if (!cls_pol)
            continue;                   /* 副本无此类：该钩子层号不使用 */
        g_cls_pol[tclass] = (se_u16)cls_pol;
        ncls_ok++;

        for (i = 0; i < SE_PERM_MAX; i++) {
            se_u64 perm_ptr = 0;
            char pname[40];
            se_u32 pn = 0;

            g_perm_bit[tclass][i] = 0;

            if (se_kread(&perm_ptr, (void *)(g_scm_addr +
                         (unsigned long)(tclass - 1u) * SE_SCM_SZ +
                         8u + 8u * i), 8))
                break;
            if (!se_kptr_ok(perm_ptr))
                break;                  /* NULL 终止=该类权限尾 */
            memset(pname, 0, sizeof(pname));
            if (se_kread(pname, (void *)perm_ptr, sizeof(pname) - 1u))
                break;
            while (pn < sizeof(pname) - 1u && pname[pn])
                pn++;
            if (!pn)
                continue;

            /* 内核函数：权限名 → 1<<(perdatum->value-1) = policy 位。
             * 副本无此权限位 → 保留 0（该钩子层位恒 deny，fail-closed）。 */
            g_perm_bit[tclass][i] =
                ((se_u32 (*)(void *, se_u16, const char *))p_str2av)
                    (L.copy, (se_u16)cls_pol, pname);
        }
        g_nperm_tab[tclass] = i;
    }

    /* 完整性下界：secclass_map 类数 >60（内核 classmap.h），副本类定义
     * 与 live 一致（blob 吸收类数校验）→ 全部应解出；低于 32=表不可信。
     * （不依赖任何具体类号常量。） */
    if (ncls_ok < 32u) {
        pr_info("sehide: perm tab build failed (cls_ok=%u) copy-query off\n",
                ncls_ok);
        return -8;
    }

    g_tab_ready = 1;
    pr_info("sehide: perm tab built via kernel string_to_* (%u classes)\n",
            ncls_ok);
    /* g_scm_addr 此刻才就绪（本函数内 se_scm_resolve）——install 期的
     * se_ksu_recal 首调只会 deferred，此处补建 KSU 规则表（幂等）。 */
    se_ksu_recal();
    return 0;
}

int se_copy_query_allow(se_u32 ssid, se_u32 tsid, se_u32 tclass,
                        se_u32 requested)
{
    se_u32 type_s = 0, type_t = 0;
    se_u8 key[8];
    void *node;
    se_u32 datum = 0;
    se_u32 i;
    static unsigned int qf_n;    /* 失败诊断限频（≤16） */

#define QF_FAIL(tag, vals...)                                    \
    do {                                                         \
        if (qf_n < 16u) {                                        \
            qf_n++;                                              \
            pr_info("sehide: cq " tag "\n", ##vals);             \
        }                                                        \
    } while (0)

    if (!g_tab_ready || !L.ok || !L.copy || !L.avtab_off) {
        QF_FAIL("no-table ready=%d copy=%d", g_tab_ready, !!L.copy);
        return 0;
    }
    if (!tclass || tclass >= SE_CLS_MAX || !g_cls_pol[tclass]) {
        QF_FAIL("no-cls tclass=%u pol=%u", tclass,
                tclass < SE_CLS_MAX ? g_cls_pol[tclass] : 0u);
        return 0;
    }

    /* ① sid → context.type：按符号存在性分派——v5.5 及以前
     * sidtab_search 是真函数；v5.6 起变 sidtab.h static inline
     * （kallsyms 无符号），sidtab_search_entry 出现。两符号存在性
     * 互斥，按存在性选路对 5.6-5.9 同样正确（按版本号分界会错分）。 */
    if (p_sidtab_entry) {
        se_u64 entry;

        if (!p_sidtab_entry) {
            QF_FAIL("no-sym-entry");
            return 0;
        }
        entry = ((se_u64(*)(void *, se_u32))p_sidtab_entry)(L.sidtab, ssid);
        if (!entry || !se_kptr_ok(entry) ||
            se_kread(&type_s, (void *)(se_ulong)(entry + 16u), 4)) {
            QF_FAIL("sid-s fail ssid=%u entry=%llx", ssid,
                    (se_u64)entry);
            return 0;
        }
        entry = ((se_u64(*)(void *, se_u32))p_sidtab_entry)(L.sidtab, tsid);
        if (!entry || !se_kptr_ok(entry) ||
            se_kread(&type_t, (void *)(se_ulong)(entry + 16u), 4)) {
            QF_FAIL("sid-t fail tsid=%u", tsid);
            return 0;
        }
    } else {
        se_u64 ctx;

        if (!p_sidtab_search) {
            QF_FAIL("no-sym-search");
            return 0;
        }
        ctx = ((se_u64(*)(void *, se_u32))p_sidtab_search)(L.sidtab, ssid);
        if (!ctx || !se_kptr_ok(ctx) ||
            se_kread(&type_s, (void *)(se_ulong)(ctx + 8u), 4)) {
            QF_FAIL("sid-s fail4 ssid=%u", ssid);
            return 0;
        }
        ctx = ((se_u64(*)(void *, se_u32))p_sidtab_search)(L.sidtab, tsid);
        if (!ctx || !se_kptr_ok(ctx) ||
            se_kread(&type_t, (void *)(se_ulong)(ctx + 8u), 4)) {
            QF_FAIL("sid-t fail4 tsid=%u", tsid);
            return 0;
        }
    }
    if (!type_s || !type_t) {
        QF_FAIL("zero-type s=%u t=%u", type_s, type_t);
        return 0;
    }

    /* ② 副本 avtab 查 AVTAB_ALLOWED 节点（key 布局与 se_add_allow_at
     * 同款：{u16 src, u16 tgt, u16 cls, u16 specified}，cls=policy 值）。 */
    key[0] = (se_u8)type_s;  key[1] = (se_u8)(type_s >> 8);
    key[2] = (se_u8)type_t;  key[3] = (se_u8)(type_t >> 8);
    key[4] = (se_u8)g_cls_pol[tclass];
    key[5] = (se_u8)(g_cls_pol[tclass] >> 8);
    key[6] = 0x01;           /* AVTAB_ALLOWED */
    key[7] = 0x00;

    /* avtab_search_node 语义（avtab.c verbatim）：返回第一个 specified
     * 相交的节点——同 key 多节点并存（出厂 AUDITDENY + 生态 ALLOWED）
     * 时可能返回非 ALLOWED 节点。内核 compute_av 的做法 = 沿 next
     * 遍历直到 key 不匹配，取 specified&AVTAB_ALLOWED 的节点，对齐。 */
    node = 0;
    {
        void *cur = 0;
        se_u16 cspec = 0;

        if (p_avtab_node_search) {
            cur = (void *)((unsigned long (*)(void *, void *))
                           p_avtab_node_search)
                ((se_u8 *)L.copy + L.avtab_off, key);
        } else if (p_avtab_search) {
            cur = (void *)((unsigned long (*)(void *, void *))
                           p_avtab_search)
                ((se_u8 *)L.copy + L.avtab_off, key);
        } else {
            QF_FAIL("no-search-sym");
            return 0;
        }
        if (!cur || ((se_ulong)cur >> 48) != 0xffffull) {
            QF_FAIL("no-node s=%u t=%u cls=%u", type_s, type_t,
                    g_cls_pol[tclass]);
            return 0;
        }
        /* 遍历同 key 链（next@+16，avtab_node{key8,datum8,next}） */
        while (cur && se_kptr_ok((se_u64)(se_ulong)cur)) {
            se_u32 ckey = 0;

            if (se_kread(&cspec, (se_u8 *)cur + 6u, 2) ||
                se_kread(&ckey, (se_u8 *)cur, 4))
                break;
            if ((ckey & 0xffffu) != type_s ||
                ((ckey >> 16u) & 0xffffu) != type_t)
                break;                        /* 出段：key 升序越过 */
            if (cspec & 0x01u) {              /* AVTAB_ALLOWED */
                node = cur;
                break;
            }
            if (se_kread(&cur, (se_u8 *)cur + 16u, 8))
                break;
        }
        if (!node) {
            QF_FAIL("no-allowed-node s=%u t=%u cls=%u first=%04x",
                    type_s, type_t, g_cls_pol[tclass], cspec);
            return 0;
        }
        if (se_kread(&datum, (se_u8 *)node + 8u, 4)) {
            QF_FAIL("datum-kread fail");
            return 0;
        }
    }

    /* ③ 位判定：钩子层位 i 的 policy 掩码来自预建表。i >= 表内权限数
     * 的请求位按 map_decision auditdeny 语义视作 deny。 */
    for (i = 0; i < SE_PERM_MAX && i < 32u; i++) {
        if (!(requested & (1u << i)))
            continue;
        if (i >= g_nperm_tab[tclass]) {
            QF_FAIL("perm-oor tclass=%u i=%u nperm=%u", tclass, i,
                    g_nperm_tab[tclass]);
            return 0;
        }
        if (!(datum & g_perm_bit[tclass][i])) {
            QF_FAIL("bit-miss tclass=%u i=%u datum=%08x mask=%08x",
                    tclass, i, datum, g_perm_bit[tclass][i]);
            return 0;
        }
    }
#undef QF_FAIL
    return 1;
}

static int se_su_or_comp_hit(se_u32 ssid, se_u32 tsid)
{
    if (g_su_sid && (ssid == g_su_sid || tsid == g_su_sid))
        return 1;
    if (g_comp_sid && (ssid == g_comp_sid || tsid == g_comp_sid))
        return 1;
    return 0;
}

/* ==================== KSU 规则集建表 / 刷新 / 判定 ==================== */

/* secclass_map 单类条目权限位查找：类基址 = g_scm_addr+(cls-1)*SE_SCM_SZ，
 * perms[] 起始偏移 8（name 指针之后），NULL 指针名终止（se_perm_tab_build
 * 同款读取骨架，services.c/avc_ss.h 源码结构定义）。命中返回 1<<i
 * （钩子层静态序 perm 位），未命中/不可读返回 0。 */
static se_u32 se_ksu_perm_bit(unsigned long cls_base, const char *perm)
{
    se_u32 i;

    for (i = 0; i < SE_PERM_MAX; i++) {
        se_u64 pp = 0;
        char pname[40];
        se_u32 pn = 0;

        if (se_kread(&pp, (void *)(cls_base + 8u + 8u * (unsigned long)i), 8))
            break;
        if (!se_kptr_ok(pp))
            break;                       /* NULL 终止 = 该类权限尾 */
        memset(pname, 0, sizeof(pname));
        if (se_kread(pname, (void *)pp, sizeof(pname) - 1u))
            break;
        while (pn < sizeof(pname) - 1u && pname[pn])
            pn++;
        if (pn && se_streq(pname, perm))
            return 1u << i;              /* 钩子层静态序位 */
    }
    return 0;
}

/* secclass_map 按名解析钩子层类号；未命中（6.1 无 memfd_file 等）
 * 返回 0。读取骨架同 se_perm_tab_build。 */
static se_u16 se_ksu_class_of(const char *cls)
{
    unsigned long off;
    se_u16 idx = 0;

    for (off = 0; off < (unsigned long)SE_CLS_MAX * SE_SCM_SZ;
         off += SE_SCM_SZ) {
        se_u64 np = 0;
        char name[48];
        se_u32 cn = 0;

        if (se_kread(&np, (void *)(g_scm_addr + off), 8))
            break;                       /* 读失败 = 表尾 */
        if (!se_kptr_ok(np))
            break;
        memset(name, 0, sizeof(name));
        if (se_kread(name, (void *)np, sizeof(name) - 1u))
            break;
        while (cn < sizeof(name) - 1u && name[cn])
            cn++;
        if (cn && se_streq(name, cls)) {
            idx = (se_u16)(off / SE_SCM_SZ + 1u);   /* 钩子层类号 1 起 */
            break;
        }
    }
    return idx;
}

/* KSU 规则集建表：类号 + 逐规则 perm 掩码（rules.c 行号见段注释）。
 * 前提 g_scm_addr 已自证（se_scm_resolve，se_perm_tab_build 内执行）；
 * 未就绪 → ready=0 → 判定全 0（B 类型，fail-closed）。幂等。 */
static void se_ksu_tab_build(void)
{
    unsigned long base;
    se_u16 c;

    g_ksu_tab_ready = 0;
    if (!g_scm_addr) {
        /* fail-visible：静默 return 会让"表没建"与"没调用"无法从
         * 日志区分，装机排查失去锚点。 */
        pr_info("sehide: ksu rule tab deferred (scm not ready)\n");
        return;
    }

#define KSU_PARSE(cls_name, var_cls)                                    \
    do {                                                                \
        (var_cls) = se_ksu_class_of(cls_name);                          \
        if (!(var_cls)) {                                               \
            pr_info("sehide: ksu rule tab build failed "                \
                    "(class %s unresolved)\n", cls_name);               \
            return;  /* 静态表必含架构类；缺失 = 错地址，全关 */        \
        }                                                               \
        base = g_scm_addr +                                             \
               (unsigned long)((var_cls) - 1u) * SE_SCM_SZ;             \
    } while (0)

    /* binder ALL（:153）：类号命中即全位，无需逐 perm。 */
    KSU_PARSE("binder", g_ksu_c_binder);
    g_ksu_m_binder = 0xffffffffu;

    KSU_PARSE("fd", g_ksu_c_fd);
    g_ksu_m_fd = se_ksu_perm_bit(base, "use");               /* :128 */

    KSU_PARSE("fifo_file", g_ksu_c_fifo);                    /* :129-132 */
    g_ksu_m_fifo = se_ksu_perm_bit(base, "write") |
                   se_ksu_perm_bit(base, "read") |
                   se_ksu_perm_bit(base, "open") |
                   se_ksu_perm_bit(base, "getattr");

    KSU_PARSE("unix_stream_socket", g_ksu_c_uss);            /* :133-137 */
    g_ksu_m_uss = se_ksu_perm_bit(base, "read") |
                  se_ksu_perm_bit(base, "write") |
                  se_ksu_perm_bit(base, "connectto") |
                  se_ksu_perm_bit(base, "getopt") |
                  se_ksu_perm_bit(base, "getattr");

    KSU_PARSE("process", g_ksu_c_proc);
    g_ksu_p_sigchld = se_ksu_perm_bit(base, "sigchld");      /* :119 */
    g_ksu_p_getpgid = se_ksu_perm_bit(base, "getpgid");      /* :156 */
    g_ksu_p_sigkill = se_ksu_perm_bit(base, "sigkill");      /* :157 */
    g_ksu_p_getattr = se_ksu_perm_bit(base, "getattr");      /* :118/:150 */

    KSU_PARSE("dir", g_ksu_c_dir);
    g_ksu_p_search   = se_ksu_perm_bit(base, "search");      /* :114/:122/:147 */
    g_ksu_p_dir_read = se_ksu_perm_bit(base, "read");        /* :115 */

    KSU_PARSE("file", g_ksu_c_file);
    g_ksu_p_file_open   = se_ksu_perm_bit(base, "open");     /* :116/:124/:149 */
    g_ksu_p_file_read   = se_ksu_perm_bit(base, "read");     /* :117/:123/:148 */
    (void)se_ksu_perm_bit(base, "getattr");  /* logd :125 —— 与 read/open 同掩码使用，见 file 组 */

    /* memfd_file（:140-144）：6.1 无此类 → 0 → 自动失效。 */
    c = se_ksu_class_of("memfd_file");
    g_ksu_c_memfd = c;
    g_ksu_m_memfd = c ? (se_ksu_perm_bit(g_scm_addr +
                          (unsigned long)(c - 1u) * SE_SCM_SZ, "execute") |
                         se_ksu_perm_bit(g_scm_addr +
                         (unsigned long)(c - 1u) * SE_SCM_SZ, "getattr") |
                         se_ksu_perm_bit(g_scm_addr +
                         (unsigned long)(c - 1u) * SE_SCM_SZ, "map") |
                         se_ksu_perm_bit(g_scm_addr +
                         (unsigned long)(c - 1u) * SE_SCM_SZ, "read") |
                         se_ksu_perm_bit(g_scm_addr +
                         (unsigned long)(c - 1u) * SE_SCM_SZ, "write"))
                      : 0;

#undef KSU_PARSE
    g_ksu_tab_ready = 1;
    pr_info("sehide: ksu rule tab built binder=%u fd=%u fifo=%u uss=%u "
            "proc=%u dir=%u file=%u memfd=%u\n",
            g_ksu_c_binder, g_ksu_c_fd, g_ksu_c_fifo, g_ksu_c_uss,
            g_ksu_c_proc, g_ksu_c_dir, g_ksu_c_file, g_ksu_c_memfd);
}

/* KSU 源域 sid 解析（se_recal.c 标定同款双通道；sehide_main.c install
 * 与 recal light/full 的既有先例）。0 = 失败 → 该源域规则失效
 * （fail-closed：B 类型透传）。 */
static se_u32 se_ksu_sid_of(const char *ctx)
{
    se_u32 sid = 0;

    if (p_secctx_to_sid)
        ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
            (ctx, (se_u32)strlen(ctx), &sid);
    if (!sid)
        se_ctx_to_sid(ctx, &sid);
    return sid;
}

/* KSU 规则集刷新：掩码建表一次（secclass_map 为内核静态数据，policy
 * 重载不影响）；源域 sid 随 sidtab 换代重算（recal light/full 与
 * install 均调用）。幂等。 */
void se_ksu_recal(void)
{
    if (!g_scm_addr) {
        /* r15 修复：决策面 selftest（init→su binder 必 deny 出厂前提）
         * 依赖 G4 init 全类规则翻转；scm/规则表 deferred 时 selftest
         * 必返 -13 → 决策面永久降级。scm 解析仅依赖内核
         * 符号，与副本无关——提前到决策面安装前执行。 */
        if (se_scm_resolve())
            return;
    }
    if (!g_ksu_tab_ready)
        se_ksu_tab_build();

    /* kernel_service 类号解析（幂等，一次）：SECCLASS_* 常量 = secclass_map
     * 顺序（钩子层号），扫内核静态表按名定位，与 policy 重载无关。
     * 用途：setcon 翻转判据——KP set_security_override_from_ctx →
     * security_kernel_act_as 的 avc_has_perm(当前域→su, kernel_service,
     * use_as_override) 不放行则 selinux_kernel_act_as 不写 sid（hooks.c
     * 源码），setcon 静默失败进程留原域。 */
    if (!g_ksvc_cls && g_scm_addr) {
        se_u32 t;

        for (t = 1; t < SE_CLS_MAX; t++) {
            se_u64 name_ptr = 0;
            char name[24];

            if (se_kread(&name_ptr, (void *)(g_scm_addr +
                         (unsigned long)(t - 1u) * SE_SCM_SZ), 8))
                break;                          /* 表尾 */
            if (!se_kptr_ok(name_ptr))
                break;
            memset(name, 0, sizeof(name));
            if (se_kread(name, (void *)name_ptr, sizeof(name) - 1u))
                break;
            if (!strncmp(name, "kernel_service", sizeof(name))) {
                g_ksvc_cls = t;
                pr_info("sehide: kernel_service class=%u\n", t);
                break;
            }
        }
        if (!g_ksvc_cls)
            pr_info("sehide: kernel_service class not found\n");
    }

    g_ksu_sid_init = se_ksu_sid_of("u:r:init:s0");
    g_ksu_sid_sm   = se_ksu_sid_of("u:r:servicemanager:s0");
    g_ksu_sid_logd = se_ksu_sid_of("u:r:logd:s0");
    g_ksu_sid_hws  = se_ksu_sid_of("u:r:hwservicemanager:s0");
    g_ksu_sid_ss   = se_ksu_sid_of("u:r:system_server:s0");
    pr_info("sehide: ksu rule sids init=%u sm=%u logd=%u hws=%u ss=%u\n",
            g_ksu_sid_init, g_ksu_sid_sm, g_ksu_sid_logd,
            g_ksu_sid_hws, g_ksu_sid_ss);
}

/* KSU 规则集判定：返回 (源域限定后的) 钩子层 perm 掩码。
 *   0xffffffff = 全类组（G4 init 源）；
 *   0          = 未覆盖 → B 类型透传出厂；
 *   其他       = 位组，仅放行规则点名的位。
 * 调用前提：tsid ∈ {su, comp}（主干已保证）。 */
static se_u32 se_ksu_rule_mask(se_u32 ssid, se_u32 tclass)
{
    se_u32 m = 0;

    if (!g_ksu_tab_ready)
        return 0;

    /* G4：init → su 全类（rules.c:110 init→ksu ALL ALL）。 */
    if (g_ksu_sid_init && ssid == g_ksu_sid_init)
        return 0xffffffffu;

    if (tclass == g_ksu_c_binder)
        return g_ksu_m_binder;
    if (tclass == g_ksu_c_fd)
        return g_ksu_m_fd;
    if (tclass == g_ksu_c_fifo)
        return g_ksu_m_fifo;
    if (tclass == g_ksu_c_uss)
        return g_ksu_m_uss;
    if (g_ksu_c_memfd && tclass == g_ksu_c_memfd)
        return g_ksu_m_memfd;
    if (tclass == g_ksu_c_proc) {
        m = g_ksu_p_sigchld;                       /* 任意源（:119） */
        if (g_ksu_sid_ss && ssid == g_ksu_sid_ss)
            m |= g_ksu_p_getpgid | g_ksu_p_sigkill;    /* :156-157 */
        if ((g_ksu_sid_sm && ssid == g_ksu_sid_sm) ||
            (g_ksu_sid_hws && ssid == g_ksu_sid_hws))
            m |= g_ksu_p_getattr;                      /* :118/:150 */
        return m;
    }
    if (tclass == g_ksu_c_dir) {
        if (g_ksu_sid_sm && ssid == g_ksu_sid_sm)
            m |= g_ksu_p_search | g_ksu_p_dir_read;    /* :114-115 */
        if ((g_ksu_sid_logd && ssid == g_ksu_sid_logd) ||
            (g_ksu_sid_hws && ssid == g_ksu_sid_hws))
            m |= g_ksu_p_search;                       /* :122/:147 */
        return m;
    }
    if (tclass == g_ksu_c_file) {
        if (g_ksu_sid_sm && ssid == g_ksu_sid_sm)
            m |= g_ksu_p_file_open | g_ksu_p_file_read;    /* :116-117 */
        if (g_ksu_sid_logd && ssid == g_ksu_sid_logd)
            m |= g_ksu_p_file_read | g_ksu_p_file_open;    /* :123-125 */
        if (g_ksu_sid_hws && ssid == g_ksu_sid_hws)
            m |= g_ksu_p_file_read | g_ksu_p_file_open;    /* :148-149 */
        return m;
    }
    return 0;
}


/* avc_denied 收口的 replace。入口按 AAPCS64 接住 9 个参数槽
 * （x0-x7 + 第 9 个栈槽），再按 sehide.h 的静态版本形状表重排：
 *
 *   <=6.3   (9S) 有效参数从槽 1 起，avd 在槽 8
 *   6.4-6.12 (8) 有效参数从槽 0 起，avd 在槽 7；槽 8 是调用方栈上
 *                无关值，只在 orig 透传时原样带回（原函数只读 8 个）
 *   >=6.13  (9B) 有效参数从槽 0 起，avd 在槽 8（中间插的 base_perm
 *                只进 avc_update_node 记账，判定逻辑不消费）
 *
 * 这里只做 ABI 重排，不做任何形状探测。分支顺序：相关性分诊放最前
 * —— 非 su/comp 相关请求透传（见下）；放行判据 = KSU 原版规则集的
 * sid/类型匹配（详见 KSU 规则集段注释），uid 不参与本层任何判定。 */
static int se_aden_replace(void *a0, void *a1, void *a2, void *a3,
                           void *a4, void *a5, void *a6, void *a7, void *a8)
{
    void *v[9];
    enum se_aden_shape sh = se_kver_aden();
    se_u32 off = (sh == SE_ADEN_9S) ? 1u : 0u;
    void *avd = (sh == SE_ADEN_8) ? a7 : a8;
    se_u32 ssid, tsid, tclass, requested;
    se_u32 *f;

    v[0] = a0; v[1] = a1; v[2] = a2; v[3] = a3; v[4] = a4;
    v[5] = a5; v[6] = a6; v[7] = a7; v[8] = a8;

    ssid      = (se_u32)(se_u64)v[off + 0u];
    tsid      = (se_u32)(se_u64)v[off + 1u];
    tclass    = (se_u32)(se_u64)v[off + 2u] & 0xffffu;
    requested = (se_u32)(se_u64)v[off + 3u];

    /* 诊断打印（只读，限流，特权/非特权请求均经过此处）：1/65536 采样。
     * 风暴期 denial 每秒千级，
     * 1/1024 在 denial 风暴期仍会刷屏，1/65536 ≈ 分钟级 1 条。 */
    if ((++se_rdiag_n & 0xffffu) == 1u)
        pr_info("sehide: rp-pt s=%u t=%u c=%u r=%x tr=%08x %08x\n",
                ssid, tsid, tclass, requested, se_aden_tramp[0],
                se_aden_tramp[1]);

    /* 非特权（非 su/comp sid 相关）请求仅此一次分诊判决即透传内核
     * 原版——不查副本、不参与探测计数，放行与否完全由内核判决
     * （时序面 = 2 次整数比较）。判定集唯一：域基准（ssid/tsid）。
     * uid0 不参与判定：setcon 链闭环（secctx 别名 +
     * kernel_service 翻转）后 su 进程必然进 su 域，由 outbound 翻转
     * 覆盖——uid0 属超宽判据（非授权 uid0 daemon 也放行），不符合
     * 决策层"域基准 + 单一透传/翻转"设计。
     *
     * 已知缺口（仅特权路径，非特权路径不受影响）：KP 的 trusted-manager
     * per-task 旗标（task_ext->priv_sel_allow，管理器进程 uid10320/
     * untrusted_app 域）在本层无等效兑现——管理器进程本体的 SELinux
     * 拒绝（如 patch state 的 symlink）透传出厂 EACCES。不影响
     * supercall 路径（不涉 SELinux）与 apd 路径（exec 钩子切 su 域），
     * 仅管理器进程直接文件操作受限。若需修复：denial 时查 KP
     * get_current_task_ext 的旗标并按 pid 缓存（首次 O(1024)，
     * 缓存命中 ns 级）——未实现，避免热路径回归。 */
    if (!se_su_or_comp_hit(ssid, tsid))
        goto orig;

    /* setcon 到 su 域授权检查翻转（位于 su/comp 命中分支内：非特权路径
     * 仅前面 2 次整数比较即透传，本判据零触及）。secclass_map 钩子层
     * 类号安装期解析（g_ksvc_cls），运行时 = 2 次整数比较。 */
    if (g_ksvc_cls && tclass == g_ksvc_cls && tsid == g_su_sid)
        goto flip;

    /* 组件域升级探测与指纹自愈已整体移出透传链，由 recal worker
     * 周期静默巡检（se_recal.c）——deny 路径只保留分诊与翻转。 */

    /* outbound：源=su/comp → 全类翻转 */
    if ((g_su_sid && ssid == g_su_sid) ||
        (g_comp_sid && ssid == g_comp_sid)) {
        goto flip;
    }

    /* inbound —— KSU 原版规则集 (类,perm,源域) 匹配。
     * 全类组（init 源 / binder ALL）→ 全置 flip；位组 → 仅放行规则
     * 点名的位（allowed |= requested&mask、auditdeny 同步清位），规则
     * 未点名的位维持出厂 deny —— 与 KSU live 引擎逐位判定等价。 */
    {
        se_u32 kmask = se_ksu_rule_mask(ssid, tclass);

        if (kmask == 0xffffffffu) {
            goto flip;
        }
        if (kmask & requested) {
            if (avd) {
                f = (se_u32 *)avd;
                f[SE_AVD_OFF_ALLOWED / 4]   |= (requested & kmask);
                f[SE_AVD_OFF_AUDITDENY / 4] &= ~(requested & kmask);
            }
            return 0;
        }
    }

    /* 副本收口：规则集外的 su/comp 相关请求查生态规则（副本 = 出厂
     * 基底 + 生态规则 + 引擎盖章；出厂 allow 的请求不会进 denied 收口，
     * 故查询命中 ⟺ 生态规则新增授权）。查询未就绪/未命中 → orig
     * （fail-closed 出厂语义）。 */
    if (se_copy_query_allow(ssid, tsid, tclass, requested)) {
        goto flip;
    }

    /* inbound deny 失败路径：判定走 orig（出厂 -EACCES），但调用方
     * avc_audit 用同一栈上 avd 计算 audited = denied & auditdeny
     * （avc.h:134-136，avc.c:1193）——出厂 auditdeny 非零，审计记录
     * 会带出 tcontext=su/comp 域（探针经 logcat 读回即 root 证据）。
     * 清位 = dontaudit 语义：avd 为调用方栈副本（avc.c:1157 memcpy 自
     * 缓存节点），清位不污染 avc 缓存、不写 live；allowed 位不动，
     * 判定结果逐位保持出厂。仅 su/comp 相关请求清位，非相关透传
     * （上方 goto orig）保持出厂纯净。RCU 读临界区内单条整数写，
     * 无睡眠无分配，与 flip 同款纪律。 */
    goto orig_audit_suppress;

flip:
    /* r17 诊断：outbound 翻转 1/128 采样（1/65536 太稀，outbound 才是
     * su 存活判据；inbound G4 翻转仅 selftest/生态触发，采样并入）。 */
    if ((++se_rdiag_n & 0x7fu) == 1u)
        pr_info("sehide: rp-flip s=%u t=%u c=%u r=%x avd=%016lx\n",
                ssid, tsid, tclass, requested, (se_u64)(se_ulong)avd);
    if (avd) {
        f = (se_u32 *)avd;
        f[SE_AVD_OFF_ALLOWED / 4]    = 0xffffffffu;
        f[SE_AVD_OFF_AUDITALLOW / 4] = 0u;
        f[SE_AVD_OFF_AUDITDENY / 4]  = 0u;
    }
    return 0;

orig_audit_suppress:
    if (avd) {
        f = (se_u32 *)avd;
        f[SE_AVD_OFF_AUDITDENY / 4] &= ~requested;
    }
    /* fallthrough */
orig:
    /* 原样透传全部 9 个槽：8 参形状下第 9 个是无关值，原函数忽略。
     * 透传路径零打印零计数——热路径（denial 可达每秒千级）
     * 任何打印都会灌满 dmesg 环形缓冲。 */
    return ((se_aden_orig_t)(se_u64)se_aden_tramp)
           (a0, a1, a2, a3, a4, a5, a6, a7, a8);
}

/* policy 重载（recal light/full）后刷新 KSU 规则集 —— 掩码基于内核
 * 静态 secclass_map（重载不变，仅首次建表）；源域 sid 随 sidtab 换代
 * 必须重算。幂等。 */
void se_decision_recalibrate(void)
{
    /* 本层判定 = KSU 规则集（掩码 + 源域 sid）；预建翻译表由
     * build_copy 尾部重建，此处只做 KSU 刷新与日志锚点。 */
    se_ksu_recal();
    pr_info("sehide: ksu rule refreshed (tab=%d)\n", g_ksu_tab_ready);
}

/* 第二接管点的 replace：live 命中原样透传；live 失败但副本有效的
 * 上下文（生态注入域）→ 别名 comp_sid。限频打印。 */
static int se_secctx_replace(const char *secctx, se_u32 seclen, se_u32 *secid)
{
    int rc = ((se_sec_fn)(se_u64)se_sec_tramp)(secctx, seclen, secid);

    if (!rc || !secid)
        return rc;
    {
        char buf[96];
        se_u8 ctx[SE_CTX_BUF];
        se_u32 n = seclen;
        static int sn, sfn;
        int prc;

        if (!L.ok || !L.copy || n == 0 || n >= sizeof(buf) || !g_comp_sid) {
            if (sfn < 16u) {        /* secctx 低频（仅 setcon/配置态）：
                                     * 每次失败都打，总量封顶防异常风暴 */
                sfn++;
                pr_info("sehide: secctx gate fail rc=%d n=%u ok=%d copy=%d "
                        "comp=%u\n", rc, n, L.ok, !!L.copy, g_comp_sid);
            }
            return rc;
        }
        memcpy(buf, secctx, n);
        buf[n] = 0;
        memset(ctx, 0, sizeof(ctx));
        /* 形态校验门（不依赖副本/注入时序）：3-5 段冒号分隔、user/role/
         * type 非空 = 合法 SELinux 上下文。已观测到：用户态注入未
         * 跑（无 /load absorbed）时副本 symtab 无注入类型（seg_val -2），
         * 按"副本必须含此类型"设门会让别名依赖注入是否发生——错误。
         * live 查找已失败（进到此处的前提）+ 形态合法 → 直接别名 su 域：
         * setcon 目的只是把进程送进被覆盖域，su:s0 是 live 有效 sid，
         * 出厂 magisk 类型存在与否无关紧要。副本 parse 可用时仍先走
         * （更严：拒绝副本也不认的上下文）。 */
        {
            unsigned int ci, seg = 1, seg_ok = 1, len = 0;

            for (ci = 0; ci < n; ci++) {
                if (buf[ci] == ':') {
                    if (!len)
                        seg_ok = 0;     /* 空段 */
                    seg++;
                    len = 0;
                } else {
                    len++;
                }
            }
            if (!len || seg < 3u || seg > 5u)
                seg_ok = 0;
            if (!seg_ok) {
                if (sfn < 16u) {
                    sfn++;
                    pr_info("sehide: secctx shape fail n=%u seg=%u "
                            "ctx='%.16s'\n", n, seg, buf);
                }
                return rc;              /* 非法形态：出厂失败语义 */
            }
        }
        prc = se_parse_ctx(buf, ctx);
        if (prc && prc != -2) {
            if (sfn < 16u) {
                unsigned int hi;

                sfn++;
                pr_info("sehide: secctx parse fail rc=%d n=%u ctx='%.16s' "
                        "hex=", prc, n, buf);
                for (hi = 0; hi < 16u && hi < n; hi++)
                    pr_cont("%02x", buf[hi]);
                pr_cont("\n");
            }
            return rc;              /* 结构异常：出厂失败语义 */
        }
        /* prc==-2 = 副本 symtab 无此类型（注入未跑/未吸收）：形态已合法，
         * 照常别名（不再依赖副本内容）。 */
        *secid = g_comp_sid;
        if ((++sn & 0x0fu) == 1u)
            pr_info("sehide: secctx alias '%s' -> su sid=%u (n=%d)\n",
                    buf, g_comp_sid, sn);
        return 0;
    }
}

/* 第二接管点安装（avc 接管成功后调用）。独立失败仅告警——决策面
 * 主功能不依赖本点，6.1 的 su 切域依赖它。 */
static int se_sec_install(void)
{
    se_u32 e[5] = {0, 0, 0, 0, 0};
    se_u32 insns[SE_ADEN_PATCH_N];
    unsigned long lo;
    int i, rc, pad_bti = 0;

    if (se_sec_on || !p_secctx_to_sid || !p_kp_hpnosync)
        return -1;
    se_sec_target = (unsigned long)p_secctx_to_sid;

    for (i = 0; i < 5; i++) {
        if (se_kread(&e[i], (void *)(se_sec_target +
                     (unsigned long)i * 4u), 4))
            return -2;
    }
    switch (e[0]) {
    case 0xd503233fu: case 0xd503237fu:
    case 0xd503245fu: case 0xd503249fu:
    case 0xd50324dfu:
        pad_bti = 1;
        break;
    default:
        if ((e[0] >> 24u) == 0xa9u || (e[0] >> 24u) == 0xa8u ||
            (e[0] >> 24u) == 0xd1u || e[0] == 0xd503201fu)
            pad_bti = 0;
        else {
            pr_info("sehide: secctx entry %08x not a prologue, skip\n", e[0]);
            return -3;
        }
    }
    se_sec_bak_n = pad_bti ? 5u : 4u;
    for (i = 0; i < (int)se_sec_bak_n; i++) {
        if (se_kread(&se_sec_saved[i], (void *)(se_sec_target +
                     (unsigned long)i * 4u), 4))
            return -4;
        if (se_insn_pc_related(se_sec_saved[i])) {
            pr_info("sehide: secctx inst[%d] %08x pc-relative, skip\n",
                    i, se_sec_saved[i]);
            return -5;
        }
    }
    lo = (unsigned long)se_secctx_replace;
    if (pad_bti) {
        insns[0] = 0xd50324dfu;
        insns[1] = 0x58000051u;
        insns[2] = 0xd61f0220u;
        insns[3] = (se_u32)(lo & 0xFFFFFFFFu);
        insns[4] = (se_u32)(lo >> 32u);
    } else {
        insns[0] = 0x58000051u;
        insns[1] = 0xd61f0220u;
        insns[2] = (se_u32)(lo & 0xFFFFFFFFu);
        insns[3] = (se_u32)(lo >> 32u);
    }
    /* trampoline：前缀副本 + 跳回（单词写已验证路径）。 */
    {
        int (*wn)(void *, unsigned int) =
            (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;
        unsigned long back = se_sec_target +
            (unsigned long)se_sec_bak_n * 4u;
        int tn = (int)se_sec_bak_n + 4;

        for (i = 0; i < (int)se_sec_bak_n; i++)
            se_sec_tramp[i] = se_sec_saved[i];
        se_sec_tramp[se_sec_bak_n]     = 0x58000051u;
        se_sec_tramp[se_sec_bak_n + 1] = 0xd61f0220u;
        se_sec_tramp[se_sec_bak_n + 2] = (se_u32)(back & 0xFFFFFFFFu);
        se_sec_tramp[se_sec_bak_n + 3] = (se_u32)(back >> 32u);
        for (i = 0; i < tn; i++) {
            volatile se_u32 *rv = (volatile se_u32 *)
                (unsigned long)((unsigned long)se_sec_tramp +
                                (unsigned long)i * 4u);

            rc = wn((void *)(unsigned long)
                    ((unsigned long)se_sec_tramp +
                     (unsigned long)i * 4u), se_sec_tramp[i]);
            if (rc || *rv != se_sec_tramp[i]) {
                pr_info("sehide: secctx tramp w%d FAIL\n", i);
                return -6;
            }
        }
        /* 入口补丁（单词写 + volatile 逐词验证）。 */
        for (i = 0; i < (int)se_sec_bak_n; i++) {
            volatile se_u32 *rv = (volatile se_u32 *)
                (unsigned long)(se_sec_target +
                                (unsigned long)i * 4u);

            rc = wn((void *)(unsigned long)(se_sec_target +
                    (unsigned long)i * 4u), insns[i]);
            if (rc || *rv != insns[i]) {
                pr_info("sehide: secctx entry w%d FAIL\n", i);
                for (; i >= 0; i--)
                    wn((void *)(unsigned long)(se_sec_target +
                       (unsigned long)i * 4u), se_sec_saved[i]);
                return -7;
            }
        }
        se_sec_patched = 1;
        for (i = 0; i < (int)se_sec_bak_n; i++)
            se_sec_live[i] = insns[i];
        if (p_msleep_interruptible)
            ((void (*)(se_ulong))p_msleep_interruptible)(10);
        for (i = 0; i < (int)se_sec_bak_n; i++) {
            volatile se_u32 *rv = (volatile se_u32 *)
                (unsigned long)(se_sec_target +
                                (unsigned long)i * 4u);

            if (*rv != insns[i]) {
                pr_info("sehide: secctx verify FAIL @%d\n", i);
                for (i = (int)se_sec_bak_n - 1; i >= 0; i--)
                    wn((void *)(unsigned long)(se_sec_target +
                       (unsigned long)i * 4u), se_sec_saved[i]);
                se_sec_patched = 0;
                return -8;
            }
        }
        se_sec_on = 1;
        pr_info("sehide: secctx takeover on %016lx (prologue %08x bak=%d)\n",
                se_sec_target, se_sec_saved[0], se_sec_bak_n);
        return 0;
    }
}

static void se_sec_restore(void)
{
    int i;

    if (!se_sec_patched || !se_sec_target || !p_kp_hpnosync)
        return;
    {
        int (*wn)(void *, unsigned int) =
            (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;

        for (i = 0; i < se_sec_bak_n; i++)
            wn((void *)(se_sec_target + (unsigned long)i * 4u),
               se_sec_saved[i]);
    }
    se_sec_patched = 0;
    se_sec_on = 0;
    pr_info("sehide: secctx takeover restored\n");
}

/* 入口巡检（recal worker 周期调用）：读 avc_denied 入口逐词比对快照。
 * 被还原/被改 → 单词写重新接管（install 同款已验证路径）并复验；
 * 复验仍失败 → 返回负值由调用方降级决策。返回 0=在岗/已自愈。
 * 修复打印限频由调用方控制，此处每次实况只打一条。 */
int se_decision_entry_check(void)
{
    se_u32 cur[SE_ADEN_PATCH_N];
    int i, bad = 0, rc, sw = 0;

    if (!se_decision_on || !se_aden_patched || !se_aden_target)
        return 0;
    for (i = 0; i < se_aden_bak_n; i++)
        cur[i] = 0;
    if (se_kread(cur, (void *)(se_aden_target),
                 (unsigned long)se_aden_bak_n * 4u))
        return -1;
    for (i = 0; i < se_aden_bak_n; i++)
        if (cur[i] != se_aden_live[i])
            bad = 1;
    /* 第二接管点在岗校验 + 自愈（同款单词写路径）。与 avc 巡检独立：
     * avc 在岗时也必须检查 secctx 接管点。 */
    if (se_sec_on && se_sec_patched && se_sec_target) {
        se_u32 sc[SE_ADEN_PATCH_N];
        int sbad = 0, sw = 0;

        for (i = 0; i < se_sec_bak_n; i++)
            sc[i] = 0;
        if (!se_kread(sc, (void *)(se_sec_target),
                      (unsigned long)se_sec_bak_n * 4u)) {
            for (i = 0; i < se_sec_bak_n; i++)
                if (sc[i] != se_sec_live[i])
                    sbad = 1;
            if (sbad && p_kp_hpnosync) {
                int (*wn)(void *, unsigned int) =
                    (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;

                for (i = 0; i < se_sec_bak_n; i++)
                    wn((void *)(se_sec_target +
                                (unsigned long)i * 4u), se_sec_live[i]);
                for (i = 0; i < se_sec_bak_n; i++) {
                    volatile se_u32 *rv = (volatile se_u32 *)
                        (unsigned long)(se_sec_target +
                                        (unsigned long)i * 4u);

                    if (*rv != se_sec_live[i])
                        sbad = 2;
                }
                sw = 1;
            }
            pr_info("sehide: secctx entry %s (n=%d)\n",
                    sbad == 0 ? "ok" : (sbad == 2 ? "heal FAIL" : "healed"),
                    se_sec_bak_n);
        }
    }
    if (!bad)
        return sw ? 1 : 0;
    pr_info("sehide: entry drift %08x %08x %08x %08x %08x (n=%d), re-take\n",
            cur[0], cur[1], cur[2], cur[3], cur[4], se_aden_bak_n);
    if (!p_kp_hpnosync)
        return -2;
    {
        int (*wn)(void *, unsigned int) =
            (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;

        for (i = 0; i < se_aden_bak_n; i++) {
            rc = wn((void *)(se_aden_target +
                             (unsigned long)i * 4u), se_aden_live[i]);
            if (rc)
                return -3;
        }
    }
    for (i = 0; i < se_aden_bak_n; i++)
        cur[i] = 0;
    if (se_kread(cur, (void *)(se_aden_target),
                 (unsigned long)se_aden_bak_n * 4u))
        return -4;
    for (i = 0; i < se_aden_bak_n; i++)
        if (cur[i] != se_aden_live[i])
            return -5;
    pr_info("sehide: entry re-take ok (n=%d)\n", se_aden_bak_n);
    return 1;
}

/* 入口恢复：把备份的落点前缀写回（模块卸载 / 自检失败回退共用）。
 * direct 模式：avc_denied 复原为原始函数（KP 已 unhook，记录已释放，
 * 系统回到"无任何 SELinux hook"态）；coexist 模式：KP replace 入口
 * 复原，KP 自身 hook/backup 链原样。 */
static void se_aden_restore(void)
{
    int i;

    if (!se_aden_patched || !se_aden_target)
        return;

    /* 恢复写路径：多词写（fixmap/alias 两原语）曾在历史会话只正确落
     * 前半（后 2 词丢/坏），恢复用多词 = 恢复出错位态（ueventd 在
     * restore 窗口执行半成品入口崩）。单词 nosync 逐词写 + 跨核
     * 视图风险窗口 µs 级，为当前最可靠恢复手段。 */
    if (p_kp_hpnosync) {
        int (*wn)(void *, unsigned int) =
            (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;

        for (i = 0; i < se_aden_bak_n; i++)
            wn((void *)(se_aden_target + (unsigned long)i * 4u),
               se_aden_saved[i]);
    } else if (p_patch_text) {
        void *addrs[SE_ADEN_PATCH_N];

        for (i = 0; i < se_aden_bak_n; i++)
            addrs[i] = (void *)(se_aden_target + (unsigned long)i * 4u);
        ((int (*)(void **, se_u32 *, int))p_patch_text)
            (addrs, se_aden_saved, se_aden_bak_n);
    }
    se_aden_patched = 0;
}

/* 模块卸载：恢复落点入口原始前缀，决策面下线。由 sehide_exit 调用。 */
void se_decision_uninstall(void)
{
    if (!se_aden_patched)
        return;
    se_aden_restore();
    se_decision_on = 0;
    pr_info("sehide: decision-plane uninstalled, entry restored (mode=%s)\n",
            se_aden_mode == 1 ? "direct" : "coexist");
    /* bypass 形态下 KP 的 hook 已被我们 unhook——装回 KP（恢复 root
     * 放行与审计静音），系统完整回到 KP 原态。 */
    se_kp_rehook_avc();
    se_kp_rehook_slow();
    se_sec_restore();
}

/* S4 鉴别实验：patch 参数数组从栈改全局——栈版本在 unhook 后两写
 * 原语（内核 fixmap / KP alias-PTE）落盘同模式 stride-2 错位，写
 * 原语已排除；栈数组是与两条原语共享的剩余环节。若全局版落盘
 * 正确 → 错位源 = 栈内容在 patch 调用窗口被改写；若仍错位 → 排除
 * 栈，指向更深层。 */
static void *se_aden_addrs[SE_ADEN_PATCH_N];
static se_u32 se_aden_insns[SE_ADEN_PATCH_N];
static void *se_tramp_addrs[SE_ADEN_TRAMP_N];
static se_u32 se_tramp_insns[SE_ADEN_TRAMP_N];
static int se_tramp_word_ok;   /* tramp 单词写全词验证通过 → entry 同法 */
/* r12：KPM data/bss 区 store→load 不可靠实锤（memtest：写入值偏移
 * 2 词、原位置出现跨 boot 恒定的外来值）——参数数组全部迁往内核
 * vmalloc（rp 门同款分配），写入后自测，绕开 KPM 映射层。 */
static void *se_va_buf;
static unsigned long se_va_saved;

/* 模块卸载：恢复落点入口原始前缀，决策面下线。由 sehide_exit 调用。 */
int se_decision_install(void)
{
    void **addrs;
    se_u32 *insns;
    unsigned long back, target, lo;
    se_u32 init_sid = 0, binder_cls = 0;
    int i, rc, pad_bti = 0;

    if (se_decision_on)
        return 0;

    /* r12：参数数组 vmalloc 化。布局：addrs(48B=6 槽)|insns@48(24B)|
     * taddrs@96(48B)|tinsns@144(48B)|sig@192 = 288B → 512B。
     * r15 修复：原 addrs 仅 32B（4 槽），BTI pad bak_n=5 时第 5 个
     * 64 位指针溢出 8B 覆盖 insns[0..1]（BTI JC/LDR X17 被替换为
     * addrs[4]=target+0x10 的 quad）→ 入口首词执行非法指令 panic
     *（6.1 PACIASP 序言形态下）。insns 起点移至 +48 与 addrs 5 槽隔离。 */
    if (!p_vmalloc_user || !p_vfree) {
        pr_info("sehide: vmalloc syms missing\n");
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -1;
    }
    se_va_buf = ((void *(*)(se_u64))p_vmalloc_user)(512u);
    if (!se_va_buf) {
        pr_info("sehide: vmalloc(256) fail\n");
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -1;
    }
    {
        volatile se_u32 *t = (volatile se_u32 *)se_va_buf;
        int ok = 1;

        for (i = 0; i < 8; i++)
            t[i] = 0xA0000000u + (se_u32)i;
        for (i = 0; i < 8; i++)
            if (t[i] != 0xA0000000u + (se_u32)i)
                ok = 0;
        pr_info("sehide: va selftest ok=%d r=%08x %08x %08x %08x\n",
                ok, t[0], t[1], t[2], t[3]);
        if (!ok) {
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            se_kp_rehook_avc();
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -1;
        }
    }
    addrs = se_va_buf;
    insns = (se_u32 *)((unsigned long)se_va_buf + 48u);

    if (!p_adenied || !p_patch_text || !p_ahp || !g_su_sid) {
        pr_info("sehide: decision syms missing adenied=%016lx l3=%016lx "
                "ptext=%016lx ahp=%016lx su=%u\n",
                (se_u64)(se_ulong)p_adenied, (se_u64)(se_ulong)p_adenied_l3,
                (se_u64)(se_ulong)p_patch_text, (se_u64)(se_ulong)p_ahp,
                g_su_sid);
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -1;
    }

    {
        se_u32 e[3] = {0, 0, 0};

        if (se_kread(&e[0], (void *)(se_ulong)p_adenied, 4) ||
            se_kread(&e[1], (void *)(se_ulong)(p_adenied + 4), 4) ||
            se_kread(&e[2], (void *)(se_ulong)(p_adenied + 8), 4)) {
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -1;
        }

        if ((e[0] == 0xd50324dfu && e[1] == 0x58000051u) ||
            (e[0] == 0x58000051u && e[1] == 0xd61f0220u)) {
            /* 态① KP pad 在岗 → avc_denied 直挂 + KP replace 保留为链上
             * 下一跳：备份 KP pad（仅卸载恢复用，不再被执行）；补丁写
             * avc_denied（内核 text 是稳定写入面）；trampoline 纯
             * 重定向——不复制、不跳过任何指令，kp_replace 从其真实入口
             * 原样执行（KP task_ext 按任务授予完整保留）。
             * 约束：kpimg 只读——patch_map 对 KP 分配 VA 的地址翻译
             * 不可靠，详见函数头注释。 */
            se_u32 q0 = 0, q1 = 0;

            if (e[0] == 0xd50324dfu && e[2] != 0xd61f0220u) {
                pr_info("sehide: adenied bti entry word2 %08x != BR X17\n",
                        e[2]);
                ((void (*)(void *))p_vfree)(se_va_buf);
                se_va_buf = 0;
                return -2;
            }
            if (se_kread(&q0, (void *)(se_ulong)(p_adenied + 12), 4) ||
                se_kread(&q1, (void *)(se_ulong)(p_adenied + 16), 4)) {
                ((void (*)(void *))p_vfree)(se_va_buf);
                se_va_buf = 0;
                return -1;
            }
            target = (e[0] == 0xd50324dfu)
                     ? ((unsigned long)q0 | ((unsigned long)q1 << 32u))
                     : ((unsigned long)e[2] | ((unsigned long)q0 << 32u));
            if ((target >> 48u) != 0xffffu) {
                pr_info("sehide: kp replace target %016lx not kernel-text form\n",
                        target);
                ((void (*)(void *))p_vfree)(se_va_buf);
                se_va_buf = 0;
                return -3;
            }
            se_kp_replace_addr = target;
            se_aden_target = p_adenied;
            /* bypass 尝试：p_kp_unhook 让 KP 交还原始前缀（权威来源 =
             * KP boot 期 origin_insts 备份，stop_machine 原子写回），
             * 重读入口走 direct 组装（前缀副本 + 跳回 = 内核原生时序，
             * 拒绝路径不再经过 kp_replace 的 O(1024) task_ext 扫表）。
             * unhook 幂等（hook_t 缺失即 no-op，hmem.c:67-77）。
             * 失败链：重读失败/序言异常 → p_kp_hook 装回 → coexist。
             * 装回前提满足：KP 重装重读"当前入口"作 origin_insts，
             * 此刻入口 = unhook 写回的原始指令，与 boot 期语义一致。 */
            {
                se_u32 f[5];
                int bypassed = 0;

                if (p_kp_unhook) {
                    ((void (*)(void *))p_kp_unhook)((void *)(se_ulong)p_adenied);
                    /* KP hook_t 已被 unhook 释放（成功与否）——无论 bypass
                     * 结果如何置位，供失败/卸载路径的 re-hook 语义。 */
                    se_kp_avc_unhooked = 1;
                    for (i = 0; i < 5; i++) {
                        if (se_kread(&f[i], (void *)(se_ulong)(p_adenied +
                                     (unsigned long)i * 4u), 4))
                            break;
                    }
                    if (i == 5) {
                        switch (f[0]) {
                        case 0xd503233fu: /* PACIASP */
                        case 0xd503237fu: /* PACIBSP */
                        case 0xd503245fu: /* BTI C */
                        case 0xd503249fu: /* BTI J */
                        case 0xd50324dfu: /* BTI JC */
                            pad_bti = 1;
                            bypassed = 1;
                            break;
                        default:
                            if ((f[0] >> 24u) == 0xa9u || (f[0] >> 24u) == 0xa8u ||
                                f[0] == 0xd503201fu) {
                                pad_bti = 0;
                                bypassed = 1;
                            }
                            break;
                        }
                    }
                    if (bypassed) {
                        se_aden_bak_n = pad_bti ? 5 : 4;
                        se_aden_mode = 1;
                        se_kp_avc_unhooked = 1;
                        pr_info("sehide: kp unhooked, direct takeover "
                                "(prologue %08x bak=%d)\n", f[0], se_aden_bak_n);
                    } else {
                        /* 白名单拒：绝不 p_kp_hook 重装——重装会把 KP pad
                         * 内容备份成 origin_insts，破坏 KP relo 链（backup
                         * 变 pad 副本 → BR krep → kp_replace 死循环 → PC
                         * 乱飞 el1 崩溃）。直接 coexist：
                         *   unhook 成功场景 = KP 旧 backup（warp 内容未清）
                         *   仍指向原始前缀副本，链路完整；
                         *   unhook 失败场景 = 入口仍为 KP pad，现状语义。
                         *   两种场景 coexist patch 覆盖入口后均安全。 */
                        pr_info("sehide: post-unhook entry "
                                "%08x %08x %08x %08x %08x unexpected, coexist\n",
                                f[0], f[1], f[2], f[3], f[4]);
                    }
                } else {
                    pr_info("sehide: kp unhook symbol missing, coexist\n");
                }
                if (!bypassed) {
                    /* coexist 回退（现状语义）：tramp 纯重定向 kp_replace，
                     * KP pad 由主备份循环备份（此时入口已回到 KP pad）。 */
                    se_aden_bak_n = (e[0] == 0xd50324dfu) ? 5 : 4;
                    se_aden_mode = 3;
                    pad_bti = (e[0] == 0xd50324dfu);
                    pr_info("sehide: coexist mount on avc_denied (kp replace "
                            "via trampoline) %016lx, kpform=%s\n",
                            target, e[0] == 0xd50324dfu ? "A-bti5" : "B-nobti4");
                }
            }
        } else {
            /* 态② 原始入口 → direct 接管。序言白名单：PACIASP/PACIBSP/BTI*
             * 本身即间接跳转合法落点（架构规定 PACI 隐式授予 BTI），我们
             * 的补丁以 BTI JC 开头保持该属性（KP hook_prepare:561-567
             * 同款），补丁/备份各 5 条；其余序言（STP 族/NOP）4 条。 */
            switch (e[0]) {
            case 0xd503233fu: /* PACIASP */
            case 0xd503237fu: /* PACIBSP */
            case 0xd503245fu: /* BTI C */
            case 0xd503249fu: /* BTI J */
            case 0xd50324dfu: /* BTI JC */
                pad_bti = 1;
                break;
            default:
                if ((e[0] >> 24u) == 0xa9u || (e[0] >> 24u) == 0xa8u ||
                    (e[0] >> 24u) == 0xd1u ||
                    e[0] == 0xd503201fu) /* STP 族 / SUB (imm)（4.19 clang
                     * 常见栈帧开场 SUB SP,SP,#imm（d100c3ff）
                     * / NOP——均 PC 无关，可安全复制 */
                    pad_bti = 0;
                else {
                    pr_info("sehide: adenied entry %08x %08x %08x not a "
                            "prologue, refuse\n", e[0], e[1], e[2]);
                    ((void (*)(void *))p_vfree)(se_va_buf);
                    se_va_buf = 0;
                    return -2;
                }
            }
            se_aden_target = p_adenied;
            se_aden_bak_n = pad_bti ? 5 : 4;
            se_aden_mode = 1;
            pr_info("sehide: direct takeover avc_denied %016lx "
                    "(prologue %08x bti=%d bak=%d)\n",
                    (se_u64)(se_ulong)p_adenied, e[0], pad_bti,
                    se_aden_bak_n);
        }
    }
    if (p_adenied_l3 && p_adenied_l3 != p_adenied) {
        pr_info("sehide: adenied sources disagree %016lx vs %016lx\n",
                (se_u64)(se_ulong)p_adenied, (se_u64)(se_ulong)p_adenied_l3);
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -3;
    }

    /* 前缀备份（bak_n 条）。direct 模式备份 avc_denied 原始本体（含
     * PACIBSP——SP 修饰、无 PC 依赖，trampoline 内执行签名/验签自洽），
     * PC 相关校验：命中即 off（复制后会再执行）。mode=3 备份的是 KP pad
     * 5 词——仅作卸载恢复、不再被执行（trampoline 纯重定向 kp_replace），
     * 其中 LDR/BR 字面量形态属正常内容，PC 校验跳过。 */
    for (i = 0; i < se_aden_bak_n; i++) {
        if (se_kread(&se_aden_saved[i],
                     (void *)(se_aden_target + (unsigned long)i * 4u), 4)) {
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -1;
        }
        if (se_aden_mode != 3 && se_insn_pc_related(se_aden_saved[i])) {
            pr_info("sehide: target inst[%d] %08x pc-relative, off\n",
                    i, se_aden_saved[i]);
            se_kp_rehook_avc();
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -4;
        }
    }

    /* inbound 判定 = KSU 规则集：类号/权限位按名解析自内核
     * secclass_map（钩子层序而非 policy 序 —— 详见 KSU 规则集段注释）。 */

    /* S4 签名探针：位置编码图案 insns[i]=0xA0000000+i 经多词原语写入
     * 模块 bss 16 字节，回读即得 (落点, insns 下标) 的真实配对映射——
     * 直接观测 cb 行为而非推断。探针区无人执行零风险。 */
    {
        /* 探针数组同迁 va：sa1@+192 sv1@+224 sa2@+240 sv2@+272（sig 值
         * 直接写 sv，回读 sv 即观测）。 */
        void **sa1 = (void **)((unsigned long)se_va_buf + 192u);
        se_u32 *sv1 = (se_u32 *)((unsigned long)se_va_buf + 224u);
        void **sa2 = (void **)((unsigned long)se_va_buf + 240u);
        se_u32 *sv2 = (se_u32 *)((unsigned long)se_va_buf + 272u);
        int j, r1, r2;

        for (j = 0; j < 4; j++) {
            sa1[j] = (void *)((unsigned long)se_va_buf + 224u + (unsigned long)j * 4u);
            sv1[j] = 0xA0000000u + (se_u32)j;
            sa2[j] = (void *)((unsigned long)se_va_buf + 272u + (unsigned long)j * 4u);
            sv2[j] = 0xA0000000u + (se_u32)j;
        }
        r1 = p_kp_hotpatch
             ? ((int (*)(void **, se_u32 *, int))p_kp_hotpatch)(sa1, sv1, 4)
             : -99;
        r2 = p_patch_text
             ? ((int (*)(void **, se_u32 *, int))p_patch_text)(sa2, sv2, 4)
             : -99;
        pr_info("sehide: sig hp rc=%d %08x %08x %08x %08x | pt rc=%d "
                "%08x %08x %08x %08x (exp A0 A1 A2 A3)\n",
                r1, sv1[0], sv1[1], sv1[2], sv1[3],
                r2, sv2[0], sv2[1], sv2[2], sv2[3]);
    }

    /* 组装 backup trampoline。mode=3（KP pad 在岗）：**纯重定向 4 词**
     * [LDR X17,#8; BR X17; quad(kp_replace)] —— 不复制任何指令，kp_replace
     * 从其真实入口原样执行（KP task_ext 授予零损失）。mode=1（direct）：
     * [0..bak_n-1] 复制落点前缀；[bak_n..+3] 绝对跳回 target+bak_n*4。
     * trampoline 位于本模块 .text，写入走内核 patch_text。 */
    {
        void **taddrs = (void **)((unsigned long)se_va_buf + 96u);
        se_u32 *tinsns = (se_u32 *)((unsigned long)se_va_buf + 144u);
        int tn;

        if (se_aden_mode == 3) {
            tn = 4;
            back = se_kp_replace_addr;
            tinsns[0] = 0x58000051u;      /* LDR X17, #8 */
            tinsns[1] = 0xD61F0220u;      /* BR X17 */
            tinsns[2] = (se_u32)(back & 0xFFFFFFFFu);
            tinsns[3] = (se_u32)(back >> 32u);
        } else {
            tn = se_aden_bak_n + 4;
            for (i = 0; i < se_aden_bak_n; i++)
                tinsns[i] = se_aden_saved[i];
            back = se_aden_target + (unsigned long)se_aden_bak_n * 4u;
            tinsns[se_aden_bak_n]     = 0x58000051u;      /* LDR X17, #8 */
            tinsns[se_aden_bak_n + 1] = 0xD61F0220u;      /* BR X17 */
            tinsns[se_aden_bak_n + 2] = (se_u32)(back & 0xFFFFFFFFu);
            tinsns[se_aden_bak_n + 3] = (se_u32)(back >> 32u);
        }
        /* S4 鉴别实验②：单词写。多词数组传递已排除栈（全局数组同
         * 错位）——两条多词原语（内核 fixmap / KP hotpatch cb）共享
         * 的剩余环节 = 多词数组/cb 循环。单词写逐词独立调用，无数组
         * stride 可错。tramp 区无人执行，写坏零危害。 */
        if (p_kp_hpnosync) {
            int (*wn)(void *, unsigned int) =
                (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;

            for (i = 0; i < tn; i++) {
                volatile se_u32 *rv = (volatile se_u32 *)
                    (unsigned long)((unsigned long)se_aden_tramp +
                                    (unsigned long)i * 4u);

                rc = wn((void *)(unsigned long)
                        ((unsigned long)se_aden_tramp +
                         (unsigned long)i * 4u), tinsns[i]);
                pr_info("sehide: tramp w%d rc=%d rb=%08x exp=%08x\n",
                        i, rc, *rv, tinsns[i]);
                if (rc || *rv != tinsns[i]) {
                    pr_info("sehide: tramp word-write FAIL @%d\n", i);
                    rc = -1;
                    break;
                }
            }
            se_tramp_word_ok = (rc == 0);
        } else {
            for (i = 0; i < tn; i++)
                taddrs[i] = (void *)(unsigned long)
                            ((unsigned long)se_aden_tramp +
                             (unsigned long)i * 4u);
            if (p_kp_hotpatch)
                rc = ((int (*)(void **, se_u32 *, int))p_kp_hotpatch)
                     (taddrs, tinsns, tn);
            else
                rc = ((int (*)(void **, se_u32 *, int))p_patch_text)
                     (taddrs, tinsns, tn);
            se_tramp_word_ok = 0;
        }
        if (rc) {
            pr_info("sehide: tramp patch rc=%d\n", rc);
            se_kp_rehook_avc();
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -5;
        }
        /* 诊断：tramp 写入回读（patch_text 生效性实证）。 */
        {
            se_u32 tb[4];
            int j;

            for (j = 0; j < 4; j++)
                tb[j] = 0;
            if (!se_kread(&tb, (void *)se_aden_tramp, 16))
                pr_info("sehide: tramp rb %08x %08x %08x %08x\n",
                        tb[0], tb[1], tb[2], tb[3]);
        }
        /* 延迟回读：若 rb2 != rb，patch 之后有第三方写者改写了 tramp。 */
        if (p_msleep_interruptible)
            ((void (*)(se_ulong))p_msleep_interruptible)(10);
        {
            se_u32 tb2[4];
            int j;

            for (j = 0; j < 4; j++)
                tb2[j] = 0;
            if (!se_kread(&tb2, (void *)se_aden_tramp, 16))
                pr_info("sehide: tramp rb2 %08x %08x %08x %08x\n",
                        tb2[0], tb2[1], tb2[2], tb2[3]);
            /* 回读校验闸门：单词写路径已在写入循环内逐词 volatile
             * 验证（se_tramp_word_ok），此处 16B 块读仅作观测——
             * 块读（probe_kernel_read）对刚写区域可返回
             * 旋转视图，不能作为判据。多词路径仍用块读判定。 */
            if (!se_tramp_word_ok &&
                (tb2[0] != 0x58000051u || tb2[1] != 0xD61F0220u)) {
                pr_info("sehide: tramp verify FAIL, abort (entry untouched)\n");
                /* unhook 已发生：中止时必须把 KP hook
                 * 装回，否则 KP root 放行悬空 + 决策面缺席 → su 域
                 * SELinux 全 deny（"看似有 root 实则什么都干不了"）。 */
                se_kp_rehook_avc();
                ((void (*)(void *))p_vfree)(se_va_buf);
                se_va_buf = 0;
                return -5;
            }
        }
        if (se_tramp_word_ok)
            pr_info("sehide: tramp verified via word writes\n");
    }

    /* 写落点入口：[BTI JC 前缀（落点带 BTI 属性时）] + LDR X17/BR X17/
     * quad(se_aden_replace)；补丁条数 = 备份条数（整段覆盖备份区）。 */
    lo = (unsigned long)se_aden_replace;
    insns[0] = 0x58000051u;           /* LDR X17, #8 */
    insns[1] = 0xD61F0220u;           /* BR X17 */
    insns[2] = (se_u32)(lo & 0xFFFFFFFFu);
    insns[3] = (se_u32)(lo >> 32u);
    if (pad_bti) {
        insns[4] = insns[3];
        insns[3] = insns[2];
        insns[2] = insns[1];
        insns[1] = insns[0];
        insns[0] = 0xd50324dfu;       /* BTI JC */
    }
    for (i = 0; i < se_aden_bak_n; i++)
        addrs[i] = (void *)(p_adenied + (unsigned long)i * 4u);
    /* r11 内存自测①：模块 bss 纯 C store/load（同核、同 VA、无任何
     * patch 原语参与）——判模块 data 区 store/load 基本可靠性。
     * 位置签名图案错位即实锤 KPM 内存映射层异常（KP 加载器）。 */
    {
        static void *mt[4];
        static se_u32 mw[4];

        for (i = 0; i < 4; i++) {
            mt[i] = (void *)(0xB0000000ul + (unsigned long)i * 4u);
            mw[i] = 0xA0000000u + (se_u32)i;
        }
        pr_info("sehide: memtest ptr=%016lx %016lx %016lx %016lx "
                "w=%08x %08x %08x %08x\n",
                (se_u64)(se_ulong)mt[0], (se_u64)(se_ulong)mt[1],
                (se_u64)(se_ulong)mt[2], (se_u64)(se_ulong)mt[3],
                mw[0], mw[1], mw[2], mw[3]);
        pr_info("sehide: memtest r =%016lx %016lx %016lx %016lx "
                "rw=%08x %08x %08x %08x\n",
                (se_u64)(se_ulong)mt[0], (se_u64)(se_ulong)mt[1],
                (se_u64)(se_ulong)mt[2], (se_u64)(se_ulong)mt[3],
                *(volatile se_u32 *)&mw[0], *(volatile se_u32 *)&mw[1],
                *(volatile se_u32 *)&mw[2], *(volatile se_u32 *)&mw[3]);
    }
    /* r11 内存自测②：addrs 构造回读（闸门前的构造值快照）。 */
    pr_info("sehide: addrs built %016lx %016lx %016lx %016lx (exp ...%lx +%lx+%lx+%lx)\n",
            (se_u64)(se_ulong)addrs[0], (se_u64)(se_ulong)addrs[1],
            (se_u64)(se_ulong)addrs[2], (se_u64)(se_ulong)addrs[3],
            (se_u64)(se_ulong)p_adenied & 0xffffu,
            (se_u64)(se_ulong)p_adenied >> 16 & 0xffffu, 0xfffful, 0xfffful);
    /* 确定性闸门：写入地址必须逐词恒等于 p_adenied。历史会话曾观测到
     * a0 = p_adenied+12（源码对该偏移无任何运算）——中间量传递
     * 存在被改写路径，在写入前于源头直接比对拦截，绝不允许写到
     * 函数中部。 */
    if (addrs[0] != (void *)(se_ulong)p_adenied ||
        addrs[se_aden_bak_n - 1] != (void *)(se_ulong)(p_adenied +
        (unsigned long)(se_aden_bak_n - 1) * 4u)) {
        pr_info("sehide: entry addr mismatch a0=%016lx aden=%016lx "
                "a3=%016lx exp3=%016lx bak_n=%d, abort (entry untouched)\n",
                (se_u64)(se_ulong)addrs[0],
                (se_u64)(se_ulong)p_adenied,
                (se_u64)(se_ulong)addrs[se_aden_bak_n - 1],
                (se_u64)(se_ulong)(p_adenied +
                (unsigned long)(se_aden_bak_n - 1) * 4u),
                se_aden_bak_n);
        se_kp_rehook_avc();
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -5;
    }
    /* 调用前完整快照（含第 5 词与首地址）。 */
    pr_info("sehide: entry pre n=%d insns=%08x %08x %08x %08x | s4=%08x a0=%016lx\n",
            se_aden_bak_n, insns[0], insns[1], insns[2], insns[3], insns[4],
            (se_u64)(se_ulong)addrs[0]);
    /* 写路径：tramp 单词写已验证成功 → entry 同法（逐词独立调用 +
     * volatile 回读）；tramp 单词失败/无符号 → 多词 hotpatch（闸门
     * 兜底）。 */
    if (se_tramp_word_ok && p_kp_hpnosync) {
        int (*wn)(void *, unsigned int) =
            (int (*)(void *, unsigned int))(se_ulong)p_kp_hpnosync;

        rc = 0;
        for (i = 0; i < se_aden_bak_n; i++) {
            volatile se_u32 *rv = (volatile se_u32 *)addrs[i];

            int w = wn(addrs[i], insns[i]);

            pr_info("sehide: entry w%d rc=%d rb=%08x exp=%08x\n",
                    i, w, *rv, insns[i]);
            if (w || *rv != insns[i]) {
                pr_info("sehide: entry word-write FAIL @%d\n", i);
                rc = -1;
                break;
            }
        }
    } else if (p_kp_hotpatch) {
        rc = ((int (*)(void **, se_u32 *, int))p_kp_hotpatch)(addrs, insns,
                                                              se_aden_bak_n);
    } else {
        rc = ((int (*)(void **, se_u32 *, int))p_patch_text)(addrs, insns,
                                                             se_aden_bak_n);
    }
    if (rc) {
        pr_info("sehide: entry patch rc=%d\n", rc);
        /* 多条补丁可能部分落盘——无条件写回备份恢复原始前缀
         * （patched 守卫未置位，restore 内部有门槛，此处直接置位）。 */
        se_aden_patched = 1;
        se_aden_restore();
        se_kp_rehook_avc();
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -6;
    }
    se_aden_patched = 1;
    for (i = 0; i < se_aden_bak_n; i++)
        se_aden_live[i] = insns[i];

    /* 诊断：入口写入回读（patch 后立即读实际生效内容）。 */
    {
        se_u32 rb[5];
        int j;

        for (j = 0; j < 5; j++)
            rb[j] = 0;
        if (!se_kread(&rb, (void *)(se_aden_target),
                      (unsigned long)se_aden_bak_n * 4u))
            pr_info("sehide: entry rb %08x %08x %08x %08x %08x (n=%d)\n",
                    rb[0], rb[1], rb[2], rb[3], rb[4], se_aden_bak_n);
    }
    /* 延迟回读：若与首次回读不一致，说明 patch 之后有第三方写者改写了
     * 落点。
     * 注意：若落盘错位已发生，此延迟窗口内系统处于危险态，
     * 其他 CPU 的任何 denial 都会触发崩溃——但 rb2 打印在
     * selftest 之前，崩溃前必已落 printk 环形缓冲。 */
    if (p_msleep_interruptible)
        ((void (*)(se_ulong))p_msleep_interruptible)(10);
    {
        /* 校验判据 = volatile 逐词读（16B 块读对内核
         * text 刚写区域返回旋转视图，不可作判据；单词路径在写入
         * 循环内已逐词验证，此处复验一次延迟态）。 */
        int ok = 1;
        int j;

        for (j = 0; j < se_aden_bak_n; j++) {
            volatile se_u32 *rv = (volatile se_u32 *)addrs[j];

            if (*rv != insns[j]) {
                ok = 0;
                break;
            }
        }
        pr_info("sehide: entry verify2 ok=%d rb=%08x %08x %08x %08x\n",
                ok, *(volatile se_u32 *)addrs[0],
                *(volatile se_u32 *)addrs[1],
                *(volatile se_u32 *)addrs[2],
                *(volatile se_u32 *)addrs[3]);
        if (!ok) {
            pr_info("sehide: entry verify FAIL, restore+rehook\n");
            pr_info("sehide: verify dbg a0=%016lx a3=%016lx aden=%016lx "
                    "tgt=%016lx\n",
                    (se_u64)(se_ulong)addrs[0],
                    (se_u64)(se_ulong)addrs[se_aden_bak_n - 1],
                    (se_u64)(se_ulong)p_adenied,
                    (se_u64)(se_ulong)se_aden_target);
            se_aden_patched = 1;
            se_aden_restore();
            se_kp_rehook_avc();
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -6;
        }
    }

    /* 活体自检：出厂对 (init → su, binder, 全权) 必 deny（AccessTest
     * init→su binder 全 deny），rc==0 当且仅当我们的 hook 在岗
     * （all_allow_sid 不放行该 inbound）——唯一归因。
     * 失败 → 恢复落点前缀 → 引擎 off。 */
    /* r17 修复：selftest 的翻转路径依赖 G4 init 全类规则（se_ksu_rule
     * _mask），规则表必须先于 selftest 就绪——原调用点在 selftest 之后
     * （表 deferred → mask=0 → 出厂 -13 → 永久降级）。
     * se_ksu_recal 内含 scm 解析（仅内核符号依赖）+ 表建 + sid 解析，
     * 幂等，此处失败不阻断 selftest（表缺失 = 走原降级路径）。 */
    se_ksu_recal();
    if (p_secctx_to_sid)
        ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
            ("u:r:init:s0", sizeof("u:r:init:s0") - 1u, &init_sid);
    if (!init_sid)
        se_ctx_to_sid("u:r:init:s0", &init_sid);
    /* binder 类编号 = 内核钩子层序 57（classmap.h verbatim），不能用
     * policy 序 49——用 49 内核按"packet 类"决策，deny 恰好命中旧
     * 白名单，selftest 会自欺通过、无法暴露类号错位。 */
    binder_cls = 57u;
    if (!p_selinux_state || !init_sid || !binder_cls) {
        pr_info("sehide: selftest prerequisites missing (st=%016lx init=%u cls=%u)\n",
                (se_u64)(se_ulong)p_selinux_state, init_sid, binder_cls);
        se_aden_restore();
        se_kp_rehook_avc();
        ((void (*)(void *))p_vfree)(se_va_buf);
        se_va_buf = 0;
        return -7;
    }
    {
        int src;

        /* avc_has_perm：<=6.3 六参带 state，v6.4 起五参（同一个
         * state 全局单例化改动）。按静态版本表分派，不写死 6 参。 */
        pr_info("sehide: selftest begin st=%016lx s=%u t=%u c=%u r=%x sh=%d\n",
                (se_u64)(se_ulong)p_selinux_state, init_sid, g_su_sid,
                binder_cls, 0xfu, (int)se_kver_aden());
        if (se_kver_has_state())
            src = ((int (*)(void *, se_u32, se_u32, se_u16, se_u32, void *))
                   p_ahp)((void *)(se_ulong)p_selinux_state,
                          init_sid, g_su_sid, (se_u16)binder_cls, 0xfu,
                          (void *)0);
        else
            src = ((int (*)(se_u32, se_u32, se_u16, se_u32, void *))
                   p_ahp)(init_sid, g_su_sid, (se_u16)binder_cls, 0xfu,
                          (void *)0);

        if (src != 0) {
            pr_info("sehide: decision selftest FAILED rc=%d, engine off\n", src);
            se_aden_restore();
            se_kp_rehook_avc();
            ((void (*)(void *))p_vfree)(se_va_buf);
            se_va_buf = 0;
            return -8;
        }
        pr_info("sehide: decision selftest ok (rc=0 via our flip)\n");
    }

    /* KSU 规则集初始化（掩码建表 + 源域 sid 首标）。表未建好
     * 不阻塞装机——判定全 0 = 透传出厂（fail-closed），dmesg 可见。 */
    se_ksu_recal();

    /* KP slow_avc_audit unhook：审计路径恢复原生（决策面对 su/comp
     * 翻转清 auditdeny 位 → allow 不进审计慢路径；非相关 deny = 出厂
     * 语义）。独立失败仅告警，不影响决策面。 */
    if (p_slow_audit && p_kp_unhook) {
        se_u32 s0 = 0, s1 = 0, s2 = 0, sq0 = 0, sq1 = 0;
        unsigned long strep;

        if (!se_kread(&s0, (void *)(se_ulong)p_slow_audit, 4) &&
            !se_kread(&s1, (void *)(se_ulong)(p_slow_audit + 4), 4) &&
            !se_kread(&s2, (void *)(se_ulong)(p_slow_audit + 8), 4) &&
            ((s0 == 0xd50324dfu && s1 == 0x58000051u) ||
             (s0 == 0x58000051u && s1 == 0xd61f0220u)) &&
            !se_kread(&sq0, (void *)(se_ulong)(p_slow_audit + 12), 4) &&
            !se_kread(&sq1, (void *)(se_ulong)(p_slow_audit + 16), 4)) {
            /* 形态 1（[BTI_JC,LDR,BR,lo,hi]）：quad 在 +12/+16；
             * 形态 2（[LDR,BR,lo,hi]）：lo 在 +8、hi 在 +12。 */
            strep = (s0 == 0xd50324dfu)
                    ? ((unsigned long)sq0 | ((unsigned long)sq1 << 32u))
                    : ((unsigned long)s2 | ((unsigned long)sq0 << 32u));
            if ((strep >> 48u) == 0xffffu) {
                ((void (*)(void *))p_kp_unhook)((void *)(se_ulong)p_slow_audit);
                se_kp_slow_replace = strep;
                se_kp_slow_unhooked = 1;
                pr_info("sehide: kp slow_avc_audit unhooked (replace %016lx)\n",
                        strep);
            }
        }
    }

    /* KP SELinux 层全量卸载：决策面接管期间任何 SELinux 路径上
     * 不得保留 KP 钩子，与 selinux_hide 开关状态无关。钩子全集：
     * SELinux 层的钩子全集 = avc_denied/slow_avc_audit（bypass_selinux
     * 无条件装，上面已卸）+ security_load_policy（selinux_sepolicy.c
     * 无条件装）+ selinux_hide 使能时五点（sel_write_context/access、
     * selinux_setprocattr、sel_read/mmap_handle_status）。KP unhook()
     * 对未挂钩地址是安全 no-op（hook.c:640 无记录直接返回），逐点调用
     * 即可实现"有则卸、无则跳"。独立失败仅告警，不阻断主链。
     * 注意：内核符号必须走 se_sym（内核 kallsyms 解析链）——
     * symbol_lookup_name 只搜 KP 自有符号表，对内核符号恒返回 0
     * ）。 */
    if (p_kp_unhook) {
        static const char *const seh_names[] = {
            "security_load_policy",
            "selinux_setprocattr",
            "sel_write_context",
            "sel_write_access",
            "sel_read_handle_status",
            "sel_mmap_handle_status",
        };
        unsigned int ui;

        for (ui = 0; ui < sizeof(seh_names) / sizeof(seh_names[0]); ui++) {
            unsigned long fa = se_sym(seh_names[ui]);

            if (fa && (fa >> 48u) == 0xffffu) {
                ((void (*)(void *))p_kp_unhook)((void *)fa);
                pr_info("sehide: kp %s unhooked @%016lx\n",
                        seh_names[ui], (se_u64)fa);
            }
        }
    }

    /* 写入完成，参数数组使命结束——释放 va（决策面运行期不依赖）。 */
    ((void (*)(void *))p_vfree)(se_va_buf);
    se_va_buf = 0;

    se_decision_on = 1;
    pr_info("sehide: decision-plane flip on (mode=%s avc_denied=%016lx "
            "target=%016lx su=%u comp=%u)\n",
            se_aden_mode == 1 ? "direct" : "coexist",
            (se_u64)(se_ulong)p_adenied, (se_u64)se_aden_target,
            g_su_sid, g_comp_sid);
    /* 第二接管点：域翻译（生态注入域别名 su 域）。独立失败仅告警。 */
    rc = se_sec_install();
    if (rc)
        pr_info("sehide: secctx takeover skipped rc=%d (su setcon may fail "
                "for injected domains)\n", rc);
    return 0;
}

int se_decision_enabled(void)
{
    return se_decision_on;
}