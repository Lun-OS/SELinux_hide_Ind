/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_decision：决策面翻转 —— su/组件域的放行通道（live 恒出厂）。
 *
 * 唯一 hook 点：avc_denied（denied 唯一收口，6.1 avc.c:1021 / 4.19
 * avc.c:1017，两版 9 参 verbatim 同构，noinline 不随 LTO 漂移；
 * 缓存命中/miss/xperm 三路全必经）。可替代层不可用：hooks.c:3121
 * （inode_permission）与 hooks.c:1608（cred_capable）直调 noaudit
 * 绕过外层入口，上移会漏 su 文件主路径；hook noaudit 符号则 LTO
 * 内联盲区回归。
 *
 * 挂载三态：
 *   direct  —— KP 未挂时直接接管 avc_denied 内核入口；
 *   coexist —— KP 补丁在岗时，备份 KP pad、补丁写 avc_denied（内核
 *              text），trampoline 纯重定向到 KP replace（KP task_ext
 *              按任务授予完整保留）。
 * 运行链：调用方 → 我们补丁 → 判定；不匹配 → backup trampoline →
 * 原始函数本体（非特权透传内核原生处理）。
 *
 * 补丁原语：
 *   1) 地址解析：主源 p_adenied = se_sym("avc_denied")（kallsyms 裸名；
 *      解析地址上恰为 KP 标准补丁格式即活体交叉验证）；互证源
 *      patch_config->avc_denied（可达即比对，不一致拒挂）；L3
 *      by_suffix 备用。
 *   2) 前缀备份 + PC 相关校验（B/BL/B.cond/ADR/ADRP/LDR 字面量/CB/TB
 *      命中即 off——复制后会再执行）。
 *   3) 写入：内核原生 aarch64_insn_patch_text（自带 stop_machine +
 *      RO 处理 + icache），改写为 [BTI JC] + LDR X17/BR X17/addr64。
 *      红线：补丁落点只允许内核 text 与本模块 .text；KP 分配 VA
 *      （kpimg/KPM 映射区）经 patch_map 的地址翻译不可靠（写入落错
 *      物理页 → 随机内核 text 损坏），一律禁止作为目标。
 *   4) trampoline：本模块 .text，内容由内核 patch_text 写入。
 *   5) 活体自检：avc_has_perm(init→su, binder, 全权)——出厂必 deny，
 *      rc==0 当且仅当 hook 在岗，唯一归因；失败恢复前缀、引擎 off。
 *   6) 卸载对称：patch_text 恢复备份前缀。
 *
 * replace 语义：
 *   - 相关性分诊（第一分支）：非 su/comp sid 相关请求 → 透传内核
 *     （见 se_aden_replace 内注释）；
 *   - outbound（源==su/comp）全类 flip：改 avd（allowed=全 1/
 *     auditallow=0/auditdeny=0）+ return 0 —— 不写缓存（缓存保留
 *     出厂真值，每次 denied 现场放行）、不打 audit 日志；
 *   - inbound（目标==su/comp）→ KSU 规则集 (类,perm,源域) 精确匹配
 *     （se_ksu_rule_mask）：全类组全置；位组 allowed |= requested&mask、
 *     auditdeny 同步清位，未点名位维持出厂 deny；
 *   - 副本收口：规则集外的 su/comp 相关请求查副本生态规则；
 *   - 其余 → backup 链（KP 语义 → 原函数）。
 *   - 签名 9 参，4.19/6.1 verbatim 同构写死；第 9 参 avd 在栈上。
 *
 * 版本历史与演进记录：见 docs/selinux-hide/KPM-1.1.0-注释工作日志归档.md */

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
static int se_aden_mode;
/* coexist 回退形态下的 KP replace 地址（日志/诊断用）。 */
static unsigned long se_kp_replace_addr;

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

/* inbound 白名单语义：/proc/<pid> 文件类刻意保持出厂 deny——app.te
 * neverallow appdomain 访问非 app 域 file，放行文件类会让 isolated
 * helper 读到 su 域进程的 mountinfo（mountinfo 泄露面）。
 *
 * 类编号语义（机制关键）：内核存在两个类编号空间——
 *   a) 钩子层：avc_denied 收到的 tclass = secclass_map 静态序
 *      （classmap.h 编译期固化）—— 本 hook 所在层语义；
 *   b) policy 层：policydb/symtab/avtab 的类 value（设备 policy 布局，
 *      binder=49 vs 钩子层 57）。
 *   内核在 security_compute_av 内经 unmap_class + map_decision 桥接；
 *   avc_denied 调用点不做映射 —— 直收钩子层序。错用 policy 序会让
 *   inbound binder 全部失配（process/fd/fifo/us 恰好两空间同值，会
 *   掩盖错位）。
 *   类号/权限位一律按名解析：遍历内核 secclass_map（g_scm_addr，自证）
 *   按类名/权限名定位钩子层类号与位 index —— 零硬编码类号，跨
 *   policy 版本稳定。memfd_file：6.1 无此类 → 解析 0 → 规则自动失效；
 *   内核强制钩子不会发起该类请求，仅用户态 oracle 可引用。
 * （se_policydb.c 的副本 inbound stamp 含 memfd_file：副本求值走
 * policy 层语义，服务 oracle 一致性，正确。） */

/* ==================== KSU 原版规则集匹配（决策面放行判据） =====
 *
 * 放行判据 = KSU 原版 apply_kernelsu_rules（KernelSU
 * kernel/selinux/rules.c:45-166 verbatim）写入 live 的规则集等效判定
 * —— 规则点名走本层特权规则（flip/副本收口），其余透传出厂 live。
 * uid 不参与本层判定（uid 只在问侧门存在）。
 *
 * 规则集 → 本层判定映射（rules.c 行号 verbatim）：
 *   G1 outbound  :88/:99  ksu permissive + allow ALL → 主干 ssid==su/comp
 *                 全类 flip（原语义，本就无 uid）；
 *   G2 inbound   :153 binder ALL / :128 fd use / :129-132 fifo_file
 *                 write/read/open/getattr / :133-137 unix_stream_socket
 *                 read/write/connectto/getopt/getattr / :119 process
 *                 sigchld（任意源）/ :156-157 system_server process
 *                 getpgid|sigkill / :118/:150 servicemanager|
 *                 hwservicemanager process getattr / :114-125+:147-149
 *                 servicemanager|logd|hwservicemanager 的 dir/file
 *                 源域限定 / :140-144 memfd_file 5perm（6.1 解析 0）；
 *   G3 目标类型  :96 domain→ksu_file ALL —— KSU 专属文件类型；KPM 生态
 *                 的对应物 = 副本盖章规则（se_stamp_*），由副本收口
 *                 承接，本层不硬编码；
 *   G4 源域全类  :110 init→ksu ALL → init 源对 su/comp 目标全类 flip。
 *
 * 位序：avc_denied 收到的 tclass/requested 均为钩子层静态序（avc_ss.h
 * secclass_map 序，4.19/6.1 逐字同构）—— 掩码按同序建立（1<<位
 * index），与 requested 直接位与。KSU 规则集不含 dyntransition/
 * transition/setcurrent → 跨域身份切换不在 A 类型内，天然透传出厂拒。
 * 未解析（类不存在/表未建）→ 掩码 0 → B 类型（fail-closed）。
 * ========================================================================== */

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

static unsigned int se_orig_probe_n;  /* 生态域升级探测限频计数 */

/* ==================== 副本收口查询（内核函数组合，零布局知识零扫描） ====================
 *
 * 定稿原则：内核源码级固定路径——内核自己怎么建翻译表，我们就怎么建。
 *（历史演进记录见归档 md。）
 *
 * 内核 selinux_set_mapping 的建表逻辑（verbatim，6.1 services.c:133/151 =
 * 4.19 :137/155）：
 *     p_out->value = string_to_security_class(pol, p_in->name);
 *     p_out->perms[k] = string_to_av_perm(pol, p_out->value, p_in->perms[k]);
 * 两函数均为 policydb.c 非 static 导出（policydb.h:387-388 extern 声明；
 * 6.1 policydb.c:1809/1822 = 4.19 :1810/1821 逐字同构），内核
 * kallsyms T 段可见。语义：
 *     string_to_security_class(p, name) = symtab_search(&p->p_classes,
 *                                         name)->value    —— 类名→类值
 *     string_to_av_perm(p, cls, name)   = 1<<(perdatum->value-1)
 *                                       —— 权限名→policy 位掩码
 * 第一参数是 struct policydb *——传副本 L.copy 即按副本 symtab 求值
 * （副本类定义与 live 一致：blob 吸收时类数校验兜底）。
 *
 * 钩子层语义的唯一持有者 = secclass_map（4.19/6.1 avc_ss.h 逐字同构：
 * struct { const char *name; const char *perms[sizeof(u32)*8+1]; } ——
 * 元素 8+33*8=272B，NULL 名终止；这是内核源码结构定义，非设备提取）。
 * 其地址解析不用 L1 直读（kallsyms_lookup_name 对 D 段数据符号有
 * 错地址前科，装机实证），改走 KP 导出的 kallsyms_on_each_match_symbol
 * （start.c:148 KP_EXPORT_SYMBOL verbatim：内核原函数优先 + 6.1 nomod
 * 回退，全 kallsyms 表按名精确匹配回调）——内核官方机制确定调用。
 * 地址自证：[0].name=="security" && [1].name=="process"（SELinux 架构
 * 基础类序，规范不变量）——错地址在此 fail-closed。
 *
 * 建表（se_perm_tab_build，build_copy 成功尾部调用；换代不改类定义，
 * 无需重建）：对 tclass=1..：name=scm[tclass-1].name（非法指针=表尾）→
 * g_cls_pol[tclass]=string_to_security_class(L.copy, name)；对 i=0..：
 * perm=scm[tclass-1].perms[i]（NULL=该类权限尾）→ g_perm_bit[tclass][i]=
 * string_to_av_perm(L.copy, cls_pol, perm)。与内核 mapping 同源同语义。
 *
 * 查询（se_copy_query_allow）：入参=钩子层语义。type_s/t = sidtab 查
 * type（4.19 sidtab_search 直返 context*，type@+8；5.10+ entry 形态
 * context@+8 → type@+16）；node = avtab_search_node(副本 avtab,
 * {type_s, type_t, g_cls_pol[tclass], AVTAB_ALLOWED})；放行 ⟺ requested
 * 每位 i：datum & g_perm_bit[tclass][i] 非零（副本 avtab datum=policy
 * 位序，与内核 avtab 一致；钩子层位→policy 位由本表重排）。全失败 →
 * g_tab_ready=0 fail-closed（出厂语义）。
 * ========================================================================== */

#define SE_CLS_MAX   96u    /* 翻译表覆盖上限（钩子层类号安全界） */
#define SE_SCM_SZ    272u   /* sizeof(struct security_class_mapping)
                             * = 8 + (4*8+1)*8，4.19/6.1 avc_ss.h 逐字同构 */
#define SE_PERM_MAX  32u

static se_u16 g_cls_pol[SE_CLS_MAX];                /* tclass → policy 类值 */
static se_u32 g_perm_bit[SE_CLS_MAX][SE_PERM_MAX];  /* tclass → 位 i 的 policy 位掩码 */
static se_u32 g_nperm_tab[SE_CLS_MAX];              /* 每类钩子层权限数 */
static int g_tab_ready;
static unsigned long g_scm_addr;                     /* 自证通过的 secclass_map 地址 */

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
    if (!g_ksu_tab_ready)
        se_ksu_tab_build();

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

    /* 非特权（非 su/comp sid 相关）请求仅此一次分诊判决即透传内核
     * 原版——不查副本、不参与探测计数，放行与否完全由内核判决
     * （时序面 = 一次整数比较）。生态规则收口查询保留在 su/comp 路径。 */
    if (!se_su_or_comp_hit(ssid, tsid))
        goto orig;

    /* 组件域升级探测置旗（每 256 次相关流量一次）：探测本体含
     * GFP_KERNEL 分配，RCU 读临界区禁睡眠——置旗由门/bprm（进程
     * 上下文）代跑。探测本体 = se_ctx_type→security_secctx_to_secid
     * （4.19 hooks.c:6626 verbatim GFP_KERNEL）。 */
    if ((++se_orig_probe_n & 0xffu) == 0u)
        g_comp_pending = 1;

    /* outbound：源=su/comp → 全类翻转 */
    if ((g_su_sid && ssid == g_su_sid) ||
        (g_comp_sid && ssid == g_comp_sid))
        goto flip;

    /* inbound —— KSU 原版规则集 (类,perm,源域) 匹配。
     * 全类组（init 源 / binder ALL）→ 全置 flip；位组 → 仅放行规则
     * 点名的位（allowed |= requested&mask、auditdeny 同步清位），规则
     * 未点名的位维持出厂 deny —— 与 KSU live 引擎逐位判定等价。 */
    {
        se_u32 kmask = se_ksu_rule_mask(ssid, tclass);

        if (kmask == 0xffffffffu)
            goto flip;
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
    if (se_copy_query_allow(ssid, tsid, tclass, requested))
        goto flip;

    /* KP 静默重载自愈触发器：su 目标未翻转请求 = sid 失配的直接信号，
     * 做廉价三读校验（container/len/vers），失配置旗。recalibrate
     * 含 policydb_read 大量 GFP_KERNEL 分配，RCU 读临界区禁睡眠——
     * 置旗由门/bprm 代跑（自愈晚一个周期，boot 后毫秒级）。 */
    if (se_su_or_comp_hit(ssid, tsid) && !se_live_ok())
        g_recal_pending = 1;

    goto orig;

flip:
    if (avd) {
        f = (se_u32 *)avd;
        f[SE_AVD_OFF_ALLOWED / 4]    = 0xffffffffu;
        f[SE_AVD_OFF_AUDITALLOW / 4] = 0u;
        f[SE_AVD_OFF_AUDITDENY / 4]  = 0u;
    }
    return 0;

orig:
    /* 原样透传全部 9 个槽：8 参形状下第 9 个是无关值，原函数忽略。 */
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

/* 入口恢复：把备份的落点前缀写回（模块卸载 / 自检失败回退共用）。
 * direct 模式：avc_denied 复原为原始函数（KP 已 unhook，记录已释放，
 * 系统回到"无任何 SELinux hook"态）；coexist 模式：KP replace 入口
 * 复原，KP 自身 hook/backup 链原样。 */
static void se_aden_restore(void)
{
    void *addrs[SE_ADEN_PATCH_N];
    int i;

    if (!se_aden_patched || !p_patch_text || !se_aden_target)
        return;

    for (i = 0; i < se_aden_bak_n; i++)
        addrs[i] = (void *)(se_aden_target + (unsigned long)i * 4u);

    ((int (*)(void **, se_u32 *, int))p_patch_text)
        (addrs, se_aden_saved, se_aden_bak_n);
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
}

int se_decision_install(void)
{
    void *addrs[SE_ADEN_PATCH_N];
    se_u32 insns[SE_ADEN_PATCH_N];
    unsigned long back, target, lo;
    se_u32 init_sid = 0, binder_cls = 0;
    int i, rc, pad_bti = 0;

    if (se_decision_on)
        return 0;
    if (!p_adenied || !p_patch_text || !p_ahp || !g_su_sid) {
        pr_info("sehide: decision syms missing adenied=%016lx l3=%016lx "
                "ptext=%016lx ahp=%016lx su=%u\n",
                (se_u64)(se_ulong)p_adenied, (se_u64)(se_ulong)p_adenied_l3,
                (se_u64)(se_ulong)p_patch_text, (se_u64)(se_ulong)p_ahp,
                g_su_sid);
        return -1;
    }

    /* 入口两态判定：
     *
     *   态① KP 补丁在岗 → **avc_denied 直挂 + KP replace 保留为链上
     *        下一跳**（终态）：备份 KP pad 5/4 词（仅卸载恢复用，不再
     *        被执行）；补丁写 avc_denied（内核 text = 实测稳定写入面）；
     *        trampoline = [LDR/BR/quad(kp_replace)] 纯重定向 4 词——
     *        不复制、不跳过任何指令，kp_replace 从其真实入口原样执行
     *        （KP task_ext 按任务授予完整保留）。
     *        红线（为什么补丁落点回到 avc_denied 内核 text，kpimg 零
     *        写入）：patch_map 对 KP 分配 VA（kpimg/KPM 映射区，运行时
     *        基址每次 boot 由 KP 自选）的地址翻译不可靠 → 写入落错
     *        物理页 → 随机内核 text 损坏（pstore 三信号收敛，见归档
     *        md）。唯一实测稳定面 = 内核 text（avc_denied）+ 本模块
     *        .text。
     *   态② 原始入口（KP bypass 未装机）→ direct 接管：备份原始前缀、
     *        补丁写 avc_denied。原始入口首指令需过序言白名单（错地址
     *        第二道防线）。
     *
     * 非特权纯度（共存形态）：avc_denied → KP pad → KP replace → 我们
     * 补丁 → 判定（KSU 规则集/副本匹配，未命中）→ KP replace 主体 →
     * 原函数。KP replace 对非特权 = 只读判定、零结果改变，且该 hop
     * 自 KP 开机起就在非特权的 deny 路径上（宿主既有行为）。
     *
     * KP 补丁形态（hook.c:309-316 + hook_prepare:561-567 verbatim）：
     *   A: [0]=0xd50324df BTI JC, [1]=0x58000051 LDR X17,#8,
     *      [2]=0xd61f0220 BR X17, [3:4]=quad（内核函数带 PAC 序言时）
     *   B: [0]=0x58000051 LDR X17,#8, [1]=0xd61f0220 BR X17, [2:3]=quad */
    {
        se_u32 e[3] = {0, 0, 0};

        if (se_kread(&e[0], (void *)(se_ulong)p_adenied, 4) ||
            se_kread(&e[1], (void *)(se_ulong)(p_adenied + 4), 4) ||
            se_kread(&e[2], (void *)(se_ulong)(p_adenied + 8), 4))
            return -1;

        if ((e[0] == 0xd50324dfu && e[1] == 0x58000051u) ||
            (e[0] == 0x58000051u && e[1] == 0xd61f0220u)) {
            /* 态① KP pad 在岗 → avc_denied 直挂 + KP replace 保留为链上
             * 下一跳：备份 KP pad（仅卸载恢复用，不再被执行）；补丁写
             * avc_denied（内核 text = 实测稳定写入面）；trampoline 纯
             * 重定向——不复制、不跳过任何指令，kp_replace 从其真实入口
             * 原样执行（KP task_ext 按任务授予完整保留）。
             * 红线：kpimg 零写入（patch_map 对 KP 分配 VA 地址翻译
             * 不可靠，详见函数头注释）。 */
            se_u32 q0 = 0, q1 = 0;

            if (e[0] == 0xd50324dfu && e[2] != 0xd61f0220u) {
                pr_info("sehide: adenied bti entry word2 %08x != BR X17\n",
                        e[2]);
                return -2;
            }
            if (se_kread(&q0, (void *)(se_ulong)(p_adenied + 12), 4) ||
                se_kread(&q1, (void *)(se_ulong)(p_adenied + 16), 4))
                return -1;
            target = (e[0] == 0xd50324dfu)
                     ? ((unsigned long)q0 | ((unsigned long)q1 << 32u))
                     : ((unsigned long)e[2] | ((unsigned long)q0 << 32u));
            if ((target >> 48u) != 0xffffu) {
                pr_info("sehide: kp replace target %016lx not kernel-text form\n",
                        target);
                return -3;
            }
            se_kp_replace_addr = target;
            se_aden_target = p_adenied;
            /* 补丁条数跟随 KP 的实际形态，不再写死 5。
             * 约束：KP relo 返回点 = avc_denied + KP 补丁词数×4，我们的
             * 补丁覆盖区必须恰好等于 KP 补丁区，多写一词就砸掉返回点
             * （多写的那词会被当指令执行 → el1_undef）：
             *   A（落点带 BTI）：KP 写 5 词，relo 返回 +0x14，我们写 5 词；
             *   B（无 BTI，clang 内核无 PAC/BTI 序言）：KP 写 4 词，
             *     relo 返回 +0x10，我们写 4 词。 */
            se_aden_bak_n = (e[0] == 0xd50324dfu) ? 5 : 4;
            se_aden_mode = 3;
            pad_bti = (e[0] == 0xd50324dfu);
            pr_info("sehide: coexist mount on avc_denied (kp replace via "
                    "trampoline) %016lx, kp pad backed up, kpform=%s\n",
                    target, e[0] == 0xd50324dfu ? "A-bti5" : "B-nobti4");
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
                    e[0] == 0xd503201fu) /* STP 族 / NOP */
                    pad_bti = 0;
                else {
                    pr_info("sehide: adenied entry %08x %08x %08x not a "
                            "prologue, refuse\n", e[0], e[1], e[2]);
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
        return -3;
    }

    /* 前缀备份（bak_n 条）。direct 模式备份 avc_denied 原始本体（含
     * PACIBSP——SP 修饰、无 PC 依赖，trampoline 内执行签名/验签自洽），
     * PC 相关校验：命中即 off（复制后会再执行）。mode=3 备份的是 KP pad
     * 5 词——仅作卸载恢复、不再被执行（trampoline 纯重定向 kp_replace），
     * 其中 LDR/BR 字面量形态属正常内容，PC 校验跳过。 */
    for (i = 0; i < se_aden_bak_n; i++) {
        if (se_kread(&se_aden_saved[i],
                     (void *)(se_aden_target + (unsigned long)i * 4u), 4))
            return -1;
        if (se_aden_mode != 3 && se_insn_pc_related(se_aden_saved[i])) {
            pr_info("sehide: target inst[%d] %08x pc-relative, off\n",
                    i, se_aden_saved[i]);
            return -4;
        }
    }

    /* inbound 判定 = KSU 规则集：类号/权限位按名解析自内核
     * secclass_map（钩子层序而非 policy 序 —— 详见 KSU 规则集段注释）。 */

    /* 组装 backup trampoline。mode=3（KP pad 在岗）：**纯重定向 4 词**
     * [LDR X17,#8; BR X17; quad(kp_replace)] —— 不复制任何指令，kp_replace
     * 从其真实入口原样执行（KP task_ext 授予零损失）。mode=1（direct）：
     * [0..bak_n-1] 复制落点前缀；[bak_n..+3] 绝对跳回 target+bak_n*4。
     * trampoline 位于本模块 .text，写入走内核 patch_text。 */
    {
        void *taddrs[SE_ADEN_TRAMP_N];
        se_u32 tinsns[SE_ADEN_TRAMP_N];
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
        for (i = 0; i < tn; i++)
            taddrs[i] = (void *)(unsigned long)((unsigned long)se_aden_tramp +
                                                (unsigned long)i * 4u);
        rc = ((int (*)(void **, se_u32 *, int))p_patch_text)
             (taddrs, tinsns, tn);
        if (rc) {
            pr_info("sehide: tramp patch rc=%d\n", rc);
            return -5;
        }
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
        addrs[i] = (void *)(se_aden_target + (unsigned long)i * 4u);
    rc = ((int (*)(void **, se_u32 *, int))p_patch_text)(addrs, insns,
                                                         se_aden_bak_n);
    if (rc) {
        pr_info("sehide: entry patch rc=%d\n", rc);
        return -6;
    }
    se_aden_patched = 1;

    /* 活体自检：出厂对 (init → su, binder, 全权) 必 deny（AccessTest
     * 实测 init→su binder 全 deny），rc==0 当且仅当我们的 hook 在岗
     * （all_allow_sid 不放行该 inbound）——唯一归因。
     * 失败 → 恢复落点前缀 → 引擎 off。 */
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
        return -7;
    }
    {
        int src;

        /* avc_has_perm：<=6.3 六参带 state，v6.4 起五参（同一个
         * state 全局单例化改动）。按静态版本表分派，不写死 6 参。 */
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
            return -8;
        }
        pr_info("sehide: decision selftest ok (rc=0 via our flip)\n");
    }

    /* KSU 规则集初始化（掩码建表 + 源域 sid 首标）。表未建好
     * 不阻塞装机——判定全 0 = 透传出厂（fail-closed），dmesg 可见。 */
    se_ksu_recal();

    se_decision_on = 1;
    pr_info("sehide: decision-plane flip on (mode=%s avc_denied=%016lx "
            "target=%016lx su=%u comp=%u)\n",
            se_aden_mode == 1 ? "direct" : "coexist",
            (se_u64)(se_ulong)p_adenied, (se_u64)se_aden_target,
            g_su_sid, g_comp_sid);
    return 0;
}

int se_decision_enabled(void)
{
    return se_decision_on;
}