/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_symbol：kallsyms/KP 符号解析 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"

/* ---------------- 符号解析（含 LTO 变体） ---------------- */

int walk_cb(void *data, const char *name, struct module *mod, unsigned long addr)
{
    struct walk_ctx *ctx = data;
    se_ulong l;

    (void)mod;
    if (!name || !addr)
        return 0;

    l = strlen(name);
    if (l <= ctx->len || strncmp(name, ctx->base, ctx->len) != 0)
        return 0;
    if (name[ctx->len] != '.' && name[ctx->len] != '$')
        return 0;

    ctx->addr = addr;
    return 1;
}

/*
 * v82：三级符号解析链。
 *
 * 6.1 GKI 装机（fp_br21）实证：KP 填给 KPM 的 kallsyms_lookup_name 函数
 * 指针在 GKI 6.1.157 上失效（security_read_policy/selinux_state 解析出
 * 错误地址 -> security_read_policy 返回 -EINVAL -> 引擎 off），而 KP 自己
 * 的 kallsyms_lookup_name_by_suffix（start.c:212，先查 KP 符号表、再内核
 * kallsyms、后后缀扫描，内部已处理 6.1+ 的 kallsyms_on_each_symbol 签名
 * 差异）在同设备成功解析（capture 1.8MB blob 实证）。
 *
 * 三级顺序固定、谁通谁生效：
 *   L1  内核 kallsyms_lookup_name（KP 填的指针）—— 4.19 等一级命中；
 *   L2  内核 kallsyms_on_each_symbol 遍历 —— 仅 kver<5.10（walk_cb 为
 *       4.19 签名，5.10+ 签名不同不可混用；5.10+ 由 L3 承担）；
 *   L3  KP 的 kallsyms_lookup_name_by_suffix —— KP 符号表导出，
 *       KP 内部已做签名适配，GKI 6.x 实证可用。
 * 全失败返回 0（引擎照旧安全 off），任一级成功即用。
 */
static unsigned long p_ksym_by_suffix;   /* KP 的 kallsyms_lookup_name_by_suffix */
static int g_sym_diag;                   /* 一次性诊断计数 */

unsigned long se_sym(const char *name)
{
    unsigned long addr;

    if (kallsyms_lookup_name) {
        addr = kallsyms_lookup_name(name);
        if (addr)
            return addr;
    }

    if (kver < VERSION(5, 10, 0) && kallsyms_on_each_symbol) {
        struct walk_ctx ctx;

        ctx.base = name;
        ctx.len = strlen(name);
        ctx.addr = 0;
        kallsyms_on_each_symbol(walk_cb, &ctx);
        if (ctx.addr)
            return ctx.addr;
    }

    if (p_ksym_by_suffix) {
        addr = ((unsigned long (*)(const char *))p_ksym_by_suffix)(name);
        if (addr) {
            if (g_sym_diag < 4) {
                g_sym_diag++;
                pr_info("sehide: sym '%s' resolved via KP suffix lookup\n", name);
            }
            return addr;
        }
    }

    if (g_sym_diag < 6) {
        g_sym_diag++;
        pr_info("sehide: sym '%s' unresolved (k=%llu oes=%llu sfx=%llu)\n",
                name, (se_u64)(se_ulong)kallsyms_lookup_name,
                (se_u64)(se_ulong)(kver < VERSION(5, 10, 0) ? kallsyms_on_each_symbol : 0),
                (se_u64)p_ksym_by_suffix);
    }
    return 0;
}

void se_sym_fill(struct sym_slot *s)
{
    s->addr = se_sym(s->name);
    s->matched[0] = '\0';
    if (s->addr)
        strncpy(s->matched, s->name, sizeof(s->matched) - 1);
}

/* ---------------- 平台层 ---------------- */

unsigned long p_read_policy;
unsigned long p_pdb_read;
unsigned long p_pdb_write;
unsigned long p_pdb_destroy;
unsigned long p_kread;
unsigned long p_kvzalloc;
unsigned long p_kvfree;
unsigned long p_ebitmap_set;
unsigned long p_hashtab_ins;
unsigned long p_kthread_create_on_node;
unsigned long p_wake_up_process;
unsigned long p_kthread_should_stop;
unsigned long p_msleep_interruptible;
unsigned long p_flex_prealloc;
unsigned long p_flex_get;
unsigned long p_str_to_ctx;
unsigned long p_ctx_to_str;
unsigned long p_compute_av;
unsigned long p_sidtab_entry;
unsigned long p_write_op;
unsigned long p_sel_write_access;
unsigned long p_sel_write_context;
unsigned long p_bprm_sym;
unsigned long p_hook_heads;
unsigned long p_scall_table;
unsigned long p_scall_update;
unsigned long p_blob_sizes;
unsigned long p_fp_hook;
unsigned long p_strncpy_user;

unsigned long p_sidtab_to_sid;
unsigned long p_sidtab_search;
unsigned long p_get_bit;
unsigned long p_cred_getsecid;
unsigned long p_secctx_to_sid;
unsigned long p_selinux_state;
unsigned long p_avtab_insert;
unsigned long p_avtab_search;
unsigned long p_avtab_node_search;
unsigned long p_avtab_add;
unsigned long p_avtab_read;
unsigned long p_symtab_search;
unsigned long p_hashtab_search;
unsigned long p_get_perms;
unsigned long p_kfree;

/*
 * avc 缓存刷新（重载自愈的最后一步）。规律全部来自各版本源码核对：
 *   - avc_ss_reset：4.19/5.4/5.10/5.15/6.1/6.2/6.3 均为双参
 *     (struct selinux_avc *avc, u32 seqno)；v6.4 起单参 (u32 seqno)
 *     ——v-fix 复审 20261104：v6.4 tag 三处实测一致（avc_ss.h 声明 +
 *     services.c:2165 + selinuxfs.c:175 调用形态），旧注按 commit 归
 *     6.5 属误判（merge window 实为 6.4）。
 *   - 内部 avc_flush 的 avc_node_delete 自 4.19 到 6.12 一律 call_rcu
 *     异步释放，函数自身不 synchronize_rcu —— 进程上下文调用安全；
 *     真正不能碰的是 RCU 读临界区（v44 在 KP event 线程调它挂了第一屏）。
 *   - avc 指针：4.19~6.4 内核重载路径用 state->avc，而 selinux_avc_init
 *     就是 `*avc = &selinux_avc`（avc.c 文件级单例，static 但进 kallsyms
 *     b 段，4.19~6.12 各版均有）—— 所以传全局实例地址本身，
 *     不需要任何 selinux_state 结构偏移，版本无关。
 *   - seqno 传 0：内核自己就有这个用法（4.19 selinuxfs.c:179 setenforce
 *     路径 avc_ss_reset(state->avc, 0)），语义是"只清缓存、不推高
 *     latest_notif"，后续任何 avd->seqno 都能正常入缓存。
 */
unsigned long p_avc_reset;
unsigned long p_avc_struct;

struct sym_slot syms[35] = {
    { "selinux_state", 0, "" },
    { "security_read_policy", 0, "" },
    { "policydb_read", 0, "" },
    { "policydb_destroy", 0, "" },
    { "copy_from_kernel_nofault", 0, "" },
    { "probe_kernel_read", 0, "" },
    { "__kmalloc", 0, "" },
    { "ebitmap_set_bit", 0, "" },
    { "ebitmap_get_bit", 0, "" },
    { "security_cred_getsecid", 0, "" },
    { "security_secctx_to_secid", 0, "" },
    { "string_to_context_struct", 0, "" },
    { "context_struct_to_string", 0, "" },
    { "context_struct_compute_av", 0, "" },
    { "write_op", 0, "" },
    { "sel_write_access", 0, "" },
    { "sel_write_context", 0, "" },
    { "sel_load_ops", 0, "" },
    { "selinux_bprm_creds_for_exec", 0, "" },
    { "selinux_bprm_set_creds", 0, "" },
    { "security_hook_heads", 0, "" },
    { "static_calls_table", 0, "" },
    { "__static_call_update", 0, "" },
    { "selinux_blob_sizes", 0, "" },
    { "sidtab_context_to_sid", 0, "" },
    { "avtab_search", 0, "" },
    { "avtab_search_node", 0, "" },
    { "avtab_insert_nonunique", 0, "" },
    { "avtab_read", 0, "" },
    { "symtab_search", 0, "" },
    { "hashtab_search", 0, "" },
    { "security_get_permissions", 0, "" },
    { "avc_ss_reset", 0, "" },
    { "selinux_avc", 0, "" },
    { "kfree", 0, "" },
};

unsigned long p_kp_hook;
unsigned long p_kp_unhook;

/*
 * current_uid 也是 KernelPatch 导出符号（utils.c:172 KP_EXPORT_SYMBOL），
 * 内核 kallsyms 里没有，运行期从 KP 私表取（同 fp_hook 的教训）。
 * 门用它实现 LKM 的 uid 判据（selinux_hide.c:700/726：
 * `current_uid().val < 10000 && se_copy` 才走副本渲染）。
 * uid_t 即 u32（linux/types.h）。查不到时 p_kuid 为 0，门退化为
 * "服务所有 uid" —— 非特权本来就不可达这两个节点（neverallow 锁死），
 * 行为不变，只是少了这层防御性判据。
 */
unsigned long p_kuid;
unsigned long p_set_sec_override;   /* v81：组件域切轨用（设备 kallsyms T 实证） */
/* 新增（改①②）：定义补齐（sehide.h 仅 extern） */
unsigned long p_sel_write_load;
unsigned long p_copy_from_user;
unsigned long p_filp_open;
unsigned long p_filp_close;
unsigned long p_kernel_read;
unsigned long p_sel_read_status;   /* v61：status 冻结 */
unsigned long p_status_ops;        /* v61：sel_handle_status_ops（r 段数据符号） */

/* v54：影子页/坐标系（定义） */
unsigned long p_sel_load_ops;
unsigned long p_vmalloc;
unsigned long p_vfree;
unsigned long p_stop_machine;
unsigned long p_gfp;
unsigned long p_memstart;
unsigned long p_kimage_voff;
unsigned long p_swapper;
unsigned long p_text;

/* 新增：符号绑定自 sehide_init 抽出（原 L2967-3035，纯搬移 + 死符号清理 + 新增绑定） */
void se_bind_symbols(void)
{
    unsigned int i;

    for (i = 0; i < NSYM; i++)
        se_sym_fill(&syms[i]);

    p_selinux_state  = se_sym("selinux_state");
    p_read_policy    = se_sym("security_read_policy");
    p_pdb_read       = se_sym("policydb_read");
    p_pdb_destroy    = se_sym("policydb_destroy");
    p_kread          = se_sym("copy_from_kernel_nofault");
    if (!p_kread)
        p_kread      = se_sym("probe_kernel_read");
    p_kvzalloc       = se_sym("__kmalloc");
    p_ebitmap_set    = se_sym("ebitmap_set_bit");
    p_hashtab_ins    = se_sym("hashtab_insert");
    p_kthread_create_on_node = se_sym("kthread_create_on_node");
    p_wake_up_process        = se_sym("wake_up_process");
    p_kthread_should_stop    = se_sym("kthread_should_stop");
    p_msleep_interruptible   = se_sym("msleep_interruptible");  /* v68：ss/hashtab.c 非静态，kallsyms T */
    p_flex_prealloc  = se_sym("flex_array_prealloc");  /* v68：设备 kallsyms T 实证 */
    p_flex_get       = se_sym("flex_array_get");       /* v68：同上 */
    p_get_bit        = se_sym("ebitmap_get_bit");
    p_cred_getsecid  = se_sym("security_cred_getsecid");
    p_secctx_to_sid  = se_sym("security_secctx_to_secid");
    p_str_to_ctx     = se_sym("string_to_context_struct");
    p_ctx_to_str     = se_sym("context_struct_to_string");
    p_compute_av     = se_sym("context_struct_compute_av");
    p_write_op       = se_sym("write_op");
    p_sel_write_access = se_sym("sel_write_access");
    p_sel_write_context = se_sym("sel_write_context");
    p_sel_write_load  = se_sym("sel_write_load");   /* 改②：/load 写门目标 */
    p_bprm_sym       = se_sym("selinux_bprm_creds_for_exec");
    if (!p_bprm_sym)
        p_bprm_sym   = se_sym("selinux_bprm_set_creds");
    p_hook_heads     = se_sym("security_hook_heads");
    p_scall_table    = se_sym("static_calls_table");
    p_scall_update   = se_sym("__static_call_update");
    p_blob_sizes     = se_sym("selinux_blob_sizes");
    /*
     * fp_hook 是 KernelPatch 的 API（base/fphook.c:220 KP_EXPORT_SYMBOL），
     * 不在这台内核的 kallsyms 里，只能用 KP 的符号表查。以前用 se_sym 查
     * 内核符号表，永远拿到 0，于是 SE_FPHOOK 全是空操作 —— 两道 gate 和
     * bprm 钩子都"装上了"但什么都没改。这是 4.19 上最隐蔽的一处。
     */
    p_fp_hook        = symbol_lookup_name("fp_hook");
    p_strncpy_user   = se_sym("compat_strncpy_from_user");
    if (!p_strncpy_user)
        p_strncpy_user = se_sym("strncpy_from_user");
    p_sidtab_to_sid  = se_sym("sidtab_context_to_sid");
    p_avtab_search   = se_sym("avtab_search");
    p_avtab_node_search = se_sym("avtab_search_node");
    p_avtab_add      = se_sym("avtab_insert_nonunique");
    p_avtab_read     = se_sym("avtab_read");
    p_symtab_search  = se_sym("symtab_search");
    p_hashtab_search = se_sym("hashtab_search");
    /*
     * avc 刷新两件套。selinux_avc 是 avc.c 的文件级 static 实例（4.19~6.12
     * 各版都存在，kallsyms b 段可查），avc_ss_reset 的内核重载路径
     * (state->avc, ...) 里 state->avc == &selinux_avc（selinux_avc_init），
     * 所以直接传它的地址、不依赖任何 selinux_state 布局偏移。
     */
    p_avc_reset      = se_sym("avc_ss_reset");
    p_avc_struct     = se_sym("selinux_avc");
    p_get_perms      = se_sym("security_get_permissions");
    p_kfree          = se_sym("kfree");
    p_copy_from_user = se_sym("copy_from_user");
    if (!p_copy_from_user)
        p_copy_from_user = se_sym("_copy_from_user");
    if (!p_copy_from_user)
        /* 4.19 arm64：copy_from_user 是 static inline，kallsyms 只有汇编
         * 底层 __arch_copy_from_user（T 可见，带 .fixup 异常表——坏页返回
         * 剩余字节数而非 Oops）。调用方（se_load_write）必须先做用户区间
         * 粗校验，见 se_gate.c。 */
        p_copy_from_user = se_sym("__arch_copy_from_user");
    p_filp_open      = se_sym("filp_open");
    p_filp_close     = se_sym("filp_close");
    p_kernel_read    = se_sym("kernel_read");   /* 改①：批量规则文件读取 */
    p_sel_read_status = se_sym("sel_read_handle_status");   /* v61：status 冻结 */
    p_status_ops      = se_sym("sel_handle_status_ops");    /* v61：fops 数据符号 */
    p_kvfree         = se_sym("kvfree");
    if (!p_kvfree)
        p_kvfree     = p_kfree;

    /* v54：影子页/坐标系重建所需的 kallsyms 可见符号。
     * memstart_addr（memory.h:204 PHYS_OFFSET）、kimage_voffset（memory.h:210）、
     * swapper_pg_dir、_text 均为数据/代码符号，System.map d/T 段实证可见；
     * 4.19 上由 se_sym 运行期判定，绑不到则影子页子系统拒绝启用。 */
    p_sel_load_ops   = se_sym("sel_load_ops");
    p_vmalloc        = se_sym("vmalloc");
    p_vfree          = se_sym("vfree");
    p_stop_machine   = se_sym("stop_machine");
    p_gfp            = se_sym("__get_free_pages");
    p_memstart       = se_sym("memstart_addr");
    p_kimage_voff    = se_sym("kimage_voffset");
    p_swapper        = se_sym("swapper_pg_dir");
    p_text           = se_sym("_text");

    /* KernelPatch 自己的符号要走 KP 的符号表，内核 kallsyms 里没有 */
    p_kp_hook        = symbol_lookup_name("hook");
    p_kp_unhook      = symbol_lookup_name("unhook");
    p_kuid           = symbol_lookup_name("current_uid");
    /* v81c：symbol_lookup_name 只搜 KP 自有符号表（base/symbol.c
     * symbol_start..symbol_end），不搜内核 kallsyms——set_security_override
     * 不在 KP 表（v81b 装机 symbol=0 实证）。改走 se_sym（内核
     * kallsyms_lookup_name -> kallsyms_on_each_symbol 回退链）。 */
    p_set_sec_override = se_sym("set_security_override");
    /* v82：KP 的后缀解析器（KP_EXPORT_SYMBOL，KP 符号表必有）——
     * GKI 6.x 上 kallsyms_lookup_name 函数指针失效时的第三级回退 */
    p_ksym_by_suffix = symbol_lookup_name("kallsyms_lookup_name_by_suffix");
    pr_info("sehide: kp hook=%016lx unhook=%016lx current_uid=%016lx\n",
            p_kp_hook, p_kp_unhook, p_kuid);
}

