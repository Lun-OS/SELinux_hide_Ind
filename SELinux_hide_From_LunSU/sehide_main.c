/* SPDX-License-Identifier: GPL-2.0-or-later */
/* sehide_main：模块入口/装配/控制面 */
#include "sehide.h"

KPM_NAME("SELinux_hide_From_LunSU");
KPM_VERSION("1.1.0");
KPM_LICENSE("AGPL v3");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("LunSU SELinux hide engine for KernelPatch");

/* 版本历史与演进记录：见 docs/selinux-hide/KPM-1.1.0-注释工作日志归档.md */
static const char *se_ver = "1.1.0";

long sehide_init(const char *args, const char *event, void *__user reserved)
{
    unsigned int i;

    (void)args;
    (void)event;
    (void)reserved;

    /* 横幅自证版本：装机日志核对刷入版本与分派形状；只打印表查询结果，
     * 不做探测、不据此开关任何功能。 */
    pr_info("sehide: kernel %x, kernelpatch %x, v%s shape=%s state=%d\n",
            kver, kpver, se_ver,
            se_kver_aden() == SE_ADEN_9S ? "9s" :
                (se_kver_aden() == SE_ADEN_8 ? "8" : "9b"),
            se_kver_has_state());
    se_bind_symbols();

    /* 影子页坐标系重建（TCR/TTBR1 + kallsyms 符号，双自证）。
     * 失败只关影子页子系统，fops 数据槽路径不受影响。 */
    se_shadow_init();

    for (i = 0; i < NSYM; i++)
        pr_info("sehide: %-26s %016lx %s\n", syms[i].name, syms[i].addr,
                syms[i].addr ? "ok" : "MISSING");

    if (!p_read_policy || !p_pdb_read || !p_kread || !p_kvzalloc || !p_selinux_state) {
        pr_info("sehide: required symbol missing, engine off\n");
        return 0;
    }

    /*
     * 只绑符号，不碰策略。
     *
     * KPM 默认在 pre-kernel-init 装载，那时 SELinux 策略还没读进来，
     * security_read_policy() 的第一句就是 `if (!state->initialized)
     * return -EINVAL;`，标定必然 -22。策略是在 Android init 的
     * selinux_initialize() 里加载的，早于 early-init，所以真正的安装挂到
     * .kpm.event 的 init 阶段事件上（见 sehide_event）。
     */
    pr_info("sehide: symbols bound, waiting for init event\n");
    return 0;
}

/*
 * 安装引擎：标定 -> 决策面/副本 -> 门与钩子。
 *
 * 红线：不能在 KPM_EVENT（RCU 读临界区）里做任何睡眠类操作或 grace
 * 等待——本函数只允许在 se_bprm_wrap（真进程上下文，可睡眠，调用方
 * 已持 g_recal_busy CAS 锁）里执行。
 */
int se_install_engine(void)
{
    int rc;

    rc = se_calibrate();
    if (rc) {
        pr_info("sehide: calibration failed rc=%d, engine off\n", rc);
        return rc;
    }

    /* su 的 type：只用 live 的 policydb 解析上下文串，不改任何东西 */
    rc = se_ctx_type("u:r:su:s0", &L.su_type);
    if (rc) {
        pr_info("sehide: parse su ctx rc=%d\n", rc);
        return 0;
    }
    pr_info("sehide: su type=%u\n", L.su_type);

    /*
     * 组件域 = 生态域：KP 生态在 execve 路径把组件会话安排进
     * u:r:magisk:s0，且其策略加载钩子保证 live 里必有 magisk 类型；
     * 硬编码 su 会覆盖生态域、断掉 KP package_config 通道（zygisk
     * 全灭）。标定：live 有 magisk → comp=magisk；否则（旧生态）→ su。
     */
    if (se_ctx_type("u:r:magisk:s0", &g_comp_type) == 0 && g_comp_type) {
        g_comp_ctx = "u:r:magisk:s0";
        g_comp_tname = "magisk";
    } else {
        g_comp_type = L.su_type;
        g_comp_ctx = "u:r:su:s0";
        g_comp_tname = "su";
    }
    pr_info("sehide: comp domain=%s type=%u\n", g_comp_ctx, g_comp_type);

    /*
     * 装配顺序契约（对齐 LunSU "Gates first, bits second"）：
     * 标定 → sid 标定 → 决策面挂载 → 副本 → 门。
     *
     * live 保持干净：live 是内核当前管理的实时策略，"干净" = 非特权
     * 全部视角与未 root 无差异；特权善后只在我们的代码（副本 + 决策面
     * 翻转），live 恒出厂。
     *
     * 决策面挂载（自建，不调用 KP hook()）：p_adenied 地址链
     * （patch_config → 内核 kallsyms 直查）→ 前缀备份+PC 相关校验 →
     * aarch64_insn_patch_text 写 KP replace 入口 → 活体自检
     * （avc_has_perm(非su源→su, binder) rc==0 唯一归因）。
     */
    rc = se_derive_layout();
    if (rc) {
        pr_info("sehide: derive rc=%d (symtab/avtab)\n", rc);
    } else {
        pr_info("sehide: layout symoff=%u stride=%u avtab=%u nel=%u\n",
                L.symtab_off, L.symtab_stride, L.avtab_off, L.avtab_nel);
        {
            se_u32 sid = 0;

            /* sid 标定（决策面判定依赖 g_su_sid/g_comp_sid） */
            if (p_secctx_to_sid)
                ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                    ("u:r:su:s0", sizeof("u:r:su:s0") - 1u, &sid);
            if (!sid)
                se_ctx_to_sid("u:r:su:s0", &sid);
            g_su_sid = sid;
            pr_info("sehide: su sid=%u lbs=%u\n", g_su_sid, g_lbs_cred);

            {
                se_u32 csid = 0;

                if (p_secctx_to_sid && g_comp_ctx)
                    ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                        (g_comp_ctx, (se_u32)strlen(g_comp_ctx), &csid);
                if (!csid && g_comp_ctx)
                    se_ctx_to_sid(g_comp_ctx, &csid);
                g_comp_sid = csid ? csid : sid;
            }
            pr_info("sehide: comp sid=%u (%s)\n", g_comp_sid, g_comp_ctx);
        }

        /* 决策面挂载 + 活体自检。失败 = 降级（DEGRADED）：门照装——
         * 红线：拦生态注入是 live 干净的硬需求，门必须先于/独立于决策面
         * 在岗，否则生态注入裸奔落 live，非特权 oracle 全可见；
         * 翻转缺失（su 功能缺）显性化；副本不打 inbound stamp（oracle 与
         * 实际一致保持在出厂语义侧）。 */
        if (se_decision_install())
            pr_info("sehide: decision-plane unavailable, DEGRADED "
                    "(gates on, live stock, no flip)\n");
        else
            pr_info("sehide: live clean (decision-plane flip covers comp %s type %u)\n",
                    g_comp_ctx, g_comp_type);

        se_build_copy();      /* 副本按 se_decision_ready() 决定 inbound stamp */
        se_selftest();

        /* ---- 门（无论决策面成败都装，见上方红线） ---- */
        if (se_install_gate())
            pr_info("sehide: gate access not installed\n");
        if (se_install_gate_ctx())
            pr_info("sehide: gate ctx not installed\n");
        /*
         * /load 门：LunSU 生态模块规则的唯一通道是 handle_sepolicy
         * supercall（进副本，"live is never written"）；APatch 生态的
         * 注入通道是写 /sys/fs/selinux/load（apd/libsepol），不拦则
         * magisk/lsp 类型与规则真落 live —— 非特权 oracle 全可见。
         * 现行门行为 = 吸收进副本，非丢弃：特权 blob 经 se_absorb_blob
         * （se_policydb.c）解析（policydb_read 到新副本 → 类数校验 →
         * 镜像长度倒退保护 → 盖章 → se_retire_copy 换代）——生态规则
         * 自此经副本在决策面收口查询生效。"丢弃 + 假成功"只是失败降级
         * 路径（pdb_read 失败/类数不匹配/stale blob/未就绪 → 丢弃且
         * 返回 0）——红线：reject 返回会让 apd 静默退出、zygisk 全灭。
         * /policy 读门配套：apd 读到副本序列化再打包写回，避免单模块
         * blob 互相覆盖。live 恒干净，门对非特权照旧透传。 */
        if (se_install_load_gate())
            pr_info("sehide: gate load not installed\n");

        /* /policy 读门——特权读策略答副本序列化（apd "读现行→加规则→
         * 写回"的链式累积依赖）；权限检查不动（非特权原版即拒零暴露）。 */
        if (se_install_read_gate())
            pr_info("sehide: gate read not installed\n");

        /* status 页冻结门：非特权（uid>=10000）读到冻结的出厂快照
         * （policyload=1 / 真 enforcing），特权透传真实值——出厂覆盖
         * live 走内核重载推高 policyload 时的前置保险。 */
        if (se_status_install())
            pr_info("sehide: status freeze not installed\n");

        /*
         * bprm 钩子保留为"首触安装触发器 + 纯透传"（root 走 KP 核心
         * supercall，不依赖 bprm 放行，也绝不写 live 规则）。
         * 钩子本体已在 event 期原子安装（se_install_hook_early），
         * 这里仅在 event 期未装成时兜底重试。
         */
        {
            if (!g_hook_done && se_install_hook_early())
                pr_info("sehide: bprm hook not installed\n");
        }
    }

    /*
     * 红线：这里不能调 avc_ss_reset()——4.19 的 avc_ss_reset →
     * avc_callbacks 会走到 selinux_netcache_avc_callback() →
     * synchronize_net() → synchronize_rcu()，在 RCU 读段里等 grace
     * = 自己等自己（Illegal synchronize_rcu() panic，init 卡死）。
     *
     * install 后的 flush 用 se_avc_flush_after_recal()（call_rcu 异步，
     * 无 grace 等待）：清掉 pre-engine 窗口内按出厂语义缓存的决策节点。
     * flush 不是正确性依赖（su sid 刚解析，avc 里本无其条目），保留仅
     * 为消除窗口内的 deny 审计噪音。se_recalibrate 内部同款 flush。
     */

    pr_info("sehide: avtab search=%d add=%d\n",
            p_avtab_search ? 1 : 0, p_avtab_add ? 1 : 0);
    se_avc_flush_after_recal();
    pr_info("sehide: engine up\n");
    return 0;
}

static long se_ctl_sepolicy(const char *path);   /* 改① 入口，定义在下方 */

long sehide_control0(const char *args, char *__user out_msg, int outlen)
{
    /* sepolicy 批处理子命令分发（诊断输出走 else） */
    if (args && args[0] == 's' && !strncmp(args, "sepolicy ", 9))
        return se_ctl_sepolicy(args + 9);

    /* 诊断子命令："probe" 手动触发 avtab 探针（写一次内核 .text，仅供
     * 取证）；"shadow" 打印影子页坐标系状态 */
    if (args && se_streq(args, "probe")) {
        char buf[128];
        struct se_out o;
        int rc = L.ok ? se_probe_avtab() : -11;

        o.buf = buf; o.cap = sizeof(buf); o.n = 0;
        se_o_s(&o, "probe rc=");
        se_o_dec(&o, (se_u32)rc);
        se_o_s(&o, " avtab_off=");
        se_o_dec(&o, L.avtab_off);
        se_o_s(&o, " nel=");
        se_o_dec(&o, L.avtab_nel);
        if (out_msg && outlen > 0)
            compat_copy_to_user(out_msg, buf, o.n < outlen ? o.n : outlen);
        return 0;
    }
    if (args && se_streq(args, "shadow")) {
        char buf[192];
        struct se_out o;
        o.buf = buf; o.cap = sizeof(buf); o.n = 0;
        se_o_s(&o, "shadow mm_ok=");
        se_o_dec(&o, (se_u32)g_mm_ok);
        se_o_s(&o, " pshift=");
        se_o_dec(&o, (se_u32)g_mm_page_shift);
        se_o_s(&o, " installed=");
        se_o_dec(&o, (se_u32)g_shadow_installed);
        se_o_s(&o, " ready=");
        se_o_dec(&o, (se_u32)se_shadow_ready());
        if (out_msg && outlen > 0)
            compat_copy_to_user(out_msg, buf, o.n < outlen ? o.n : outlen);
        return 0;
    }

    char buf[1536];
    int n = 0;
    unsigned int i;

    (void)args;

    {
        struct se_out o;

        o.buf = buf;
        o.cap = sizeof(buf);
        o.n = 0;

        se_o_s(&o, "kernel="); se_o_hex(&o, (se_u64)kver, 1);
        se_o_s(&o, " kp=");    se_o_hex(&o, (se_u64)kpver, 1);
        se_o_s(&o, "\ncalib ok="); se_o_dec(&o, (se_u32)L.ok);
        se_o_s(&o, " vers=");  se_o_dec(&o, L.vers);
        se_o_s(&o, " len=");   se_o_dec(&o, L.bin_len);
        se_o_s(&o, " perm=");  se_o_dec(&o, L.perm);
        se_o_s(&o, " lenoff=");se_o_dec(&o, L.lenoff);
        se_o_s(&o, " slot=");  se_o_dec(&o, L.slot);
        se_o_s(&o, " pdboff=");se_o_dec(&o, L.pdb_off);
        se_o_s(&o, " su_type="); se_o_dec(&o, L.su_type);
        se_o_s(&o, "\nlayout symoff="); se_o_dec(&o, L.symtab_off);
        se_o_s(&o, " stride="); se_o_dec(&o, L.symtab_stride);
        se_o_s(&o, " avtab=");  se_o_dec(&o, L.avtab_off);
        se_o_s(&o, " nel=");    se_o_dec(&o, L.avtab_nel);
        se_o_s(&o, " rules ok="); se_o_dec(&o, L.rules_ok);
        se_o_s(&o, " skip=");   se_o_dec(&o, L.rules_fail);
        se_o_s(&o, "\n");

        for (i = 0; i < NSYM; i++) {
            se_o_pad(&o, syms[i].name, 26);
            se_o_hex(&o, (se_u64)syms[i].addr, 16);
            se_o_c(&o, '\n');
        }
        n = (int)o.n;
    }

    if (out_msg && outlen > 0)
        compat_copy_to_user(out_msg, buf, n < outlen ? n : outlen);
    return 0;
}

/*
 * 新增：kpatch ctl 子命令 —— sepolicy 批处理入口
 *
 * KP 的控制面（KPM_CTL0）只有字符串 args，没有 KSU supercall 的 __user
 * 指针，所以批量 payload 走文件：内核侧 filp_open + kernel_read 读入后
 * 调 se_handle_sepolicy。wire format 与 KSU 完全同构。上限 8MB
 * （对齐 KSU_SEPOLICY_MAX_BATCH_SIZE）。
 */
static long se_ctl_sepolicy(const char *path)
{
    void *f = 0;
    se_u8 *buf = 0;
    se_u32 off = 0;
    loff_t pos = 0;
    long ret;

    if (!se_gate_privileged())
        return -1;
    if (!p_filp_open || !p_filp_close || !p_kernel_read || !L.ok)
        return -95;

    buf = se_alloc(KSU_SEPOLICY_MAX_BATCH_SIZE);
    if (!buf)
        return -12;

    f = ((void *(*)(const char *, int, unsigned int))p_filp_open)(path, 0, 0);
    if (!f || !se_kptr_ok((se_u64)(se_ulong)f)) {
        se_free(buf);
        return -2;
    }

    while (off < KSU_SEPOLICY_MAX_BATCH_SIZE) {
        long n = ((long (*)(void *, void *, unsigned long, loff_t *))p_kernel_read)
            (f, buf + off, KSU_SEPOLICY_MAX_BATCH_SIZE - off, &pos);

        if (n <= 0)
            break;
        off += (se_u32)n;
    }
    ((long (*)(void *, void *))p_filp_close)(f, 0);   /* filp_close(file, fl_owner_t) 两参 */

    if (!off) {
        se_free(buf);
        return -22;
    }

    ret = se_handle_sepolicy(buf, off);
    se_free(buf);
    return ret;
}

long sehide_exit(void *__user reserved)
{
    (void)reserved;
    pr_info("sehide: exit\n");

    /* 影子页还原（BBM 换回原描述符 + 释放影子页） */
    se_shadow_remove_all();

    /* 决策面卸载（恢复 KP replace 入口前缀，与挂载相反的顺序纪律） */
    se_decision_uninstall();

    /* 门与 bprm 钩子槽位写回原函数，模块退出后零悬空指针 */
    se_uninstall_gates();
    se_uninstall_hook();

    /*
     * 释放两代副本（对齐 LKM 模块移除路径）。门卸载后不再有人无锁读
     * L.copy，此刻立即析构是安全的；延迟一代只是运行期换代的纪律。
     */
    if (L.copy && p_pdb_destroy)
        ((void (*)(void *))p_pdb_destroy)(L.copy);
    se_free(L.copy);
    L.copy = 0;
    if (g_copy_prev && p_pdb_destroy)
        ((void (*)(void *))p_pdb_destroy)(g_copy_prev);
    se_free(g_copy_prev);
    g_copy_prev = 0;
    return 0;
}
/*
 * KP 在 early-init / init / late-init / boot-completed 这些 rc 动作里跑
 * `kpatch event <name>`，supercmd 收下后派发到每个模块的
 * .kpm.event（module.c:685-698，全程持 rcu_read_lock）。post-fs-data 走
 * 的是 apd，不经过这条路，所以这里只用上面四个名字。
 *
 * 红线：event 回调运行在 RCU 读临界区内，睡眠类操作（policydb_read/
 * se_alloc）与 grace 等待全部禁止。这里只做原子安全的 bprm 钩子安装
 * （fp_hook 数据槽 / 影子页，均无 grace 等待）；引擎主体延到首个 exec
 * 的 se_bprm_wrap（真进程上下文，可睡眠，CAS 互斥）——时机必然晚于
 * 策略加载。g_su_sid 未定时 wrap 直透原函数，安装前零行为影响。
 */
static long sehide_event(const char *event, const char *args, void *__user reserved)
{
    (void)args;
    (void)reserved;

    if (!event)
        return 0;

    if (!se_streq(event, "early-init") && !se_streq(event, "init") &&
        !se_streq(event, "late-init") && !se_streq(event, "boot-completed"))
        return 0;

    pr_info("sehide: event %s, installing bprm hook (engine deferred to first exec)\n",
            event);
    se_install_hook_early();
    return 0;
}

KPM_EVENT(sehide_event);

KPM_INIT(sehide_init);
KPM_CTL0(sehide_control0);
KPM_EXIT(sehide_exit);