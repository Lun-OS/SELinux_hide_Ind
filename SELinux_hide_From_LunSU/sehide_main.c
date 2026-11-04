/* SPDX-License-Identifier: GPL-2.0-or-later */
/* sehide_main：模块入口/装配/控制面 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"

KPM_NAME("SELinux_hide_From_LunSU");
KPM_VERSION("1.0.0-beta");
KPM_LICENSE("AGPL v3");
KPM_AUTHOR("Lun.");
KPM_DESCRIPTION("LunSU SELinux hide engine for KernelPatch");

static const char *se_ver = "1.0.0-beta";

long sehide_init(const char *args, const char *event, void *__user reserved)
{
    unsigned int i;

    (void)args;
    (void)event;
    (void)reserved;

    /* v84b：横幅自证版本 —— 防止"刷入版本与验证日志不对应"的空转 */
    pr_info("sehide: kernel %x, kernelpatch %x, v%s\n", kver, kpver, se_ver);
    se_bind_symbols();

    /* v54：影子页坐标系重建（TCR/TTBR1 + kallsyms 符号，双自证）。
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
 * 安装引擎：标定 -> 写 live -> 装门与钩子。
 *
 * v54：由 se_bprm_wrap 在首个 exec 时调用（真正的进程上下文，可睡眠）。
 * KPM_EVENT 分发持 rcu_read_lock（module.c:691-704），睡眠类操作全部
 * 移出 event —— v44 的 synchronize_rcu 卡死已证明该上下文不能等 grace。
 * 调用方（se_bprm_wrap）已持 g_recal_busy CAS 锁。
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
     * v85：组件域 = 生态域（LunSU 语义：三件套/切域/副本盖章作用于
     * 生态组件域，而非硬编码 su）。
     *
     * 依据（fp_br28 装机日志实证）：KP 生态（FolkPatch d09+）在 execve
     * 路径上把组件会话安排进 u:r:magisk:s0（handle_before_execve），且
     * KP 的 security_load_policy 钩子（0.003s 装载）保证每次策略加载
     * 都注入 magisk 类型 —— live 里必有。v84b 硬编码 su 把 KP 设置好的
     * magisk 域覆盖掉，apd 被夺走生态域后 KP package_config 通道断，
     * post-fs-data 提前退出，Zygisk Next 注入脚本全部没跑 —— zygisk
     * 全灭的根因。
     *
     * 标定：live 有 magisk → comp=magisk；否则（4.19 等旧生态）→ su，
     * 行为与 v84b 逐字一致（装机验证路径，零回归）。
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
     * v65（LunSU 验证形态，逐项照抄 ksu_selinux_hide_install 序列）：
     *
     * LunSU 源码（LunSU selinux_hide.c v22 教训注释）实证：
     * inbound 规则不写 live 时 "zygisk and every LSPosed module were dead
     * while root itself worked"——init/zygote 域的注入器访问 su 域对象
     * （payload fd / binder / socket）需要 live 里有 inbound 规则，内核
     * 判定从不读副本。v63/v64 的零写入正是 LSP 异常的机制。
     *
     * 顺序对齐 LunSU："Gates first, bits second"——门先装（live 带写入
     * 而无门是唯一禁止状态），role 条件位测量驱动（live 已接受 su 上下文
     * 则不写，本设备 parse 成功即已接受，恰好避开该机 role 数组定位问题），
     * inbound 规则与 permissive 位随后。
     *
     * 三件套非特权不可见：/policy avc 门挡内容（st_size 只在成功 open 时
     * 刷新）；行为面只作用 su 域；原位写不 bump policyload 计数
     * （"Why not a policy load"——LunSU 头注释 L49）。
     */
    rc = se_derive_layout();
    if (rc) {
        pr_info("sehide: derive rc=%d (symtab/avtab)\n", rc);
    } else {
        pr_info("sehide: layout symoff=%u stride=%u avtab=%u nel=%u\n",
                L.symtab_off, L.symtab_stride, L.avtab_off, L.avtab_nel);
        se_build_copy();
        se_selftest();
        if (se_install_gate())
            pr_info("sehide: gate access not installed\n");
        if (se_install_gate_ctx())
            pr_info("sehide: gate ctx not installed\n");
        /*
         * v90：/load 门归队（LunSU 形态适配层）。LunSU 生态模块规则的
         * 唯一通道是 handle_sepolicy supercall（进副本，"live is never
         * written"）；APatch 生态的注入通道是写 /sys/fs/selinux/load
         * （apd/libsepol），不拦则 magisk/lsp 类型与规则真落 live ——
         * duck_detector 实测三项失守（context oracle 识别 magisk/
         * lsposed_file、policyload=5、access oracle allowed）。门把
         * blob 全丢弃（se_absorb_blob v90），live = 出厂 + 三件套，
         * apd 拿到假成功继续跑 post-fs-data.sh（4.19 v84b 全链实证）。 */
        if (se_install_load_gate())
            pr_info("sehide: gate load not installed\n");
        /*
         * v87：/load 门摘除 —— 回归 v63 的 LunSU 形态定稿（"/load 不劫持，
         * live 变化后由指纹自愈处理"），v68 的归队决定作废。
         *
         * 装机对照实证（fp_br29，同设备同 KP）：05:56 无 KPM 时生态自洽
         * —— apd PostFsData 完整跑（sepolicy 注入 → 模块 rule →
         * post-fs-data.sh），zn-daemon64 注入 zygote，组件域/规则集/
         * transition 全部由生态自己写进 live；KPM 在场时 /load 门把
         * 这条链的写入吸进副本、live 永不重载，生态域（magisk 类型/
         * 规则/transition）整体缺失，组件失去生态生存面 —— zygisk 全灭。
         *
         * LunSU 没有 /load 门：非特权观测面安全的依据是出厂 avc 门
         * （/policy 需 security:read_policy，app 域全无）+ status 冻结，
         * 不是 live 零修改。摘除后 live 形态与"无 KPM 的生态"逐字一致
         * ——检测差异天然为零，这就是天生兼容：KPM 退为纯增益层
         * （三件套 + 副本 + 问门），exec 路径与策略重载路径零干预。
         * 模块经生态通道（apd）写的规则随生态；KPM 自己的 sepolicy 批
         * 走 se_ctl_sepolicy 控制面进副本，不碰 live —— 规则永不进 live
         * 的语义只约束 KPM 自身，不拦生态。 */

        /* LunSU：inbound 规则先于位。失败不阻断安装（少一条规则少一个
         * 功能，中止安装丢 root）。v85：对象 = 生态组件域。
         * v88：inbound + permissive + policydb.len 维护一体（se_apply_trio）——
         * 6.1 的 put_entry 溢出检查（4.19 无）要求 live 的每次有效写入
         * 同步扩 len，否则 apd 读 /sys/fs/selinux/policy 时
         * policydb_write 返回 -EINVAL，PostFsData 注入链在 from_file
         * 处静默失败（fp_br30 根因）。 */
        se_apply_trio(g_comp_type ? g_comp_type : L.su_type);
        pr_info("sehide: live marked (inbound rules + permissive bit for comp %s type %u)\n",
                g_comp_ctx, g_comp_type);

        /* v64：status 冻结撤除——LunSU 无此组件（它靠"自己绝不触发
         * policy load"保计数干净；LSP 的 load 是 LSP 自己的行为，与
         * 引擎无关）。自创动作即新增暴露面，完全对齐 LunSU。 */
        /* v63（LunSU 形态定稿）：/load 不劫持。
         *
         * LunSU 源码实证（LunSU selinux_hide.c）：没有 /load 门，
         * 模块规则由 LSP 自己真写 live（live=出厂+LSP 规则），su 标记随
         * 指纹自愈重写。非特权观测面安全的依据是出厂 avc 门（/policy 要
         * security:read_policy，app 域全无此权限）+ status 冻结（v61），
         * 不是 live 零修改——v62 劫持导致 lspd 域类型不存在、LSP 死。
         * live 变化后的副本换代由指纹自愈（se_live_ok -> se_recalibrate）
         * 处理，实测链路健在。 */

        /*
         * bprm 钩子保留为"首触安装触发器 + 纯透传"（v60 起 su 判定逻辑
         * 全部移除——root 走 KP 核心 supercall，不依赖 bprm 放行）。
         * 钩子本体已在 event 期原子安装（se_install_hook_early），
         * 这里仅在 event 期未装成时兜底重试。
         */
        {
            se_u32 sid = 0;

            /* v60：g_su_sid 仅作日志观测（root 判定已不依赖）；钩子兜底重试 */
            if (p_secctx_to_sid)
                ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                    ("u:r:su:s0", sizeof("u:r:su:s0") - 1u, &sid);
            if (!sid)
                se_ctx_to_sid("u:r:su:s0", &sid);
            g_su_sid = sid;
            pr_info("sehide: su sid=%u lbs=%u\n", g_su_sid, g_lbs_cred);

            /* v85：组件域 sid 标定（切域写入值；KP 生态=magisk sid） */
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

            if (!g_hook_done && se_install_hook_early())
                pr_info("sehide: bprm hook not installed\n");
        }
    }

    /*
     * 这里不能调 avc_ss_reset()。
     *
     * KP 的 event 分发是在 RCU 读临界区里跑的，而 4.19 的 avc_ss_reset →
     * avc_callbacks 会走到 selinux_netcache_avc_callback() → synchronize_net()
     * → synchronize_rcu()，那是要睡眠的；在 RCU 读段里等 grace period 就是
     * 自己等自己 —— 现场日志正是 kernel/rcu/tree_plugin.h:342 的
     * "Illegal synchronize_rcu() in RCU read-side critical section"，init
     * 从此卡住，第一屏起不来。
     *
     * 不 flush 也不影响正确性：su 的 sid 是这次刚解析出来的，early-init 之前
     * 没有任何进程访问过它，avc 里本来就没有它的条目，第一次判定必然重新
     * 走 security_compute_av()，读到的就是刚写进去的 permissive 位和规则。
     * 需要 flush 的场景是"改一个已经被缓存过的域"，这里不存在。
     */

    pr_info("sehide: avtab search=%d add=%d\n",
            p_avtab_search ? 1 : 0, p_avtab_add ? 1 : 0);
    pr_info("sehide: engine up\n");
    return 0;
}

static long se_ctl_sepolicy(const char *path);   /* 改① 入口，定义在下方 */

long sehide_control0(const char *args, char *__user out_msg, int outlen)
{
    /* 新增：改① 子命令分发（诊断输出保持原样，走 else） */
    if (args && args[0] == 's' && !strncmp(args, "sepolicy ", 9))
        return se_ctl_sepolicy(args + 9);

    /* v54 诊断："probe" 手动触发 avtab inline hook 探针（v54 起退出主路径，
     * 写一次内核 .text，仅供取证）；"shadow" 打印影子页坐标系状态 */
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
 * 新增：改① 入口 —— kpatch ctl SELinux_hide_From_LunSU "sepolicy <path>"
 *
 * KP 的控制面（KPM_CTL0）只有字符串 args，没有 KSU supercall 的 __user
 * 指针，所以批量 payload 走文件：内核侧 filp_open + kernel_read 读入后
 * 调 se_handle_sepolicy。wire format 与 KSU 完全同构，入口通道按 KPM 平台
 * 落地（方案文档四.1）。上限 8MB（对齐 KSU_SEPOLICY_MAX_BATCH_SIZE）。
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

    /* v54：影子页还原（BBM 换回原描述符 + 释放影子页） */
    se_shadow_remove_all();

    /* v60：槽位还原——门与 bprm 钩子写回原函数，模块退出后零悬空指针
     * （write_op[]/security_hook_heads 恢复出厂内容）。 */
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
 * `kpatch event <name>`，supercmd 收下后经 report_user_event ->
 * extra_event_init_args -> notify_modules_event 派发到每个模块的
 * .kpm.event（module.c:685-698，全程持 rcu_read_lock）。post-fs-data 走
 * 的是 apd，不经过这条路，所以这里只用上面四个名字。
 *
 * v54：event 回调运行在 RCU 读临界区内（module.c:691-704 实证），睡眠类
 * 操作（policydb_read/se_alloc）与 grace 等待全部禁止 —— v44 的
 * synchronize_rcu 卡死第一屏就是教训。这里只做原子安全的 bprm 钩子安装
 * （fp_hook 数据槽 / 影子页，均无 grace 等待）；引擎主体延到首个 exec 的
 * se_bprm_wrap（真进程上下文，可睡眠，CAS 互斥）—— 时机必然晚于策略
 * 加载，自动消掉 4.19 实测的 -22。g_su_sid 未定时 wrap 直透原函数，
 * 安装前零行为影响。
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