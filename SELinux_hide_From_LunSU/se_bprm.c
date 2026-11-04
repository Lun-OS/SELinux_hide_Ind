/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_bprm：exec 过渡钩子 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"


/* ---------------- bprm 过渡钩子（与 LKM 版同一套逻辑） ---------------- */

int (*g_orig_bprm)(void *bprm);
se_u32 g_cred_off;
se_u32 g_lbs_cred;
se_u32 g_su_sid;

/*
 * v85：组件域（生态域）。默认 su（= v84b 及之前行为，4.19 等无 magisk
 * 生态的装机验证路径）；se_install_engine 标定到 magisk 时整体切换。
 * 定义在 se_bprm.c（与 g_su_sid 同处），声明在 sehide.h。
 */
se_u32 g_comp_type;
se_u32 g_comp_sid;
const char *g_comp_ctx = "u:r:su:s0";
const char *g_comp_tname = "su";

int g_hook_done;
int g_install_fails;   /* v54：延迟安装失败计数（进程上下文重试上限） */

/*
 * v81：组件域切轨（LunSU 组件生存模型的完整移植）。
 *
 * LunSU 生态里组件不需要 live 有任何模块规则也能活，因为 ksud 把组件
 * 进程授权进了 su 域：live 的 su 三件套（inbound 规则 + permissive 位）
 * 恰好覆盖 su 域的一切操作——源是 su 的 denial 由 permissive 位放行，
 * 目标是 su 对象的操作由 inbound 放行。live 本来就是为 su 域组件设计的
 * 生存空间，规则自始不必进 live。
 *
 * 本机（APatch/FolkPatch 生态）组件链（apd -> post-fs-data.sh ->
 * 各 daemon/注入器）实测全在 u:r:init:s0 域、无任何 KP 授权标记
 * （活体 ps -AZ + dmesg commit_common_su 全为事件自用实证）——组件的
 * 操作撞上 enforcing 的 live 就被真拒（dontaudit 静默）。
 *
 * 修复：bprm 钩子对「uid==0 且 exec 文件位于 /data/adb/ 下」的 exec，
 * 在 selinux_bprm_set_creds 原函数返回后（bprm->cred 的 SELinux 域已
 * 定型）用内核原生 set_security_override 把 bprm->cred 的域改写为 su。
 * commit_creds 之后组件进程域 = u:r:su:s0，进入 LunSU 组件生存域。
 *
 *   - live 零改动：放行完全由既有 su 三件套承担（LunSU 底线不动）；
 *   - 通用：判定只看「root 的 exec 且文件在 /data/adb/ 下」，任何 root
 *     管理器生态的组件脚本/daemon/注入器全部命中，零个体适配；
 *   - 精确：系统服务 exec /system/bin/* 不命中，SELinux 对系统域的
 *     隔离不动；binfmt_script 重入（called_set_creds 后 orig 秒回）
 *     时重复调用 set_security_override 幂等无害；
 *   - 失败安全：符号缺失/cred 或 filename 标定失败/uid 不为 0 一律
 *     原样透传，行为不劣于修复前。
 */
/* p_set_sec_override 在 se_symbol.c 绑定（与 p_kp_hook 同一解析点） */

/*
 * cred->security 的偏移未知，也不需要知道：
 * 在 cred 前 0x100 字节里逐个把内核指针当 security 用，
 * 看 *(u32 *)(p + lbs_cred) 是否等于 su 的 sid。命中即"新身份是 su"。
 */
/*
 * 这个 cred 的 SELinux sid 是不是 su。
 *
 * 优先让内核自己回答：security_cred_getsecid 是 EXPORT_SYMBOL（4.19
 * security.c:1024 起，八个版本全在），内部跑 cred_getsecid 钩子，SELinux
 * 那边返回 cred_sid()。这样不需要 cred->security 偏移、不需要
 * selinux_blob_sizes、也不需要 task_security_struct.sid 的位置。
 *
 * 取不到符号时退回扫描：在 cred 前 0x100 里找"看起来像 security 指针"
 * 的字段，按 blob 偏移读出 sid 比对。
 */
int se_cred_is_su(se_u64 cred)
{
    if (p_cred_getsecid && g_su_sid) {
        se_u32 sid = 0;

        ((void (*)(const void *, se_u32 *))p_cred_getsecid)
            ((const void *)(se_ulong)cred, &sid);
        if (sid == g_su_sid)
            return 1;
    }

    /*
     * 回退扫描要靠 blob 偏移才能定位 task_security_struct.sid；4.19 没有
     * selinux_blob_sizes，g_lbs_cred 永远是 0，扫 p+0 读到的是 osid 而不是
     * sid，会误判。这种情况直接放弃回退，上面的 getsecid 已经是权威答案。
     */
    if (!g_lbs_cred)
        return 0;

    {
        se_u32 i;

        for (i = 0; i + 8u <= 0x100u; i += 8u) {
            se_u64 p = 0;
            se_u32 sid = 0;

            if (se_kread(&p, (se_u8 *)(se_ulong)cred + i, 8))
                continue;
            if (!se_kptr_ok(p))
                continue;
            if (se_kread(&sid, (se_u8 *)(se_ulong)p + g_lbs_cred, 4))
                continue;
            if (sid == g_su_sid)
                return 1;
        }
    }
    return 0;
}

/*
 * 解 bprm->cred 偏移：selinux_bprm_creds_for_exec() 第一句就是
 *     tsec = selinux_cred(bprm->cred);
 * 所以它前几十条指令里必有一条 ldr Xt,[X0,#imm]，x0 = bprm，imm = cred 偏移。
 * AArch64：ldr Xt,[Xn,#imm] = 0xF9400000 | Rn<<5 | Rt | imm12<<10，imm = imm12*8。
 * 每个候选都用 bprm+imm 处的值校验（内核堆指针 + usage 合理），唯一才采用。
 */
/* 这个偏移处是不是一个"像 cred"的指针：内核地址 + 头 4 字节是合理 usage */
int se_off_is_cred(void *bprm, se_u32 off)
{
    se_u64 p = 0;
    se_u32 usage = 0;

    if (se_kread(&p, (se_u8 *)bprm + off, 8))
        return 0;
    if (!se_kptr_ok(p))
        return 0;
    if (se_kread(&usage, (se_u8 *)(se_ulong)p, 4))
        return 0;
    return usage > 0 && usage <= 0x10000u;
}

/*
 * 解 selinux_bprm_creds_for_exec / selinux_bprm_set_creds 开头的取数指令，
 * 找出 bprm->cred 的偏移。
 *
 * 判据不是"指针值像不像 cred"，而是结构定义本身：
 *
 *     struct linux_binprm {
 *         ...
 *         struct file *file;
 *         struct cred *cred;        <- 紧跟在 file 后面
 *         ...
 *     };
 *
 * 4.19 / 5.10 / 6.1 / 6.6 / 6.12 / 6.18 六个版本的 include/linux/binfmts.h
 * 里这两行都是连着的，所以 cred 的偏移恒等于 file 的偏移 + 8。
 * SELinux 的这个钩子只需要读 file 和 cred 两个字段，于是：
 *
 *   - 编译器用 ldp x1,x2,[x0,#imm] 一次读这对相邻字段 -> cred = imm + 8
 *   - 编译器用两条独立的 ldr -> 找到相差 8 的那一对，后一个是 cred
 *
 * 两种代码生成方式都覆盖，且都要求 cred 一侧通过"内核指针 + 合理 usage"
 * 复核。RANDSTRUCT 打开时这对字段可能不再相邻，两条判据都失败，返回 0，
 * 钩子不装（不是猜一个偏移去用）。
 */
se_u32 se_derive_cred_off(void *bprm)
{
    se_u32 insn[32];
    se_u32 i, j, n = 0;
    se_u32 cand[8];

    if (!p_bprm_sym || !bprm)
        return 0;
    if (se_kread(insn, (void *)(se_ulong)p_bprm_sym, sizeof(insn)))
        return 0;

    /* 判据一：ldp x1, x2, [x0, #imm] —— 一次读走相邻的 file/cred */
    for (i = 0; i < 32u; i++) {
        se_u32 v = insn[i];
        se_u32 imm;

        if ((v & 0xFFC00000u) != 0xA9400000u)   /* LDP 64-bit */
            continue;
        if (((v >> 5) & 0x1Fu) != 0u)           /* Rn == x0 (bprm) */
            continue;

        imm = ((v >> 15) & 0x7Fu) * 8u;
        if (imm == 0 || imm >= 0x3F8u)
            continue;
        if (se_off_is_cred(bprm, imm + 8u))
            return imm + 8u;
    }

    /* 收集所有 64 位 ldr [x0,#imm] 的候选 */
    for (i = 0; i < 32u && n < 8u; i++) {
        se_u32 v = insn[i];
        se_u32 imm;
        se_u64 p = 0;

        if ((v & 0xFFC00000u) != 0xF9400000u)   /* LDR 64-bit */
            continue;
        if (((v >> 5) & 0x1Fu) != 0u)
            continue;

        imm = ((v >> 10) & 0xFFFu) * 8u;
        if (imm == 0 || imm >= 0x400u)
            continue;
        if (se_kread(&p, (se_u8 *)bprm + imm, 8))
            continue;
        if (!se_kptr_ok(p))
            continue;

        cand[n++] = imm;
    }

    /* 判据二：相差 8 的一对，后一个是 cred */
    for (i = 0; i + 1u < n; i++) {
        for (j = i + 1u; j < n; j++) {
            if (cand[j] == cand[i] + 8u && se_off_is_cred(bprm, cand[j]))
                return cand[j];
            if (cand[i] == cand[j] + 8u && se_off_is_cred(bprm, cand[i]))
                return cand[i];
        }
    }

    /* 判据三（兜底）：只有一个候选通过 cred 复核时采用 */
    {
        se_u32 hits = 0, off = 0;

        for (i = 0; i < n; i++) {
            if (se_off_is_cred(bprm, cand[i])) {
                hits++;
                off = cand[i];
            }
        }
        if (hits == 1u)
            return off;
    }

    return 0;
}

/*
 * v81：bprm 内核字符串槽里是否出现 "/data/adb/" 前缀。
 *
 * 4.19 binfmts.h 布局（cred 之后）：unsafe(4)+per_clear(4)+argc(4)+envc(4)
 * = 16 字节，filename@cred+24，interp@cred+32；__randomize_layout 时布局
 * 作废，因此不硬编码偏移，扫 [cred+8, cred+72] 的全部 8 字节槽：
 *   - 值必须是内核可读指针（argc/envc/unsafe/per_clear 拼槽是小整数，
 *     se_kptr_ok 全部滤除）；
 *   - 指向的字符串首字符 '/' 且前 16 字节可读；
 *   - 内容前缀匹配 "/data/adb/"（10 字节全匹配）。
 * filename（/data/adb/...）与 interp（/system/bin/sh）都会出现在槽里，
 * interp 永不在 /data/adb 下，前缀判定天然只对 filename 命中——无需区分
 * 两个槽位，无需布局假设。
 */
static int se_bprm_is_adb_bin(void *bprm)
{
    se_u32 i;

    for (i = g_cred_off + 8u; i + 8u <= g_cred_off + 72u; i += 8u) {
        se_u64 s = 0;
        char pbuf[16];

        if (se_kread(&s, (se_u8 *)bprm + i, 8) || !se_kptr_ok(s))
            continue;
        if (se_kread(pbuf, (void *)(se_ulong)s, sizeof(pbuf)))
            continue;
        if (pbuf[0] != '/')
            continue;
        {
            se_u32 k;

            for (k = 0; k < sizeof(pbuf); k++) {
                char ch = pbuf[k];

                if (ch == 0)
                    break;
                if ((ch < 0x20u || ch > 0x7eu) && ch != 0)
                    return 0;   /* 不可打印：不是路径字符串 */
            }
        }
        if (pbuf[0] == '/' && pbuf[1] == 'd' && pbuf[2] == 'a' &&
            pbuf[3] == 't' && pbuf[4] == 'a' && pbuf[5] == '/' &&
            pbuf[6] == 'a' && pbuf[7] == 'd' && pbuf[8] == 'b' &&
            pbuf[9] == '/')
            return 1;
    }
    return 0;
}

/*
 * v85b：apd 自身排除切域。
 *
 * 装机对照实证（fp_br29 boot_737 vs boot_05:56 同设备）：05:56（无 KPM）
 * apd 由 init exec、KP commit_common_su 提权、域保持生态原生（init），随后
 * PostFsData 完整执行（sepolicy 注入 → 模块 rule → post-fs-data.sh →
 * remove update flag）→ zygiskd（zn-daemon64）注入 zygote → 全链活。
 * KPM 在场时 apd 被切进组件域后，在 KP package_config 加载成功之后、
 * PostFsData 事件之前静默消失（logcat 19:15:07.556 起全程覆盖、PostFsData
 * 零输出、无 crash 痕迹），生态的 sepolicy 注入随之消失 —— magisk 类型/
 * 规则集/transition 全部不进 live，组件与注入器失去生存面。
 *
 * apd 的域管理是 KP 生态自己的事（supercall 提权，不靠域），KPM 一律
 * 不碰：filename 槽精确等于 "/data/adb/apd"（13 字节 + NUL）即排除。
 */

/*
 * v81：uid0 + /data/adb 组件 exec -> bprm->cred 域改写为 su。
 * 在 orig（selinux_bprm_set_creds）返回后调用：此时 bprm->cred 的
 * security blob 已由 SELinux 填好，set_security_override 覆盖其 sid，
 * 随后的 commit_creds 让新进程以 u:r:su:s0 落地。
 */
static int g_diag_n;   /* v81b：一次性诊断计数 */

/*
 * v86：组件域切轨（行为判定版）。
 *
 * 判定改为对照 orig 前后的 cred sid：
 *   orig 目标域 != 调用者域  →  生态已安排 transition（KP 注入后的
 *   magisk 域等任何目标域）→ 透传不覆盖，组件域写入值跟随观察值；
 *   orig 目标域 == 调用者域  →  生态未安排 → 切组件域（4.19 现状路径）。
 *
 * 零命名依赖：不再查 "magisk" 字符串——任何生态、任何目标域自动跟随，
 * 这是"一定范围内的通用兼容"：判定依据是生态行为（transition 有无），
 * 不是生态的类型命名。
 *
 * 依据（6.1.157 本地树实证）：security_cred_getsecid 为 EXPORT_SYMBOL
 * （security.c:1754，内部 cred_getsecid 钩子 = cred_sid()）；bprm->cred
 * 在 orig 前由 prepare_creds 复制调用者 cred（其 security blob = 调用者
 * 域副本），orig 之后为 transition 计算结果（hooks.c bprm_creds_for_exec）。
 * 前后各一次 getsecid 即得调用者域与生态目标域，零新增符号。
 */
/*
 * v90：组件域切轨回归 v84b 装机验证形态（uid0 + /data/adb -> comp 域）。
 *
 * /load 门恢复后 live = 出厂 + 三件套，magisk/lsp 类型不在 live —— 生态
 * 的 su -Z magisk（KP 裸 sid）覆盖为 su（出厂类型，permissive 三件套），
 * 组件在 su 域存活（4.19 v84b 全链实证：apd/模块脚本/zygiskd 同形态活）。
 * su 域是出厂类型，检测器的 context oracle / setprocattr oracle 对它
 * 求值 = 出厂行为，无新增可观测差异。
 *
 * v86 的行为判定与 v87 的关闭开关（区分实验已完成：apd 死因 = 6.1
 * put_entry 溢出，v88 len 维护修复）整体退役。
 */
static void se_switch_to_su(void *bprm)
{
    se_u64 cred = 0;
    se_u32 uid, tgt;
    int rc;

    tgt = g_comp_sid ? g_comp_sid : g_su_sid;
    if (!p_set_sec_override || !tgt) {
        if (g_diag_n < 2) {
            g_diag_n++;
            pr_info("sehide: skip symbol=%llx comp_sid=%u su_sid=%u\n",
                    (se_u64)p_set_sec_override, g_comp_sid, g_su_sid);
        }
        return;
    }

    uid = ((se_u32 (*)(void))p_kuid)();
    if (uid != 0u)
        return;

    if (!g_cred_off) {
        g_cred_off = se_derive_cred_off(bprm);
        if (!g_cred_off) {
            if (g_diag_n < 4) {
                g_diag_n++;
                pr_info("sehide: cred off derive failed (uid0)\n");
            }
            return;
        }
        g_diag_n = 4;
        pr_info("sehide: cred off=%u\n", g_cred_off);
    }

    if (!se_bprm_is_adb_bin(bprm))
        return;

    if (se_kread(&cred, (se_u8 *)bprm + g_cred_off, 8) || !se_kptr_ok(cred))
        return;

    rc = ((int (*)(void *, se_u32))p_set_sec_override)
        ((void *)(se_ulong)cred, tgt);
    pr_info("sehide: component exec -> %s domain (uid0 /data/adb) rc=%d\n",
            g_comp_ctx, rc);
}

int se_bprm_wrap(void *bprm)
{
    if (!g_orig_bprm)
        return -1;

    /*
     * v60：钩子唯一职责 = 首触安装触发器 + 纯透传。
     *
     * v53 时代这里做"orig 拒绝后判定 cred 是 su 则强制放行"，配合 live 的
     * domain->su transition 规则工作。v60 起 root 全部走 KP 核心 supercall
     * （commit_common_su，本机日志 rc=0 实证）+ avc_denied 兜底，不依赖
     * bprm 放行，也绝不写 live 规则 —— su 判定逻辑整体退役，exec 热路径
     * 上只剩透传。
     *
     * 首触安装机制保留（v54 设计）：event 上下文持 RCU 读锁不能睡眠，
     * 引擎主体（policydb_read/se_alloc）延到策略就绪后的第一个 exec，
     * 在真进程上下文里跑；连续失败 3 次封顶（四铁律 R4）。
     */
    if (!L.ok) {
        if (!se_cas32(&g_recal_busy, 0, 1))
            return g_orig_bprm(bprm);
        if (g_install_fails < 3) {
            se_install_engine();
            if (!L.ok) {
                g_install_fails++;
                pr_info("sehide: deferred install failed #%d\n", g_install_fails);
            }
        }
        g_recal_busy = 0;
        if (!L.ok)
            return g_orig_bprm(bprm);
    }

    /*
     * live 重载（KP 6.5s / 模块 /load）后副本换代自愈：指纹三读三比，
     * 变了才重标定，未变零开销。
     */
    if (!se_live_ok())
        se_recalibrate();

    {
        int rc;

        if (!g_cred_off) {
            g_cred_off = se_derive_cred_off(bprm);
            if (!g_cred_off) {
                if (g_diag_n < 4) {
                    g_diag_n++;
                    pr_info("sehide: v81 cred off derive failed (uid0)\n");
                }
                return g_orig_bprm(bprm);   /* 标定失败：透传，下次重试 */
            }
            g_diag_n = 4;
            pr_info("sehide: v81 cred off=%u\n", g_cred_off);
        }
        rc = g_orig_bprm(bprm);

        /* v90：orig 后组件域切轨（v84b 装机形态）；引擎未就绪/降级
         * 路径直接透传 */
        if (!g_degraded && L.ok)
            se_switch_to_su(bprm);
        return rc;
    }
}

/*
 * v60：卸载还原。在 security_hook_heads 链表里找仍指向 se_bprm_wrap 的槽，
 * 写回原函数（与安装同一 SE_FPHOOK 通道，回读验证）。幂等。
 * 影子页路径的还原由 se_shadow_remove_all() 负责（exit 先调它）。
 */
void se_uninstall_hook(void)
{
    se_u32 h;

    if (!g_hook_done || !p_hook_heads || !g_orig_bprm)
        return;

    for (h = 0; h < 512u; h++) {
        se_u64 node = 0;
        se_u32 guard = 0;

        if (se_kread(&node, (se_u8 *)(se_ulong)p_hook_heads + h * 8u, 8))
            break;
        if (!se_kptr_ok(node))
            continue;

        while (node && se_kptr_ok(node) && guard++ < 64u) {
            se_u32 fo = 0;

            if (se_find_fn_field(node, (se_u64)(se_ulong)se_bprm_wrap, &fo)) {
                void *slot = (void *)((se_u8 *)(se_ulong)node + fo);
                void *bak = 0;
                se_u64 chk = 0;

                SE_FPHOOK(slot, (void *)g_orig_bprm, &bak);
                if (se_kread(&chk, slot, 8) || chk != (se_u64)(se_ulong)g_orig_bprm)
                    pr_info("sehide: bprm restore failed h=%u off=%u\n", h, fo);
                else {
                    g_hook_done = 0;
                    pr_info("sehide: bprm hook restored h=%u off=%u\n", h, fo);
                }
                return;
            }
            {
                se_u64 next = 0;

                if (se_kread(&next, (se_u8 *)(se_ulong)node, 8))
                    break;
                node = next;
            }
        }
    }
}

/* 在结构体头 64 字节里找值为 target 的字段，避开 randomize_layout 的字段顺序 */
int se_find_fn_field(se_u64 base, se_u64 target, se_u32 *off_out)
{
    se_u32 fo;

    for (fo = 0; fo + 8u <= 64u; fo += 8u) {
        se_u64 v = 0;

        if (se_kread(&v, (se_u8 *)(se_ulong)base + fo, 8))
            return 0;
        if (v == target) {
            *off_out = fo;
            return 1;
        }
    }
    return 0;
}

/*
 * v54：event 期原子安装（原 se_install_hook）。
 *
 * 只保留数据面路径：
 *   ≤6.11  security_hook_heads 数据槽（fp_hook，实测存活）；
 *   6.12+  静态调用分发不经 security_hook_heads —— 原 __static_call_update
 *          路径是 text_poke 写指令（MKP 设备必死，v12 实证），整支删除；
 *          改用影子页改函数入口，对 static_call/直调全体调用方等效且
 *          不写任何内核指令。
 * KPM_EVENT 持 rcu_read_lock（module.c:691-704），本函数只做 fp_hook 数据槽
 * 写（hotpatch_nosync 原子序列，无 grace 等待）与影子页 stop_machine ——
 * 均不睡眠等待 grace，4.19 经典 RCU 读段内无自死锁面（对照 v44 的
 * synchronize_rcu 卡死）。
 */
int se_install_hook_early(void)
{
    void *bak = 0;
    se_u32 fo;

    if (g_hook_done)
        return 0;
    if (!p_bprm_sym)
        return -1;

    g_orig_bprm = (int (*)(void *))p_bprm_sym;

    /* ≤ 6.11：security_hook_heads 每钩一个 hlist_head，节点即 security_hook_list */
    if (p_hook_heads) {
        se_u32 h;

        for (h = 0; h < 512u; h++) {
            se_u64 node = 0;
            se_u32 guard = 0;

            if (se_kread(&node, (se_u8 *)(se_ulong)p_hook_heads + h * 8u, 8))
                break;
            if (!se_kptr_ok(node))
                continue;

            while (node && se_kptr_ok(node) && guard++ < 64u) {
                if (se_find_fn_field(node, (se_u64)p_bprm_sym, &fo)) {
                    se_u64 chk = 0;

                    SE_FPHOOK((void *)((se_u8 *)(se_ulong)node + fo),
                            (void *)se_bprm_wrap, &bak);
                    if (se_kread(&chk, (se_u8 *)(se_ulong)node + fo, 8) ||
                        chk != (se_u64)(se_ulong)se_bprm_wrap) {
                        pr_info("sehide: hook write not applied h=%u off=%u\n", h, fo);
                        continue;
                    }
                    g_hook_done = 1;
                    pr_info("sehide: hook installed via list h=%u off=%u\n", h, fo);
                    return 0;
                }
                {
                    se_u64 next = 0;

                    if (se_kread(&next, (se_u8 *)(se_ulong)node, 8))
                        break;
                    node = next;
                }
            }
        }
    }

    /* 6.12+ / hook_heads 不可用：影子页（mkpms 同类，零内核指令写入） */
    if (se_shadow_ready()) {
        void *sbackup = 0;

        if (!se_shadow_hook((void *)(se_ulong)p_bprm_sym,
                            (void *)se_bprm_wrap, &sbackup)) {
            g_orig_bprm = (int (*)(void *))sbackup;   /* 影子页内续体 */
            g_hook_done = 1;
            pr_info("sehide: hook installed via shadow page\n");
            return 0;
        }
        pr_info("sehide: shadow hook fallback failed\n");
    } else {
        pr_info("sehide: hook unavailable (no list, shadow not ready)\n");
    }

    return -2;
}
