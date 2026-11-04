/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_recal：被动指纹自愈 - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"

/* 策略重载自愈（定义在 se_calibrate 之后，见那段注释） */
int g_degraded;
int g_eco_loaded;   /* v87：生态重载已发生 */
volatile int g_recal_busy;
se_u32 g_recal_total;
int se_live_ok(void);
void se_recalibrate(void);

/* ---------------- 策略重载自愈 ---------------- */

/*
 * 引擎装上之后策略还可能被再装几次 —— 这不是假设，是本机的实测时间线：
 *   [ 4.420] sehide: calib ok ... len=1206692     （early-init 时标定的那份）
 *   [ 6.510] KP: captured clean policy blob (len 1206992)
 *   [ 6.536] KP: loaded policy len 1220691 carries root markers
 *   [ 6.609] SELinux: Converting 923 SID table entries            ← 整体重载
 * security_load_policy 会整体重建 policydb（4.19 是往 ss->policydb 原地拷贝，
 * 5.10+ 是换掉 state->policy 指针），引擎写进 live 的 permissive 位、inbound
 * 规则、transition 规则全部随旧策略消失，g_su_sid 也随新策略重新编号。
 * 上一版"engine up 但不生效"的直接原因就在这里：4.4s 装的东西 6.5s 就没了。
 *
 * 处理（架构不变，不加任何新钩子）：在这个引擎本来就有的三个入口
 * （/access、/context 两道 gate + bprm 钩子）头部做一次廉价校验 ——
 * container 指针、len、policyvers 三读三比。任一不匹配说明策略换了，
 * 重跑标定并重写 live。内核重载时自己会 avc_ss_reset
 * （security_load_policy 内部），所以重写后的位第一次判定就能被看到。
 *
 * 局限要说明：如果某次重载后的策略 len 和 vers 与旧策略完全相同，这里
 * 会漏检（三个锚点都撞上）。本机实测的每次重载 len 都不同；出现那种
 * 重载时需要再加锚点（比如 symtab 里 classes 的 nprim）。
 */
int se_live_ok(void)
{
    se_u64 container = 0;
    se_u32 len = 0, pv = 0;

    if (!p_selinux_state || !L.ok)
        return 0;
    if (se_kread(&container, (se_u8 *)(se_ulong)p_selinux_state + L.slot * 8u, 8))
        return 0;
    if ((void *)(se_ulong)container != L.container)
        return 0;
    if (se_kread(&len, (se_u8 *)L.pdb + L.lenoff, 4))
        return 0;
    if (len != L.bin_len)
        return 0;
    if (se_kread(&pv, (se_u8 *)L.pdb + L.lenoff + 8u, 4))
        return 0;
    return pv == L.vers;
}

/*
 * 重标定 + 重写 live。三道入口都可能并发进来，CAS 保证只有一个在跑；
 * 没抢到的那个用旧数据答这一次（4.19 是原地重载、内存有效，答案最多
 * 陈旧一拍；5.10+ 指针换了，se_kread 是 nofault 的，只会读到失败）。
 *
 * 失败就降级：g_degraded 置位后三道入口直接回落内核原函数 —— 宁可
 * 没有隐藏，也不能拿着悬空指针算判定。
 */
/*
 * aarch64 CAS，内联汇编写死。
 *
 * 血的教训（13:33 那次启动）：用 __sync_bool_compare_and_swap，GCC 在无 LSE
 * 的目标上把它编成对 libgcc 助手 __aarch64_cas4_sync 的调用，内核里没有这个
 * 符号，KP 加载器按 unknown symbol 把整个模块拒了（rc=-2），一行日志都没有。
 * KPM 只跑在 aarch64 上，直接 LDXR/STXR，不引入任何运行期符号。
 * 返回 1 = 已换成 newv；0 = 别人先改了。
 */
int se_cas32(volatile int *p, int oldv, int newv)
{
    int rd, st;

    __asm__ __volatile__(
        "1: ldxr    %w0, %2\n"
        "   cmp     %w0, %w3\n"
        "   b.ne    2f\n"
        "   stxr    %w1, %w4, %2\n"
        "   cbnz    %w1, 1b\n"
        "2:\n"
        : "=&r"(rd), "=&r"(st), "+Q"(*p)
        : "Ir"(oldv), "r"(newv)
        : "cc", "memory");
    return rd == oldv;
}

/*
 * 轻量重载自愈：只重解析"内容"，不重推"结构"。
 *
 * 方法论（v50 反思后定死）：perm/lenoff/slot/pdboff/symtab/avtab 这些偏移
 * 是内核编译期属性（struct policydb 的字段位置），换一份策略文件不会变；
 * 重载变的只有内容 —— 二进制长度、vers、su 的 type 值、sid、规则。
 * 所以重载后只需：按新 blob 更新锚点值 -> se_locate 在已知偏移上重验 ->
 * 重解析 su type -> 重写位与规则 -> 重建副本 -> 重解析 sid。
 * 不跑差分标定、不跑探针（探针要 inline hook 内核文本，绝不该反复做）。
 * se_locate 失败（偏移真的对不上）才回退全量。
 */
int se_recalibrate_light(void)
{
    void *b = 0;
    se_ulong blen = 0;
    struct bin_hdr h;
    se_u32 sid = 0;
    int rc;

    rc = se_read_policy(&b, &blen);
    if (rc)
        return rc;

    rc = se_parse_hdr((se_u8 *)b, (se_u32)blen, &h);
    if (rc)
        goto out;

    L.bin_len = (se_u32)blen;
    L.vers = h.vers;
    L.sym_num = h.sym_num;

    /* 已知偏移上的锚点重验：len == 新 blob 长度、vers == 新头（见 se_scan_pdb） */
    rc = se_locate();
    if (rc) {
        pr_info("sehide: light locate rc=%d\n", rc);
        goto out;
    }

    rc = se_ctx_type("u:r:su:s0", &L.su_type);
    if (rc) {
        pr_info("sehide: light ctx rc=%d\n", rc);
        goto out;
    }

    /*
     * v85b：组件域持续重判。magisk 类型进 live 的时刻（KP/apd 的
     * sepolicy 注入，装机实证 ~4s）晚于 install 标定（~2.6s）——install
     * 时一次判定必然回退 su（fp_br29: comp domain=u:r:su:s0 实锤）。
     * live 重载（指纹失效 → 本函数）时重新查 magisk：出现即升级，
     * 三件套/副本盖章/切域随 g_comp_* 自动跟随。su 生态（4.19）live
     * 永无 magisk → 永不升级，路径不变。
     */
    if (strcmp(g_comp_ctx, "u:r:magisk:s0") != 0) {
        se_u32 mt = 0;

        if (se_ctx_type("u:r:magisk:s0", &mt) == 0 && mt) {
            g_comp_type = mt;
            g_comp_ctx = "u:r:magisk:s0";
            g_comp_tname = "magisk";
            pr_info("sehide: comp domain upgraded to magisk type=%u\n", mt);
        }
    }
    if (!g_comp_type || (strcmp(g_comp_ctx, "u:r:su:s0") == 0))
        g_comp_type = L.su_type;

    /* v65（LunSU ksu_se_rebuild 同款）：live 重载抹掉了我们的写入，按
     * 安装顺序重写。v88：inbound+permissive+len 维护一体（se_apply_trio）。 */
    se_apply_trio(g_comp_type ? g_comp_type : L.su_type);

    /* v70：副本 live 锚定（ksu_se_rebuild 同款）。/load 劫持下 live 无
     * 外部规则，此路径只在 live 真实变化时触发；模块规则由 se_absorb_blob
     * 阶段 E 并入副本，重标定若在模块装载前发生，组件下一次 /load 的
     * 幂等合并自愈（blob 是全量补丁）。
     * 换代全部交给 se_build_copy：retire-swap、旧副本延迟一代释放，
     * 这里绝不能先析构旧副本（渲染器无锁读指针，UAF）。 */
    rc = se_build_copy();
    if (rc) {
        pr_info("sehide: light bcopy rc=%d\n", rc);
        goto out;
    }

    if (p_secctx_to_sid)
        ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
            ("u:r:su:s0", sizeof("u:r:su:s0") - 1u, &sid);
    if (!sid)
        se_ctx_to_sid("u:r:su:s0", &sid);
    g_su_sid = sid;

    /* v85：组件域 sid 同步重标定（切域写入值，KP 生态=magisk sid） */
    {
        se_u32 csid = 0;

        if (p_secctx_to_sid && g_comp_ctx)
            ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                (g_comp_ctx, (se_u32)strlen(g_comp_ctx), &csid);
        if (!csid && g_comp_ctx)
            se_ctx_to_sid(g_comp_ctx, &csid);
        g_comp_sid = csid ? csid : sid;
    }
    rc = 0;
out:
    se_free(b);
    return rc;
}

/* 全量回退：偏移失效时才走（v49 之前的整套，含差分标定与探针） */
int se_recalibrate_full(void)
{
    se_u32 sid = 0;
    int rc;

    /* 旧副本不在这里析构：se_build_copy 内部 retire-swap、延迟一代释放 */
    rc = se_calibrate();
    if (rc)
        return rc;

    rc = se_ctx_type("u:r:su:s0", &L.su_type);
    if (rc)
        return rc;

    /* v85b：全量路径同样持续重判组件域（magisk 出现即升级） */
    if (strcmp(g_comp_ctx, "u:r:magisk:s0") != 0) {
        se_u32 mt = 0;

        if (se_ctx_type("u:r:magisk:s0", &mt) == 0 && mt) {
            g_comp_type = mt;
            g_comp_ctx = "u:r:magisk:s0";
            g_comp_tname = "magisk";
            pr_info("sehide: comp domain upgraded to magisk type=%u\n", mt);
        }
    }
    if (!g_comp_type || (strcmp(g_comp_ctx, "u:r:su:s0") == 0))
        g_comp_type = L.su_type;

    /* v65（LunSU 同款）：full 重标定同样重写 live 的组件域标记。
     * v88：len 维护并入 trio。 */
    se_apply_trio(g_comp_type ? g_comp_type : L.su_type);
    se_derive_layout();

    rc = se_build_copy();
    if (rc)
        return rc;

    if (p_secctx_to_sid)
        ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
            ("u:r:su:s0", sizeof("u:r:su:s0") - 1u, &sid);
    if (!sid)
        se_ctx_to_sid("u:r:su:s0", &sid);
    g_su_sid = sid;

    /* v85：组件域 sid 重标定 */
    {
        se_u32 csid = 0;

        if (p_secctx_to_sid && g_comp_ctx)
            ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                (g_comp_ctx, (se_u32)strlen(g_comp_ctx), &csid);
        if (!csid && g_comp_ctx)
            se_ctx_to_sid(g_comp_ctx, &csid);
        g_comp_sid = csid ? csid : sid;
    }
    return 0;
}

/*
 * 重载后刷内核 avc 缓存（v52 修复，规律来自多版本源码核对，非任何设备）。
 *
 * 为什么必须刷：内核 avc 快路径命中的节点只在建节点那一刻读一次
 * permissive_map，之后 avc_lookup（1058 行）不再重估；重载在 6.4~6.8s
 * 把 permissive 位抹掉，此窗口内建立的节点把"无位"结果缓存下来，
 * 引擎 6.5/6.8s 重写位后这些节点依旧陈旧 —— 实测 40s 后 dyntransition
 * 仍打 permissive=0，就是这个洞。内核自己免疫是因为 security_load_policy
 * 末尾必调 avc_ss_reset（4.19 services.c:2235）；我们只补位、必须同样补刷。
 *
 * 调用方式按版本分流（4.19/5.4/5.10/5.15/6.1/6.2/6.3 双参
 * (avc, seqno)；v6.4 起单参 (seqno) —— v-fix 复审 20261104：v6.4 tag
 * 三处源码一致（avc_ss.h/services.c/selinuxfs.c），旧注 6.5 属误判）：
 *   avc 指针传 &selinux_avc 全局实例（kallsyms 可查，各版均在），
 *   不依赖 selinux_state 布局；seqno 传 0（内核 setenforce 路径先例，
 *   4.19 selinuxfs.c:179），只清缓存不推 notif。
 *
 * 安全性：avc_ss_reset 内部 avc_flush 用 call_rcu 异步释放（4.19~6.12
 * 未变），不 synchronize_rcu；但 v44 实测过 —— 绝不能从 KP event 线程
 * （RCU 读临界区）调。本函数的调用点只有重标定路径，入口是两道门与
 * bprm 钩子，全部是进程上下文，可睡眠，安全。
 */
void se_avc_flush_after_recal(void)
{
    if (!p_avc_reset)
        return;
    if (kver >= VERSION(6, 4, 0))
        ((int (*)(se_u32))p_avc_reset)(0);
    else if (p_avc_struct)
        ((int (*)(void *, se_u32))p_avc_reset)((void *)(se_ulong)p_avc_struct, 0);
}

void se_recalibrate(void)
{
    int rc;

    if (g_degraded)
        return;
    if (!L.ok)
        return;   /* v54：未安装阶段归 se_install_engine（bprm 首触）管，不进重标定 */
    if (!se_cas32(&g_recal_busy, 0, 1))
        return;

    /* 抢到锁再核一次：调用方看到指纹失效到进锁之间可能已被别处修好 */
    if (se_live_ok()) {
        g_recal_busy = 0;
        return;
    }

    rc = se_recalibrate_light();
    if (rc) {
        pr_info("sehide: light recalibrate rc=%d, full fallback\n", rc);
        rc = se_recalibrate_full();
    }
    if (rc)
        goto bad;

    /* 位与规则重写完，立刻作废重载窗口里按"无位"缓存的 avc 节点 */
    se_avc_flush_after_recal();

    /*
     * 自洽断言 + 总量上限 —— 这两道保险是 712 次重标定风暴换来的：
     * 刚重写完指纹必须立刻通过，通不过说明校验逻辑自身有 bug（比如
     * v49 把 policyvers 读在 lenoff+4），不拦住就是每次 exec 一遍全量
     * 标定。健康系统整机重载 0~3 次，超过 8 次视为风暴，一并降级。
     * 降级 = 三入口回落内核原函数，卡顿停止、系统保持健康。
     */
    if (!se_live_ok()) {
        g_degraded = 1;
        pr_info("sehide: fingerprint self-check failed after recalibrate, degraded\n");
    } else if (++g_recal_total > 8) {
        g_degraded = 1;
        pr_info("sehide: %u recalibrations, degraded (reload storm)\n",
                g_recal_total);
    }

    g_recal_busy = 0;
    if (!g_degraded) {
        /*
         * v87：第一次重标定成功 = 生态的重载发生过（APatch apd 的
         * sepolicy 注入等）。此后 exec 路径零干预：切域关闭，组件域由
         * 生态自理（magisk 域/规则集/transition 已随重载进 live），
         * 三件套/副本盖章对象已由本函数的 comp 重判跟随生态域。
         * 天生兼容：KPM 在重载后的世界里不做任何主动动作。
         */
        if (!g_eco_loaded) {
            g_eco_loaded = 1;
            pr_info("sehide: ecosystem reload observed, exec path hands off\n");
        }
        pr_info("sehide: recalibrated after policy reload su=%u inbound ok=%u skip=%u\n",
                L.su_type, L.rules_ok, L.rules_fail);
    }
    return;
bad:
    g_degraded = 1;
    g_recal_busy = 0;
    pr_info("sehide: recalibrate failed rc=%d, gates fallback to kernel\n", rc);
}
