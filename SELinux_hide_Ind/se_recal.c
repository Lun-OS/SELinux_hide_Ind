/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_recal：被动指纹自愈 */
#include "sehide.h"

/* 策略重载自愈 */
int g_degraded;
int g_eco_loaded;   /* 生态重载已发生：exec 路径交接标记 */
volatile int g_recal_busy;
/* 决策面（avc_denied，RCU 读临界区，禁睡眠）只置旗，由门/bprm
 * （进程上下文）代跑——自愈/探测晚一个周期。普通整数写，RCU 内合法。
 * 代跑顺序：自愈优先（recalibrate 的 light 路径本就带 se_comp_upgrade），
 * 探测旗单独处理。 */
volatile int g_recal_pending;
volatile int g_comp_pending;
se_u32 g_recal_total;
int se_live_ok(void);
void se_recalibrate(void);

/* ---------------- 策略重载自愈 ---------------- */

/*
 * live 三锚点校验：container 指针、len、policyvers 三读三比。
 * 任一不匹配说明 live 被重载（security_load_policy 整体重建
 * policydb，引擎写入全部随旧策略消失），需要重标定。
 * 局限：len+vers 与旧策略完全相同的重载会漏检。
 */
int se_live_ok(void)
{
    se_u64 container = 0;

    if (!p_selinux_state || !L.ok)
        return 0;
    if (se_kread(&container, (se_u8 *)(se_ulong)p_selinux_state + L.slot * 8u, 8))
        return 0;
    if ((void *)(se_ulong)container != L.container)
        return 0;
    /* len(u64@lenoff) 低 32 位 + vers(u32@lenoff+8) 合并单次读 */
    {
        se_u8 lv[12];

        if (se_kread(lv, (se_u8 *)L.pdb + L.lenoff, 12))
            return 0;
        if (se_rd32(lv) != L.bin_len)
            return 0;
        return se_rd32(lv + 8) == L.vers;
    }
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
 * aarch64 CAS，内联汇编写死（LDXR/STXR）。
 * 机制约束：不能用 __sync_bool_compare_and_swap——GCC 在无 LSE 目标上
 * 会编成对 libgcc 助手 __aarch64_cas4_sync 的调用，内核无此符号，
 * KP 加载器按 unknown symbol 拒载整个模块。返回 1=已换成 newv。
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
 * perm/lenoff/slot/pdboff/symtab/avtab 是内核编译期属性（struct policydb
 * 字段位置），换策略文件不变；重载变的只有内容 —— 二进制长度、vers、
 * su 的 type/sid、规则。所以重载后只需：按新 blob 更新锚点值 ->
 * se_locate 在已知偏移上重验 -> 重解析 su type -> 重建副本。
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

    /* 组件域持续重判：生态（KP/apd）把 magisk 类型注入 live 的时刻晚于
     * install 标定，且 KP 的 in-place 注入无指纹变化——升级只能靠重标定
     * 路径与决策面置旗探测（见 se_comp_upgrade）。 */
    se_comp_upgrade();

    if (p_secctx_to_sid)
        ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
            ("u:r:su:s0", sizeof("u:r:su:s0") - 1u, &sid);
    if (!sid)
        se_ctx_to_sid("u:r:su:s0", &sid);
    g_su_sid = sid;

    {
        se_u32 csid = 0;

        if (p_secctx_to_sid && g_comp_ctx)
            ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                (g_comp_ctx, (se_u32)strlen(g_comp_ctx), &csid);
        if (!csid && g_comp_ctx)
            se_ctx_to_sid(g_comp_ctx, &csid);
        g_comp_sid = csid ? csid : sid;
    }

    if (se_decision_ready()) {
        se_decision_recalibrate();  /* 白名单随重载刷新 */
        pr_info("sehide: recal light — decision-plane flip active, live clean\n");
    } else {
        pr_info("sehide: recal light — decision-plane OFF, live stays stock\n");
    }

    /* 副本换代全部交给 se_build_copy：retire-swap、旧副本延迟一代释放，
     * 这里绝不能先析构旧副本（渲染器无锁读指针，UAF）。 */
    rc = se_build_copy();
    if (rc) {
        pr_info("sehide: light bcopy rc=%d\n", rc);
        goto out;
    }

    /* sid 重算已前移（决策面判定用新 sid），此处不再重复。 */
    rc = 0;
out:
    se_free(b);
    return rc;
}

/* 全量回退：偏移失效时才走（含差分标定与探针） */
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

    /* 全量路径同样持续重判组件域（magisk 出现即升级） */
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

    if (p_secctx_to_sid)
        ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
            ("u:r:su:s0", sizeof("u:r:su:s0") - 1u, &sid);
    if (!sid)
        se_ctx_to_sid("u:r:su:s0", &sid);
    g_su_sid = sid;

    {
        se_u32 csid = 0;

        if (p_secctx_to_sid && g_comp_ctx)
            ((int (*)(const char *, se_u32, se_u32 *))p_secctx_to_sid)
                (g_comp_ctx, (se_u32)strlen(g_comp_ctx), &csid);
        if (!csid && g_comp_ctx)
            se_ctx_to_sid(g_comp_ctx, &csid);
        g_comp_sid = csid ? csid : sid;
    }

    /* 同 light —— live 恒出厂。 */
    if (se_decision_ready()) {
        se_decision_recalibrate();  /* 白名单随重载刷新 */
        pr_info("sehide: recal full — decision-plane flip active, live clean\n");
    } else {
        pr_info("sehide: recal full — decision-plane OFF, live stays stock\n");
    }
    se_derive_layout();

    rc = se_build_copy();
    if (rc)
        return rc;

    /* sid 重算已前移（决策面判定用新 sid），此处不再重复。 */
    return 0;
}

/*
 * 重载后刷内核 avc 缓存。
 *
 * 为什么必须刷：内核 avc 快路径命中的节点只在建节点那一刻读一次
 * permissive_map，之后 avc_lookup 不再重估；重载窗口内建立的节点把
 * "无位"结果缓存下来，引擎重写位后这些节点依旧陈旧。内核自己免疫
 * 是因为 security_load_policy 末尾必调 avc_ss_reset（4.19
 * services.c:2235）；我们只补位、必须同样补刷。
 *
 * 调用方式按版本分流（4.19/5.4/5.10/5.15/6.1/6.2/6.3 双参
 * (avc, seqno)；v6.4 起单参 (seqno)）：
 *   avc 指针传 &selinux_avc 全局实例（kallsyms 可查，各版均在），
 *   不依赖 selinux_state 布局；seqno 传 0（内核 setenforce 路径先例，
 *   4.19 selinuxfs.c:179），只清缓存不推 notif。
 *
 * avc_ss_reset 内部 avc_flush 用 call_rcu 异步释放，不
 * synchronize_rcu——但绝不能从 KP event 线程（RCU 读临界区）调。
 * 本函数的调用点只有重标定路径，入口是两道门与 bprm 钩子，全部是
 * 进程上下文，可睡眠，安全。
 */
void se_avc_flush_after_recal(void)
{
    if (!p_avc_reset)
        return;
    if (kver >= SE_KVER_64)
        ((int (*)(se_u32))p_avc_reset)(0);
    else if (p_avc_struct)
        ((int (*)(void *, se_u32))p_avc_reset)((void *)(se_ulong)p_avc_struct, 0);
}

/* 组件域持续重判（幂等）。KP/apd 的 sepolicy 注入走 KP 的 in-place
 * 机制（selinux_sepolicy.c verbatim：刻意不走 security_load_policy、
 * 无指纹变化）——magisk 类型进 live 的时刻晚于 install 标定，且
 * se_live_ok 三锚点对原地改写全部无感 → 原依赖"指纹失效"触发的升级
 * 永不运行。现由决策面置旗（g_comp_pending）与重标定路径触发。 */
int se_comp_upgrade(void)
{
    int upgraded = 0;

    if (strcmp(g_comp_ctx, "u:r:magisk:s0") != 0) {
        se_u32 mt = 0;

        if (se_ctx_type("u:r:magisk:s0", &mt) == 0 && mt) {
            g_comp_type = mt;
            g_comp_ctx = "u:r:magisk:s0";
            g_comp_tname = "magisk";
            pr_info("sehide: comp domain upgraded to magisk type=%u\n", mt);
            upgraded = 1;
        }
    }
    if (!g_comp_type || (strcmp(g_comp_ctx, "u:r:su:s0") == 0))
        g_comp_type = L.su_type;
    return upgraded;
}

void se_recalibrate(void)
{
    int rc;

    if (g_degraded)
        return;
    if (!L.ok)
        return;   /* 未安装阶段归 se_install_engine（bprm 首触）管，不进重标定 */
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
     * 自洽断言 + 总量上限：刚重写完指纹必须立刻通过，通不过说明校验
     * 逻辑自身有 bug，不拦住就是每次 exec 一遍全量标定。健康系统整机
     * 重载 0~3 次，超过 8 次视为风暴，一并降级。降级 = 三入口回落内核
     * 原函数，卡顿停止、系统保持健康。
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
         * 第一次重标定成功 = 生态的重载发生过（APatch apd 的 sepolicy
         * 注入等）。此后组件域由生态自理（magisk 域/规则集/transition
         * 已随重载进 live），KPM 在重载后的世界里不做任何主动动作。
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

/* ---------------- 旗排水 worker ----------------
 * 门/bprm 写入路径只清旗；recal/build_copy/avc flush 等重活全部移到
 * 本线程执行，避免重活落在探针/普通写入调用内（时序毛刺根因）。
 * 符号缺失时 worker 不启动，门内原地排水回退（行为同 1.1.1）。 */

static void *g_recal_task;
int g_recal_worker_ready;
static int g_recal_pin_done;   /* start 期绑核已成功（fn 不再重复尝试） */
static int g_patrol_dead;      /* uptime 超阈值后周期巡检永久停止 */

/*
 * kthread 绑核：把模块自有 kthread 钉在单核，调度干扰集中到该核，
 * 不再随机落在任意 CPU 抢占透传链（+1145us 离群根因）。
 * 目标 = CPU7（8 核机型的 prime 核惯例）；不在位（4 核/命名差异）
 * 则不绑核，保持旧行为。cpumask 按位图传参：栈上 256B 零填充，
 * 覆盖 ≤2048 CPU 的位图宽度，读取越界面为零。
 */
int se_worker_pin(const char *tag, void *t)
{
    unsigned long mask[32];
    int rc;

    if (!t || !p_set_cpus_allowed_ptr)
        return -1;
    memset(mask, 0, sizeof(mask));
    mask[7 / (sizeof(unsigned long) * 8u)] =
        1ul << (7u % (sizeof(unsigned long) * 8u));
    rc = ((int (*)(void *, const void *))p_set_cpus_allowed_ptr)(t, mask);
    pr_info("sehide: %s pinned to cpu7 rc=%d\n", tag, rc);
    return rc;
}

static int se_recal_worker_fn(void *arg)
{
    unsigned int tick = 0;
    int pin_rc;
    unsigned int pin_try = 0;
    unsigned int status_try = 0;

    /* 自身 task_struct 取自 g_recal_task（start 在 wake 前已赋值，
     * 首次循环必然可见）。绑核在 create 期可能撞 CPU7 尚未 online
     * （4.19 core.c:1083 唯一 EINVAL 路径：cpumask_any_and
     * (cpu_online_mask) 无交集——启动期逐核上线晚于 sehide_init），
     * 此处周期重试直到成功；30 次（~30s）封顶后放弃。 */
    /* start 期已成功绑核则跳过首循环补试（避免同一次启动打印
     * 两条 pinned 日志）；未成功才补试，之后周期重试 30 次封顶。 */
    pin_rc = g_recal_pin_done ? 0 :
             (g_recal_task ? se_worker_pin("recal worker", g_recal_task) : -1);
    while (!((int (*)(void))p_kthread_should_stop)()) {
        int busy = 0;

        ++tick;
        if (pin_rc && pin_try < 30u && (tick & 0x7fu) == 0u) {
            pin_try++;
            pin_rc = se_worker_pin("recal worker", g_recal_task);
        }

        if (g_recal_pending) {
            g_recal_pending = 0;
            se_recalibrate();
            busy = 1;
        }
        if (g_comp_pending) {
            g_comp_pending = 0;
            se_comp_upgrade();
            busy = 1;
        }
        /* 静默监控：透传链/deny 路径已无任何探测与指纹检查，
         * 指纹自愈与组件域升级由本线程周期巡检完成（进程上下文，
         * 可睡眠；~512 个空闲轮 × 8ms ≈ 4.1s 一次）。旗置位事件
         * （决策面/门）仍即时响应，巡检只兜底无事件窗口。 */
        /* 周期巡检仅限启动初期：uptime 超过 60s 后入口/指纹/组件域
         * 均已稳定，事件驱动路径（旗置位）足以覆盖后续状态变化，
         * 周期扫描停止以消除常驻线程的持续内核读与日志噪声。
         * 归属说明：巡检是后台自检线程，不属于特权/非特权任一请求
         * 路径；停用后两条路径的行为与时序均不变。 */
        if (!g_patrol_dead && (tick & 0x1ffu) == 0u) {
            if (p_ktime_get_seconds &&
                ((long long (*)(void))p_ktime_get_seconds)() >= 60) {
                g_patrol_dead = 1;
                pr_info("sehide: periodic patrol disabled (uptime > 60s)\n");
            } else if (L.ok && !g_degraded) {
            /* 入口在岗巡检 + 自愈（被还原 = 决策面失明，su 无兜底全灭）。
             * 仅漂移/自愈/失败才打印。 */
            if (se_decision_enabled()) {
                int erc = se_decision_entry_check();
                static int edbg_n;

                if (erc && edbg_n < 8u) {
                    edbg_n++;
                    pr_info("sehide: entry check rc=%d (1=healed, <0=fail)\n",
                            erc);
                }
            }
            if (!se_live_ok())
                se_recalibrate();
            else
                se_comp_upgrade();
            }
        }
        /* status freeze 延迟补装：selinuxfs 挂载可能晚于首个 exec
         * （实测启动早期 3.7s 内核态读 enforce 失败）；安装本身只做
         * 文件读 + 数据槽写，进程上下文安全。巡检节拍 ~4.1s，5 次封顶。 */
        if (status_try < 5u && (tick & 0x1ffu) == 0u && L.ok &&
            !se_status_ready()) {
            status_try++;
            /* -20 = 内核 read 原语不支持 selinuxfs（确定性）——立即停
             * 止重试，避免每 ~4s 重复打印内核 WARN；open 失败(-2)才是
             * 挂载时序问题，保留重试。 */
            if (se_status_install() == -20)
                status_try = 99u;
        }
        if (!busy)
            ((void (*)(se_ulong))p_msleep_interruptible)(8);
    }
    return 0;
}

int se_recal_worker_start(void)
{
    void *t;

    if (g_recal_task)
        return 0;
    if (!p_kthread_create_on_node || !p_wake_up_process ||
        !p_kthread_should_stop || !p_msleep_interruptible || !p_kthread_stop)
        return -1;
    t = ((void *(*)(int (*)(void *), void *, int, const char *, ...))
         p_kthread_create_on_node)(se_recal_worker_fn, 0, -1, "sehide_recal");
    if (!t || (se_ulong)t >= (se_ulong)-4095L)
        return -1;
    g_recal_task = t;
    g_recal_worker_ready = 1;
    /* start 期绑核；成功登记 g_recal_pin_done，fn 首循环不再重复
     * ）。失败留给 fn 自重试（CPU7 未 online 场景）。 */
    if (!se_worker_pin("recal worker", t))
        g_recal_pin_done = 1;
    ((int (*)(void *))p_wake_up_process)(t);
    pr_info("sehide: recal worker started\n");
    return 0;
}

void se_recal_worker_stop(void)
{
    if (!g_recal_worker_ready || !g_recal_task)
        return;
    ((int (*)(void *))p_kthread_stop)(g_recal_task);
    g_recal_task = 0;
    g_recal_worker_ready = 0;
    pr_info("sehide: recal worker stopped\n");
}
