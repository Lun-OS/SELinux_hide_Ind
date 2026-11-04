/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_gate：问门（/access /context）+ 写门（/load） - 自 v52 单文件纯搬移切分（sehide.h 为共享头） */
#include "sehide.h"

/*
 * v58 门路由收紧（elish 实测实锤：DirtySepolicy raw access protocol 暴露）。
 *
 * 旧判据 uid<10000：system(1000)/shell(2000) 等域落入门内——而门在移植时
 * 丢失了 LKM 原版的权限检查（selinux_hide.c my_write_access 进门第一步
 * avc_has_perm(current_sid, security, security, COMPUTE_AV/CHECK_CONTEXT)，
 * 失败即 EACCES 与出厂一致）——出厂策略下这些域无该权限，本应被原版
 * 权限门挡死，结果被我们直接喂了副本答案 → 检测 SDK 发现自己能 raw 访问
 * selinuxfs 查询协议并拿到 su 判定/transition → Dirty 暴露。
 *
 * 新判据：uid==0（KP 授权的 root 会话）才答副本；其余一律透传内核原版
 * ——原版自己的权限门按出厂策略执行，行为与未接管逐字一致。
 * p_kuid 绑定失败时 fail-closed（全部透传），绝不能退化为"服务所有人"。
 */
int se_gate_privileged(void)
{
    if (!p_kuid)
        return 0;
    /* v62：特权 = uid<10000（root/system/shell，用户裁定定义）。
     * 特权读写执行全部劫持走副本，非特权（uid>=10000）透传出厂。 */
    return ((se_u32 (*)(void))p_kuid)() < 10000u;
}

/* 内核原函数指针：渲染失败时回落，绝不让调用方拿到错误。
 * 必须在两个写处理器之前声明 —— 上一版审计把声明挪到了函数后面，
 * 使用先于声明，直接编译不过（这正是要防的低级错误）。 */
void *g_orig_access_write;
void *g_orig_context_write;

void *g_orig_load_write;

/*
 * /access 的写处理器：输入 "scontext tcontext tclass"，输出与 4.19
 * selinuxfs.c:864-869 完全一致的六字段格式（详见函数体内注释）。
 */
long se_access_write(void *file, char *ubuf, se_ulong size)
{
    char kbuf[512];
    char out[160];
    char *sc, *tc, *cs;
    se_u8 sctx[SE_CTX_BUF], tctx[SE_CTX_BUF];
    se_u32 cls = 0, allowed = 0, flags = 0;
    int n, len;

    (void)file;

    /* 策略可能在安装之后被重载（见 se_live_ok），先保证 live 是新的 */
    if (!se_live_ok())
        se_recalibrate();
    if (g_degraded)
        goto fallback;

    /*
     * v68：恢复 LunSU 门分流（v67 全 uid 答快照是自创偏离，撤）。
     * 特权（uid<10000）答出厂+su 副本；非特权直通内核原版对 live 求值
     * ——live 现在只有出厂+su 三件套+空类型声明（规则全丢弃），直通
     * 答案与出厂一致（LunSU ksu_access_write 同款）。
     */
    if (!se_gate_privileged())
        goto fallback;

    if (size == 0 || size >= sizeof(kbuf))
        return -22;   /* 出厂同款：入参畸形按 EINVAL 返回 */
    n = SE_STRNCPY_USER(kbuf, ubuf, sizeof(kbuf) - 1);
    if (n < 0)
        goto fallback;
    kbuf[n] = 0;

    /*
     * v66：出厂 EINVAL 对齐。出厂 sel_write_access 对解析失败/类名未知/
     * 上下文无效一律返回 security_* 原样错误（EINVAL=-22）——检测报告的
     * 控制组就是这个语义（malformed=errno22，stock 有效上下文=errno13）。
     * 此前这些失败一律 fail-open 回落内核原版，live 上被 LSP 注入的类型
     * （magisk/lsposed_file）在快照查不到 → 回落 → live 答 allowed → 判脏。
     * 现改为直接返回 -22：与"该类型在出厂策略中不存在"的出厂行为逐字一致。
     * 只有快照上求值失败（类型存在但渲染出错，init/system_server 自检
     * 路径）才保留 fail-open 回落。
     */
    if (se_parse3(kbuf, &sc, &tc, &cs))
        return -22;
    if (se_class_val(cs, &cls))
        return -22;
    if (se_parse_ctx(sc, sctx) || se_parse_ctx(tc, tctx))
        return -22;
    if (se_compute_av(sctx, tctx, cls, &allowed, &flags))
        goto fallback;

    {
        struct se_out o;

        o.buf = out;
        o.cap = sizeof(out);
        o.n = 0;

        /*
         * 必须严格照抄 4.19 selinuxfs.c:864-869 的格式：
         *   scnprintf(buf, ..., "%x %x %x %x %u %x",
         *             avd.allowed, 0xffffffff, avd.auditallow,
         *             avd.auditdeny, avd.seqno, avd.flags);
         * 第二项是写死的 0xffffffff，第五项是十进制。
         * libselinux 那边是 sscanf(buf, "%x %x %x %x %u %x")，
         * 以前输出成 "allowed=... auditallow=..."，它一个字段都解析不到，
         * system_server 的每次权限检查都拿空结果 —— 这就是卡第一屏的原因。
         */
        se_o_hex(&o, g_avd[0], 8);
        se_o_c(&o, ' ');
        se_o_hex(&o, 0xffffffffu, 8);
        se_o_c(&o, ' ');
        se_o_hex(&o, g_avd[1], 8);
        se_o_c(&o, ' ');
        se_o_hex(&o, g_avd[2], 8);
        se_o_c(&o, ' ');
        se_o_dec(&o, g_avd[3]);
        se_o_c(&o, ' ');
        se_o_hex(&o, g_avd[4], 8);
        len = (int)o.n;
    }

    if (compat_copy_to_user(ubuf, out, len))
        goto fallback;
    return len;

fallback:
    /*
     * 跟前一版最大的差别：任何一步失败都回落到内核原来的 sel_write_access。
     * init / system_server 会通过这个节点做自检，这里报错不是"我们答不上来"
     * 那么轻，而是它们眼里的异常，足以把启动卡死 —— 上一版就是这样卡第一屏的。
     * 回落之后返回的是 live 的答案（出厂策略），只有"特权看副本"这一点会退化。
     */
    if (g_orig_access_write)
        return ((long (*)(void *, char *, se_ulong))g_orig_access_write)
            (file, ubuf, size);
    return -1;
}


/* 扫 write_op[]，用函数地址反查下标，不写死 SEL_ACCESS */
int se_install_gate(void)
{
    se_u8 tmp[8];
    se_u32 i;
    void *bak = 0;

    if (!p_write_op || !p_sel_write_access)
        return -1;

    for (i = 0; i < 64u; i++) {
        se_u64 v = 0;

        if (se_kread(&v, (se_u8 *)(se_ulong)p_write_op + i * 8u, 8))
            return -2;
        if (v == (se_u64)p_sel_write_access) {
            se_u64 chk = 0;

            SE_FPHOOK((void *)((se_u8 *)(se_ulong)p_write_op + i * 8u),
                    (void *)se_access_write, &bak);

            /* fp_hook 改的是 .rodata 里的 const 数组，必须回读确认真的写进去了 */
            if (se_kread(&chk, (se_u8 *)(se_ulong)p_write_op + i * 8u, 8) ||
                chk != (se_u64)(se_ulong)se_access_write) {
                pr_info("sehide: gate write not applied (slot %u)\n", i);
                return -4;
            }
            g_orig_access_write = bak;
            pr_info("sehide: gate installed at write_op[%u]\n", i);
            return 0;
        }
    }
    (void)tmp;
    return -3;
}


/* /context 的写处理器：输入上下文串，返回内核规范化后的串 */
long se_context_write(void *file, char *ubuf, se_ulong size)
{
    char kbuf[512];
    char out[256];
    se_u8 cbuf[SE_CTX_BUF];
    int n, r;

    (void)file;

    if (!se_live_ok())
        se_recalibrate();
    if (g_degraded)
        goto fallback;

    /* v68：uid 判据恢复（LunSU ksu_context_write 同款） */
    if (!se_gate_privileged())
        goto fallback;
    if (size == 0 || size >= sizeof(kbuf))
        return -22;   /* 出厂同款 EINVAL */
    n = SE_STRNCPY_USER(kbuf, ubuf, sizeof(kbuf) - 1);
    if (n < 0)
        goto fallback;
    kbuf[n] = 0;

    /* 只取第一段，去掉行尾空白 */
    {
        char *p = kbuf;

        while (*p && *p != ' ' && *p != '\n' && *p != '\t' && *p != '\r')
            p++;
        *p = 0;
    }
    if (!kbuf[0])
        return -22;

    /* v66：快照查不到的上下文（LSP 注入类型）返回出厂同款 EINVAL，
     * 不回落 live——validity oracle 的 magisk/lsposed_file 由此判干净 */
    if (se_parse_ctx(kbuf, cbuf))
        return -22;
    if (se_ctx_to_str(cbuf, out, sizeof(out)))
        goto fallback;

    r = strlen(out);
    if (compat_copy_to_user(ubuf, out, r))
        goto fallback;
    return r;

fallback:
    if (g_orig_context_write)
        return ((long (*)(void *, char *, se_ulong))g_orig_context_write)
            (file, ubuf, size);
    return -1;
}

/* 装第二道门：/context */
int se_install_gate_ctx(void)
{
    se_u32 i;
    void *bak = 0;

    if (!p_write_op || !p_sel_write_context)
        return -1;

    for (i = 0; i < 64u; i++) {
        se_u64 v = 0;

        if (se_kread(&v, (se_u8 *)(se_ulong)p_write_op + i * 8u, 8))
            return -2;
        if (v == (se_u64)p_sel_write_context) {
            se_u64 chk = 0;

            SE_FPHOOK((void *)((se_u8 *)(se_ulong)p_write_op + i * 8u),
                    (void *)se_context_write, &bak);

            if (se_kread(&chk, (se_u8 *)(se_ulong)p_write_op + i * 8u, 8) ||
                chk != (se_u64)(se_ulong)se_context_write) {
                pr_info("sehide: gate ctx write not applied (slot %u)\n", i);
                return -4;
            }
            g_orig_context_write = bak;
            pr_info("sehide: gate ctx at write_op[%u]\n", i);
            return 0;
        }
    }
    return -3;
}



/* ---------------- v79：/load 异步化（专用线程 + 单槽交接） ----------------
 *
 * KPM 自身的通用问题（v78 装机实证）：/load 是所有策略修改组件的公共
 * 入口——任何模块的 sepolicy 批都以 blob 形式到达这里。v78 的同步处理
 * （每次 policydb_read+盖章 ~130ms）使每个 blob 都阻塞写方进程与
 * post-fs-data 事件流：5 次 /load 把事件窗口拉长 0.62s，导致在该窗口
 * 内启动、并依赖"策略装载完成后立刻行动"这一时序的组件全部错过竞速
 * （工作态基线：post-fs-data 仅 0.31s）。这不是对某个组件的适配——
 * 处理模型本身阻塞，受害者是任何经 /load 修改 SELinux 的加载方。
 *
 * 修复（通用）：处理函数只做入队即返回（~1ms），重活由专用线程做：
 *   处理端  cas(0->1) 占槽 -> 发布 pend -> cas(1->2) -> 唤醒 -> 返回 size
 *   线程    cas(2->1) 取件 -> se_absorb_blob（parse+盖章+换代） -> 清槽
 * g_recal_busy 由线程持有（与 light recal 的 build_copy 互斥换代）。
 * 线程不可用（符号缺失）时回退同步 se_absorb_blob（v78 行为）。
 */

static void *se_load_pend;
static se_u32 se_load_pend_len;
static se_u32 se_load_busy;         /* 0=空 1=线程持有 2=待处理 */
static void *se_load_task;

static int se_load_worker_fn(void *arg)
{
    (void)arg;
    while (!((int (*)(void))p_kthread_should_stop)()) {
        se_u8 *blob;
        se_u32 len;
        int rc;

        if (!se_cas32(&se_load_busy, 2, 1)) {
            ((void (*)(se_ulong))p_msleep_interruptible)(2);
            continue;
        }
        blob = se_load_pend;
        len = se_load_pend_len;
        se_load_pend = 0;
        while (!se_cas32(&g_recal_busy, 0, 1))
            ((void (*)(se_ulong))p_msleep_interruptible)(10);
        rc = se_absorb_blob(blob, len);
        g_recal_busy = 0;
        if (rc)
            pr_info("sehide: async /load rc=%d\n", rc);
        se_free(blob);
        se_load_busy = 0;
    }
    return 0;
}

int se_load_worker_start(void)
{
    void *t;

    if (se_load_task)
        return 0;
    if (!p_kthread_create_on_node || !p_wake_up_process ||
        !p_kthread_should_stop || !p_msleep_interruptible)
        return -1;
    t = ((void *(*)(int (*)(void *), void *, int, const char *, ...))
         p_kthread_create_on_node)(se_load_worker_fn, 0, -1, "sehide_load");
    if (!t || (se_ulong)t >= (se_ulong)-4095L)
        return -1;
    se_load_task = t;
    ((int (*)(void *))p_wake_up_process)(t);
    return 0;
}

long se_load_write(void *file, char *ubuf, se_ulong size)
{
    se_u8 *blob = 0;
    long ret;

    (void)file;

    if (!L.ok || !L.copy || g_degraded)
        goto passthrough;
    if (!p_kuid || ((se_u32 (*)(void))p_kuid)() >= 10000u)
        goto passthrough;

    if (size == 0 || size > (se_ulong)SE_MAX_BIN) {
        ret = -7;
        goto reject0;
    }

    blob = se_alloc((se_ulong)size);
    if (!blob) {
        ret = -12;
        goto reject0;
    }
    if (!p_copy_from_user) {
        se_free(blob);
        goto passthrough;
    }
    if (((se_ulong)ubuf >> 48) == 0xffffu) {
        if (!se_kptr_ok((se_ulong)ubuf)) {
            ret = -14;
            goto reject;
        }
        memcpy(blob, ubuf, (size_t)size);
    } else {
        if (((long (*)(void *, const void *, se_ulong))p_copy_from_user)
                (blob, ubuf, size) != 0) {
            ret = -14;
            goto reject;
        }
    }

    /* v79：入队即返回——重活（parse+盖章+换代）由专用线程做，
     * /load 写方不再被 130ms 级解析阻塞，post-fs-data 事件窗口
     * 恢复到装载前水平（通用：窗口内启动的任何策略依赖组件都
     * 因此不再错过时序）。线程不可用则同步回退。 */
    if ((!se_load_task && se_load_worker_start())) {
        int rc2 = se_absorb_blob(blob, (se_u32)size);

        se_free(blob);
        if (rc2) {
            ret = rc2;
            goto reject0;
        }
        return size;
    }
    while (!se_cas32(&se_load_busy, 0, 1))
        ((void (*)(se_ulong))p_msleep_interruptible)(2);
    se_load_pend = blob;
    se_load_pend_len = (se_u32)size;
    se_cas32(&se_load_busy, 1, 2);
    if (se_load_task)
        ((int (*)(void *))p_wake_up_process)(se_load_task);
    return size;

reject:
    se_free(blob);
reject0:
    pr_info("sehide: /load rejected rc=%ld (fail-closed)\n", ret);
    return ret;

passthrough:
    if (g_orig_load_write)
        return ((long (*)(void *, char *, se_ulong))g_orig_load_write)
            (file, ubuf, size);
    return -1;
}

/*
 * v54：/load 门安装重写。
 *
 * v53 用 KP inline hook（p_kp_hook）改 sel_write_load 函数体 —— hotpatch_nosync
 * 清 stage-1 PTE RO 后裸写原物理页（hotpatch.c:80-95），MKP 设备上必死（v12
 * 实证）。现改两级：
 *   1) fops 数据槽：sel_load_ops 是 const file_operations，.write = sel_write_load
 *      （6.1 selinuxfs.c:674-677），与 write_op[] 两道问门同机制，System.map
 *      d 段实证可见。头 64 字节值匹配（RANDSTRUCT 安全，同 se_find_fn_field），
 *      fp_hook 后回读验证。
 *   2) 回读失败（该机 rodata 写也被保护）→ 影子页改 sel_write_load 入口
 *      （se_shadow.c，mkpms 同类，零物理页写入）。
 * g_orig_load_write 两种形态均与原函数签名等效（fops 槽=原函数本体，
 * 影子页=影子页内续体），se_load_write 的 passthrough 无需改动。
 */
int se_install_load_gate(void)
{
    se_u32 fo;

    if (!p_sel_write_load)
        return -1;

    if (p_sel_load_ops) {
        for (fo = 0; fo + 8u <= 64u; fo += 8u) {
            se_u64 v = 0;

            if (se_kread(&v, (se_u8 *)(se_ulong)p_sel_load_ops + fo, 8))
                return -2;
            if (v != (se_u64)p_sel_write_load)
                continue;

            {
                se_u64 chk = 0;
                void *bak = 0;

                SE_FPHOOK((void *)((se_u8 *)(se_ulong)p_sel_load_ops + fo),
                          (void *)se_load_write, &bak);
                if (!se_kread(&chk, (se_u8 *)(se_ulong)p_sel_load_ops + fo, 8) &&
                    chk == (se_u64)(se_ulong)se_load_write) {
                    g_orig_load_write = bak;
                    pr_info("sehide: /load gate installed via fops slot %u\n", fo);
                    return 0;
                }
                pr_info("sehide: /load fops write not applied (slot %u)\n", fo);
                break;
            }
        }
    }

    /* fops 不可用或写不进 → 影子页 */
    if (se_shadow_ready()) {
        void *sbackup = 0;

        if (!se_shadow_hook((void *)(se_ulong)p_sel_write_load,
                            (void *)se_load_write, &sbackup)) {
            g_orig_load_write = sbackup;
            pr_info("sehide: /load gate installed via shadow page\n");
            return 0;
        }
        pr_info("sehide: /load shadow fallback failed\n");
    }
    return -3;
}


/*
 * v60：卸载还原。把 write_op[] 中仍指向我们 wrapper 的槽写回原函数。
 * 幂等：找不到（未装/已还原）静默跳过。模块退出后槽位绝不能悬空指向
 * 已释放的模块内存 —— 这是既有缺口，本轮一并补上。
 */
static void se_restore_slot(unsigned long base, void *ours, void *orig, const char *tag)
{
    se_u32 i;

    if (!base || !ours || !orig)
        return;
    for (i = 0; i < 64u; i++) {
        se_u64 v = 0;
        void *slot = (void *)((se_u8 *)(se_ulong)base + (se_u64)i * 8u);

        if (se_kread(&v, slot, 8))
            return;
        if (v != (se_u64)(se_ulong)ours)
            continue;
        {
            void *bak = 0;
            se_u64 chk = 0;

            SE_FPHOOK(slot, orig, &bak);
            if (se_kread(&chk, slot, 8) || chk != (se_u64)(se_ulong)orig)
                pr_info("sehide: restore %s failed (slot %u)\n", tag, i);
            else
                pr_info("sehide: %s restored (slot %u)\n", tag, i);
        }
        return;
    }
}

void se_uninstall_gates(void)
{
    se_restore_slot(p_write_op, (void *)se_access_write,
                    g_orig_access_write, "access gate");
    se_restore_slot(p_write_op, (void *)se_context_write,
                    g_orig_context_write, "context gate");
}
