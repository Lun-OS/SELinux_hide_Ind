/* SPDX-License-Identifier: GPL-2.0-or-later */
/* se_gate：问门（/access /context）+ 写门（/load） */
#include "sehide.h"

/*
 * 门路由原则：特权（uid<10000，root/system/shell，见
 * se_gate_privileged）走副本答案；非特权（uid>=10000）透传内核原版
 * —— 原版自己的权限门按出厂策略执行，行为与未接管逐字一致。
 * p_kuid 绑定失败时 fail-closed（全部透传），绝不能退化为"服务所有人"。
 * 红线（门最小化）：内核原生已拦截的地方不许多加门——本门只做 uid
 * 分流，非特权必须透传内核原版处理器（含原版权限门），不可由我们
 * 代码构造/改写返回内容。
 * 版本历史见 docs/selinux-hide/KPM-1.1.0-注释工作日志归档.md。
 */
int se_gate_privileged(void)
{
    if (!p_kuid)
        return 0;
    /* 特权 = uid<10000（root/system/shell）。
     * 特权读写执行全部劫持走副本，非特权（uid>=10000）透传出厂。 */
    return ((se_u32 (*)(void))p_kuid)() < 10000u;
}

/* 内核原函数指针：渲染失败时回落，绝不让调用方拿到错误。
 * 约束：必须在两个写处理器之前声明（使用先于声明会编译不过）。 */
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
    se_u32 av5[5];   /* se_compute_av 栈上出参——g_avd 是全局，并发查询互踩 */
    int n, len;

    (void)file;

    /* 策略可能在安装之后被重载（见 se_live_ok），先保证 live 是新的。
     * 决策面置旗的待办在此代跑（本点=进程上下文）。 */
    if (g_recal_pending) {
        g_recal_pending = 0;
        se_recalibrate();
    } else if (!se_live_ok()) {
        se_recalibrate();
    }
    if (g_comp_pending) {
        g_comp_pending = 0;
        se_comp_upgrade();
    }
    if (g_degraded)
        goto fallback;

    /*
     * 门分流：特权（uid<10000）答副本（出厂基底 + 盖章，内核原生求值）；
     * 非特权直通内核原版对 live 求值 —— 直通答案与未 root 逐位一致。
     */
    if (!se_gate_privileged())
        goto fallback;

    if (size == 0 || size >= sizeof(kbuf))
        return -22;   /* 出厂同款：入参畸形按 EINVAL 返回 */

    /*
     * ubuf 是内核页地址（selinuxfs transaction 机制：simple_transaction_get
     * 用 copy_from_user 拷进 get_zeroed_page 后传内核地址，fs/libfs.c:910-913）。
     * strncpy_from_user 对内核地址恒 -EFAULT（src_addr < TASK_SIZE_MAX 恒假，
     * 6.1 lib/strncpy_from_user.c:124）——必须用内核安全读原语按 size 限界
     * 拷贝 + 自补 NUL（simple_transaction_get 不补 NUL，零页零填充复用时
     * 不可依赖）。
     */
    n = (int)size;   /* 已保证 1 <= size < sizeof(kbuf) */
    if (se_kread(kbuf, ubuf, (se_ulong)size))
        goto fallback;
    kbuf[n] = 0;

    /*
     * 出厂 EINVAL 对齐：出厂 sel_write_access 对解析失败/类名未知/
     * 上下文无效一律返回 security_* 原样错误（EINVAL=-22）——检测报告
     * 的控制组就是这个语义。快照上查不到的类型（LSP 注入类型）直接
     * 返回 -22，与"该类型在出厂策略中不存在"的出厂行为逐字一致；
     * 只有快照求值失败（类型存在但渲染出错）才 fail-open 回落。
     */
    if (se_parse3(kbuf, &sc, &tc, &cs))
        return -22;

    /*
     * tclass 段是数字——libselinux 的 userspace ABI（内核
     * sel_write_access sscanf "%s %s %hu"，selinuxfs.c:927，第三段 %hu
     * 数字）。se_class_val 按类名字符串查 symtab，对 "2" 这类数字串
     * 恒查不到。数字段直接换算（u16 上限），非数字才查名字表。
     * 数字类号 = live 类号（libselinux 从 live 的 class 目录索引构建），
     * 副本 = live 拷贝，编号自洽。
     */
    cls = 0;
    {
        const char *p = cs;
        int is_num = (*p != 0);

        while (*p) {
            if (*p < '0' || *p > '9') {
                is_num = 0;
                break;
            }
            p++;
        }
        if (is_num) {
            for (p = cs; *p; p++)
                cls = cls * 10u + (se_u32)(*p - '0');
            if (cls == 0 || cls > 0xffffu)
                return -22;   /* 出厂 sscanf %hu 对溢出/0 同样拒绝 */
        } else if (se_class_val(cs, &cls)) {
            return -22;
        }
    }

    if (se_parse_ctx(sc, sctx) || se_parse_ctx(tc, tctx))
        return -22;
    if (se_compute_av(sctx, tctx, cls, &allowed, &flags, av5))
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
         * libselinux 那边是 sscanf(buf, "%x %x %x %x %u %x")——
         * 任何字段错位它都解析不到，system_server 每次权限检查拿空
         * 结果 = 框架初始化挂死。
         */
        se_o_hex(&o, av5[0], 8);
        se_o_c(&o, ' ');
        se_o_hex(&o, 0xffffffffu, 8);
        se_o_c(&o, ' ');
        se_o_hex(&o, av5[1], 8);
        se_o_c(&o, ' ');
        se_o_hex(&o, av5[2], 8);
        se_o_c(&o, ' ');
        se_o_dec(&o, av5[3]);
        se_o_c(&o, ' ');
        se_o_hex(&o, av5[4], 8);
        len = (int)o.n;
    }

    /*
     * ubuf 是内核页（transaction 响应页），copy_to_user 对内核地址必
     * EFAULT——内核原版直接内存写该页（返回 len 后
     * simple_transaction_set 走 read 路径），这里对称地用内核安全写
     * 原语。
     */
    if (se_kwrite(ubuf, out, (se_ulong)len))
        goto fallback;
    return len;

fallback:
    /*
     * 任何一步失败都回落到内核原来的 sel_write_access。
     * init / system_server 会通过这个节点做自检，这里报错在它们眼里
     * 是异常、足以把启动卡死。回落之后返回的是 live 的答案（出厂
     * 策略），只有"特权看副本"这一点会退化。
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

    /* 同 /access——决策面置旗待办在此代跑。 */
    if (g_recal_pending) {
        g_recal_pending = 0;
        se_recalibrate();
    } else if (!se_live_ok()) {
        se_recalibrate();
    }
    if (g_comp_pending) {
        g_comp_pending = 0;
        se_comp_upgrade();
    }
    if (g_degraded)
        goto fallback;

    /* uid 分流（与 /access 同款） */
    if (!se_gate_privileged())
        goto fallback;
    if (size == 0 || size >= sizeof(kbuf))
        return -22;   /* 出厂同款 EINVAL */
    /*
     * 注意：strncpy_from_user 对 ubuf（内核页）恒 -EFAULT（同 /access
     * 门根因），本门实际恒 fallback —— 输出 = 内核原版 = stock，无害。
     * 维持现状：接管需先修 se_ctx_to_str 丢 MLS 段的渲染缺陷（自检
     * "test ctx->str 'u:r:su'" 实证），否则 /context 会输出缺 :s0 的
     * context 破坏 libselinux 解析。留待 MLS 渲染修复批次。
     */
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

    /* 快照查不到的上下文（LSP 注入类型）返回出厂同款 EINVAL，
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



/* ---------------- /load 异步化（专用线程 + 单槽交接） ----------------
 *
 * /load 是所有策略修改组件的公共入口，任何模块的 sepolicy 批都以
 * blob 形式到达这里。同步处理（每次 policydb_read+盖章 ~130ms）会
 * 阻塞写方进程与 post-fs-data 事件流。处理函数只做入队即返回
 * （~1ms），重活由专用线程做：
 *   处理端  cas(0->1) 占槽 -> 发布 pend -> cas(1->2) -> 唤醒 -> 返回 size
 *   线程    cas(2->1) 取件 -> se_absorb_blob（parse+盖章+换代） -> 清槽
 * g_recal_busy 由线程持有（与 light recal 的 build_copy 互斥换代）。
 * 线程不可用（符号缺失）时回退同步 se_absorb_blob。
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

    /* 入队即返回——重活（parse+盖章+换代）由专用线程做，/load 写方
     * 不再被 130ms 级解析阻塞。线程不可用则同步回退。 */
    if ((!se_load_task && se_load_worker_start())) {
        int rc2;

        /* 同步回退与 load 线程同款持锁——se_absorb_blob 内
         * se_mirror_capture 换代（vfree 旧→挂新）必须与 /policy 读门
         * 的镜像 memcpy 互斥，否则读方拿旧指针撞已释放页。
         * 进程上下文，可睡眠等待。 */
        while (!se_cas32(&g_recal_busy, 0, 1))
            ((void (*)(se_ulong))p_msleep_interruptible)(10);
        rc2 = se_absorb_blob(blob, (se_u32)size);
        g_recal_busy = 0;

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
 * /load 门安装。红线：不能用 KP inline hook（p_kp_hook）改 sel_write_load
 * 函数体——hotpatch_nosync 清 stage-1 PTE RO 后裸写原物理页，MKP 设备
 * 上必死。两级：
 *   1) fops 数据槽：sel_load_ops 是 const file_operations，.write =
 *      sel_write_load（6.1 selinuxfs.c:674-677），与 write_op[] 两道问门
 *      同机制。头 64 字节值匹配（RANDSTRUCT 安全），fp_hook 后回读验证。
 *   2) 回读失败（该机 rodata 写也被保护）→ 影子页改 sel_write_load 入口
 *      （se_shadow.c，mkpms 同类，零物理页写入）。
 * g_orig_load_write 两种形态均与原函数签名等效，passthrough 无需改动。
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


/* ==================== /policy 读门（fops 槽 + 内容自证） ====================
 *
 * 动机：apd 加载模块规则 = "读现行策略 → 加本模块规则 → 写回 /load"。
 * live 恒出厂 → 每个 blob = 出厂 + 单模块规则 → 整本吸收互相覆盖 →
 * LSPosed 规则被冲。修复 = 特权读 /policy 时把副本序列化给它，apd
 * 下次打包自动携带全部已收规则（链式累积）。
 *
 * 定位：hook 内核自己的活指针——sel_policy_ops（selinuxfs.c:505
 * verbatim）的 .open 槽 = sel_open_policy 真地址，内核链接期写死、
 * 每次 open 都在用——零符号解析风险。bak/槽定位全部经 KP 全表枚举
 * + 槽内容匹配自证，不依赖 L1 直读。
 *
 * hook（.open 槽替换，fp_hook 机制=access 门同款）：
 *   rc = bak(inode, filp)            —— 原版全链：avc 门/快照/i_size 原生
 *   rc!=0 → 返回（非特权被原版 avc 拒，零干预）
 *   特权（uid<10000）→ 内容自证定位 plm：filp 内指针槽 → 堆块前 8B ==
 *   L.bin_len（出厂策略长度，全系统唯一值）→ private_data 偏移标定缓存；
 *   inode 定位同理（内部含 ==L.bin_len 的槽 = i_size）→ 副本序列化替换：
 *   vfree(plm->data)（原出厂快照）→ plm->data/len = policydb_write(L.copy)
 *   输出（policy_file 游标语义 verbatim）→ i_size 同步（标定成功时）。
 *   任一步失败 → 保持原版快照（出厂语义，fail-closed）。
 *   release 原版 vfree(plm->data) 释放副本数据——内存闭环。
 * 自测：装完内核态 filp_open 一次 /policy；区分"open 环境失败"（不降级，
 * 等真实流量）与"open 成功但 served=0"（=槽指错 → 恢复槽降级）。
 * ========================================================================== */

static unsigned long g_rp_ops_base;      /* sel_policy_ops 基址（枚举） */
static int g_rp_open_off;                /* .open 槽偏移（槽匹配标定） */
static unsigned long g_rp_bak_open;      /* 原 sel_open_policy（=枚举值） */
static int g_rp_pd_off = -1;             /* filp->private_data 偏移（标定缓存） */
static int g_rp_finode_off = -1;         /* filp->f_inode 偏移（标定缓存） */
static int g_rp_isize_off = -1;          /* inode->i_size 偏移（标定缓存） */
static int g_rp_off_ready;
int g_rp_served;                          /* 自测命中计数 */

/* 在 [obj, obj+span) 内找 8 对齐的指针槽：指向"前 8B == magic"的堆块。
 * 返回槽偏移；-1=未找到。内容自证（magic=L.bin_len 全系统唯一）。 */
static long se_scan_ptr_slot(unsigned long obj, se_u32 span, se_u64 magic)
{
    se_u32 off;

    for (off = 0; off + 8u <= span; off += 8u) {
        se_u64 p = 0;

        if (se_kread(&p, (void *)(obj + off), 8))
            break;
        if (!se_kptr_ok(p))
            continue;
        {
            se_u64 head = 0;

            if (se_kread(&head, (void *)(se_ulong)p, 8))
                continue;
            if (head == magic)
                return (long)off;
        }
    }
    return -1;
}

/* inode->i_size 偏移标定：inode 内含 ==magic（=原版刚写的 len）的 8 对齐
 * 槽。唯一命中才可信（i_size 值全对象唯一性极强）。返回偏移或 -1。 */
static long se_scan_val_slot(unsigned long obj, se_u32 span, se_u64 magic)
{
    se_u32 off;
    long hit = -1;
    int n = 0;

    for (off = 0; off + 8u <= span; off += 8u) {
        se_u64 v = 0;

        if (se_kread(&v, (void *)(obj + off), 8))
            break;
        if (v == magic) {
            if (n == 0)
                hit = (long)off;
            n++;
        }
    }
    return n == 1 ? hit : -1;
}

long se_policy_open_hook(void *inode, void *filp)
{
    long rc;
    se_u64 plm = 0;

    rc = ((long (*)(void *, void *))g_rp_bak_open)(inode, filp);
    if (rc)
        return rc;                       /* 非特权等：原版 avc 拒，零干预 */
    if (!se_gate_privileged() || !L.ok || !L.copy || !L.lenoff ||
        L.bin_len < 65536u || L.bin_len > SE_MAX_BIN ||
        !p_vmalloc_user || !p_vfree) {
        return rc;                       /* 保持原版出厂快照 */
    }

    /* 偏移标定（首次；结构恒定，缓存复用） */
    if (!g_rp_off_ready) {
        long o;

        o = se_scan_ptr_slot((se_ulong)filp, 512u,
                             (se_u64)L.bin_len);
        if (o < 0) {
            pr_info("sehide: rp plm not found in filp, keep factory\n");
            return rc;                   /* 降级：出厂快照 */
        }
        g_rp_pd_off = (int)o;

        /* f_inode：指向"内部含 ==L.bin_len 槽（i_size）"的对象的槽 */
        {
            se_u32 off;
            int fin = -1, iso = -1;

            for (off = 0; off + 8u <= 512u; off += 8u) {
                se_u64 p = 0;
                long io;

                if (off == (se_u32)g_rp_pd_off)
                    continue;
                if (se_kread(&p, (void *)((se_ulong)filp + off), 8))
                    break;
                if (!se_kptr_ok(p))
                    continue;
                io = se_scan_val_slot((se_ulong)p, 2048u,
                                      (se_u64)L.bin_len);
                if (io >= 0) {
                    fin = (int)off;
                    iso = (int)io;
                    break;               /* 首个唯一命中对象 */
                }
            }
            if (fin < 0 || iso < 0) {
                pr_info("sehide: rp inode/isize not calibrated "
                        "(read_to_end still ok)\n");
                /* i_size 降级：read_to_end 由 plm->len 驱动，仍工作 */
            } else {
                g_rp_finode_off = fin;
                g_rp_isize_off = iso;
            }
        }
        g_rp_off_ready = 1;
        pr_info("sehide: rp calibrated pd_off=%d finode_off=%d "
                "isize_off=%d\n",
                g_rp_pd_off, g_rp_finode_off, g_rp_isize_off);
    }

    if (se_kread(&plm, (void *)((se_ulong)filp + (se_u64)g_rp_pd_off), 8)) {
        pr_info("sehide: rp plm read fail\n");
        return rc;
    }

    /* 镜像直供（副本含 KPM 盖章组合规则——序列化 >4.69MB 爆缓冲且不应
     * 给生态；镜像 = 盖章前序列化存档 = 出厂+全部生态规则，正是 apd
     * 链式累积需要的完整内容）。 */
    {
        se_u64 mlen = (se_u64)g_rp_mirror_len;
        void *nd;
        se_u64 odata = 0, olen = 0;

        if (!mlen || mlen < 65536u || mlen > SE_MAX_BIN)
            return rc;                   /* 无有效镜像：出厂快照 */

        if (se_kread(&odata, (void *)(se_ulong)(plm + 8u), 8) ||
            se_kread(&olen, (void *)(se_ulong)plm, 8) ||
            olen != (se_u64)L.bin_len) {
            pr_info("sehide: rp plm mismatch olen=%llu expect=%u\n",
                    (se_u64)olen, L.bin_len);
            return rc;
        }

        nd = (void *)((void *(*)(se_u64))p_vmalloc_user)(mlen);
        if (!nd) {
            pr_info("sehide: rp vmalloc(%llu) fail\n", mlen);
            return rc;
        }
        /* memcpy 读 1.8MB 镜像（百微秒级）期间，load 线程/同步回退的
         * se_mirror_capture 可能 vfree 旧镜像→挂新——读方手里旧指针变
         * 已释放页（vmalloc 页表被拆，确定性 Oops）。CAS 抱 g_recal_busy
         * 与全部换代方互斥；抢不到=换代进行中，放弃直供回落出厂快照
         * （/policy 读低频，可接受）。 */
        if (!se_cas32(&g_recal_busy, 0, 1)) {
            ((void (*)(void *))p_vfree)(nd);
            pr_info("sehide: rp mirror busy, serve stock snapshot\n");
            return rc;
        }
        memcpy(nd, g_rp_mirror, (unsigned long)mlen);
        g_recal_busy = 0;

        /* 替换快照：释放原出厂数据，挂镜像拷贝；回读验证在挂载前 */
        ((void (*)(void *))p_vfree)((void *)(se_ulong)odata);
        se_wr64((void *)(se_ulong)(plm + 8u), (se_u64)(se_ulong)nd);
        se_wr64((void *)(se_ulong)plm, mlen);

        /* i_size 同步（标定成功时） */
        if (g_rp_isize_off >= 0 && g_rp_finode_off >= 0) {
            se_u64 ino = 0;

            if (!se_kread(&ino, (void *)((se_ulong)filp +
                          (se_u64)g_rp_finode_off), 8) &&
                se_kptr_ok(ino))
                se_wr64((void *)(ino + (se_u64)g_rp_isize_off), mlen);
        }

        pr_info("sehide: /policy served from mirror (len=%llu)\n", mlen);
        g_rp_served++;
    }
    return rc;
}

int se_install_read_gate(void)
{
    unsigned long ops, open_addr = 0;
    void *bak = 0;
    se_u32 off;
    se_u64 chk = 0;

    if (!p_vmalloc_user || !p_vfree)
        return -1;
    if (g_rp_ops_base)
        return 0;

    ops = se_sym_via_enum("sel_policy_ops");
    if (!ops || !se_kptr_ok((se_u64)ops)) {
        pr_info("sehide: rp sel_policy_ops enum unavailable\n");
        return -2;
    }
    open_addr = se_sym_via_enum("sel_open_policy");
    if (!open_addr || !se_kptr_ok((se_u64)open_addr)) {
        pr_info("sehide: rp sel_open_policy enum unavailable\n");
        return -3;
    }

    /* 槽定位：扫描 ops 匹配枚举值（内容自证，非布局假设） */
    for (off = 0; off + 8u <= 128u; off += 8u) {
        se_u64 v = 0;

        if (se_kread(&v, (void *)(ops + off), 8))
            return -4;
        if (v == (se_u64)open_addr)
            break;
    }
    if (off + 8u > 128u) {
        pr_info("sehide: rp .open slot not found in ops\n");
        return -5;
    }
    g_rp_ops_base = ops;
    g_rp_open_off = (int)off;
    g_rp_bak_open = open_addr;

    SE_FPHOOK((void *)(ops + off), (void *)se_policy_open_hook, &bak);
    if (se_kread(&chk, (void *)(ops + off), 8) ||
        chk != (se_u64)(se_ulong)se_policy_open_hook) {
        pr_info("sehide: rp fops write not applied\n");
        g_rp_ops_base = 0;
        return -6;
    }
    pr_info("sehide: /policy read gate installed via fops slot %u "
            "(bak=%016lx)\n", off, (se_u64)open_addr);

    /* 自测：内核态 open 一次 /policy。区分环境失败（不降级）与
     * served=0（槽指错 → 恢复降级）。 */
    {
        void *f = ((void *(*)(const char *, unsigned long,
                              unsigned long))p_filp_open)
            ("/sys/fs/selinux/policy", 0, 0);

        if (f && se_kptr_ok((se_u64)(se_ulong)f)) {
            ((void (*)(void *, void *))p_filp_close)(f, (void *)0);
            pr_info("sehide: rp selftest done (served=%d)\n", g_rp_served);
            if (!g_rp_served) {
                void *rb = 0;

                SE_FPHOOK((void *)(ops + off), bak, &rb);
                g_rp_ops_base = 0;
                pr_info("sehide: rp selftest MISS -> slot restored "
                        "(degraded)\n");
                return -7;
            }
            g_rp_served = 0;
        } else {
            pr_info("sehide: rp selftest open failed (env), "
                    "keep gate for real traffic\n");
        }
    }
    return 0;
}

static void se_uninstall_read_gate(void)
{
    void *rb = 0;
    se_u64 chk = 0;

    if (!g_rp_ops_base || !g_rp_bak_open)
        return;
    SE_FPHOOK((void *)(g_rp_ops_base + (se_u64)g_rp_open_off),
              (void *)(se_ulong)g_rp_bak_open, &rb);
    if (se_kread(&chk, (void *)(g_rp_ops_base + (se_u64)g_rp_open_off), 8) ||
        chk != (se_u64)g_rp_bak_open)
        pr_info("sehide: /policy read gate restore failed\n");
    else
        pr_info("sehide: /policy read gate restored\n");
    g_rp_ops_base = 0;
}

/* 卸载还原。把 write_op[] 中仍指向我们 wrapper 的槽写回原函数。
 * 幂等：找不到（未装/已还原）静默跳过。模块退出后槽位绝不能悬空指向
 * 已释放的模块内存。
 * 流程红线：链接期未解析符号编译静默——每次产物必须 nm -u 对比基线
 * （历史上发生过卸载函数被误删导致 KP 加载器拒载的整模块事故）。 */
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
    se_uninstall_read_gate();
    se_restore_slot(p_write_op, (void *)se_access_write,
                    g_orig_access_write, "access gate");
    se_restore_slot(p_write_op, (void *)se_context_write,
                    g_orig_context_write, "context gate");
}
