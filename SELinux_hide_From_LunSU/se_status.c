/*
 * v61：status 页冻结（LunSU fake_status 的 KPM 移植，最小实现）。
 *
 * 背景：/sys/fs/selinux/status 是世界可读的内核状态页，其中 policyload
 * 字段每次策略载入 +1（出厂 boot 只载 1 次）。KP 核心重载与模块策略
 * 注入都会推高它 —— 非特权观测面由此偏离出厂状态（本机实测
 * policyload=6，出厂应为 1）。LunSU 的解法是 fake_status 冻结页
 * （LKM selinux_hide.c initialize_fake_status / my_sel_open_handle_status）。
 *
 * 本实现只替换 sel_handle_status_ops 的 .read 槽（rodata 数据槽写，与
 * write_op[] 门同一 SE_FPHOOK 通道 + 回读验证）：uid>=10000（非特权）
 * 读到冻结的出厂快照，uid<10000（特权：root/system/shell）走原版读
 * 真实值。open/mmap 槽不动 —— 原版 open 正确设置 private_data，
 * read/mmap 路径对特权完整保留；非特权 mmap 该节点的场景在检测面中
 * 未见使用（read 是 cat/Java IO 的唯一常规路径），残余风险已明示。
 *
 * 冻结值全部真值化，零硬编码偏移：
 *   struct selinux_kernel_status（security.h:366-375，__packed 20 字节，
 *   4.19~6.6 双树逐字一致）：
 *   version      = 1（结构版本常量，两树恒 1）
 *   sequence     = 0（出厂 boot 结束语义；LunSU late_load 同款 <6.10 填 0）
 *   enforcing    = 安装期读 /sys/fs/selinux/enforce（真值）
 *   policyload   = 1（出厂语义：boot 载入一次）
 *   deny_unknown = 安装期读 /sys/fs/selinux/deny_unknown（S_IRUGO，真值）
 * 任一读取失败 → 冻结功能整体关闭（四铁律 R4，read 槽不换，不猜）。
 */

#include "sehide.h"

static se_u8 g_frozen[20];
static int g_status_ready;
static void *g_read_slot;
static void *g_orig_status_read;

/* 读一个 selinuxfs 数值节点（filp_open + kernel_read，sepolicy 通道同基建） */
static int se_read_u32_node(const char *path, se_u32 *val)
{
    void *f;
    se_u8 buf[16];
    loff_t pos = 0;
    long n, i;
    se_u32 v = 0;

    if (!p_filp_open || !p_kernel_read || !p_filp_close)
        return -1;

    f = ((void *(*)(const char *, int, unsigned int))p_filp_open)(path, 0, 0);
    if (!f || !se_kptr_ok((se_u64)(se_ulong)f))
        return -2;

    n = ((long (*)(void *, void *, unsigned long, loff_t *))p_kernel_read)
        (f, buf, sizeof(buf) - 1, &pos);
    ((long (*)(void *, void *))p_filp_close)(f, 0);
    if (n <= 0)
        return -3;

    buf[n] = 0;
    for (i = 0; i < n; i++) {
        if (buf[i] < '0' || buf[i] > '9')
            break;
        v = v * 10u + (se_u32)(buf[i] - '0');
    }
    if (!i)
        return -4;
    *val = v;
    return 0;
}

/*
 * .read 替换体：uid>=10000 返回冻结快照，uid<10000 透传原版。
 * ppos 是内核指针（指向 filp->f_pos），进程上下文直接读写。
 */
long se_status_read(void *file, char *ubuf, se_ulong count, se_u64 *ppos)
{
    se_u64 off;
    se_ulong n;

    if (g_status_ready && p_kuid &&
        ((se_u32 (*)(void))p_kuid)() >= 10000u) {
        off = *ppos;
        if (off >= 20u)
            return 0;
        n = count;
        if (n > 20u - (se_ulong)off)
            n = 20u - (se_ulong)off;
        if (compat_copy_to_user(ubuf, g_frozen + off, (int)n))
            return -14;   /* -EFAULT */
        *ppos = off + n;
        return (long)n;
    }

    return ((long (*)(void *, char *, se_ulong, se_u64 *))g_orig_status_read)
        (file, ubuf, count, ppos);
}

int se_status_install(void)
{
    se_u32 enforcing = 0, deny_unknown = 0;
    se_u32 fo = 0;
    void *bak = 0;
    se_u64 chk = 0;

    if (g_status_ready)
        return 0;
    if (!p_status_ops || !p_sel_read_status || !p_kuid)
        return -1;
    if (!p_filp_open || !p_kernel_read || !p_filp_close)
        return -1;

    if (se_read_u32_node("/sys/fs/selinux/enforce", &enforcing) ||
        enforcing > 1u) {
        pr_info("sehide: status freeze off (enforce read rc)\n");
        return -2;
    }
    if (se_read_u32_node("/sys/fs/selinux/deny_unknown", &deny_unknown)) {
        pr_info("sehide: status freeze off (deny_unknown read rc)\n");
        return -3;
    }

    se_wr32(g_frozen + 0, 1u);            /* version */
    se_wr32(g_frozen + 4, 0u);            /* sequence：出厂 boot 语义 */
    se_wr32(g_frozen + 8, enforcing);
    se_wr32(g_frozen + 12, 1u);           /* policyload：出厂仅 boot 载入一次 */
    se_wr32(g_frozen + 16, deny_unknown);

    /* .read 槽：fops 内值匹配原版 read 地址（write_op[] 门同手法） */
    if (!se_find_fn_field((se_u64)(se_ulong)p_status_ops,
                          (se_u64)p_sel_read_status, &fo))
        return -4;
    g_read_slot = (void *)((se_u8 *)(se_ulong)p_status_ops + (se_u64)fo);

    SE_FPHOOK(g_read_slot, (void *)se_status_read, &bak);
    if (se_kread(&chk, g_read_slot, 8) ||
        chk != (se_u64)(se_ulong)se_status_read) {
        pr_info("sehide: status read-slot write not applied\n");
        return -5;
    }
    g_orig_status_read = bak;
    g_status_ready = 1;
    pr_info("sehide: status frozen (enf=%u deny_unk=%u) off=%u\n",
            enforcing, deny_unknown, fo);
    return 0;
}

void se_status_restore(void)
{
    void *bak = 0;
    se_u64 chk = 0;

    if (!g_status_ready)
        return;
    SE_FPHOOK(g_read_slot, g_orig_status_read, &bak);
    if (se_kread(&chk, g_read_slot, 8) ||
        chk != (se_u64)(se_ulong)g_orig_status_read)
        pr_info("sehide: status restore failed\n");
    else
        pr_info("sehide: status read-slot restored\n");
    g_status_ready = 0;
}
