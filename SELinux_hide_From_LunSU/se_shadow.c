/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * se_shadow.c - mkpms 式页分裂影子页 hook。
 *
 * 原理（全部源码实证，禁止猜测）：
 *   KP 的 hook()/fp_hook() 都走 hotpatch_nosync（hotpatch.c:80-95）——清 stage-1
 *   PTE 的 RO 位后裸写原 VA，即写原物理页。stage-2（MTK MKP/EL2）锁的是物理页，
 *   装机实证 text 写必死。影子页方案：分配新物理页承载修改，改 stage-1 页表
 *   （页表页不在 MKP 的 krn code/krn rodata 保护清单）让 VA 执行流走
 *   影子页，原物理页一字节不动。
 *
 * 坐标系重建：
 *   KP 内部全局 page_shift/linear_voffset/pgd_va 不在 KP 符号表（仅
 *   KP_EXPORT_SYMBOL 进表，symbol.h:23 + kpimg.lds:89），KPM 引用即 unknown
 *   symbol 拒载。本文件按 KP 自身的运行期探测法（map.c:123-168）重建：
 *     - page_shift：TCR_EL1.TG1（bits31:30；1→16K、3→64K、0→4K，map.c:130-137）
 *     - va_bits：64 - TCR_EL1.T1SZ（bits21:16，map.c:126 同式）
 *     - PAGE_OFFSET = -(1<<va_bits)（6.1 memory.h:44）
 *     - PHYS_OFFSET = memstart_addr（memory.h:204，kallsyms D 段可见）
 *     - linear_voff = PAGE_OFFSET - PHYS_OFFSET（memory.h:308 __phys_to_virt）
 *     - kimage_voff：kallsyms 可见变量读出（memory.h:210）
 *     - pgd = TTBR1_EL1.BADDR + linear_voff（map.c:165-168 同式）
 *   自证两条，任一失败整个影子页子系统拒绝启用：
 *     ① ttbr1 BADDR == swapper_pg_dir - kimage_voffset（TTBR1 即内核主 pgd）
 *     ② walk(_text) 得到的 PA == _text - kimage_voffset（walk 与 phys 换算自洽）
 *
 * 分裂：
 *   6.1 内核自己的重映射通道不可用——alloc_init_cont_pte() 第一句
 *   BUG_ON(pmd_sect(pmd))（mmu.c:204），对已存在的 2MB block 做页级重映射直接
 *   BUG 崩溃。故分裂手写：PTE 表 512 项由块描述符派生（PMD_TYPE_TABLE=3<<0 /
 *   PMD_TYPE_SECT=1<<0 / PTE_TYPE_PAGE=3<<0，pgtable-hwdef.h:115/116/145），
 *   CONT 位必须清（pgattr_change_is_safe：mmu.c:150-152 "live contiguous
 *   mappings may not be manipulated at all"），块描述符带 CONT 时 v1 直接拒绝。
 *
 * 换页：
 *   stop_machine（stop_machine.c:624-633，cpus=NULL 即全 online 核停）内做
 *   break-before-make（invalid → dsb+tlbi → new → dsb+tlbi）——停住的核不会
 *   经过该页，无取指撕裂窗口。TLB 维护指令按 pgtable.h 的 tlbi 宏原样自写
 *   （flush_tlb_kernel_range 引用 page_shift 全局，不能直接调）。
 *
 * backup：
 *   影子页含原函数完整拷贝，跳板 16B（BTI/PAC 变体 20B）之后的地址就是原函数
 *   续体——backup = shadow + off + tramp_len，零指令重定位（对比 KP hook 的
 *   relo 机制少一整类边界 bug，hook.c:471-545）。
 */
#include "sehide.h"
#include <pgtable.h>
#include <hook.h>
#include <cache.h>

struct se_shadow_rec {
    se_u64 target;
    se_u64 entry_va;
    se_u64 old_desc;
    void *shadow;
    int kind;            /* 0 = page 级换 PTE，1 = block 分裂换表项 */
    int tramp_len;
};

static struct se_shadow_rec g_rec;
int g_shadow_installed;
int g_mm_ok;
int g_mm_page_shift;

/* 页表坐标系（map.c:123-168 同式重建） */
struct se_mm {
    int ok;
    int page_shift;
    int page_level;
    se_u64 linear_voff;
    se_u64 kimage_voff;
    se_u64 pgd_va;
};
static struct se_mm MM;

static void se_tlb_va(se_u64 va)
{
    /* pgtable.h:231-236 tlbi_vaddr + flush_tlb_kernel_page 同式，asid=0 */
    se_u64 x = (va >> 12) & mask_ul(43, 0);

    dsb(ishst);
    asm volatile("tlbi vaale1is, %0\n"
                 "dsb ish\n"
                 "tlbi vaale1is, %0\n"
                 :: "r"(x) : "memory");
    dsb(ish);
    isb();
}

static void se_tlb_range(se_u64 start, se_u64 end)
{
    se_u64 v;

    for (v = start & ~0xFFFull; v < end; v += 0x1000ull)
        se_tlb_va(v);
}

/* 页表遍历（pgtable_entry，start.c:315-350 同式，但带 level 回传）。
 * 返回 1 = 块描述符，0 = page 描述符（走满四级），负 = 失败。 */
static int se_walk(se_u64 va, se_u64 *entry_out, se_u64 *desc_out, int *lv_out)
{
    int ps = MM.page_shift, pxd_bits = ps - 3;
    se_u64 ptrs = 1ull << pxd_bits;
    se_u64 cur = MM.pgd_va;
    se_u64 entry_va = 0, desc = 0;
    int lv;

    for (lv = 4 - MM.page_level; lv < 4; lv++) {
        se_u64 shift = (se_u64)((ps - 3) * (4 - lv) + 3);
        se_u64 idx = (va >> shift) & (ptrs - 1);
        se_u64 pa;

        entry_va = cur + idx * 8;
        if (se_kread(&desc, (void *)(se_ulong)entry_va, 8))
            return -1;
        if ((desc & 3ull) == 1ull) {           /* block（lv1/lv2） */
            *entry_out = entry_va;
            *desc_out = desc;
            *lv_out = lv;
            return 1;
        }
        if ((desc & 3ull) != 3ull)
            return -2;                          /* invalid */
        pa = desc & mask_ul(47, ps);
        cur = pa + MM.linear_voff;
    }
    *entry_out = entry_va;                      /* lv3 page 描述符 */
    *desc_out = desc;
    *lv_out = 3;
    return 0;
}

/* 物理地址（pgtable_phys，start.c:352-375 同式） */
static se_u64 se_pa(se_u64 va)
{
    int ps = MM.page_shift, pxd_bits = ps - 3;
    se_u64 ptrs = 1ull << pxd_bits;
    se_u64 cur = MM.pgd_va, pa = 0;
    int lv;

    for (lv = 4 - MM.page_level; lv < 4; lv++) {
        se_u64 shift = (se_u64)((ps - 3) * (4 - lv) + 3);
        se_u64 idx = (va >> shift) & (ptrs - 1);
        se_u64 desc;

        if (se_kread(&desc, (void *)(se_ulong)(cur + idx * 8), 8))
            return 0;
        if ((desc & 3ull) == 3ull) {
            pa = desc & mask_ul(47, ps);
            cur = pa + MM.linear_voff;
        } else if ((desc & 3ull) == 1ull) {
            se_u64 bits = (se_u64)((3 - lv) * pxd_bits);
            se_u64 block_bits = bits + (se_u64)ps;

            return (desc & mask_ul(47, (int)block_bits)) +
                   (va & ((1ull << bits) - 1ull));
        } else {
            return 0;
        }
    }
    return pa ? pa + (va & ((1ull << ps) - 1ull)) : 0;
}

static se_u64 linear_voff_override;

int se_shadow_init(void)
{
    se_u64 tcr, ttbr1, memstart = 0, kimgvoff = 0;
    int t1sz, tg1;

    MM.ok = 0;
    g_mm_ok = 0;

    if (!p_memstart || !p_kimage_voff || !p_swapper || !p_text)
        return -1;

    /* TCR_EL1：T1SZ bits[21:16]、TG1 bits[31:30]（map.c:123-137 同式） */
    __asm__ __volatile__("mrs %0, tcr_el1" : "=r"(tcr));
    t1sz = (int)((tcr >> 16) & 0x3full);
    tg1 = (int)((tcr >> 30) & 3ull);
    MM.page_shift = (tg1 == 1) ? 14 : (tg1 == 3) ? 16 : 12;
    {
        int va_bits = 64 - t1sz;
        int pxd_bits = MM.page_shift - 3;

        MM.page_level = (va_bits - 4) / pxd_bits;       /* map.c:156 同式 */
    }

    /*
     * linear 映射偏移改用 KP 的运行期实测值。
     *
     * 根因终审（br_0249 闭环）：memstart 双源同值（0x40000000，合理）
     * 但 walk 仍 0 → 公式假设（PAGE_OFFSET=-(1<<va_bits)、PHYS_OFFSET=
     * memstart_addr、或运算等价性）与该设备内核实际线性映射配置不符。
     * KP 的 linear_voffset（map.c:141-148 verbatim）在 boot 早期用内核
     * memblock 分配器传精确 phys 拿 virt 实测——绕开一切公式假设，KP
     * hook 在本机工作正常即其正确性的活体证明。KP 的实测函数是 __init
     * （boot 后已释放），KPM install 时机无法重演 → 直接读 KP 实测好的
     * linear_voffset 全局（symbol_lookup_name 走 KP 符号表，精确）。
     * 这是 boot 期才可获得的信息、KP 宿主必在——"必须经过"边界内的
     * 数据依赖，非机制依赖。旧公式保留为兜底（KP 符号缺失时）。
     * 强自证 = walk(_text) PA == va-kimgvoff（三方自洽）不变。
     */
    {
        unsigned long kp_lvoff = symbol_lookup_name("linear_voffset");
        se_u64 lv = 0;

        if (kp_lvoff && !se_kread(&lv, (void *)kp_lvoff, 8) && lv)
            linear_voff_override = lv;
    }

    if (se_kread(&memstart, (void *)(se_ulong)p_memstart, 8))
        return -2;
    if (se_kread(&kimgvoff, (void *)(se_ulong)p_kimage_voff, 8))
        return -3;

    /*
     * memstart_addr 是 D 段数据符号，L1 对其错地址（secclass_map
     * 同族实证）→ linear_voff 错 → walk
     * 全链 0（历次装机 selfcheck2 fail phys=0，selfcheck1
     * 不依赖 linear 故仍过——日志特征吻合）。修复：走完换算+自证②，
     * 失败时用 KP 全表枚举重解析 memstart_addr 再试一轮；强自证 =
     * walk(_text) 的 PA 与 kimg 换算一致（三方自洽），错值必然失败。
     * 两轮都失败 → MM.ok=0（影子页整支关闭，fail-closed）。
     */
    {
        int retry;

        for (retry = 0; retry < 2; retry++) {
            se_u64 phys;

            /* PAGE_OFFSET = -(1<<va_bits)（memory.h:44）；PHYS_OFFSET =
             * memstart_addr（memory.h:204）；__phys_to_virt(x) =
             * (x - PHYS_OFFSET) | PAGE_OFFSET（memory.h:308）=>
             * linear_voff = PAGE_OFFSET - PHYS_OFFSET */
            /* KP 实测值优先（boot 期 memblock 实测，见上）；公式为兜底 */
            MM.linear_voff = linear_voff_override ?
                linear_voff_override :
                (se_u64)(0ull - (1ull << (64 - t1sz))) - memstart;
            MM.kimage_voff = kimgvoff;

            /* pgd：TTBR1_EL1 BADDR（map.c:165-168 同式） */
            __asm__ __volatile__("mrs %0, ttbr1_el1" : "=r"(ttbr1));
            MM.pgd_va = (ttbr1 & 0xFFFFFFFFFFFEull) + MM.linear_voff;

            /* 自证①：TTBR1 即内核主 pgd（swapper_pg_dir - kimage_voffset）。
             * KPTI 内核运行期 TTBR1 也是 swapper_pg_dir（tramp_pg_dir 仅
             * 入口切换用）。不依赖 linear_voff，两轮等价。 */
            if ((ttbr1 & 0xFFFFFFFFFFFEull) !=
                ((se_u64)p_swapper - kimgvoff)) {
                pr_info("sehide: shadow selfcheck1 fail ttbr1=%016lx "
                        "swapper=%016lx kimgvoff=%016llx\n",
                        (unsigned long)(ttbr1 & 0xFFFFFFFFFFFEull),
                        (unsigned long)p_swapper,
                        (unsigned long long)kimgvoff);
                return -4;
            }

            /* 自证②：walk(_text) 的 PA 与 kimg 换算一致（三方自洽） */
            phys = se_pa((se_u64)p_text);
            if (phys && phys == (se_u64)p_text - kimgvoff)
                break;                   /* 本轮换算可信 */

            pr_info("sehide: shadow selfcheck2 retry=%d text=%016lx "
                    "phys=%016llx memstart=%016llx src=%s\n",
                    retry, (unsigned long)p_text,
                    (unsigned long long)phys,
                    (unsigned long long)memstart,
                    retry ? "enum" : "l1");

            if (retry)
                return -5;               /* 两轮皆败：影子页整支关闭 */

            /* KP 全表枚举重解析 memstart_addr（D 段可靠通道），重算再验 */
            {
                unsigned long m2 = se_sym_via_enum("memstart_addr");

                if (!m2 || se_kread(&memstart, (void *)m2, 8)) {
                    pr_info("sehide: shadow memstart enum unavailable\n");
                    return -6;
                }
            }
        }
    }

    MM.ok = 1;
    g_mm_ok = 1;
    g_mm_page_shift = MM.page_shift;
    pr_info("sehide: shadow mm ok ps=%d levels=%d lvoff=%016llx kimgvoff=%016llx pgd=%016lx\n",
            MM.page_shift, MM.page_level,
            (unsigned long long)MM.linear_voff,
            (unsigned long long)MM.kimage_voff,
            (unsigned long)MM.pgd_va);
    return 0;
}

int se_shadow_ready(void)
{
    return MM.ok && p_vmalloc && p_vfree && p_stop_machine && p_gfp;
}

/* stop_machine 回调：BBM 换描述符。其余核已停在安全点，不会取指该页。 */
struct se_stop_arg {
    se_u64 entry_va;
    se_u64 old_desc;
    se_u64 new_desc;
    se_u64 flush_start;
    se_u64 flush_end;
};

static int se_shadow_stop_cb(void *arg)
{
    struct se_stop_arg *sa = arg;
    volatile se_u64 *entry = (volatile se_u64 *)(se_ulong)sa->entry_va;

    *entry = sa->old_desc & ~1ull;      /* BBM 第一步：invalid */
    dsb(ish);
    se_tlb_range(sa->flush_start, sa->flush_end);

    *entry = sa->new_desc;              /* 第二步：新描述符 */
    dsb(ish);
    se_tlb_range(sa->flush_start, sa->flush_end);
    return 0;
}

/* 清影子页自身 PTE 的 PXN/GP（start.c:444 KP hook 区 RWX 化同款；
 * 写的是 vmalloc 区自己的页表页，不碰保护面）。CONT 组按
 * hotpatch.c:60-78 modify_entry_kernel 的纪律整组处理。 */
static int se_shadow_make_exec(void *shadow)
{
    se_u64 entry_va, desc;
    int lv;

    if (se_walk((se_u64)(se_ulong)shadow, &entry_va, &desc, &lv) < 0)
        return -1;
    /* CONT 组纪律（mmu.c:150-152）：vmalloc 页带 CONT 极罕见
     * （仅 VM_ALLOW_HUGE_VMAP），拒绝而非整组改写 —— 与目标页的
     * 拒绝策略一致，不引入 CONFIG_ARM64_CONT_PTE_SHIFT 依赖。 */
    if (desc & (1ull << 52))
        return -2;
    {
        volatile se_u64 *entry = (volatile se_u64 *)(se_ulong)entry_va;

        *entry = *entry & ~(1ull << 53) & ~(1ull << 50);
    }
    se_tlb_va((se_u64)(se_ulong)shadow);
    return 0;
}

int se_shadow_hook(void *target, void *replace, void **backup)
{
    se_u64 tva = (se_u64)(se_ulong)target;
    se_u64 entry_va = 0, desc = 0, page_va, off, shadow_pa;
    void *shadow;
    se_u64 new_desc, flush_start, flush_end;
    se_u32 first = 0, tramp[5];
    int lv = 0, kind, tramp_n = 0, rc, ps = MM.page_shift;
    se_ulong page_size = 1ull << ps;
    struct se_stop_arg sa;

    if (!MM.ok)
        return -10;
    rc = se_walk(tva, &entry_va, &desc, &lv);
    if (rc < 0)
        return -11;

    /* CONT 组纪律：live contiguous mappings may not be manipulated（mmu.c:150）。
     * v1 拒绝这类页，功能关闭打日志，绝不打折扣。 */
    if (desc & (1ull << 52))
        return -21;

    if (rc == 1) {
        kind = 1;                       /* block（lv1/lv2，2MB/1GB） */
    } else {
        kind = 0;                       /* page（lv3 PTE） */
    }

    page_va = tva & ~(page_size - 1ull);
    off = tva - page_va;

    /* 影子页：vmalloc（hotpatch.c:186 alias_page 同款通道） */
    shadow = ((void *(*)(se_ulong))p_vmalloc)(page_size);
    if (!shadow)
        return -12;
    if (se_kread(shadow, (void *)(se_ulong)page_va, page_size)) {
        ((void (*)(void *))p_vfree)(shadow);
        return -13;
    }

    /* 跳板：branch_absolute 编码（hook.c:307-315），BTI/PAC 首指令处理
     * （hook.c:536-541 hook_prepare 同款） */
    se_kread(&first, target, 4);
    if (first == ARM64_PACIASP || first == ARM64_PACIBSP)
        tramp[tramp_n++] = ARM64_BTI_JC;
    tramp[tramp_n++] = 0x58000051;      /* LDR X17, #8 */
    tramp[tramp_n++] = 0xd61f0220;      /* BR X17 */
    tramp[tramp_n++] = (se_u32)((se_u64)(se_ulong)replace & 0xffffffffull);
    tramp[tramp_n++] = (se_u32)((se_u64)(se_ulong)replace >> 32);
    memcpy((se_u8 *)shadow + off, tramp, (se_u32)(tramp_n * 4));

    /* 影子页 icache + 可执行化 */
    flush_icache_all();
    if (se_shadow_make_exec(shadow)) {
        ((void (*)(void *))p_vfree)(shadow);
        return -14;
    }
    shadow_pa = se_pa((se_u64)(se_ulong)shadow);
    if (!shadow_pa) {
        ((void (*)(void *))p_vfree)(shadow);
        return -15;
    }

    memset(&sa, 0, sizeof(sa));
    sa.entry_va = entry_va;
    sa.old_desc = desc;

    if (kind == 0) {
        se_u64 pa_mask = mask_ul(47, ps);

        new_desc = (desc & ~pa_mask) | (shadow_pa & pa_mask);
        flush_start = page_va;
        flush_end = page_va + page_size;
        pr_info("sehide: shadow page kind off=%llu shadow_pa=%016llx\n",
                (unsigned long long)off, (unsigned long long)shadow_pa);
    } else {
        int block_bits = (3 - lv) * (ps - 3) + ps;
        se_u64 block_mask = mask_ul(47, block_bits);
        se_u64 block_pa = desc & block_mask;
        se_u64 block_va = tva & ~((1ull << block_bits) - 1ull);
        se_u32 order = (se_u32)(ps - 12);
        se_u64 table_va, table_pa;
        se_u64 n_entries = 1ull << (block_bits - ps);
        se_u64 i, attrs, tidx;

        /* PTE 表页：__get_free_pages（kmalloc 不保证页对齐物理）。
         * 表页被硬件页表引用，故意不释放（与 KP 自身常驻分配同类）。 */
        table_va = ((se_u64 (*)(se_u32, se_u32))p_gfp)(0xcc0u, order);
        if (!table_va || !se_kptr_ok(table_va))
            return -16;
        memset((void *)(se_ulong)table_va, 0, page_size);

        attrs = desc & (mask_ul(63, 48) | 0xFFCull);   /* 属性位：63:48 + 11:2 */
        for (i = 0; i < n_entries; i++) {
            se_u64 base = block_pa + i * page_size;
            se_u64 pte = (base & mask_ul(47, ps)) | attrs | 3ull;

            *(se_u64 *)(se_ulong)(table_va + i * 8ull) = pte;
        }
        tidx = (tva - block_va) >> ps;
        *(se_u64 *)(se_ulong)(table_va + tidx * 8ull) =
            (shadow_pa & mask_ul(47, ps)) | attrs | 3ull;

        table_pa = se_pa(table_va);
        if (!table_pa || !se_kptr_ok(table_pa))
            return -17;
        /* table 描述符：PMD_TYPE_TABLE | PMD_TABLE_UXN（mmu.c:205-209，
         * NO_EXEC 才加 PXN —— 我们要 exec，不加） */
        new_desc = (table_pa & mask_ul(47, ps)) | 3ull | (1ull << 60);
        flush_start = block_va;
        flush_end = block_va + (1ull << block_bits);
        g_rec.entry_va = entry_va;
        g_rec.old_desc = desc;
        pr_info("sehide: shadow split blk=%dK n=%llu tidx=%llu table_pa=%016llx\n",
                (1 << (block_bits - 10)), (unsigned long long)n_entries,
                (unsigned long long)tidx, (unsigned long long)table_pa);
    }

    sa.new_desc = new_desc;
    sa.flush_start = flush_start;
    sa.flush_end = flush_end;
    rc = ((int (*)(void *, void *, void *))p_stop_machine)
        (se_shadow_stop_cb, &sa, 0);
    if (rc) {
        ((void (*)(void *))p_vfree)(shadow);
        return -18;
    }

    g_rec.target = tva;
    if (kind == 0) {
        g_rec.entry_va = entry_va;
        g_rec.old_desc = desc;
    }
    g_rec.shadow = shadow;
    g_rec.kind = kind;
    g_rec.tramp_len = tramp_n * 4;
    g_shadow_installed = 1;

    /* backup = 影子页内原函数续体：跳板之后的地址即原文（零重定位） */
    if (backup)
        *backup = (void *)((se_u8 *)shadow + off + (se_u64)(tramp_n * 4));
    pr_info("sehide: shadow hook installed at %016lx kind=%d\n",
            (unsigned long)tva, kind);
    return 0;
}

void se_shadow_remove_all(void)
{
    struct se_stop_arg sa;

    if (!g_shadow_installed || !p_stop_machine)
        return;

    memset(&sa, 0, sizeof(sa));
    sa.entry_va = g_rec.entry_va;
    sa.old_desc = g_rec.old_desc & ~1ull;
    sa.new_desc = g_rec.old_desc;
    if (g_rec.kind == 0) {
        sa.flush_start = g_rec.target & ~((1ull << g_mm_page_shift) - 1ull);
        sa.flush_end = sa.flush_start + (1ull << g_mm_page_shift);
    } else {
        sa.flush_start = g_rec.target & ~0x1FFFFFull;
        sa.flush_end = sa.flush_start + 0x200000ull;
    }
    ((int (*)(void *, void *, void *))p_stop_machine)(se_shadow_stop_cb, &sa, 0);
    if (g_rec.shadow && p_vfree)
        ((void (*)(void *))p_vfree)(g_rec.shadow);
    g_shadow_installed = 0;
    pr_info("sehide: shadow hook removed\n");
}
