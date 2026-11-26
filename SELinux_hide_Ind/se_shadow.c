/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * se_shadow.c - mkpms 式页分裂影子页 hook。
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

/* 页表坐标系 */
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

/* 物理地址 */
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

    __asm__ __volatile__("mrs %0, tcr_el1" : "=r"(tcr));
    t1sz = (int)((tcr >> 16) & 0x3full);
    tg1 = (int)((tcr >> 30) & 3ull);
    MM.page_shift = (tg1 == 1) ? 14 : (tg1 == 3) ? 16 : 12;
    {
        int va_bits = 64 - t1sz;
        int pxd_bits = MM.page_shift - 3;

        MM.page_level = (va_bits - 4) / pxd_bits;      
    }

    /*
     * linear 映射偏移改用 KP 的运行期标定值。
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

    {
        int retry;

        for (retry = 0; retry < 2; retry++) {
            se_u64 phys;

            MM.linear_voff = linear_voff_override ?
                linear_voff_override :
                (se_u64)(0ull - (1ull << (64 - t1sz))) - memstart;
            MM.kimage_voff = kimgvoff;

            __asm__ __volatile__("mrs %0, ttbr1_el1" : "=r"(ttbr1));
            MM.pgd_va = (ttbr1 & 0xFFFFFFFFFFFEull) + MM.linear_voff;

            if ((ttbr1 & 0xFFFFFFFFFFFEull) !=
                ((se_u64)p_swapper - kimgvoff)) {
                pr_info("sehide: shadow selfcheck1 fail ttbr1=%016lx "
                        "swapper=%016lx kimgvoff=%016llx\n",
                        (unsigned long)(ttbr1 & 0xFFFFFFFFFFFEull),
                        (unsigned long)p_swapper,
                        (unsigned long long)kimgvoff);
                return -4;
            }

            phys = se_pa((se_u64)p_text);
            if (phys && phys == (se_u64)p_text - kimgvoff)
                break;         

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

/* 清影子页自身 PTE 的 PXN/GP；
 * 写的是 vmalloc 区自己的页表页，不碰保护面）。CONT 组按
 * hotpatch.c:60-78 modify_entry_kernel 的纪律整组处理。 */
static int se_shadow_make_exec(void *shadow)
{
    se_u64 entry_va, desc;
    int lv;

    if (se_walk((se_u64)(se_ulong)shadow, &entry_va, &desc, &lv) < 0)
        return -1;
    /* CONT 组纪律：vmalloc 页带 CONT 极罕见
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

    /* CONT 组纪律：live contiguous mappings may not be manipulated
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

    /* 影子页：vmalloc */
    shadow = ((void *(*)(se_ulong))p_vmalloc)(page_size);
    if (!shadow)
        return -12;
    if (se_kread(shadow, (void *)(se_ulong)page_va, page_size)) {
        ((void (*)(void *))p_vfree)(shadow);
        return -13;
    }

    /* 跳板：branch_absolute 编码，BTI/PAC 首指令处理 */
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
