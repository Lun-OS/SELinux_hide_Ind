/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "sehide.h"

struct sepol_data {
    se_u32 cmd;
    se_u32 subcmd;
};

struct sepol_batch_cursor {
    const se_u8 *cur;
    const se_u8 *end;
};

static size_t sepol_remaining(const struct sepol_batch_cursor *cursor)
{
    return (size_t)(cursor->end - cursor->cur);
}

static int sepol_read_cmd_header(struct sepol_batch_cursor *cursor, struct sepol_data *header)
{
    if (sepol_remaining(cursor) < sizeof(*header)) {
        return -22;
    }

    memcpy(header, cursor->cur, sizeof(*header));
    cursor->cur += sizeof(*header);

    return 0;
}

static int sepol_read_string(struct sepol_batch_cursor *cursor, const char **out)
{
    se_u32 len;
    const char *str;

    if (sepol_remaining(cursor) < sizeof(len)) {
        return -22;
    }

    len = se_rd32(cursor->cur);
    cursor->cur += sizeof(len);

    if (len >= sepol_remaining(cursor)) {
        return -22;
    }

    str = (const char *)cursor->cur;
    {
        se_u32 i;

        for (i = 0; i < len; i++) {
            if (str[i] == '\0')
                return -22;
        }
    }
    if (str[len] != '\0') {
        return -22;
    }

    cursor->cur += len + 1;
    if (len == 0) {
        *out = 0;      /* ALL */
        return 0;
    }

    *out = str;
    return 0;
}

static int sepol_expected_argc(se_u32 cmd)
{
    switch (cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        return 4;
    case KSU_SEPOLICY_CMD_XPERM:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_STATE:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
        return 2;
    case KSU_SEPOLICY_CMD_ATTR:
        return 1;
    case KSU_SEPOLICY_CMD_TYPE_TRANSITION:
        return 5;
    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
        return 4;
    case KSU_SEPOLICY_CMD_GENFSCON:
        return 3;
    default:
        return -22;
    }
}

/*
 * 一条 allow/deny 落到副本 avtab。ALL 语义对齐 LKM add_rule_raw：
 *   tgt == ALL -> 遍历副本的 attribute 类型（se_copy_attrs；失败回退超集：
 *                 全部具体 type）
 *   cls == ALL -> 1..nprim 全类
 *   perm == ALL -> 全位；否则单权限名 -> 位掩码
 */
static int sepol_apply_perm(void *db, const char *src, const char *tgt,
                            const char *cls, const char *perm, int deny)
{
    se_u32 sv = 0, cv = 0, mask = 0;
    se_u32 attrs[512];
    se_u32 n, i, c, ncls;

    if (se_type_val_at(db, src, &sv))
        return -22;

    if (cls) {
        if (se_class_val_at(db, cls, &cv))
            return -22;
        ncls = cv;
        if (se_perm_mask_name(db, cls, perm, &mask))
            return -22;
        /* 单类单 perm：直接一条 */
        if (!tgt) {
            se_u32 tgts[512];
            se_u32 nt;

            nt = se_copy_attrs(db, tgts, 512u);
            if (nt && nt < 512u) {
                for (i = 0; i < nt; i++) {
                    if (deny)
                        se_clear_allow_at(db, sv, tgts[i], cv, mask);
                    else if (se_add_allow_at(db, sv, tgts[i], cv, mask))
                        return -22;
                }
                return 0;
            }
            /* 回退超集：全部具体 type */
            {
                se_u32 ntyp = se_sym_nprim((const se_u8 *)db, 3u);
                se_u32 t;

                if (ntyp > 4096u)
                    ntyp = 4096u;
                for (t = 1; t <= ntyp; t++) {
                    if (deny)
                        se_clear_allow_at(db, sv, t, cv, mask);
                    else if (se_add_allow_at(db, sv, t, cv, mask))
                        return -22;
                }
            }
            return 0;
        }
        {
            se_u32 tv = 0;

            if (se_type_val_at(db, tgt, &tv))
                return -22;
            if (deny)
                se_clear_allow_at(db, sv, tv, cv, mask);
            else if (se_add_allow_at(db, sv, tv, cv, mask))
                return -22;
        }
        return 0;
    }

    /* cls == ALL：全类 */
    if (!tgt) {
        n = se_copy_attrs(db, attrs, 512u);
        ncls = se_sym_nprim((const se_u8 *)db, 1u);
        if (!ncls || ncls > 512u)
            ncls = 512u;
        if (n && n < 512u) {
            for (c = 1; c <= ncls; c++)
                for (i = 0; i < n; i++) {
                    if (deny)
                        se_clear_allow_at(db, sv, attrs[i], c, 0xffffffffu);
                    else
                        se_add_allow_at(db, sv, attrs[i], c, 0xffffffffu);
                }
        } else {
            se_u32 ntyp = se_sym_nprim((const se_u8 *)db, 3u);
            se_u32 t;

            if (ntyp > 4096u)
                ntyp = 4096u;
            for (c = 1; c <= ncls; c++)
                for (t = 1; t <= ntyp; t++) {
                    if (deny)
                        se_clear_allow_at(db, sv, t, c, 0xffffffffu);
                    else
                        se_add_allow_at(db, sv, t, c, 0xffffffffu);
                }
        }
        return 0;
    }
    {
        se_u32 tv = 0;

        if (se_type_val_at(db, tgt, &tv))
            return -22;
        ncls = se_sym_nprim((const se_u8 *)db, 1u);
        if (!ncls || ncls > 512u)
            ncls = 512u;
        for (c = 1; c <= ncls; c++) {
            if (deny)
                se_clear_allow_at(db, sv, tv, c, 0xffffffffu);
            else if (se_add_allow_at(db, sv, tv, c, 0xffffffffu))
                return -22;
        }
    }
    return 0;
}

static int se_got_unsupported;
static int apply_one_sepolicy_cmd(void *db, const struct sepol_data *header, const char **args)
{
    switch (header->cmd) {
    case KSU_SEPOLICY_CMD_NORMAL_PERM:
        if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_ALLOW)
            return sepol_apply_perm(db, args[0], args[1], args[2], args[3], 0);
        if (header->subcmd == KSU_SEPOLICY_SUBCMD_NORMAL_PERM_DENY)
            return sepol_apply_perm(db, args[0], args[1], args[2], args[3], 1);
        /* AUDITALLOW / DONTAUDIT 需要 avtab 的非 ALLOW 标志位 datum，v1 不支持 */
        if (!se_got_unsupported++)
            pr_info("sehide: sepol cmd=%u subcmd=%u unsupported by KPM backend\n",
                    header->cmd, header->subcmd);
        return -95;   /* -EOPNOTSUPP */

    case KSU_SEPOLICY_CMD_TYPE_STATE:
        {
            se_u32 tv = 0;

            if (!args[0] || se_type_val_at(db, args[0], &tv))
                return -22;
            if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_PERMISSIVE)
                return se_set_permissive(db, L.perm, tv);
            if (header->subcmd == KSU_SEPOLICY_SUBCMD_TYPE_STATE_ENFORCE)
                return ((int (*)(void *, se_ulong, int))p_ebitmap_set)
                    ((se_u8 *)db + L.perm, (se_ulong)tv, 0);
            return -22;
        }

    /* 以下命令需要 symtab/hashtab 级插入或 xperm datum */
    case KSU_SEPOLICY_CMD_XPERM:
    case KSU_SEPOLICY_CMD_TYPE:
    case KSU_SEPOLICY_CMD_TYPE_ATTR:
    case KSU_SEPOLICY_CMD_ATTR:
    case KSU_SEPOLICY_CMD_TYPE_TRANSITION:
    case KSU_SEPOLICY_CMD_TYPE_CHANGE:
    case KSU_SEPOLICY_CMD_GENFSCON:
        if (!se_got_unsupported++)
            pr_info("sehide: sepol cmd=%u unsupported by KPM backend (needs symtab/avtab alloc)\n",
                    header->cmd);
        return -95;

    default:
        pr_info("sehide: sepol unknown cmd %u\n", header->cmd);
        return -22;
    }
}

long se_handle_sepolicy(const se_u8 *payload, se_u32 len)
{
    struct sepol_batch_cursor cursor;
    struct sepol_data header;
    const char *args[KSU_SEPOLICY_MAX_ARGS];
    se_u32 cmd_index = 0, ok_count = 0;
    long ret = 0;

    if (!payload || !len)
        return -22;
    if (len > KSU_SEPOLICY_MAX_BATCH_SIZE)
        return -75;   /* -EOVERFLOW 近似，对齐 LKM 的 E2BIG 语义 */
    if (!L.ok || !L.copy)
        return -11;

    if (!se_cas32(&g_recal_busy, 0, 1))
        return -11;   /* 与重标定/写门互斥；忙 */

    cursor.cur = payload;
    cursor.end = payload + len;

    while (cursor.cur < cursor.end) {
        int expected_argc, a;
        int rc = sepol_read_cmd_header(&cursor, &header);

        if (rc < 0) {
            pr_info("sehide: sepol bad header #%u\n", cmd_index);
            ret = rc;
            break;
        }

        expected_argc = sepol_expected_argc(header.cmd);
        if (expected_argc < 0 || expected_argc > KSU_SEPOLICY_MAX_ARGS) {
            ret = -22;
            break;
        }
        for (a = 0; a < expected_argc; a++) {
            args[a] = 0;
            rc = sepol_read_string(&cursor, &args[a]);
            if (rc < 0) {
                pr_info("sehide: sepol bad arg #%u/#%d\n", cmd_index, a);
                break;
            }
        }
        if (rc < 0) {
            ret = rc;
            break;
        }

        rc = apply_one_sepolicy_cmd(L.copy, &header, args);
        if (rc < 0)
            pr_info("sehide: sepol cmd #%u failed cmd=%u subcmd=%u rc=%d\n",
                    cmd_index, header.cmd, header.subcmd, rc);
        else
            ok_count++;
        cmd_index++;
    }

    /* Nothing to flush: the copy is only ever read by the renderer. */
    g_recal_busy = 0;
    pr_info("sehide: sepol batch done cmds=%u ok=%u (copy only, live untouched)\n",
            cmd_index, ok_count);
    if (!ret)
        ret = (long)ok_count;
    return ret;
}
