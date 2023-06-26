// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

#include "c166_dis.h"

static const char *c166_cc[] = {
    "cc_UC", // 0
    "cc_NET", // 1
    "cc_Z/EQ", // 2
    "cc_NZ/NE", // 3
    "cc_V", // 4
    "cc_NV", // 5
    "cc_N", // 6
    "cc_NN", // 7
    "cc_C/ULT", // 8
    "cc_NC/UGE", // 9
    "cc_SGT", // A
    "cc_SLE", // B
    "cc_SLT", // C
    "cc_SGE", // D
    "cc_UGT", // E
    "cc_ULE", // F
};

static const char* c166_instr_name(ut8 instr) {
    switch (instr) {
        case C166_ADD_Rw_Rw:
        case C166_ADD_Rw_x:
        case C166_ADD_mem_reg:
        case C166_ADD_reg_mem:
        case C166_ADD_reg_data16:
            return "add";
        case C166_ADDB_Rb_Rb:
        case C166_ADDB_Rb_x:
        case C166_ADDB_mem_reg:
        case C166_ADDB_reg_mem:
        case C166_ADDB_reg_data8:
            return "addb";
        case C166_ADDC_Rw_Rw:
        case C166_ADDC_Rw_x:
        case C166_ADDC_mem_reg:
        case C166_ADDC_reg_mem:
        case C166_ADDC_reg_data16:
            return "addc";
        case C166_ADDCB_Rb_Rb:
        case C166_ADDCB_Rb_x:
        case C166_ADDCB_mem_reg:
        case C166_ADDCB_reg_mem:
        case C166_ADDCB_reg_data8:
            return "addcb";
        case C166_SUB_Rw_Rw:
        case C166_SUB_Rw_x:
        case C166_SUB_mem_reg:
        case C166_SUB_reg_mem:
        case C166_SUB_reg_data16:
            return "sub";
        case C166_SUBB_Rb_Rb:
        case C166_SUBB_Rb_x:
        case C166_SUBB_mem_reg:
        case C166_SUBB_reg_mem:
        case C166_SUBB_reg_data8:
            return "subb";
        case C166_SUBC_Rw_Rw:
        case C166_SUBC_Rw_x:
        case C166_SUBC_mem_reg:
        case C166_SUBC_reg_mem:
        case C166_SUBC_reg_data16:
            return "subc";
        case C166_SUBCB_Rb_Rb:
        case C166_SUBCB_Rb_x:
        case C166_SUBCB_mem_reg:
        case C166_SUBCB_reg_mem:
        case C166_SUBCB_reg_data8:
            return "subcb";
        case C166_MUL_Rw_Rw:
            return "mul";
        case C166_MULU_Rw_Rw:
            return "mulu";
        case C166_DIV_Rw:
            return "div";
        case C166_DIVL_Rw:
            return "divl";
        case C166_DIVLU_Rw:
            return "divlu";
        case C166_DIVU_Rw:
            return "divu";
        case C166_CPL_Rw:
            return "cpl";
        case C166_CPLB_Rb:
            return "cplb";
        case C166_NEG_Rw:
            return "neg";
        case C166_NEGB_Rb:
            return "negb";
        case C166_AND_mem_reg:
        case C166_AND_reg_data16:
        case C166_AND_reg_mem:
        case C166_AND_Rw_Rw:
        case C166_AND_Rw_x:
            return "and";
        case C166_ANDB_mem_reg:
        case C166_ANDB_reg_data8:
        case C166_ANDB_reg_mem:
        case C166_ANDB_Rb_Rb:
        case C166_ANDB_Rb_x:
            return "andb";
        case C166_OR_mem_reg:
        case C166_OR_reg_data16:
        case C166_OR_reg_mem:
        case C166_OR_Rw_Rw:
        case C166_OR_Rw_x:
            return "or";
        case C166_ORB_mem_reg:
        case C166_ORB_reg_data8:
        case C166_ORB_reg_mem:
        case C166_ORB_Rb_Rb:
        case C166_ORB_Rb_x:
            return "orb";
        case C166_XOR_mem_reg:
        case C166_XOR_reg_data16:
        case C166_XOR_reg_mem:
        case C166_XOR_Rw_Rw:
        case C166_XOR_Rw_x:
            return "xor";
        case C166_XORB_mem_reg:
        case C166_XORB_reg_data8:
        case C166_XORB_reg_mem:
        case C166_XORB_Rb_Rb:
        case C166_XORB_Rb_x:
            return "xorb";
        case C166_PRIOR_Rw_Rw:
            return "prior";
        case C166_CMP_reg_data16:
        case C166_CMP_reg_mem:
        case C166_CMP_Rw_Rw:
        case C166_CMP_Rw_x:
            return "cmp";
        case C166_CMPB_reg_data8:
        case C166_CMPB_reg_mem:
        case C166_CMPB_Rb_Rb:
        case C166_CMPB_Rb_x:
            return "cmpb";
        case C166_CMPD1_Rw_data16:
        case C166_CMPD1_Rw_data4:
        case C166_CMPD1_Rw_mem:
            return "cmpd1";
        case C166_CMPD2_Rw_data16:
        case C166_CMPD2_Rw_data4:
        case C166_CMPD2_Rw_mem:
            return "cmpd2";
        case C166_CMPI1_Rw_data16:
        case C166_CMPI1_Rw_data4:
        case C166_CMPI1_Rw_mem:
            return "cmpi1";
        case C166_CMPI2_Rw_data16:
        case C166_CMPI2_Rw_data4:
        case C166_CMPI2_Rw_mem:
            return "cmpi2";
        case C166_SCXT_reg_mem:
        case C166_SCXT_reg_data16:
            return "scxt";
        case C166_SHL_Rw_data4:
        case C166_SHL_Rw_Rw:
            return "shl";
        case C166_SHR_Rw_data4:
        case C166_SHR_Rw_Rw:
            return "shr";
        case C166_ROL_Rw_data4:
        case C166_ROL_Rw_Rw:
            return "rol";
        case C166_ROR_Rw_data4:
        case C166_ROR_Rw_Rw:
            return "ror";
        case C166_ASHR_Rw_data4:
        case C166_ASHR_Rw_Rw:
            return "ashr";
        case C166_MOV_mem_oRw:
        case C166_MOV_mem_reg:
        case C166_MOV_noRw_Rw:
        case C166_MOV_oRw_mem:
        case C166_MOV_oRw_oRw:
        case C166_MOV_oRw_oRwp:
        case C166_MOV_oRw_Rw:
        case C166_MOV_oRwp_oRw:
        case C166_MOV_reg_data16:
        case C166_MOV_reg_mem:
        case C166_MOV_Rw_data4:
        case C166_MOV_Rw_or_oRw_data16:
        case C166_MOV_oRw_data16_or_Rb:
        case C166_MOV_Rw_oRw:
        case C166_MOV_Rw_oRwp:
        case C166_MOV_Rw_Rw:
            return "mov";
        case C166_MOVB_mem_oRw:
        case C166_MOVB_mem_reg:
        case C166_MOVB_noRw_Rb:
        case C166_MOVB_oRw_data16_or_Rb:
        case C166_MOVB_oRw_mem:
        case C166_MOVB_oRw_oRw:
        case C166_MOVB_oRw_oRwp:
        case C166_MOVB_oRw_Rb:
        case C166_MOVB_oRwp_oRw:
        case C166_MOVB_Rb_or_oRw_data16:
        case C166_MOVB_Rb_oRw:
        case C166_MOVB_Rb_oRwp:
        case C166_MOVB_Rb_Rb:
        case C166_MOVB_reg_data8:
        case C166_MOVB_reg_mem:
        case C166_MOVB_Rb_data4:
            return "movb";
        case C166_MOVBS_Rw_Rb:
        case C166_MOVBS_reg_mem:
        case C166_MOVBS_mem_reg:
            return "movbs";
        case C166_MOVBZ_Rw_Rb:
        case C166_MOVBZ_reg_mem:
        case C166_MOVBZ_mem_reg:
            return "movbz";
        case C166_JMPA_cc_caddr:
            return "jmpa";
        case C166_JMPI_cc_oRw:
            return "jmpi";
        case C166_JMPR_cc_C_or_ULT_rel:
        case C166_JMPR_cc_EQ_or_Z_rel:
        case C166_JMPR_cc_N_rel:
        case C166_JMPR_cc_NC_or_NGE_rel:
        case C166_JMPR_cc_NE_or_NZ_rel:
        case C166_JMPR_cc_NET_rel:
        case C166_JMPR_cc_NN_rel:
        case C166_JMPR_cc_NV_rel:
        case C166_JMPR_cc_SGE_rel:
        case C166_JMPR_cc_SGT_rel:
        case C166_JMPR_cc_SLE_rel:
        case C166_JMPR_cc_SLT_rel:
        case C166_JMPR_cc_UC_rel:
        case C166_JMPR_cc_UGT_rel:
        case C166_JMPR_cc_ULE_rel:
        case C166_JMPR_cc_V_rel:
            return "jmpr";
        case C166_JMPS_seg_caddr:
            return "jmps";
        case C166_JB_bitaddr_rel:
            return "jb";
        case C166_JBC_bitaddr_rel:
            return "jbc";
        case C166_JNB_bitaddr_rel:
            return "jnb";
        case C166_JNBS_bitaddr_rel:
            return "jnbs";
        case C166_CALLA_cc_caddr:
            return "calla";
        case C166_CALLI_cc_Rw:
            return "calli";
        case C166_CALLR_rel:
            return "callr";
        case C166_CALLS_seg_caddr:
            return "calls";
        case C166_PCALL_reg_caddr:
            return "pcall";
        case C166_POP_reg:
            return "pop";
        case C166_PUSH_reg:
            return "push";
        case C166_TRAP_trap7:
            return "trap";
        case C166_RET:
            return "ret";
        case C166_RETS:
            return "rets";
        case C166_RETP_reg:
            return "retp";
        case C166_RETI:
            return "reti";
        case C166_BAND_bitaddr_bitaddr:
            return "band";
        case C166_BOR_bitaddr_bitaddr:
            return "bor";
        case C166_BXOR_bitaddr_bitaddr:
            return "bxor";
        case C166_BCMP_bitaddr_bitaddr:
            return "bcmp";
        case C166_BMOV_bitaddr_bitaddr:
            return "bmov";
        case C166_BMOVN_bitaddr_bitaddr:
            return "bmovn";
        case C166_BFLDL_bitoff_x:
            return "bfldl";
        case C166_BFLDH_bitoff_x:
            return "bfldh";
        case C166_BCLR_bitoff0:
        case C166_BCLR_bitoff1:
        case C166_BCLR_bitoff2:
        case C166_BCLR_bitoff3:
        case C166_BCLR_bitoff4:
        case C166_BCLR_bitoff5:
        case C166_BCLR_bitoff6:
        case C166_BCLR_bitoff7:
        case C166_BCLR_bitoff8:
        case C166_BCLR_bitoff9:
        case C166_BCLR_bitoff10:
        case C166_BCLR_bitoff11:
        case C166_BCLR_bitoff12:
        case C166_BCLR_bitoff13:
        case C166_BCLR_bitoff14:
        case C166_BCLR_bitoff15:
            return "bclr";
        case C166_BSET_bitoff0:
        case C166_BSET_bitoff1:
        case C166_BSET_bitoff2:
        case C166_BSET_bitoff3:
        case C166_BSET_bitoff4:
        case C166_BSET_bitoff5:
        case C166_BSET_bitoff6:
        case C166_BSET_bitoff7:
        case C166_BSET_bitoff8:
        case C166_BSET_bitoff9:
        case C166_BSET_bitoff10:
        case C166_BSET_bitoff11:
        case C166_BSET_bitoff12:
        case C166_BSET_bitoff13:
        case C166_BSET_bitoff14:
        case C166_BSET_bitoff15:
            return "bset";
        case C166_EXTP_Rw_irang2:
        case C166_EXTP_pag10_or_seg8_irang2:
            return "extp";
        case C166_NOP:
            return "nop";
        case C166_SRST:
            return "srst";
        case C166_IDLE:
            return "idle";
        case C166_PWRDN:
            return "pwrdn";
        case C166_SRVWDT:
            return "srvwdt";
        case C166_DISWDT:
            return "diswdt";
        case C166_EINIT:
            return "einit";
        default:
            return "invalid";
    }
}

// Return the reg interpretation in word or byte mode.
// Caller must provide a buf with at least 10 characters.
static const char* c166_reg(char* buf, ut8 reg, bool byte) {
    if (reg >= 0xF0) {
        // Short ‘reg’ addresses from F0 to FF always specify GPRs.
        if (byte)
            return c166_rb[reg & 0xF];
        else
            return c166_rw[reg & 0xF];
    } else {
        // FIXME: ESFR base is 0xF000
        const ut16 addr = 0xFE00 | (2*reg);
        snprintf(buf, 9, "0x%04x", addr);
    }
    return buf;
}

// Format a bitoff value into buf.
// Caller must provide a buf with at least 12 characters.
static const char* c166_bitoff(char* buf, ut8 bitoff) {
    if (bitoff >= 0xF0) {
        // GPR
        snprintf(buf, 11, "r%i", bitoff & 0xF);
    } else if (bitoff >= 0x80) {
        // TODO: ESFR?
        const ut16 addr = 0xFF00 + (2 * (bitoff & 0x7F));
        snprintf(buf, 11, "0x%04x", addr);
    } else {
        // Ram
        const ut16 addr = 0xFD00 + (2 * bitoff);
        snprintf(buf, 11, "0x%04x", addr);
    }
    return buf;
}

static int c166_simple_instr(struct c166_cmd *cmd, const char *instr, int ret) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s", "");
    return ret;
}

static int c166_instr_rw_rw(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "r%i, r%i", (reg >> 4) & 0xF, reg & 0xF);
    return 2;
}

static int c166_instr_rw_x(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 op = reg & 0xF;
    if ((op & 0b1100) == 0b1100) {
        // [Rw+]
        snprintf(cmd->operands, C166_MAX_OPT, "r%i, [r%i+]", (reg >> 4) & 0xF, op & 0b11);
    } else if ((op & 0b1000) == 0b1000) {
        // [Rw]
        snprintf(cmd->operands, C166_MAX_OPT, "r%i, [r%i]", (reg >> 4) & 0xF, op & 0b11);
    } else {
        // #data3
        snprintf(cmd->operands, C166_MAX_OPT, "r%i, #0x%02x", (reg >> 4) & 0xF, op);
    }
    return 2;
}

static int c166_instr_rw_data4(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "r%i, #0x%02x", reg & 0xF, (reg >> 4) & 0xF);
    return 2;
}

static int c166_instr_rb_data4(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", c166_rb[reg & 0xF], (reg >> 4) & 0xF);
    return 2;
}

static int c166_instr_rw_data16(struct c166_cmd *cmd, const char *instr, ut8 reg, ut16 data) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "r%i, #0x%04x", reg & 0xF, data);
    return 4;
}

static int c166_instr_rw_mem(struct c166_cmd *cmd, const char *instr, ut8 reg, ut16 data) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "r%i, 0x%04x", reg & 0xF, data);
    return 4;
}

static int c166_instr_rb_x(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 op = reg & 0xF;
    const char * r = c166_rb[(reg >> 4) & 0xF];
    if ((op & 0b1100) == 0b1100) {
        // [Rb+]
        snprintf(cmd->operands, C166_MAX_OPT, "%s, [%s+]", r, c166_rb[op & 0b11]);
    } else if ((op & 0b1000) == 0b1000) {
        // [Rb]
        snprintf(cmd->operands, C166_MAX_OPT, "%s, [%s]", r, c166_rb[op & 0b11]);
    } else {
        // #data3
        snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", r, op);
    }
    return 2;
}


static int c166_instr_rb_rb(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s, %s", c166_rb[(reg >> 4) & 0xF], c166_rb[reg & 0xF]);
    return 2;
}

static int c166_instr_rw_rb(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "r%i, %s", (reg >> 4) & 0xF, c166_rb[reg & 0xF]);
    return 2;
}

static int c166_instr_rw(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "r%i", (reg >> 4) & 0xF);
    return 2;
}

static int c166_instr_rb(struct c166_cmd *cmd, const char *instr, ut8 reg) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s", c166_rb[(reg >> 4) & 0xF]);
    return 2;
}


static int c166_trap_instr(struct c166_cmd *cmd, const char *instr, ut8 trap7) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut16 addr = 4 * (trap7 & 0x7F);
    snprintf(cmd->operands, C166_MAX_OPT, "#0x%04x", addr);
    return 2;
}

static int c166_instr_irang2(struct c166_cmd *cmd, const char *instr, ut8 irang2) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "#0x%02x", (irang2 >> 4) & 0b0011);
    return 2;
}

static int c166_instr_rw_irang2(struct c166_cmd *cmd, const char *instr, ut8 op) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 m = op & 0xF;
    const ut8 irang2 = (op >> 4) & 0b0011;
    snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", c166_rw[m], irang2);
    return 2;
}

static int c166_instr_pag_irang2(struct c166_cmd *cmd, const char *instr, ut8 op, ut8 op2, ut8 op3) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 irang2 = (op >> 4) & 0b0011;
    snprintf(cmd->operands, C166_MAX_OPT, "#0x%02x%02x, #0x%02x", op2, op3 & 0x3, irang2);
    return 4;
}

static int c166_instr_reg_mem(struct c166_cmd *cmd, const char *instr, ut8 reg, ut16 mem, bool byte) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s, 0x%04x", c166_reg(tmp, reg, byte), mem);
    return 4;
}

static int c166_instr_mem_reg(struct c166_cmd *cmd, const char *instr, ut8 reg, ut16 mem, bool byte) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "0x%04x, %s", mem, c166_reg(tmp, reg, byte));
    return 4;
}

static int c166_instr_reg(struct c166_cmd *cmd, const char *instr, ut8 reg, bool byte) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s", c166_reg(tmp, reg, byte));
    return 4;
}

static int c166_instr_reg_data16(struct c166_cmd *cmd, const char *instr, ut8 reg, ut16 data, bool byte) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%04x", c166_reg(tmp, reg, byte), data);
    return 4;
}

static int c166_instr_reg_data8(struct c166_cmd *cmd, const char *instr, ut8 reg, ut8 data, bool byte) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    // 8-bit immediate constant
    // (represented by #data8, where byte xx is not significant)
    // rz_read_at_le16 swaps so use lower
    snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", c166_reg(tmp, reg, byte), data & 0xFF);
    return 4;
}

static int c166_instr_seg_caddr(struct c166_cmd *cmd, const char *instr, ut8 seg, ut16 caddr) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "0x%02x, 0x%04x", seg, caddr);
    return 4;
}

static int c166_instr_reg_caddr(struct c166_cmd *cmd, const char *instr, ut8 reg, ut16 caddr) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%s, 0x%04x", c166_reg(tmp, reg, false), caddr);
    return 4;
}


static int c166_instr_bitoff(struct c166_cmd *cmd, const char *instr, ut8 q, ut8 bitoff) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 bit = (q >> 4) & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT, "%s.%i", c166_bitoff(tmp, bitoff), bit);
    return 2;
}

static int c166_instr_bitaddr_bitaddr(struct c166_cmd *cmd, const char *instr, ut8 qq, ut8 zz, ut8 qz) {
    char tmpq[12];
    char tmpz[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 q = (qz >> 4) & 0xF;
    const ut8 z = qz & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT,
        "%s.%i, %s.%i", c166_bitoff(tmpq, qq), q, c166_bitoff(tmpz, zz), z);
    return 4;
}

static int c166_instr_bitaddr_rel(struct c166_cmd *cmd, const char *instr, ut8 qq, ut8 rr, ut8 q0) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 q = (q0 >> 4) & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT, "%s.%i, %i", c166_bitoff(tmp, qq), q, (st8) rr);
    return 4;
}

static int c166_instr_call_rel(struct c166_cmd *cmd, const char *instr, ut8 rr) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    snprintf(cmd->operands, C166_MAX_OPT, "%i", (st8) rr);
    return 2;
}

static int c166_instr_jmp_rel(struct c166_cmd *cmd, const char *instr, ut8 op1, ut8 rr) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 c = (op1 >> 4) & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT, "%s, %i", c166_cc[c], (st8) rr);
    return 2;
}

static int c166_instr_cc_indirect(struct c166_cmd *cmd, const char *instr, ut8 op) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 c = (op >> 4) & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT, "%s, [r%i]", c166_cc[c], op & 0xF);
    return 2;
}

static int c166_instr_cc_caddr(struct c166_cmd *cmd, const char *instr, ut8 op, ut16 addr) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 c = (op >> 4) & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT, "%s, 0x%04x", c166_cc[c], addr);
    return 4;
}

static int c166_instr_bfld(struct c166_cmd *cmd, const char *instr, ut8 bitoff, ut8 opt1, ut8 opt2, bool high) {
    char tmp[12];
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    if (high) {
        snprintf(cmd->operands, C166_MAX_OPT,
                 "%s, #0x%02x, #0x%02x", c166_bitoff(tmp, bitoff), opt2, opt1);
    } else {
        snprintf(cmd->operands, C166_MAX_OPT,
                 "%s, #0x%02x, #0x%02x", c166_bitoff(tmp, bitoff), opt1, opt2);
    }
    return 4;
}

static int c166_instr_mov_nm(
    struct c166_cmd *cmd,
    const char *instr,
    const char *format,
    ut8 op,
    const char **n_map,
    const char **m_map
) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 n = (op >> 4) & 0xF;
    const ut8 m = op & 0xF;
    snprintf(cmd->operands, C166_MAX_OPT, format, n_map[n], m_map[m]);
    return 2;
}

static int c166_instr_mov_mem_oRw(struct c166_cmd *cmd, const char *instr, ut8 op, ut16 mem, bool swap) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 n = op & 0xF;
    if (swap) {
        snprintf(cmd->operands, C166_MAX_OPT, "[%s], 0x%04x", c166_rw[n], mem);
    } else {
        snprintf(cmd->operands, C166_MAX_OPT, "0x%04x, [%s]", mem, c166_rw[n]);
    }
    return 4;
}

static int c166_instr_mov_nm_data(struct c166_cmd *cmd, const char *instr, ut8 op, ut16 mem, const char **n_map, bool swap) {
    snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
    const ut8 n = (op >> 4) & 0xF;
    const ut8 m = op & 0xF;
    if (swap) {
        snprintf(cmd->operands, C166_MAX_OPT, "[%s+#0x%04x], %s", c166_rw[m], mem, n_map[n]);
    } else {
        snprintf(cmd->operands, C166_MAX_OPT, "%s, [%s+#0x%04x]", n_map[n], c166_rw[m], mem);
    }
    return 4;
}



int c166_decode_command(const ut8 *instr, struct c166_cmd *cmd, int len) {
    if (len >= 2) {
        // Two byte instructions
        switch (instr[0]) {
            case C166_ADD_Rw_Rw:
            case C166_ADDC_Rw_Rw:
            case C166_SUB_Rw_Rw:
            case C166_SUBC_Rw_Rw:
            case C166_MUL_Rw_Rw:
            case C166_MULU_Rw_Rw:
            case C166_AND_Rw_Rw:
            case C166_OR_Rw_Rw:
            case C166_XOR_Rw_Rw:
            case C166_PRIOR_Rw_Rw:
            case C166_CMP_Rw_Rw:
            case C166_SHL_Rw_Rw:
            case C166_SHR_Rw_Rw:
            case C166_ROL_Rw_Rw:
            case C166_ROR_Rw_Rw:
            case C166_ASHR_Rw_Rw:
            case C166_MOV_Rw_Rw:
                return c166_instr_rw_rw(cmd, c166_instr_name(instr[0]), instr[1]);
            case C166_ADDB_Rb_Rb:
            case C166_ADDCB_Rb_Rb:
            case C166_SUBB_Rb_Rb:
            case C166_SUBCB_Rb_Rb:
            case C166_ANDB_Rb_Rb:
            case C166_ORB_Rb_Rb:
            case C166_XORB_Rb_Rb:
            case C166_CMPB_Rb_Rb:
            case C166_MOVB_Rb_Rb:
                return c166_instr_rb_rb(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_ADD_Rw_x:
            case C166_ADDC_Rw_x:
            case C166_SUB_Rw_x:
            case C166_SUBC_Rw_x:
            case C166_CMP_Rw_x:
            case C166_AND_Rw_x:
            case C166_OR_Rw_x:
            case C166_XOR_Rw_x:
                return c166_instr_rw_x(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_ROL_Rw_data4:
            case C166_ROR_Rw_data4:
            case C166_SHL_Rw_data4:
            case C166_SHR_Rw_data4:
            case C166_CMPI1_Rw_data4:
            case C166_CMPI2_Rw_data4:
            case C166_CMPD1_Rw_data4:
            case C166_CMPD2_Rw_data4:
            case C166_ASHR_Rw_data4:
            case C166_MOV_Rw_data4:
                return c166_instr_rw_data4(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_MOVB_Rb_data4:
                return c166_instr_rb_data4(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_ADDB_Rb_x:
            case C166_ADDCB_Rb_x:
            case C166_SUBB_Rb_x:
            case C166_SUBCB_Rb_x:
            case C166_CMPB_Rb_x:
            case C166_ANDB_Rb_x:
            case C166_ORB_Rb_x:
            case C166_XORB_Rb_x:
                return c166_instr_rb_x(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_DIV_Rw:
            case C166_DIVL_Rw:
            case C166_DIVLU_Rw:
            case C166_DIVU_Rw:
            case C166_NEG_Rw:
            case C166_CPL_Rw:
                return c166_instr_rw(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_NEGB_Rb:
            case C166_CPLB_Rb:
                return c166_instr_rb(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_MOVBS_Rw_Rb:
            case C166_MOVBZ_Rw_Rb:
                return c166_instr_rw_rb(cmd, c166_instr_name(instr[0]), instr[1]);

            case C166_POP_reg:
            case C166_PUSH_reg:
            case C166_RETP_reg:
                return c166_instr_reg(cmd, c166_instr_name(instr[0]), instr[1], false);
            case C166_CALLR_rel:
                return c166_instr_call_rel(cmd, "callr", instr[1]);
            case C166_CALLI_cc_Rw:
                return c166_instr_cc_indirect(cmd, "calli", instr[1]);
            case C166_JMPI_cc_oRw:
                return c166_instr_cc_indirect(cmd, "jmpi", instr[1]);
            case C166_JMPR_cc_C_or_ULT_rel:
            case C166_JMPR_cc_EQ_or_Z_rel:
            case C166_JMPR_cc_N_rel:
            case C166_JMPR_cc_NC_or_NGE_rel:
            case C166_JMPR_cc_NE_or_NZ_rel:
            case C166_JMPR_cc_NET_rel:
            case C166_JMPR_cc_NN_rel:
            case C166_JMPR_cc_NV_rel:
            case C166_JMPR_cc_SGE_rel:
            case C166_JMPR_cc_SGT_rel:
            case C166_JMPR_cc_SLE_rel:
            case C166_JMPR_cc_SLT_rel:
            case C166_JMPR_cc_UC_rel:
            case C166_JMPR_cc_UGT_rel:
            case C166_JMPR_cc_ULE_rel:
            case C166_JMPR_cc_V_rel:
                return c166_instr_jmp_rel(cmd, "jmpr", instr[0], instr[1]);

            case C166_BCLR_bitoff0:
            case C166_BCLR_bitoff1:
            case C166_BCLR_bitoff2:
            case C166_BCLR_bitoff3:
            case C166_BCLR_bitoff4:
            case C166_BCLR_bitoff5:
            case C166_BCLR_bitoff6:
            case C166_BCLR_bitoff7:
            case C166_BCLR_bitoff8:
            case C166_BCLR_bitoff9:
            case C166_BCLR_bitoff10:
            case C166_BCLR_bitoff11:
            case C166_BCLR_bitoff12:
            case C166_BCLR_bitoff13:
            case C166_BCLR_bitoff14:
            case C166_BCLR_bitoff15:
                return c166_instr_bitoff(cmd, "bclr", instr[0], instr[1]);
            case C166_BSET_bitoff0:
            case C166_BSET_bitoff1:
            case C166_BSET_bitoff2:
            case C166_BSET_bitoff3:
            case C166_BSET_bitoff4:
            case C166_BSET_bitoff5:
            case C166_BSET_bitoff6:
            case C166_BSET_bitoff7:
            case C166_BSET_bitoff8:
            case C166_BSET_bitoff9:
            case C166_BSET_bitoff10:
            case C166_BSET_bitoff11:
            case C166_BSET_bitoff12:
            case C166_BSET_bitoff13:
            case C166_BSET_bitoff14:
            case C166_BSET_bitoff15:
                return c166_instr_bitoff(cmd, "bset", instr[0], instr[1]);

            case C166_MOV_Rw_oRw:
                return c166_instr_mov_nm(cmd, "mov", "%s, [%s]", instr[1], c166_rw, c166_rw);
            case C166_MOV_Rw_oRwp:
                return c166_instr_mov_nm(cmd, "mov", "%s, [%s+]", instr[1], c166_rw, c166_rw);
            case C166_MOV_oRw_Rw:
                return c166_instr_mov_nm(cmd, "mov", "[%s], %s", instr[1], c166_rw, c166_rw);
            case C166_MOV_noRw_Rw:
                return c166_instr_mov_nm(cmd, "mov", "[-%s], %s", instr[1], c166_rw, c166_rw);
            case C166_MOV_oRw_oRw:
                return c166_instr_mov_nm(cmd, "mov", "[%s], [%s]", instr[1], c166_rw, c166_rw);
            case C166_MOV_oRwp_oRw:
                return c166_instr_mov_nm(cmd, "mov", "[%s+], [%s]", instr[1], c166_rw, c166_rw);
            case C166_MOV_oRw_oRwp:
                return c166_instr_mov_nm(cmd, "mov", "[%s], [%s+]", instr[1], c166_rw, c166_rw);
            case C166_MOVB_Rb_oRw:
                return c166_instr_mov_nm(cmd, "movb", "%s, [%s]", instr[1], c166_rb, c166_rw);
            case C166_MOVB_Rb_oRwp:
                return c166_instr_mov_nm(cmd, "movb", "%s, [%s+]", instr[1], c166_rb, c166_rw);
            case C166_MOVB_oRw_Rb:
                return c166_instr_mov_nm(cmd, "movb", "[%s], %s", instr[1], c166_rw, c166_rb);
            case C166_MOVB_noRw_Rb:
                return c166_instr_mov_nm(cmd, "movb", "[-%s], %s", instr[1], c166_rw, c166_rb);
            case C166_MOVB_oRw_oRw:
                return c166_instr_mov_nm(cmd, "movb", "[%s], [%s]", instr[1], c166_rw, c166_rw);
            case C166_MOVB_oRwp_oRw:
                return c166_instr_mov_nm(cmd, "movb", "[%s+], [%s]", instr[1], c166_rw, c166_rw);
            case C166_MOVB_oRw_oRwp:
                return c166_instr_mov_nm(cmd, "movb", "[%s], [%s+]", instr[1], c166_rw, c166_rw);

            case C166_ATOMIC_or_EXTR_irang2:
                return c166_instr_irang2(cmd, "atomic", instr[1]);
            case C166_EXTP_Rw_irang2:
                return c166_instr_rw_irang2(cmd, "extp", instr[1]);

            case C166_TRAP_trap7:
                return c166_trap_instr(cmd, "trap", instr[1]);
            case C166_NOP:
                if (instr[1] == 0x00)
                    return c166_simple_instr(cmd, "nop", 2);
                break;
            case C166_RET:
                if (instr[1] == 0x00)
                    return c166_simple_instr(cmd, "ret", 2);
                break;
            case C166_RETS:
                if (instr[1] == 0x00)
                    return c166_simple_instr(cmd, "rets", 2);
                break;
            case C166_RETI:
                if (instr[1] == 0x88)
                    return c166_simple_instr(cmd, "reti", 2);
                break;
            default:
                break;
        }
    }
    if (len >= 4) {
        switch (instr[0]) {
            case C166_ADD_reg_mem:
            case C166_ADDC_reg_mem:
            case C166_SUB_reg_mem:
            case C166_SUBC_reg_mem:
            case C166_AND_reg_mem:
            case C166_OR_reg_mem:
            case C166_XOR_reg_mem:
            case C166_CMP_reg_mem:
            case C166_MOV_reg_mem:
            case C166_SCXT_reg_mem:
                return c166_instr_reg_mem(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2), false);
            case C166_ADDB_reg_mem:
            case C166_ADDCB_reg_mem:
            case C166_SUBB_reg_mem:
            case C166_SUBCB_reg_mem:
            case C166_ANDB_reg_mem:
            case C166_ORB_reg_mem:
            case C166_XORB_reg_mem:
            case C166_CMPB_reg_mem:
            case C166_MOVB_reg_mem:
            case C166_MOVBS_reg_mem:
            case C166_MOVBZ_reg_mem:
                return c166_instr_reg_mem(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2), true);

            case C166_ADD_mem_reg:
            case C166_ADDC_mem_reg:
            case C166_SUB_mem_reg:
            case C166_SUBC_mem_reg:
            case C166_AND_mem_reg:
            case C166_OR_mem_reg:
            case C166_XOR_mem_reg:
            case C166_MOV_mem_reg:
                return c166_instr_mem_reg(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2), false);
            case C166_ADDB_mem_reg:
            case C166_ADDCB_mem_reg:
            case C166_SUBB_mem_reg:
            case C166_SUBCB_mem_reg:
            case C166_ANDB_mem_reg:
            case C166_ORB_mem_reg:
            case C166_XORB_mem_reg:
            case C166_MOVB_mem_reg:
            case C166_MOVBS_mem_reg:
            case C166_MOVBZ_mem_reg:
                return c166_instr_mem_reg(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2), true);

            case C166_ADD_reg_data16:
            case C166_ADDC_reg_data16:
            case C166_SUB_reg_data16:
            case C166_SUBC_reg_data16:
            case C166_AND_reg_data16:
            case C166_OR_reg_data16:
            case C166_XOR_reg_data16:
            case C166_CMP_reg_data16:
            case C166_MOV_reg_data16:
            case C166_SCXT_reg_data16:
                return c166_instr_reg_data16(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2), false);

            case C166_CMPD1_Rw_data16:
            case C166_CMPD2_Rw_data16:
            case C166_CMPI1_Rw_data16:
            case C166_CMPI2_Rw_data16:
                return c166_instr_rw_data16(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2));

            case C166_CMPD1_Rw_mem:
            case C166_CMPD2_Rw_mem:
            case C166_CMPI1_Rw_mem:
            case C166_CMPI2_Rw_mem:
                return c166_instr_rw_mem(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2));

            case C166_ADDB_reg_data8:
            case C166_ADDCB_reg_data8:
            case C166_SUBB_reg_data8:
            case C166_SUBCB_reg_data8:
            case C166_ANDB_reg_data8:
            case C166_ORB_reg_data8:
            case C166_XORB_reg_data8:
            case C166_CMPB_reg_data8:
            case C166_MOVB_reg_data8:
                return c166_instr_reg_data8(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2), true);
            case C166_CALLS_seg_caddr:
            case C166_JMPS_seg_caddr:
                return c166_instr_seg_caddr(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2));
            case C166_CALLA_cc_caddr:
            case C166_JMPA_cc_caddr:
                return c166_instr_cc_caddr(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2));
            case C166_JB_bitaddr_rel:
            case C166_JBC_bitaddr_rel:
            case C166_JNB_bitaddr_rel:
            case C166_JNBS_bitaddr_rel:
                return c166_instr_bitaddr_rel(cmd, c166_instr_name(instr[0]), instr[1], instr[2], instr[3]);

            case C166_PCALL_reg_caddr:
                return c166_instr_reg_caddr(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2));

            case C166_MOV_mem_oRw:
                return c166_instr_mov_mem_oRw(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), false);
            case C166_MOV_oRw_mem:
                return c166_instr_mov_mem_oRw(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), true);
            case C166_MOV_Rw_or_oRw_data16:
                 return c166_instr_mov_nm_data(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), c166_rw, false);
            case C166_MOV_oRw_data16_or_Rb:
                 return c166_instr_mov_nm_data(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), c166_rw, true);
            case C166_MOVB_mem_oRw:
                return c166_instr_mov_mem_oRw(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), false);
            case C166_MOVB_oRw_mem:
                return c166_instr_mov_mem_oRw(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), true);
            case C166_MOVB_Rb_or_oRw_data16:
                return c166_instr_mov_nm_data(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), c166_rb, false);
            case C166_MOVB_oRw_data16_or_Rb:
                return c166_instr_mov_nm_data(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), c166_rb, true);

            case C166_BAND_bitaddr_bitaddr:
            case C166_BCMP_bitaddr_bitaddr:
            case C166_BMOV_bitaddr_bitaddr:
            case C166_BMOVN_bitaddr_bitaddr:
            case C166_BOR_bitaddr_bitaddr:
            case C166_BXOR_bitaddr_bitaddr:
                return c166_instr_bitaddr_bitaddr(cmd, c166_instr_name(instr[0]), instr[1], instr[2], instr[3]);

            case C166_BFLDH_bitoff_x:
                return c166_instr_bfld(cmd, "bfldh", instr[1], instr[2], instr[3], true);
            case C166_BFLDL_bitoff_x:
                return c166_instr_bfld(cmd, "bfldl", instr[1], instr[2], instr[3], false);

            case C166_EXTP_pag10_or_seg8_irang2:
                return c166_instr_pag_irang2(cmd, "extp", instr[1], instr[2], instr[3]);

            case C166_SRST:
                if ((instr[1] == 0x48) && (instr[2] == 0xB7) && (instr[3] == 0xB7))
                    return c166_simple_instr(cmd, "srst", 4);
                break;
            case C166_IDLE:
                if ((instr[1] == 0x78) && (instr[2] == 0x87) && (instr[3] == 0x87))
                    return c166_simple_instr(cmd, "idle", 4);
                break;
            case C166_PWRDN:
                if ((instr[1] == 0x68) && (instr[2] == 0x97) && (instr[3] == 0x97))
                    return c166_simple_instr(cmd, "pwrdn", 4);
                break;
            case C166_SRVWDT:
                if ((instr[1] == 0x58) && (instr[2] == 0xA7) && (instr[3] == 0xA7))
                    return c166_simple_instr(cmd, "srvwdt", 4);
                break;
            case C166_DISWDT:
                if ((instr[1] == 0x5A) && (instr[2] == 0xA5) && (instr[3] == 0xA5))
                    return c166_simple_instr(cmd, "diswdt", 4);
                break;
            case C166_EINIT:
                if ((instr[1] == 0x4A) && (instr[2] == 0xB5) && (instr[3] == 0xB5))
                    return c166_simple_instr(cmd, "einit", 4);
                break;
            default:
                break;
        }
    }
	return -1;
}
