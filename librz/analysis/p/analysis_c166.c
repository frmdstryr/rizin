// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only


#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

#include "../asm/arch/c166/c166_dis.h"

// static int c166_op_size(ut8 op) {
//     switch (op) {
//         case C166_ADD_Rw_Rw:
//         case C166_ADD_Rw_x:
//         case C166_ADDC_Rw_Rw:
//         case C166_ADDC_Rw_x:
//         case C166_ADDB_Rb_Rb:
//         case C166_ADDB_Rb_x:
//         case C166_ADDCB_Rb_Rb:
//         case C166_ADDCB_Rb_x:
//         case C166_AND_Rw_Rw:
//         case C166_AND_Rw_x:
//         case C166_ANDB_Rb_Rb:
//         case C166_ANDB_Rb_x:
//         case C166_ASHR_Rw_Rw:
//         case C166_ASHR_Rw_data4:
//         case C166_ATOMIC_or_EXTR_irang2:
//         case C166_BCLR_bitoff0:
//         case C166_BCLR_bitoff1:
//         case C166_BCLR_bitoff2:
//         case C166_BCLR_bitoff3:
//         case C166_BCLR_bitoff4:
//         case C166_BCLR_bitoff5:
//         case C166_BCLR_bitoff6:
//         case C166_BCLR_bitoff7:
//         case C166_BCLR_bitoff8:
//         case C166_BCLR_bitoff9:
//         case C166_BCLR_bitoff10:
//         case C166_BCLR_bitoff11:
//         case C166_BCLR_bitoff12:
//         case C166_BCLR_bitoff13:
//         case C166_BCLR_bitoff14:
//         case C166_BCLR_bitoff15:
//         case C166_BSET_bitoff0:
//         case C166_BSET_bitoff1:
//         case C166_BSET_bitoff2:
//         case C166_BSET_bitoff3:
//         case C166_BSET_bitoff4:
//         case C166_BSET_bitoff5:
//         case C166_BSET_bitoff6:
//         case C166_BSET_bitoff7:
//         case C166_BSET_bitoff8:
//         case C166_BSET_bitoff9:
//         case C166_BSET_bitoff10:
//         case C166_BSET_bitoff11:
//         case C166_BSET_bitoff12:
//         case C166_BSET_bitoff13:
//         case C166_BSET_bitoff14:
//         case C166_BSET_bitoff15:
//         case C166_CALLI_cc_Rw:
//         case C166_CALLR_rel:
//         case C166_CMP_Rw_Rw:
//         case C166_CMP_Rw_x:
//         case C166_CMPB_Rb_Rb:
//         case C166_CMPB_Rb_x:
//         case C166_CMPD1_Rw_data4:
//         case C166_CMPD2_Rw_data4:
//         case C166_CMPI1_Rw_data4:
//         case C166_CMPI2_Rw_data4:
//         case C166_CPL_Rw:
//         case C166_CPLB_Rb:
//         case C166_DIV_Rw:
//         case C166_DIVLU_Rw:
//         case C166_DIVL_Rw:
//         case C166_DIVU_Rw:
//         case C166_EXTP_Rw_irang2:
//         case C166_JMPI_cc_oRw:
//         case C166_JMPR_cc_C_or_ULT_rel:
//         case C166_JMPR_cc_EQ_or_Z_rel:
//         case C166_JMPR_cc_NC_or_NGE_rel:
//         case C166_JMPR_cc_NET_rel:
//         case C166_JMPR_cc_NE_or_NZ_rel:
//         case C166_JMPR_cc_NN_rel:
//         case C166_JMPR_cc_NV_rel:
//         case C166_JMPR_cc_N_rel:
//         case C166_JMPR_cc_SGE_rel:
//         case C166_JMPR_cc_SGT_rel:
//         case C166_JMPR_cc_SLE_rel:
//         case C166_JMPR_cc_SLT_rel:
//         case C166_JMPR_cc_UC_rel:
//         case C166_JMPR_cc_UGT_rel:
//         case C166_JMPR_cc_ULE_rel:
//         case C166_JMPR_cc_V_rel:
//         case C166_MOV_Rw_Rw:
//         case C166_MOV_Rw_data4:
//         case C166_MOV_Rw_oRw:
//         case C166_MOV_Rw_oRwp:
//         case C166_MOV_noRw_Rw:
//         case C166_MOV_oRw_Rw:
//         case C166_MOV_oRw_oRw:
//         case C166_MOV_oRw_oRwp:
//         case C166_MOV_oRwp_oRw:
//         case C166_MOVB_Rb_Rb:
//         case C166_MOVB_Rb_data4:
//         case C166_MOVB_Rb_oRw:
//         case C166_MOVB_Rb_oRwp:
//         case C166_MOVB_noRw_Rb:
//         case C166_MOVB_oRw_Rb:
//         case C166_MOVB_oRw_oRw:
//         case C166_MOVB_oRw_oRwp:
//         case C166_MOVB_oRwp_oRw:
//         case C166_MOVBS_Rw_Rb:
//         case C166_MOVBZ_Rw_Rb:
//         case C166_MUL_Rw_Rw:
//         case C166_MULU_Rw_Rw:
//         case C166_NEG_Rw:
//         case C166_NEGB_Rb:
//         case C166_NOP:
//         case C166_OR_Rw_Rw:
//         case C166_OR_Rw_x:
//         case C166_ORB_Rb_Rb:
//         case C166_ORB_Rb_x:
//         case C166_POP_reg:
//         case C166_PRIOR_Rw_Rw:
//         case C166_PUSH_reg:
//         case C166_RET:
//         case C166_RETI:
//         case C166_RETP_reg:
//         case C166_RETS:
//         case C166_ROL_Rw_Rw:
//         case C166_ROL_Rw_data4:
//         case C166_ROR_Rw_Rw:
//         case C166_ROR_Rw_data4:
//         case C166_SHL_Rw_Rw:
//         case C166_SHL_Rw_data4:
//         case C166_SHR_Rw_Rw:
//         case C166_SHR_Rw_data4:
//         case C166_SUB_Rw_Rw:
//         case C166_SUB_Rw_x:
//         case C166_SUBB_Rb_Rb:
//         case C166_SUBB_Rb_x:
//         case C166_SUBC_Rw_Rw:
//         case C166_SUBC_Rw_x:
//         case C166_SUBCB_Rb_Rb:
//         case C166_SUBCB_Rb_x:
//         case C166_TRAP_trap7:
//         case C166_XOR_Rw_Rw:
//         case C166_XOR_Rw_x:
//         case C166_XORB_Rb_Rb:
//         case C166_XORB_Rb_x:
//             return 2;
//         case C166_ADD_mem_reg:
//         case C166_ADD_reg_data16:
//         case C166_ADD_reg_mem:
//         case C166_ADDB_mem_reg:
//         case C166_ADDB_reg_data8:
//         case C166_ADDB_reg_mem:
//         case C166_ADDC_mem_reg:
//         case C166_ADDC_reg_data16:
//         case C166_ADDC_reg_mem:
//         case C166_ADDCB_mem_reg:
//         case C166_ADDCB_reg_data8:
//         case C166_ADDCB_reg_mem:
//         case C166_AND_mem_reg:
//         case C166_AND_reg_data16:
//         case C166_AND_reg_mem:
//         case C166_ANDB_mem_reg:
//         case C166_ANDB_reg_data8:
//         case C166_ANDB_reg_mem:
//         case C166_BAND_bitaddr_bitaddr:
//         case C166_BCMP_bitaddr_bitaddr:
//         case C166_BFLDH_bitoff_x:
//         case C166_BFLDL_bitoff_x:
//         case C166_BMOV_bitaddr_bitaddr:
//         case C166_BMOVN_bitaddr_bitaddr:
//         case C166_BOR_bitaddr_bitaddr:
//         case C166_BXOR_bitaddr_bitaddr:
//         case C166_CALLA_cc_caddr:
//         case C166_CALLS_seg_caddr:
//         case C166_CMP_reg_data16:
//         case C166_CMP_reg_mem:
//         case C166_CMPB_reg_data8:
//         case C166_CMPB_reg_mem:
//         case C166_CMPD1_Rw_data16:
//         case C166_CMPD1_Rw_mem:
//         case C166_CMPD2_Rw_data16:
//         case C166_CMPD2_Rw_mem:
//         case C166_CMPI1_Rw_data16:
//         case C166_CMPI1_Rw_mem:
//         case C166_CMPI2_Rw_data16:
//         case C166_CMPI2_Rw_mem:
//         case C166_DISWDT:
//         case C166_EINIT:
//         case C166_EXTP_pag10_or_seg8_irang2:
//         case C166_IDLE:
//         case C166_JBC_bitaddr_rel:
//         case C166_JB_bitaddr_rel:
//         case C166_JMPA_cc_caddr:
//         case C166_JMPS_seg_caddr:
//         case C166_JNBS_bitaddr_rel:
//         case C166_JNB_bitaddr_rel:
//         case C166_MOV_Rw_or_oRw_data16:
//         case C166_MOV_mem_oRw:
//         case C166_MOV_mem_reg:
//         case C166_MOV_oRw_data16_or_Rb:
//         case C166_MOV_oRw_mem:
//         case C166_MOV_reg_data16:
//         case C166_MOV_reg_mem:
//         case C166_MOVB_Rb_or_oRw_data16:
//         case C166_MOVB_mem_oRw:
//         case C166_MOVB_mem_reg:
//         case C166_MOVB_oRw_data16_or_Rb:
//         case C166_MOVB_oRw_mem:
//         case C166_MOVB_reg_data8:
//         case C166_MOVB_reg_mem:
//         case C166_MOVBS_mem_reg:
//         case C166_MOVBS_reg_mem:
//         case C166_MOVBZ_mem_reg:
//         case C166_MOVBZ_reg_mem:
//         case C166_OR_mem_reg:
//         case C166_OR_reg_data16:
//         case C166_OR_reg_mem:
//         case C166_ORB_mem_reg:
//         case C166_ORB_reg_data8:
//         case C166_ORB_reg_mem:
//         case C166_PCALL_reg_caddr:
//         case C166_PWRDN:
//         case C166_SCXT_reg_data16:
//         case C166_SCXT_reg_mem:
//         case C166_SRST:
//         case C166_SRVWDT:
//         case C166_SUB_mem_reg:
//         case C166_SUB_reg_data16:
//         case C166_SUB_reg_mem:
//         case C166_SUBC_mem_reg:
//         case C166_SUBC_reg_data16:
//         case C166_SUBC_reg_mem:
//         case C166_SUBB_mem_reg:
//         case C166_SUBB_reg_data8:
//         case C166_SUBB_reg_mem:
//         case C166_SUBCB_mem_reg:
//         case C166_SUBCB_reg_data8:
//         case C166_SUBCB_reg_mem:
//         case C166_XOR_mem_reg:
//         case C166_XOR_reg_data16:
//         case C166_XOR_reg_mem:
//         case C166_XORB_mem_reg:
//         case C166_XORB_reg_data8:
//         case C166_XORB_reg_mem:
//             return 4;
//         default:
//             return -1;
//     }
// }

static RzTypeCond c166_cc_to_cond(ut8 cc) {
    // See table 5 in C166 ISM
    switch (cc & 0xF) {
        case 0x0:
            return RZ_TYPE_COND_AL;
        case 0x1:
            return RZ_TYPE_COND_NE; // NE & not end of table
        case 0x2:
            return RZ_TYPE_COND_EQ;
        case 0x3:
            return RZ_TYPE_COND_NE;
        case 0x4:
            return RZ_TYPE_COND_VS;
        case 0x5:
            return RZ_TYPE_COND_VC;
        case 0x6:
            return RZ_TYPE_COND_MI;
        case 0x7:
            return RZ_TYPE_COND_PL;
        case 0x8:
            return RZ_TYPE_COND_HS;
        case 0x9:
            return RZ_TYPE_COND_LO;
        case 0xA:
            return RZ_TYPE_COND_GT;
        case 0xB:
            return RZ_TYPE_COND_LE;
        case 0xC:
            return RZ_TYPE_COND_LT;
        case 0xD:
            return RZ_TYPE_COND_GE;
        case 0xE:
            return RZ_TYPE_COND_HI;
        case 0xF:
            return RZ_TYPE_COND_LS;
        default:
            return RZ_TYPE_COND_EXCEPTION; // unreachable

    }
}

static void c166_set_mimo_addr_from_reg(RzAnalysisOp *op, ut16 reg) {
    if (reg < 0xF0) {
        op->mmio_address = 0xFE00 + (2 * reg);
    }
}

static void c166_set_mimo_addr_from_bitoff(RzAnalysisOp *op, ut16 reg) {
    if (reg < 0x80) {
        op->mmio_address = 0xFD00 + 2 * reg;
    } else if (reg < 0xF0) {
        op->mmio_address = 0xFF00 + 2 * (reg & 0x7F);
    }
}

static int c166_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
    struct c166_cmd cmd;
    if (!op) {
		return 1;
	}
	op->size = c166_decode_command(buf, &cmd, len);
    if (op->size < 0) {
        return -1;
    }
    op->addr = addr;
    op->type = RZ_ANALYSIS_OP_TYPE_UNK;
    switch (buf[0]) {
        case C166_ADD_Rwn_Rwm:
        case C166_ADD_Rwn_x:
        case C166_ADDC_Rwn_Rwm:
        case C166_ADDC_Rwn_x:
        case C166_ADDB_Rbn_Rbm:
        case C166_ADDB_Rbn_x:
        case C166_ADDCB_Rbn_Rbm:
        case C166_ADDCB_Rbn_x:
            op->type = RZ_ANALYSIS_OP_TYPE_ADD;
            break;
        case C166_ADD_mem_reg:
        case C166_ADD_reg_data16:
        case C166_ADD_reg_mem:
        case C166_ADDB_mem_reg:
        case C166_ADDB_reg_data8:
        case C166_ADDB_reg_mem:
        case C166_ADDC_mem_reg:
        case C166_ADDC_reg_data16:
        case C166_ADDC_reg_mem:
        case C166_ADDCB_mem_reg:
        case C166_ADDCB_reg_data8:
        case C166_ADDCB_reg_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_ADD;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_SUB_Rwn_Rwm:
        case C166_SUB_Rwn_x:
        case C166_SUBB_Rbn_Rbm:
        case C166_SUBB_Rbn_x:
        case C166_SUBC_Rwn_Rwm:
        case C166_SUBC_Rwn_x:
        case C166_SUBCB_Rbn_Rbm:
        case C166_SUBCB_Rbn_x:
            op->type = RZ_ANALYSIS_OP_TYPE_SUB;
            break;
        case C166_SUB_mem_reg:
        case C166_SUB_reg_data16:
        case C166_SUB_reg_mem:
        case C166_SUBC_mem_reg:
        case C166_SUBC_reg_data16:
        case C166_SUBC_reg_mem:
        case C166_SUBB_mem_reg:
        case C166_SUBB_reg_data8:
        case C166_SUBB_reg_mem:
        case C166_SUBCB_mem_reg:
        case C166_SUBCB_reg_data8:
        case C166_SUBCB_reg_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_SUB;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_MUL_Rwn_Rwm:
        case C166_MULU_Rwn_Rwm:
            op->type = RZ_ANALYSIS_OP_TYPE_MUL;
            break;
        case C166_DIV_Rwn:
        case C166_DIVL_Rwn:
        case C166_DIVLU_Rwn:
        case C166_DIVU_Rwn:
            op->type = RZ_ANALYSIS_OP_TYPE_DIV;
            break;
        case C166_AND_Rwn_Rwm:
        case C166_AND_Rwn_x:
        case C166_ANDB_Rbn_Rbm:
        case C166_ANDB_Rbn_x:
            op->type = RZ_ANALYSIS_OP_TYPE_AND;
            break;
        case C166_AND_mem_reg:
        case C166_AND_reg_data16:
        case C166_AND_reg_mem:
        case C166_ANDB_mem_reg:
        case C166_ANDB_reg_data8:
        case C166_ANDB_reg_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_AND;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_OR_Rwn_Rwm:
        case C166_OR_Rwn_x:
        case C166_ORB_Rbn_Rbm:
        case C166_ORB_Rbn_x:
            op->type = RZ_ANALYSIS_OP_TYPE_OR;
            break;
        case C166_OR_mem_reg:
        case C166_OR_reg_data16:
        case C166_OR_reg_mem:
        case C166_ORB_mem_reg:
        case C166_ORB_reg_data8:
        case C166_ORB_reg_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_OR;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_XOR_Rwn_Rwm:
        case C166_XOR_Rwn_x:
        case C166_XORB_Rbn_Rbm:
        case C166_XORB_Rbn_x:
            op->type = RZ_ANALYSIS_OP_TYPE_XOR;
            break;
        case C166_XOR_mem_reg:
        case C166_XOR_reg_data16:
        case C166_XOR_reg_mem:
        case C166_XORB_mem_reg:
        case C166_XORB_reg_data8:
        case C166_XORB_reg_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_XOR;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_NOP:
            op->type = RZ_ANALYSIS_OP_TYPE_NOP;
            break;
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
            op->type = RZ_ANALYSIS_OP_TYPE_STORE;
            c166_set_mimo_addr_from_bitoff(op, buf[1]);
            break;
        case C166_BFLDH_bitoff_x:
        case C166_BFLDL_bitoff_x:
            op->type = RZ_ANALYSIS_OP_TYPE_STORE;
            c166_set_mimo_addr_from_bitoff(op, buf[1]);
            break;

        case C166_RET:
        case C166_RETI:
        case C166_RETS:
            op->type = RZ_ANALYSIS_OP_TYPE_RET;
            break;
        case C166_RETP_reg:
            op->type = RZ_ANALYSIS_OP_TYPE_RET;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_POP_reg:
            op->type = RZ_ANALYSIS_OP_TYPE_POP;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_PUSH_reg: {
            op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        }
        case C166_SHL_Rwn_data4:
        case C166_SHL_Rwn_Rwm:
            op->type = RZ_ANALYSIS_OP_TYPE_SHL;
            break;
        case C166_SHR_Rwn_data4:
        case C166_SHR_Rwn_Rwm:
        case C166_ASHR_Rwn_data4:
        case C166_ASHR_Rwn_Rwm:
            op->type = RZ_ANALYSIS_OP_TYPE_SHR;
            break;
        case C166_ROL_Rwn_data4:
        case C166_ROL_Rwn_Rwm:
            op->type = RZ_ANALYSIS_OP_TYPE_ROL;
            break;
        case C166_ROR_Rwn_data4:
        case C166_ROR_Rwn_Rwm:
            op->type = RZ_ANALYSIS_OP_TYPE_ROR;
            break;

        case C166_MOV_Rwn_Rwm:
        case C166_MOV_Rwn_data4:
        case C166_MOV_Rwn_oRwm:
        case C166_MOV_Rwn_oRwmp:
        case C166_MOV_noRwm_Rwn:
        case C166_MOV_oRwm_Rwn:
        case C166_MOV_oRwn_oRwm:
        case C166_MOV_oRwn_oRwmp:
        case C166_MOV_oRwnp_oRwm:
        case C166_MOVB_Rbn_Rbm:
        case C166_MOVB_Rbn_data4:
        case C166_MOVB_Rbn_oRwm:
        case C166_MOVB_Rbn_oRwmp:
        case C166_MOVB_noRwm_Rbn:
        case C166_MOVB_oRwm_Rbn:
        case C166_MOVB_oRwn_oRwm:
        case C166_MOVB_oRwn_oRwmp:
        case C166_MOVB_oRwnp_oRwm:
        case C166_MOVBS_Rwn_Rbm:
        case C166_MOVBZ_Rwn_Rbm:
        case C166_MOV_Rwn_oRwm_data16:
        case C166_MOV_oRwm_data16_Rwn:
        case C166_MOVB_Rbn_oRwm_data16:
        case C166_MOVB_oRwm_data16_Rbn:
            op->type = RZ_ANALYSIS_OP_TYPE_MOV;
            break;
        case C166_MOV_reg_data16:
        case C166_MOV_reg_mem:
        case C166_MOVB_reg_data8:
        case C166_MOVB_reg_mem:
        case C166_MOVBS_reg_mem:
        case C166_MOVBZ_reg_mem:
        case C166_MOV_mem_reg:
        case C166_MOVB_mem_reg:
        case C166_MOVBS_mem_reg:
        case C166_MOVBZ_mem_reg: {
            op->type = RZ_ANALYSIS_OP_TYPE_MOV;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            op->ptr = rz_read_at_le16(buf, 2);
            break;
        }
        case C166_MOV_mem_oRwn:
        case C166_MOVB_mem_oRwn:
        case C166_MOV_oRwn_mem:
        case C166_MOVB_oRwn_mem: {
            op->type = RZ_ANALYSIS_OP_TYPE_MOV;
            op->mmio_address = rz_read_at_le16(buf, 2);
            break;
        }


        // case C166_NEG_Rw:
        // case C166_NEGB_Rb:
        //     op->type = RZ_ANALYSIS_OP_TYPE_NOT; // Correct?
        //     break;

        case C166_CPL_Rwn:
        case C166_CPLB_Rbn:
            op->type = RZ_ANALYSIS_OP_TYPE_CPL;
            break;

        case C166_CMP_Rwn_Rwm:
        case C166_CMP_Rwn_x:
        case C166_CMPB_Rbn_Rbm:
        case C166_CMPB_Rbn_x:
        case C166_CMPD1_Rwn_data4:
        case C166_CMPD2_Rwn_data4:
        case C166_CMPI1_Rwn_data4:
        case C166_CMPI2_Rwn_data4:
        case C166_CMPD1_Rwn_data16:
        case C166_CMPD2_Rwn_data16:
        case C166_CMPI1_Rwn_data16:
        case C166_CMPI2_Rwn_data16:
            op->type = RZ_ANALYSIS_OP_TYPE_CMP;
            break;
        case C166_CMPD1_Rwn_mem:
        case C166_CMPD2_Rwn_mem:
        case C166_CMPI1_Rwn_mem:
        case C166_CMPI2_Rwn_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_CMP;
            op->mmio_address = rz_read_at_le16(buf, 2);
            break;
        case C166_CMP_reg_data16:
        case C166_CMP_reg_mem:
        case C166_CMPB_reg_data8:
        case C166_CMPB_reg_mem:
            op->type = RZ_ANALYSIS_OP_TYPE_CMP;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_TRAP_trap7:
            op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
            break;
        case C166_JB_bitaddr_rel:
        case C166_JBC_bitaddr_rel:
            op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
            op->cond = RZ_TYPE_COND_EQ;
            op->jump = addr + op->size + (2 * ((st8) buf[2]));
            op->fail = addr + op->size;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_JNB_bitaddr_rel:
        case C166_JNBS_bitaddr_rel:
            op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
            op->cond = RZ_TYPE_COND_NE;
            op->jump = addr + op->size + (2 * ((st8) buf[2]));
            op->fail = addr + op->size;
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
        case C166_JMPA_cc_caddr:
            op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
            op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
            op->jump = rz_read_at_le16(buf, 2);
            op->fail = addr + op->size;
            break;
        case C166_JMPI_cc_oRwn:
            op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
            op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
            op->reg = c166_rw[buf[1] & 0xF];
            op->fail = addr + op->size;
            break;
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
            op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
            op->cond = c166_cc_to_cond((buf[0] >> 4) & 0xF);
            op->jump = addr + op->size + (2 * ((st8) buf[1]));
            op->fail = addr + op->size;
            break;
        case C166_JMPS_seg_caddr:
            op->type = RZ_ANALYSIS_OP_TYPE_JMP;
            op->jump = (((ut32) buf[1]) << 16) | ((ut32) rz_read_at_le16(buf, 2));
            break;
        case C166_CALLA_cc_caddr:
            op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
            op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
            op->jump = rz_read_at_le16(buf, 2);
            op->fail = addr + op->size;
            break;
        case C166_CALLI_cc_Rwn:
            op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
            op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
            op->reg = c166_rw[buf[1] & 0xF];
            op->fail = addr + op->size;
            break;
        case C166_CALLR_rel:
            op->type = RZ_ANALYSIS_OP_TYPE_CALL;
            op->jump = addr + op->size + (2 * ((st8) buf[1]));
            break;
        case C166_CALLS_seg_caddr:
            op->type = RZ_ANALYSIS_OP_TYPE_CALL;
            op->jump = (((ut32) buf[1]) << 16) | ((ut32) rz_read_at_le16(buf, 2));
            break;
        case C166_PCALL_reg_caddr:
            op->type = RZ_ANALYSIS_OP_TYPE_CALL;
            op->jump = rz_read_at_le16(buf, 2);
            c166_set_mimo_addr_from_reg(op, buf[1]);
            break;
    }
    return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_c166 = {
    .name = "c166",
    .desc = "Bosch/Siemens C166 analysis plugin",
    .license = "LGPL3",
    .arch = "c166",
    .bits = 16,
    .esil = false,
    .op = &c166_op,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
    .type = RZ_LIB_TYPE_ANALYSIS,
    .data = &rz_analysis_plugin_c166,
    .version = RZ_VERSION
};
#endif
