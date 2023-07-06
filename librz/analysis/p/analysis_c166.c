// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_types.h>
#include <rz_analysis.h>

#include "../asm/arch/c166/c166_dis.h"

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
		rz_warn_if_reached();
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

static void c166_set_jump_target_from_caddr(RzAnalysisOp *op, ut16 target) {
	// TODO: Is this correct?
	const ut32 segment = op->addr & 0xFF0000;
	op->jump = segment | (target & 0xFFFE);
}


static RzAnalysisValue* c166_new_reg_value(RzAnalysis *analysis, ut8 reg, bool byte) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_REG;
	if (reg < 0xF0) {
		//op->mmio_address = 0xFE00 + (2 * reg);
		val->base = 0xFE00 + (2 * reg);
	} else {
		if (byte) {
			val->reg = rz_reg_get(analysis->reg, c166_rb[reg & 0xF], RZ_REG_TYPE_GPR);
		} else {
			val->reg = rz_reg_get(analysis->reg, c166_rw[reg & 0xF], RZ_REG_TYPE_GPR);

		}
	}
	return val;
}

static RzAnalysisValue* c166_new_gpr_value(RzAnalysis *analysis, ut8 i, bool byte) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_REG;
	if (byte) {
		val->reg = rz_reg_get(analysis->reg, c166_rb[i & 0xF], RZ_REG_TYPE_GPR);
	} else {
		val->reg = rz_reg_get(analysis->reg, c166_rw[i & 0xF], RZ_REG_TYPE_GPR);
	}
	return val;
}

static RzAnalysisValue* c166_new_mem_value(RzAnalysis *analysis, ut16 mem) {
	//static RzRegItem r;
	//ZERO_FILL(r);
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_MEM;
	if (mem < 0x4000) {
		//r.name = "DDP0";
		//val->reg = &r;
		val->reg = rz_reg_get(analysis->reg, "DPP0", RZ_REG_TYPE_GPR);
	} else if (mem < 0x8000) {
		//r.name = "DDP1";
		//val->reg = &r;
		val->reg = rz_reg_get(analysis->reg, "DPP1", RZ_REG_TYPE_GPR);
	} else if (mem < 0xC000) {
		//r.name = "DDP2";
		//val->reg = &r;
		val->reg = rz_reg_get(analysis->reg, "DPP2", RZ_REG_TYPE_GPR);
	} else {
		//r.name = "DDP3";
		//val->reg = &r;
		val->reg = rz_reg_get(analysis->reg, "DPP3", RZ_REG_TYPE_GPR);
	}
	val->delta = mem & 0x3FFF;
	return val;
}

static RzAnalysisValue* c166_new_imm_value(ut16 data, bool absolute) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_IMM;
	val->imm = data;
	val->absolute = absolute;
	return val;
}

static inline void c166_op_rn_rm(RzAnalysis *analysis, RzAnalysisOp *op, ut8 nm, ut32 type, bool byte) {
	op->dst = c166_new_gpr_value(analysis, (nm >> 4) & 0xf, byte);
	//op->src[0] = op->dst;
	op->src[0] = c166_new_gpr_value(analysis, nm & 0xf, byte);
	op->type = type;
}

static inline void c166_op_rn_x(RzAnalysis *analysis, RzAnalysisOp *op, ut8 nx, ut32 type, bool byte) {
	op->dst = c166_new_gpr_value(analysis, (nx >> 4) & 0xf, byte);
	//op->src[0] = op->dst;
	switch ((nx >> 2) & 0b11) {
		case 0b11:
			op->src[0] = c166_new_gpr_value(analysis, nx & 0b11, false);
			op->src[0]->memref = byte ? 1: 2;
			//op->type2 = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case 0b10:
			op->src[0] = c166_new_gpr_value(analysis, nx & 0b11, false);
			op->src[0]->memref = byte ? 1: 2;
			break;
		default:
			op->src[0] = c166_new_imm_value(nx & 0b111, true);
			break;
	}
	op->type = type;
}

static int c166_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	struct c166_cmd cmd;
	if (!op) {
		return 1;
	}

	if (analysis->pcalign == 0) {
		analysis->pcalign = 2;
	}

	const ut8 size = c166_decode_command(buf, &cmd, len);
	if (size < 0) {
		return size;
	}
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->size = size;
	op->nopcode = size;
	switch (buf[0]) {
	case C166_ADD_Rwn_Rwm:
	case C166_ADDC_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_ADD, false);
		break;
	case C166_ADDB_Rbn_Rbm:
	case C166_ADDCB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_ADD, true);
		break;
	case C166_ADD_Rwn_x:
	case C166_ADDC_Rwn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_ADD, false);
		break;
	case C166_ADDB_Rbn_x:
	case C166_ADDCB_Rbn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_ADD, true);
		break;
	case C166_ADD_mem_reg:
	case C166_ADD_reg_mem:
	case C166_ADDB_mem_reg:
	case C166_ADDB_reg_mem:
	case C166_ADDC_mem_reg:
	case C166_ADDC_reg_mem:
	case C166_ADDCB_mem_reg:
	case C166_ADDCB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_ADD_reg_data16:
	case C166_ADDC_reg_data16:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (buf[1] > 0xF0) {
			op->reg = c166_rb[buf[1] & 0xF];
		}
		op->val = rz_read_at_le16(buf, 2);
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_ADDB_reg_data8:
	case C166_ADDCB_reg_data8:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (buf[1] > 0xF0) {
			op->reg = c166_rb[buf[1] & 0xF];
		}
		op->val = buf[2];
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;

	case C166_SUB_Rwn_Rwm:
	case C166_SUBC_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_SUB, false);
		break;
	case C166_SUBB_Rbn_Rbm:
	case C166_SUBCB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_SUB, true);
		break;
	case C166_SUB_Rwn_x:
	case C166_SUBC_Rwn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_SUB, false);
		break;
	case C166_SUBB_Rbn_x:
	case C166_SUBCB_Rbn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_SUB, true);
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
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_MUL, false);
		break;
	case C166_DIV_Rwn:
	case C166_DIVL_Rwn:
	case C166_DIVLU_Rwn:
	case C166_DIVU_Rwn:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case C166_AND_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_AND, false);
		break;
	case C166_ANDB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_AND, true);
		break;
	case C166_AND_Rwn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_AND, false);
		break;
	case C166_ANDB_Rbn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_AND, true);
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
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_OR, false);
		break;
	case C166_OR_Rwn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_OR, false);
		break;
	case C166_ORB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_OR, true);
		break;
	case C166_ORB_Rbn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_OR, true);
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
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_XOR, false);
		break;
	case C166_XOR_Rwn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_XOR, false);
		break;
	case C166_XORB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_XOR, true);
		break;
	case C166_XORB_Rbn_x:
		c166_op_rn_x(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_XOR, true);
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
	case C166_PUSH_reg:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_SHL_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_SHL, false);
		break;
	case C166_SHL_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;

	case C166_ASHR_Rwn_Rwm:
	case C166_SHR_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_SHR, false);
		break;
	case C166_SHR_Rwn_data4:
	case C166_ASHR_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case C166_ROL_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_ROL, false);
		break;
	case C166_ROL_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case C166_ROR_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_ROR, false);
		break;
	case C166_ROR_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;

	case C166_MOV_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_MOV, false);
		break;
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
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_reg_value(analysis, buf[1], false);
		op->src[0] = c166_new_imm_value(rz_read_at_le16(buf, 2), true);
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_MOVB_reg_data8:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_reg_value(analysis, buf[1], true);
		op->src[0] = c166_new_imm_value(rz_read_at_le16(buf, 2) & 0xFF, true);
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_MOV_reg_mem:
	case C166_MOVB_reg_mem:
	case C166_MOVBS_reg_mem:
	case C166_MOVBZ_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_reg_value(analysis, buf[1], buf[0] != C166_MOV_reg_mem);
		op->src[0] = c166_new_mem_value(analysis, rz_read_at_le16(buf, 2));
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_MOV_mem_reg:
	case C166_MOVB_mem_reg:
	case C166_MOVBS_mem_reg:
	case C166_MOVBZ_mem_reg:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->src[0] = c166_new_reg_value(analysis, buf[1], buf[0] != C166_MOV_mem_reg);
		op->dst = c166_new_mem_value(analysis, rz_read_at_le16(buf, 2));
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
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
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		op->reg = c166_rw[(buf[1] >> 4) & 0xF];
		break;
	case C166_CPLB_Rbn:
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		op->reg = c166_rb[(buf[1] >> 4) & 0xF];
		break;

	case C166_CMP_Rwn_Rwm:
	case C166_CMP_Rwn_x:
	case C166_CMPD1_Rwn_data4:
	case C166_CMPD2_Rwn_data4:
	case C166_CMPI1_Rwn_data4:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPD1_Rwn_data16:
	case C166_CMPD2_Rwn_data16:
	case C166_CMPI1_Rwn_data16:
	case C166_CMPI2_Rwn_data16:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->reg = c166_rw[(buf[1] >> 4) & 0xF];
		break;
	case C166_CMPB_Rbn_Rbm:
	case C166_CMPB_Rbn_x:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->reg = c166_rb[(buf[1] >> 4) & 0xF];
		break;

	case C166_CMPD1_Rwn_mem:
	case C166_CMPD2_Rwn_mem:
	case C166_CMPI1_Rwn_mem:
	case C166_CMPI2_Rwn_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->reg = c166_rw[buf[1] & 0xF];
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
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = RZ_TYPE_COND_EQ;
		op->jump = addr + op->size + (2 * ((st8)buf[2]));
		op->fail = addr + op->size;
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_JNB_bitaddr_rel:
	case C166_JNBS_bitaddr_rel:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = RZ_TYPE_COND_NE;
		op->jump = addr + op->size + (2 * ((st8)buf[2]));
		op->fail = addr + op->size;
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_JMPA_cc_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
		c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
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
		op->jump = addr + op->size + (2 * ((st8)buf[1]));
		op->fail = addr + op->size;
		break;
	case C166_JMPS_seg_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (((ut32)buf[1]) << 16) | ((ut32)rz_read_at_le16(buf, 2));
		break;
	case C166_CALLA_cc_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
		c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
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
		op->jump = addr + op->size + (2 * ((st8)buf[1]));
		break;
	case C166_CALLS_seg_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (((ut32)buf[1]) << 16) | ((ut32)rz_read_at_le16(buf, 2));
		break;
	case C166_PCALL_reg_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	}
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
			"=PC	pc\n"
			"=SP	sp\n"
			"=A0	r0\n"
			"=A1	r1\n"
			// "gpr	r0	.16	0	0\n"
			// "gpr	r1	.16	2	0\n"
			// "gpr	r2	.16	4	0\n"
			// "gpr	r3	.16	6	0\n"
			// "gpr	r4	.16	8	0\n"
			// "gpr	r5	.16	10	0\n"
			// "gpr	r6	.16	12	0\n"
			// "gpr	r7	.16	14	0\n"
			// "gpr	r8	.16	16	0\n"
			// "gpr	r9	.16	18	0\n"
			// "gpr	r10	.16	20	0\n"
			// "gpr	r11	.16	22	0\n"
			// "gpr	r12	.16	24	0\n"
			// "gpr	r13	.16	26	0\n"
			// "gpr	r14	.16	28	0\n"
			// "gpr	r15	.16	30	0\n"

			"gpr	r0	.16	64512	0\n"
			"gpr	r1	.16	64514	0\n"
			"gpr	r2	.16	64516	0\n"
			"gpr	r3	.16	64518	0\n"
			"gpr	r4	.16	64520	0\n"
			"gpr	r5	.16	64522	0\n"
			"gpr	r6	.16	64524	0\n"
			"gpr	r7	.16	64526	0\n"
			"gpr	r8	.16	64528	0\n"
			"gpr	r9	.16	64530	0\n"
			"gpr	r10	.16	64532	0\n"
			"gpr	r11	.16	64534	0\n"
			"gpr	r12	.16	64536	0\n"
			"gpr	r13	.16	64538	0\n"
			"gpr	r14	.16	64540	0\n"
			"gpr	r15	.16	64542	0\n"

			// Sub regs
			"gpr	rl0	.8	64512	0\n"
			"gpr	rh0	.8	64513	0\n"
			"gpr	rl1	.8	64514	0\n"
			"gpr	rh1	.8	64515	0\n"
			"gpr	rl2	.8	64516	0\n"
			"gpr	rh2	.8	64517	0\n"
			"gpr	rl3	.8	64518	0\n"
			"gpr	rh3	.8	64519	0\n"
			"gpr	rl4	.8	64520	0\n"
			"gpr	rh4	.8	64521	0\n"
			"gpr	rl5	.8	64522	0\n"
			"gpr	rh5	.8	64523	0\n"
			"gpr	rl6	.8	64524	0\n"
			"gpr	rh6	.8	64525	0\n"
			"gpr	rl7	.8	64526	0\n"
			"gpr	rh7	.8	64527	0\n"

			"gpr	DPP0	.16	65024	0\n"
			"gpr	DPP1	.16	65026	0\n"
			"gpr	DPP2	.16	65028	0\n"
			"gpr	DPP3	.16	65030	0\n"
			"gpr	CSP	    .16	65032	0\n"

			"gpr	MDH	    .16	65036	0\n"
			"gpr	MDL	    .16	65038	0\n"
			"gpr	CP	    .16	65040	0\n"
			"gpr	SP	    .16	65042	0\n"
			"gpr	STKOV	.16	65044	0\n"
			"gpr	STKUN	.16	65046	0\n"
			"gpr	PSW		.16	65296	0\n"
			"gpr	ONES	.16	65308	0\n"
			"gpr	ZEROS	.16	65310	0\n"
			;
	return strdup(p);
}

RzAnalysisPlugin rz_analysis_plugin_c166 = {
	.name = "c166",
	.desc = "Bosch/Siemens C166 analysis plugin",
	.license = "LGPL3",
	.arch = "c166",
	.bits = 16,
	.esil = false,
	.op = &c166_op,
	.get_reg_profile = &get_reg_profile
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_c166,
	.version = RZ_VERSION
};
#endif
