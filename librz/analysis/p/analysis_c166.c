// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_types.h>
#include <rz_analysis.h>
#include <rz_util/rz_str_util.h>
#include "../asm/arch/c166/c166_arch.h"



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

static const char* c166_mmio_reg(const ut32 addr) {
	switch (addr) {
	case 0xfe00:
		return "DPP0";
	case 0xfe02:
		return "DPP1";
	case 0xfe04:
		return "DPP2";
	case 0xfe06:
		return "DPP3";
	case 0xfe08:
		return "CSP";
	case 0xfe0c:
		return "MDH";
	case 0xfe0e:
		return "MDL";
	case 0xfe10:
		return "CP";
	case 0xfe12:
		return "SP";
	case 0xfe14:
		return "STKOV";
	case 0xfe16:
		return "STKUN";
	case 0xff10:
		return "PSW";
	default:
		return NULL;
	}
}

static void c166_set_mimo_addr_from_reg(RzAnalysisOp *op, ut8 reg) {
	if (reg < 0xF0) {
		op->mmio_address = 0xFE00 + (2 * reg);
	}
}

static void c166_set_mimo_addr_from_bitoff(RzAnalysisOp *op, ut8 bitoff, bool esfr) {
	if (bitoff < 0xF0) {
		// RAM
		op->mmio_address = 0xFD00 + (2 * bitoff);
	} else if (bitoff < 0xE0) {
		// SFR/EESFR
		const ut16 addr = (2 * (bitoff & 0x7F));
		const ut16 base = (esfr) ? 0xF100 : 0xFF00;
		op->mmio_address = base + addr;
	} else {
		// GPR
		op->mmio_address = 0xFE00 + (2 * (bitoff & 0x0F));
	}

}

static void c166_set_jump_target_from_caddr(RzAnalysisOp *op, ut16 target) {
	// TODO: Is this correct?
	const ut32 segment = op->addr & 0xFF0000;
	op->jump = segment | (target & 0xFFFE);
}

static void c166_set_jump_target_from_orw(RzAnalysis *analysis, RzAnalysisOp *op, ut8 r) {
	// TODO: Is this correct?
	RzRegItem* cp_reg = rz_reg_get(analysis->reg, "CP", RZ_REG_TYPE_GPR);
	RzRegItem* reg = rz_reg_get(analysis->reg, c166_rw[r & 0xF], RZ_REG_TYPE_GPR);
	const ut16 v = rz_reg_get_value(analysis->reg, reg);
	const ut16 cp = rz_reg_get_value(analysis->reg, cp_reg);
	op->jump = cp + 2 * v;
}

static void c166_set_jump_target_seg_caddr(RzAnalysisOp *op, ut8 seg, ut16 target) {
	// seg is the starting address of a 64K memory segment
	// (0, 0x10000, 0x20000, 0x30000, ...).
	op->jump = (((ut32) seg) << 16) | (target & 0xFFFE);
}

static RzAnalysisValue* c166_new_reg_value(const RzAnalysis *analysis, ut8 reg, bool byte) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_REG;
	if (reg < 0xF0) {
		val->base = 0xFE00 + (2 * reg);
		const char* mmio_reg = c166_mmio_reg(val->base);
		if (!IS_NULLSTR(mmio_reg))
			val->reg = rz_reg_get(analysis->reg, mmio_reg, RZ_REG_TYPE_GPR);
	} else if (byte) {
		val->reg = rz_reg_get(analysis->reg, c166_rb[reg & 0xF], RZ_REG_TYPE_GPR);
		val->base = 0xFC00 + (reg & 0xF);
	} else {
		val->reg = rz_reg_get(analysis->reg, c166_rw[reg & 0xF], RZ_REG_TYPE_GPR);
		val->base = 0xFC00 + 2 * (reg & 0xF);
	}
	return val;
}

static RzAnalysisValue* c166_new_gpr_value(RzAnalysis *analysis, ut8 i, bool byte) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_REG;
	if (byte) {
		val->reg = rz_reg_get(analysis->reg, c166_rb[i & 0xF], RZ_REG_TYPE_GPR);
		val->base = 0xFC00 + (i & 0xF);
	} else {
		val->reg = rz_reg_get(analysis->reg, c166_rw[i & 0xF], RZ_REG_TYPE_GPR);
		val->base = 0xFC00 + 2 * (i & 0xF);
	}
	return val;
}

static RzAnalysisValue* c166_new_mem_value(const RzAnalysis *analysis, const C166Instr *instr, ut16 mem) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_MEM;
	RzRegItem* reg;
	if (mem < 0x4000) {
		reg = rz_reg_get(analysis->reg, "DPP0", RZ_REG_TYPE_GPR);
	} else if (mem < 0x8000) {
		reg = rz_reg_get(analysis->reg, "DPP1", RZ_REG_TYPE_GPR);
	} else if (mem < 0xC000) {
		reg = rz_reg_get(analysis->reg, "DPP2", RZ_REG_TYPE_GPR);
	} else {
		reg = rz_reg_get(analysis->reg, "DPP3", RZ_REG_TYPE_GPR);
	}

	switch (instr->ext.mode) {
		case C166_EXT_MODE_NONE:
			val->reg = reg;
			val->base = rz_reg_get_value(analysis->reg, reg) << 14;
			break;
		case C166_EXT_MODE_SEG:
			val->base = ((ut32) instr->ext.value) << 16;
			break;
		case C166_EXT_MODE_PAGE:
			val->reg = reg;
			val->base = ((ut32) instr->ext.value) << 14;
			break;
	}
	val->base += mem & 0x3FFF;
	return val;
}

static RzAnalysisValue* c166_new_imm_value(ut16 data, bool absolute) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_IMM;
	val->imm = data;
	val->absolute = absolute;
	return val;
}

static RzAnalysisValue* c166_new_bitaddr_value(const RzAnalysis *analysis, const C166Instr* instr, ut8 bitoff) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_MEM;
	if (bitoff >= 0xF0) {
		val->reg = rz_reg_get(analysis->reg, c166_rw[bitoff & 0xF], RZ_REG_TYPE_GPR);
		val->base = rz_reg_get_value(analysis->reg, val->reg);
	} else if (bitoff >= 0x80) {
		if (instr->ext.esfr) {
			val->base = 0xF100 + (2 * (bitoff & 0x7F));
		} else {
			val->base = 0xFF00 + (2 * (bitoff & 0x7F));
		}
	} else {
		val->base = 0xFD00 + 2 * bitoff;
	}
	return val;
}

static void c166_op_rn_rm(RzAnalysis *analysis, RzAnalysisOp *op, ut8 nm, ut32 type, bool byte) {
	op->dst = c166_new_gpr_value(analysis, (nm >> 4) & 0xf, byte);
	op->src[0] = c166_new_gpr_value(analysis, nm & 0xf, byte);
	op->type = type;
	switch (type) {
	case RZ_ANALYSIS_OP_TYPE_MOV:
		rz_strbuf_setf(&op->esil, "%s,%s,=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_ADD:
		rz_strbuf_setf(&op->esil, "%s,%s,+=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_SUB:
		rz_strbuf_setf(&op->esil, "%s,%s,-=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_MUL:
		rz_strbuf_setf(&op->esil, "%s,%s,*=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_AND:
		rz_strbuf_setf(&op->esil, "%s,%s,&=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_OR:
		rz_strbuf_setf(&op->esil, "%s,%s,|=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_XOR:
		rz_strbuf_setf(&op->esil, "%s,%s,^=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_SHL:
		rz_strbuf_setf(&op->esil, "%s,%s,<<=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_SHR:
		rz_strbuf_setf(&op->esil, "%s,%s,>>=", op->src[0]->reg->name, op->dst->reg->name);
		break;
	case RZ_ANALYSIS_OP_TYPE_CMP:
		rz_strbuf_setf(&op->esil, "%s,%s,==", op->src[0]->reg->name, op->dst->reg->name);
		break;
	default:
		break;
	}
}

static void c166_op_rn_x(RzAnalysis *analysis, RzAnalysisOp *op, ut8 nx, ut32 type, bool byte) {
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

static void c166_op_neg(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const bool byte = buf[0] == C166_NEGB_Rbn;
	op->type = RZ_ANALYSIS_OP_TYPE_CPL;
	op->dst = c166_new_gpr_value(analysis, (buf[1] >> 4) & 0xF, byte);
	if (op->dst != NULL) {
		rz_strbuf_setf(&op->esil, "0,%s,-=", op->dst->reg->name);
	}
}

static void c166_op_ret(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	rz_strbuf_set(&op->esil, "SP,[],IP,=,2,SP,+=");
}

static void c166_op_rets(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	rz_strbuf_set(&op->esil, "SP,[],IP,=,2,SP,+=,SP,[],CSP,=,2,SP,+=");
}

static void c166_op_retp(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->dst = c166_new_reg_value(analysis, buf[1], false);
	if (op->dst != NULL) {
		if (op->dst->reg) {
			rz_strbuf_setf(&op->esil, "SP,[],IP,=,2,SP,+=,SP,[],2,SP,+=,%s,=", op->dst->reg->name);
		} else {
			rz_strbuf_setf(&op->esil, "SP,[],IP,=,2,SP,+=,SP,[],2,SP,+=,0%"PFMT64x",=[2]", op->dst->base);
		}
	}
}

static void c166_op_ext(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const ut8 irang2 = ((buf[1] >> 4) & 0b11) + 1;
	const ut8 subop = (buf[1] >> 6) & 0b11;
	// subop 00=exts, 01=extp, 10=extsr, 11=expr
	// switch (buf[0]) {
	// case C166_EXTP_or_EXTS_Rwm_irang2: // DC
	// 	if (subop == 0 || subop == 2) {
	// 		ctx->ext_mode = C166_ext_seg_reg;
	// 	} else {
	// 		ctx->ext_mode = C166_ext_page_reg;
	// 	}
	// 	ctx->ext_value = buf[1] & 0xF;
	// 	break;
	// case C166_EXTP_or_EXTS_pag10_or_seg8_irang2: // D7
	// 	if (subop == 0 || subop == 2) {
	// 		ctx->ext_mode = C166_ext_seg;
	// 	} else {
	// 		ctx->ext_mode = C166_ext_page;
	// 	}
	// 	ctx->ext_value = rz_read_at_le16(buf, 2);
	// 	break;
	// default:
	// 	rz_warn_if_reached();
	// 	break;
	// }
	op->delay = irang2;
}

static void c166_op_jmps_seg_caddr(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	c166_set_jump_target_seg_caddr(op, seg, caddr);
	rz_strbuf_setf(
		&op->esil,
		"0x%02x,CSP,=,0x%04x,IP,=,0x%" PFMT64x ",PC,=", seg, caddr, op->jump);
}

static void c166_op_jmpr_cc_rel(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	const ut8 cc = (buf[0] >> 4) & 0xF;
	op->cond = c166_cc_to_cond(cc);
	op->jump = op->addr + op->size + (2 * ((st8)buf[1]));
	op->fail = op->addr + op->size;
	switch (cc) {
	case 0x0: // always
		rz_strbuf_setf(&op->esil, "0x%"PFMT64x",PC,=", op->jump);
		break;
	// TODO cc_NET=1
	case 0x2: // Z / EQ
		rz_strbuf_setf(&op->esil, "$z,?{0x%"PFMT64x",PC,=}", op->jump);
		break;
	case 0x3: // NZ / NE
		rz_strbuf_setf(&op->esil, "$z,!,?{0x%"PFMT64x",PC,=}", op->jump);
		break;
	case 0x4: // V (overflow)
		rz_strbuf_setf(&op->esil, "$o,?{0x%"PFMT64x",PC,=}", op->jump);
		break;
	case 0x5: // NV (no overflow)
		rz_strbuf_setf(&op->esil, "$o,!,?{0x%"PFMT64x",PC,=}", op->jump);
		break;
	case 0x6: // N negative
		rz_strbuf_setf(&op->esil, "15,$s,?{0x%"PFMT64x",PC,=}", op->jump);
		break;
	case 0x7: // NN not negative
		rz_strbuf_setf(&op->esil, "15,$s,!,?{0x%"PFMT64x",PC,=}", op->jump);
		break;

	default:
		break; // TODO the rest

	}
}

static void c166_op_call_seg_caddr(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	c166_set_jump_target_seg_caddr(op, seg, caddr);
	rz_strbuf_setf(
		&op->esil,
		"2,SP,-="
		",CSP,SP,[],="
		",2,SP,-="
		",IP,SP,[],="
		",0x%02x,CSP,="
		",0x%04x,IP,="
		",0x%"PFMT64x",PC,=",
		seg, caddr, op->jump
	);
}

static void c166_op_call_rel(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	op->jump = op->addr + op->size + (2 * ((st8)buf[1]));
	rz_strbuf_setf(
		&op->esil,
		"2,SP,-="
		",IP,SP,[],="
		",0x%"PFMT64x",PC,=",
		op->jump
	);

}

static void c166_op_call_cc_caddr(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
	op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
	c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
	op->fail = op->addr + op->size;
}

static void c166_op_mov_reg_data(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const ut8 reg = buf[1];
	const bool byte = buf[0] == C166_MOVB_reg_data8;
	const ut16 mask = byte ? 0xFF : 0xFFFF;
	const ut16 data = rz_read_at_le16(buf, 2) & mask;

	op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	op->dst = c166_new_reg_value(analysis, reg, false);
	op->src[0] = c166_new_imm_value(data, true);
	if (op->dst != NULL) {
		op->mmio_address = op->dst->base;
		if (op->dst->reg != NULL) {
			rz_strbuf_setf(&op->esil, "0x%04x,%s,=", data, op->dst->reg->name);
		} else {
			const ut8 n = byte ? 1 : 2;
			rz_strbuf_setf(&op->esil, "0x%04x,0x%"PFMT64x",=[%i]", data, op->dst->base, n);
		}
	}
}

static void c166_op_mov_reg_mem(const RzAnalysis *analysis, RzAnalysisOp *op, const C166Instr* instr, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	const bool byte = buf[0] != C166_MOV_reg_mem;
	const ut16 mask = byte ? 0xFF : 0xFFFF;
	const ut32 addr = rz_read_at_le16(buf, 2) & mask;
	op->dst = c166_new_reg_value(analysis, buf[1], byte);
	op->src[0] = c166_new_mem_value(analysis, instr, addr);
	if (op->dst != NULL) {
		op->mmio_address = op->dst->base;
		if (op->dst->reg != NULL) {
			rz_strbuf_setf(&op->esil, "0x%06x,[],%s,=", addr, op->dst->reg->name);
		} else {
			const ut8 n = byte ? 1 : 2;
			rz_strbuf_setf(&op->esil, "0x%06x,[],0x%"PFMT64x",=[%i]", addr, op->dst->base, n);
		}
	}

}

static void c166_op_bfld(const RzAnalysis *analysis, RzAnalysisOp *op, const C166Instr *instr,const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	op->dst = c166_new_bitaddr_value(analysis, instr, buf[1]);
	const bool high = buf[0] == C166_BFLDH_bitoff_x;
	const ut16 mask = ~(high ? (buf[2] << 8) : buf[1]);
	const ut16 val = high ? (buf[3] << 8) : buf[3];
	if (op->dst != NULL) {
		op->mmio_address = op->dst->base;
		// dst = (mask & mem) | val
		// mem & mask -> result | val -> dst
		if (op->dst->reg != NULL) {
			rz_strbuf_setf(&op->esil, "%s,0x%04x,&,0x%04x,|,%s,=",
						   op->dst->reg->name, mask, val, op->dst->reg->name);
		} else {
			rz_strbuf_setf(&op->esil, "0x%"PFMT64x",[],0x%04x,&,0x%04x,|,0x%"PFMT64x",=[2]",
						   op->dst->base, mask, val, op->dst->base);
		}
	}

}

static void c166_op_jmp_bitoff(const RzAnalysis *analysis, RzAnalysisOp *op, const RzTypeCond cond, const C166Instr* instr, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->cond = cond;
	op->jump = op->addr + op->size + (2 * ((st8)buf[2]));
	op->fail = op->addr + op->size;
	op->src[0] = c166_new_bitaddr_value(analysis, instr, buf[1]);
	if (op->src[0]) {
		op->mmio_address = op->src[0]->base;
	}
}

static int c166_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op && buf, -1);
	if (len < 2) {
		return -1;
	}
	// if (analysis->pcalign == 0) {
	// 	analysis->pcalign = 2;
	// }
	C166State *state = c166_get_state();
	if (!state) {
		RZ_LOG_FATAL("C166ExtState was NULL.");
	}
	C166Instr instr;
	op->size = c166_disassemble_instruction(state, &instr, buf, len, addr);
	if (op->size < 0) {
		return op->size;
	}

	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;

	rz_strbuf_init(&op->esil);
	rz_strbuf_set(&op->esil, "");

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
		op->dst = c166_new_bitaddr_value(analysis, &instr, buf[1]);
		if (op->dst)
			op->mmio_address = op->dst->base;
		break;
	case C166_BFLDH_bitoff_x:
	case C166_BFLDL_bitoff_x:
		c166_op_bfld(analysis, op, &instr, buf);
		break;
	case C166_BMOV_bitaddr_bitaddr:
	case C166_BMOVN_bitaddr_bitaddr:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_bitaddr_value(analysis, &instr, buf[1]);
		op->src[0] = c166_new_bitaddr_value(analysis, &instr, buf[2]);
		if (op->dst)
			op->mmio_address = op->dst->base;
		break;
	case C166_RET:
		c166_op_ret(analysis, op, buf);
		break;
	case C166_RETI:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case C166_RETS:
		c166_op_rets(analysis, op, buf);
		break;
	case C166_RETP_reg:
		c166_op_retp(analysis, op, buf);
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
	case C166_MOVB_reg_data8:
		c166_op_mov_reg_data(analysis, op, buf);
		break;
	case C166_MOV_reg_mem:
	case C166_MOVB_reg_mem:
	// TODO: Sign/zero extend with esil
	// case C166_MOVBS_reg_mem:
	// case C166_MOVBZ_reg_mem:
		c166_op_mov_reg_mem(analysis, op, &instr, buf);
		break;
	case C166_MOV_mem_reg:
	case C166_MOVB_mem_reg:
	case C166_MOVBS_mem_reg:
	case C166_MOVBZ_mem_reg:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->src[0] = c166_new_reg_value(analysis, buf[1], buf[0] != C166_MOV_mem_reg);
		op->dst = c166_new_mem_value(analysis, &instr, rz_read_at_le16(buf, 2));
		if (op->dst)
			op->mmio_address = op->dst->base;
		break;
	case C166_MOV_mem_oRwn:
	case C166_MOVB_mem_oRwn:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_mem_value(analysis, &instr, rz_read_at_le16(buf, 2));
		if (op->dst)
			op->mmio_address = op->dst->base;
		break;
	case C166_MOV_oRwn_mem:
	case C166_MOVB_oRwn_mem: {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->src[0] = c166_new_mem_value(analysis, &instr, rz_read_at_le16(buf, 2));
		if (op->src[0])
			op->mmio_address = op->src[0]->base;
		break;
	}
	case C166_NEG_Rwn:
	case C166_NEGB_Rbn:
		c166_op_neg(analysis, op, buf);
		break;
	case C166_CPL_Rwn:
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		op->reg = c166_rw[(buf[1] >> 4) & 0xF];
		break;
	case C166_CPLB_Rbn:
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		op->reg = c166_rb[(buf[1] >> 4) & 0xF];
		break;
	case C166_CMP_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_CMP, false);
		break;
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
		c166_op_rn_rm(analysis, op, buf[1], RZ_ANALYSIS_OP_TYPE_CMP, true);
		break;
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
		c166_op_jmp_bitoff(analysis, op, RZ_TYPE_COND_EQ, &instr, buf);
		break;
	case C166_JNB_bitaddr_rel:
	case C166_JNBS_bitaddr_rel:
		c166_op_jmp_bitoff(analysis, op, RZ_TYPE_COND_NE, &instr, buf);
		break;
	case C166_JMPA_cc_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
		c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
		op->fail = addr + op->size;
		break;
	case C166_JMPI_cc_oRwn: {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
		c166_set_jump_target_from_orw(analysis, op, buf[1]);
		op->fail = addr + op->size;
		break;
	}
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
		c166_op_jmpr_cc_rel(op, buf);
		break;
	// Branches unconditionally to the absolute address specified by op2
	// within the segment specified by op1.
	// JMPS op1, op2
	// CSP = op1
	// IP = op2
	// JMPS seg, caddr - FA SS MM MM
	case C166_JMPS_seg_caddr:
		c166_op_jmps_seg_caddr(op, buf);
		break;
	case C166_CALLA_cc_caddr:
		c166_op_call_cc_caddr(op, buf);
		break;
	case C166_CALLI_cc_Rwn:
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->cond = c166_cc_to_cond((buf[1] >> 4) & 0xF);
		op->reg = c166_rw[buf[1] & 0xF];
		op->fail = addr + op->size;
		break;
	case C166_CALLR_rel:
		c166_op_call_rel(op, buf);
		break;
	case C166_CALLS_seg_caddr:
		c166_op_call_seg_caddr(op, buf);
		break;
	case C166_PCALL_reg_caddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_EXTP_or_EXTS_Rwm_irang2:
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2:
		c166_op_ext(analysis, op, buf);
		break;

	}
	//rz_strbuf_fini(&op->esil);
	return op->size;
}


static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
			"=PC	IP\n"
			"=SP	SP\n"
			"=A0	r0\n"
			"=A1	r1\n"

			"gpr	IP	.32	0	0\n"

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
			;
	return strdup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return -1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return -1;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return -1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_c166 = {
	.name = "c166",
	.desc = "Bosch/Siemens C166 analysis plugin",
	.license = "LGPL3",
	.arch = "c166",
	.bits = 16,
	.esil = true,
	.op = &c166_op,
	.archinfo = &archinfo,
	.get_reg_profile = &get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_c166,
	.version = RZ_VERSION
};
#endif
