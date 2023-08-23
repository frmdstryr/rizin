// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

#include "c166_dis.h"

const char *c166_rw[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
};

const char *c166_rb[] = {
	"rl0",
	"rh0",
	"rl1",
	"rh1",
	"rl2",
	"rh2",
	"rl3",
	"rh3",
	"rl4",
	"rh4",
	"rl5",
	"rh5",
	"rl6",
	"rh6",
	"rl7",
	"rh7",
};

const char *c166_cc[] = {
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

const char *c166_extx_names[] = {
	"exts",
	"extp",
	"extsr",
	"extpr"
};

const ut8 c166_opcode_sizes[] = {
	2, // 0x0
	2, // 0x1
	4, // 0x2
	4, // 0x3
	4, // 0x4
	4, // 0x5
	4, // 0x6
	4, // 0x7
	2, // 0x8
	2, // 0x9
	4, // 0xa
	2, // 0xb
	2, // 0xc
	2, // 0xd
	2, // 0xe
	2, // 0xf
	2, // 0x10
	2, // 0x11
	4, // 0x12
	4, // 0x13
	4, // 0x14
	4, // 0x15
	4, // 0x16
	4, // 0x17
	2, // 0x18
	2, // 0x19
	4, // 0x1a
	2, // 0x1b
	2, // 0x1c
	2, // 0x1d
	2, // 0x1e
	2, // 0x1f
	2, // 0x20
	2, // 0x21
	4, // 0x22
	4, // 0x23
	4, // 0x24
	4, // 0x25
	4, // 0x26
	4, // 0x27
	2, // 0x28
	2, // 0x29
	4, // 0x2a
	2, // 0x2b
	2, // 0x2c
	2, // 0x2d
	2, // 0x2e
	2, // 0x2f
	2, // 0x30
	2, // 0x31
	4, // 0x32
	4, // 0x33
	4, // 0x34
	4, // 0x35
	4, // 0x36
	4, // 0x37
	2, // 0x38
	2, // 0x39
	4, // 0x3a
	0, // 0x3b
	2, // 0x3c
	2, // 0x3d
	2, // 0x3e
	2, // 0x3f
	2, // 0x40
	2, // 0x41
	4, // 0x42
	4, // 0x43
	0, // 0x44
	0, // 0x45
	4, // 0x46
	4, // 0x47
	2, // 0x48
	2, // 0x49
	4, // 0x4a
	2, // 0x4b
	2, // 0x4c
	2, // 0x4d
	2, // 0x4e
	2, // 0x4f
	2, // 0x50
	2, // 0x51
	4, // 0x52
	4, // 0x53
	4, // 0x54
	4, // 0x55
	4, // 0x56
	4, // 0x57
	2, // 0x58
	2, // 0x59
	4, // 0x5a
	2, // 0x5b
	2, // 0x5c
	2, // 0x5d
	2, // 0x5e
	2, // 0x5f
	2, // 0x60
	2, // 0x61
	4, // 0x62
	4, // 0x63
	4, // 0x64
	4, // 0x65
	4, // 0x66
	4, // 0x67
	2, // 0x68
	2, // 0x69
	4, // 0x6a
	2, // 0x6b
	2, // 0x6c
	2, // 0x6d
	2, // 0x6e
	2, // 0x6f
	2, // 0x70
	2, // 0x71
	4, // 0x72
	4, // 0x73
	4, // 0x74
	4, // 0x75
	4, // 0x76
	4, // 0x77
	2, // 0x78
	2, // 0x79
	4, // 0x7a
	2, // 0x7b
	2, // 0x7c
	2, // 0x7d
	2, // 0x7e
	2, // 0x7f
	2, // 0x80
	2, // 0x81
	4, // 0x82
	0, // 0x83
	4, // 0x84
	0, // 0x85
	4, // 0x86
	4, // 0x87
	2, // 0x88
	2, // 0x89
	4, // 0x8a
	0, // 0x8b
	0, // 0x8c
	2, // 0x8d
	2, // 0x8e
	2, // 0x8f
	2, // 0x90
	2, // 0x91
	4, // 0x92
	0, // 0x93
	4, // 0x94
	0, // 0x95
	4, // 0x96
	4, // 0x97
	2, // 0x98
	2, // 0x99
	4, // 0x9a
	2, // 0x9b
	2, // 0x9c
	2, // 0x9d
	2, // 0x9e
	2, // 0x9f
	2, // 0xa0
	2, // 0xa1
	4, // 0xa2
	0, // 0xa3
	4, // 0xa4
	4, // 0xa5
	4, // 0xa6
	4, // 0xa7
	2, // 0xa8
	2, // 0xa9
	4, // 0xaa
	2, // 0xab
	2, // 0xac
	2, // 0xad
	2, // 0xae
	2, // 0xaf
	2, // 0xb0
	2, // 0xb1
	4, // 0xb2
	0, // 0xb3
	4, // 0xb4
	4, // 0xb5
	4, // 0xb6
	4, // 0xb7
	2, // 0xb8
	2, // 0xb9
	4, // 0xba
	2, // 0xbb
	2, // 0xbc
	2, // 0xbd
	2, // 0xbe
	2, // 0xbf
	2, // 0xc0
	0, // 0xc1
	4, // 0xc2
	0, // 0xc3
	4, // 0xc4
	4, // 0xc5
	4, // 0xc6
	0, // 0xc7
	2, // 0xc8
	2, // 0xc9
	4, // 0xca
	2, // 0xcb
	2, // 0xcc
	2, // 0xcd
	2, // 0xce
	2, // 0xcf
	2, // 0xd0
	2, // 0xd1
	4, // 0xd2
	0, // 0xd3
	4, // 0xd4
	4, // 0xd5
	4, // 0xd6
	4, // 0xd7
	2, // 0xd8
	2, // 0xd9
	4, // 0xda
	2, // 0xdb
	2, // 0xdc
	2, // 0xdd
	2, // 0xde
	2, // 0xdf
	2, // 0xe0
	2, // 0xe1
	4, // 0xe2
	0, // 0xe3
	4, // 0xe4
	0, // 0xe5
	4, // 0xe6
	4, // 0xe7
	2, // 0xe8
	2, // 0xe9
	4, // 0xea
	2, // 0xeb
	2, // 0xec
	2, // 0xed
	2, // 0xee
	2, // 0xef
	2, // 0xf0
	2, // 0xf1
	4, // 0xf2
	4, // 0xf3
	4, // 0xf4
	0, // 0xf5
	4, // 0xf6
	4, // 0xf7
	0, // 0xf8
	0, // 0xf9
	4, // 0xfa
	2, // 0xfb
	2, // 0xfc
	2, // 0xfd
	2, // 0xfe
	2, // 0xff
};

RZ_API c166_state* c166_get_state()
{
	static c166_state* state = NULL;
	if (state) {
		return state;
	}

	state = calloc(1, sizeof(c166_state));
	if (!state) {
		RZ_LOG_FATAL("Could not allocate memory for c166_state!");
	}
	state->esfr = false;
	state->ext_mode = C166_EXT_MODE_NONE;
	state->ext_value = 0;
	state->i = 0;
	return state;
}

RZ_API void c166_activate_ext(RZ_NONNULL c166_state* state, bool esfr, c166_ext_mode mode, ut8 count, ut16 value)
{
	rz_return_if_fail(state->i == 0);
	rz_return_if_fail(count <= 3);
	state->esfr = esfr;
	state->ext_mode = mode;
	state->i = count;
	state->ext_value = value;
}

RZ_API void c166_maybe_deactivate_ext(RZ_NONNULL c166_state* state)
{
	if (state->i > 0) {
		state->i -= 1;
	} else if (state->i == 0) {
		state->esfr = false;
		state->ext_mode = C166_EXT_MODE_NONE;
		state->ext_value = 0;
	}
}

static const char *c166_instr_name(ut8 instr) {
	switch (instr) {
	case C166_ADD_Rwn_Rwm:
	case C166_ADD_Rwn_x:
	case C166_ADD_mem_reg:
	case C166_ADD_reg_mem:
	case C166_ADD_reg_data16:
		return "add";
	case C166_ADDB_Rbn_Rbm:
	case C166_ADDB_Rbn_x:
	case C166_ADDB_mem_reg:
	case C166_ADDB_reg_mem:
	case C166_ADDB_reg_data8:
		return "addb";
	case C166_ADDC_Rwn_Rwm:
	case C166_ADDC_Rwn_x:
	case C166_ADDC_mem_reg:
	case C166_ADDC_reg_mem:
	case C166_ADDC_reg_data16:
		return "addc";
	case C166_ADDCB_Rbn_Rbm:
	case C166_ADDCB_Rbn_x:
	case C166_ADDCB_mem_reg:
	case C166_ADDCB_reg_mem:
	case C166_ADDCB_reg_data8:
		return "addcb";
	case C166_SUB_Rwn_Rwm:
	case C166_SUB_Rwn_x:
	case C166_SUB_mem_reg:
	case C166_SUB_reg_mem:
	case C166_SUB_reg_data16:
		return "sub";
	case C166_SUBB_Rbn_Rbm:
	case C166_SUBB_Rbn_x:
	case C166_SUBB_mem_reg:
	case C166_SUBB_reg_mem:
	case C166_SUBB_reg_data8:
		return "subb";
	case C166_SUBC_Rwn_Rwm:
	case C166_SUBC_Rwn_x:
	case C166_SUBC_mem_reg:
	case C166_SUBC_reg_mem:
	case C166_SUBC_reg_data16:
		return "subc";
	case C166_SUBCB_Rbn_Rbm:
	case C166_SUBCB_Rbn_x:
	case C166_SUBCB_mem_reg:
	case C166_SUBCB_reg_mem:
	case C166_SUBCB_reg_data8:
		return "subcb";
	case C166_MUL_Rwn_Rwm:
		return "mul";
	case C166_MULU_Rwn_Rwm:
		return "mulu";
	case C166_DIV_Rwn:
		return "div";
	case C166_DIVL_Rwn:
		return "divl";
	case C166_DIVLU_Rwn:
		return "divlu";
	case C166_DIVU_Rwn:
		return "divu";
	case C166_CPL_Rwn:
		return "cpl";
	case C166_CPLB_Rbn:
		return "cplb";
	case C166_NEG_Rwn:
		return "neg";
	case C166_NEGB_Rbn:
		return "negb";
	case C166_AND_mem_reg:
	case C166_AND_reg_data16:
	case C166_AND_reg_mem:
	case C166_AND_Rwn_Rwm:
	case C166_AND_Rwn_x:
		return "and";
	case C166_ANDB_mem_reg:
	case C166_ANDB_reg_data8:
	case C166_ANDB_reg_mem:
	case C166_ANDB_Rbn_Rbm:
	case C166_ANDB_Rbn_x:
		return "andb";
	case C166_OR_mem_reg:
	case C166_OR_reg_data16:
	case C166_OR_reg_mem:
	case C166_OR_Rwn_Rwm:
	case C166_OR_Rwn_x:
		return "or";
	case C166_ORB_mem_reg:
	case C166_ORB_reg_data8:
	case C166_ORB_reg_mem:
	case C166_ORB_Rbn_Rbm:
	case C166_ORB_Rbn_x:
		return "orb";
	case C166_XOR_mem_reg:
	case C166_XOR_reg_data16:
	case C166_XOR_reg_mem:
	case C166_XOR_Rwn_Rwm:
	case C166_XOR_Rwn_x:
		return "xor";
	case C166_XORB_mem_reg:
	case C166_XORB_reg_data8:
	case C166_XORB_reg_mem:
	case C166_XORB_Rbn_Rbm:
	case C166_XORB_Rbn_x:
		return "xorb";
	case C166_PRIOR_Rwn_Rwm:
		return "prior";
	case C166_CMP_reg_data16:
	case C166_CMP_reg_mem:
	case C166_CMP_Rwn_Rwm:
	case C166_CMP_Rwn_x:
		return "cmp";
	case C166_CMPB_reg_data8:
	case C166_CMPB_reg_mem:
	case C166_CMPB_Rbn_Rbm:
	case C166_CMPB_Rbn_x:
		return "cmpb";
	case C166_CMPD1_Rwn_data16:
	case C166_CMPD1_Rwn_data4:
	case C166_CMPD1_Rwn_mem:
		return "cmpd1";
	case C166_CMPD2_Rwn_data16:
	case C166_CMPD2_Rwn_data4:
	case C166_CMPD2_Rwn_mem:
		return "cmpd2";
	case C166_CMPI1_Rwn_data16:
	case C166_CMPI1_Rwn_data4:
	case C166_CMPI1_Rwn_mem:
		return "cmpi1";
	case C166_CMPI2_Rwn_data16:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPI2_Rwn_mem:
		return "cmpi2";
	case C166_SCXT_reg_mem:
	case C166_SCXT_reg_data16:
		return "scxt";
	case C166_SHL_Rwn_data4:
	case C166_SHL_Rwn_Rwm:
		return "shl";
	case C166_SHR_Rwn_data4:
	case C166_SHR_Rwn_Rwm:
		return "shr";
	case C166_ROL_Rwn_data4:
	case C166_ROL_Rwn_Rwm:
		return "rol";
	case C166_ROR_Rwn_data4:
	case C166_ROR_Rwn_Rwm:
		return "ror";
	case C166_ASHR_Rwn_data4:
	case C166_ASHR_Rwn_Rwm:
		return "ashr";
	case C166_MOV_mem_oRwn:
	case C166_MOV_mem_reg:
	case C166_MOV_noRwm_Rwn:
	case C166_MOV_oRwn_mem:
	case C166_MOV_oRwn_oRwm:
	case C166_MOV_oRwn_oRwmp:
	case C166_MOV_oRwm_Rwn:
	case C166_MOV_oRwnp_oRwm:
	case C166_MOV_reg_data16:
	case C166_MOV_reg_mem:
	case C166_MOV_Rwn_data4:
	case C166_MOV_Rwn_oRwm_data16:
	case C166_MOV_oRwm_data16_Rwn:
	case C166_MOV_Rwn_oRwm:
	case C166_MOV_Rwn_oRwmp:
	case C166_MOV_Rwn_Rwm:
		return "mov";
	case C166_MOVB_mem_oRwn:
	case C166_MOVB_mem_reg:
	case C166_MOVB_noRwm_Rbn:
	case C166_MOVB_oRwm_data16_Rbn:
	case C166_MOVB_oRwn_mem:
	case C166_MOVB_oRwn_oRwm:
	case C166_MOVB_oRwn_oRwmp:
	case C166_MOVB_oRwm_Rbn:
	case C166_MOVB_oRwnp_oRwm:
	case C166_MOVB_Rbn_oRwm_data16:
	case C166_MOVB_Rbn_oRwm:
	case C166_MOVB_Rbn_oRwmp:
	case C166_MOVB_Rbn_Rbm:
	case C166_MOVB_reg_data8:
	case C166_MOVB_reg_mem:
	case C166_MOVB_Rbn_data4:
		return "movb";
	case C166_MOVBS_Rwn_Rbm:
	case C166_MOVBS_reg_mem:
	case C166_MOVBS_mem_reg:
		return "movbs";
	case C166_MOVBZ_Rwn_Rbm:
	case C166_MOVBZ_reg_mem:
	case C166_MOVBZ_mem_reg:
		return "movbz";
	case C166_JMPA_cc_caddr:
		return "jmpa";
	case C166_JMPI_cc_oRwn:
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
	case C166_CALLI_cc_Rwn:
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
	case C166_EXTP_or_EXTS_Rwm_irang2:
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2:
		return "extp(r)/exts(r)"; // Requires op
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
		rz_warn_if_reached();
		return "invalid";
	}
}

// Return the reg interpretation in word or byte mode.
// Caller must provide a buf with at least 10 characters.
static const char *c166_reg(const c166_state* state, char *buf, ut8 reg, bool byte) {
	if (reg >= 0xF0) {
		// Short ‘reg’ addresses from F0 to FF always specify GPRs.
		if (byte)
			return c166_rb[reg & 0xF];
		else
			return c166_rw[reg & 0xF];
	} else if (state->esfr) {
		const ut16 addr = 0xF000 | (2 * reg);
		snprintf(buf, 9, "0x%04x", addr);
	} else {
		const ut16 addr = 0xFE00 | (2 * reg);
		snprintf(buf, 9, "0x%04x", addr);
	}
	return buf;
}

// Format a bitoff value into buf.
// Caller must provide a buf with at least 12 characters.
static const char *c166_bitoff(const c166_state* state, char *buf, ut8 bitoff) {
	if (bitoff >= 0xF0) {
		// GPR
		return c166_rw[bitoff & 0xF];
	} else if (bitoff >= 0x80) {
		if (state->esfr) {
			const ut16 addr = 0xF100 + (2 * (bitoff & 0x7F));
			snprintf(buf, 7, "0x%04x", addr);
		} else {
			const ut16 addr = 0xFF00 + (2 * (bitoff & 0x7F));
			snprintf(buf, 7, "0x%04x", addr);
		}
	} else {
		// Ram
		const ut16 addr = 0xFD00 + (2 * bitoff);
		snprintf(buf, 7, "0x%04x", addr);
	}
	return buf;
}

// Format a mem value into buf. Does not apply to seg or pag formats.
// Caller must provide a buf with at least 13 characters.
static const char *c166_mem(const c166_state* state, char *buf, ut16 mem) {
	const int i = (mem >> 14) & 0b11;
	switch (state->ext_mode) {
		case C166_EXT_MODE_NONE: {
			snprintf(buf, 12, "DPP%i:0x%04x", i, mem & 0x3FFF);
			break;
		}
		case C166_EXT_MODE_SEG: {
			const ut32 seg = ((ut32) (state->ext_value & 0xFF)) << 16;
			snprintf(buf, 12, "0x%06x", seg | (mem & 0x3FFF));
			break;
		}
		case C166_EXT_MODE_PAGE: {
			const ut32 page = ((ut32) state->ext_value & 0x3FF) << 14;
			snprintf(buf, 11, "0x%08x", page | (mem & 0x3FFF));
			break;
		}
	}
	return buf;
}

static int c166_simple_instr(c166_cmd *cmd, const char *instr, int ret) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s", "");
	return ret;
}

static int c166_instr_rw_rw(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "r%i, r%i", (reg >> 4) & 0xF, reg & 0xF);
	return 2;
}

static int c166_instr_rw_x(c166_cmd *cmd, const char *instr, ut8 reg) {
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

static int c166_instr_rw_data4(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "r%i, #0x%02x", reg & 0xF, (reg >> 4) & 0xF);
	return 2;
}

static int c166_instr_rb_data4(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", c166_rb[reg & 0xF], (reg >> 4) & 0xF);
	return 2;
}

static int c166_instr_rw_data16(c166_cmd *cmd, const char *instr, ut8 reg, ut16 data) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "r%i, #0x%04x", reg & 0xF, data);
	return 4;
}

static int c166_instr_rw_mem(c166_cmd *cmd, const char *instr, ut8 reg, ut16 data) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "r%i, %s", reg & 0xF, c166_mem(cmd->state, tmp, data));
	return 4;
}

static int c166_instr_rb_x(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 op = reg & 0xF;
	const char *r = c166_rb[(reg >> 4) & 0xF];
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

static int c166_instr_rb_rb(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, %s", c166_rb[(reg >> 4) & 0xF], c166_rb[reg & 0xF]);
	return 2;
}

static int c166_instr_rw_rb(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	// NOTE: It is D0 mn , NOT nm, but displayed as Rwn, Rbm
	snprintf(cmd->operands, C166_MAX_OPT, "%s, %s", c166_rw[reg & 0xF], c166_rb[(reg >> 4) & 0xF]);
	return 2;
}

static int c166_instr_rw(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "r%i", (reg >> 4) & 0xF);
	return 2;
}

static int c166_instr_rb(c166_cmd *cmd, const char *instr, ut8 reg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s", c166_rb[(reg >> 4) & 0xF]);
	return 2;
}

static int c166_trap_instr(c166_cmd *cmd, const char *instr, ut8 trap7) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut16 addr = 4 * (trap7 & 0x7F);
	snprintf(cmd->operands, C166_MAX_OPT, "#0x%04x", addr);
	return 2;
}

static int c166_instr_irang2(c166_cmd *cmd, const char *instr, ut8 irang2) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "#0x%02x", (irang2 >> 4) & 0b0011);
	return 2;
}

static int c166_instr_rw_irang2(c166_cmd *cmd, const char *instr, ut8 op) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 m = op & 0xF;
	const ut8 irang2 = ((op >> 4) & 0b0011) + 1;
	c166_activate_ext(cmd->state, true, C166_EXT_MODE_NONE, irang2, 0);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", c166_rw[m], irang2);
	return 2;
}

static int c166_instr_seg_or_pag_irang2(c166_cmd *cmd, const char *instr, ut8 op, ut16 data, bool seg) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 irang2 = ((op >> 4) & 0b0011) + 1;
	const bool esfr = (op >> 7) & 1;
	if (seg) {
		c166_activate_ext(cmd->state, esfr, C166_EXT_MODE_SEG, irang2, data & 0xFF);
		snprintf(cmd->operands, C166_MAX_OPT, "#0x%02x, #0x%02x", data & 0xFF, irang2);
	} else {
		c166_activate_ext(cmd->state, esfr, C166_EXT_MODE_PAGE, irang2, data & 0x03FF);
		snprintf(cmd->operands, C166_MAX_OPT, "#0x%04x, #0x%02x", data & 0x03FF, irang2);
	}
	return 4;
}

static int c166_instr_reg_mem(c166_cmd *cmd, const char *instr, ut8 reg, ut16 mem, bool byte) {
	char tmp[16];
	char tmp2[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, %s", c166_reg(cmd->state, tmp, reg, byte), c166_mem(cmd->state, tmp2, mem));
	return 4;
}

static int c166_instr_mem_reg(c166_cmd *cmd, const char *instr, ut8 reg, ut16 mem, bool byte) {
	char tmp[16];
	char tmp2[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, %s", c166_mem(cmd->state, tmp2, mem), c166_reg(cmd->state, tmp, reg, byte));
	return 4;
}

static int c166_instr_reg(c166_cmd *cmd, const char *instr, ut8 reg, bool byte) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s", c166_reg(cmd->state, tmp, reg, byte));
	return 2;
}

static int c166_instr_reg_data16(c166_cmd *cmd, const char *instr, ut8 reg, ut16 data, bool byte) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%04x", c166_reg(cmd->state, tmp, reg, byte), data);
	return 4;
}

static int c166_instr_reg_data8(c166_cmd *cmd, const char *instr, ut8 reg, ut8 data, bool byte) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	// 8-bit immediate constant
	// (represented by #data8, where byte xx is not significant)
	// rz_read_at_le16 swaps so use lower
	snprintf(cmd->operands, C166_MAX_OPT, "%s, #0x%02x", c166_reg(cmd->state, tmp, reg, byte), data & 0xFF);
	return 4;
}

static int c166_instr_seg_caddr(c166_cmd *cmd, const char *instr, ut8 seg, ut16 caddr) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "0x%02x, 0x%04x", seg, caddr);
	return 4;
}

static int c166_instr_reg_caddr(c166_cmd *cmd, const char *instr, ut8 reg, ut16 caddr) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%s, 0x%04x", c166_reg(cmd->state, tmp, reg, false), caddr);
	return 4;
}

static int c166_instr_bitoff(c166_cmd *cmd, const char *instr, ut8 q, ut8 bitoff) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 bit = (q >> 4) & 0xF;
	snprintf(cmd->operands, C166_MAX_OPT, "%s.%i", c166_bitoff(cmd->state, tmp, bitoff), bit);
	return 2;
}

static int c166_instr_bitaddr_bitaddr(c166_cmd *cmd, const char *instr, ut8 qq, ut8 zz, ut8 qz) {
	char tmpq[12];
	char tmpz[12];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 q = (qz >> 4) & 0xF;
	const ut8 z = qz & 0xF;
	snprintf(cmd->operands, C166_MAX_OPT,
		"%s.%i, %s.%i", c166_bitoff(cmd->state, tmpq, qq), q, c166_bitoff(cmd->state, tmpz, zz), z);
	return 4;
}

static int c166_instr_bitaddr_rel(c166_cmd *cmd, const char *instr, ut8 qq, ut8 rr, ut8 q0) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 q = (q0 >> 4) & 0xF;
	snprintf(cmd->operands, C166_MAX_OPT, "%s.%i, %i", c166_bitoff(cmd->state, tmp, qq), q, (st8)rr);
	return 4;
}

static int c166_instr_call_rel(c166_cmd *cmd, const char *instr, ut8 rr) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	snprintf(cmd->operands, C166_MAX_OPT, "%i", (st8)rr);
	return 2;
}

static int c166_instr_jmp_rel(c166_cmd *cmd, const char *instr, ut8 op1, ut8 rr) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 c = (op1 >> 4) & 0xF;
	snprintf(cmd->operands, C166_MAX_OPT, "%s, %i", c166_cc[c], (st8)rr);
	return 2;
}

static int c166_instr_cc_indirect(c166_cmd *cmd, const char *instr, ut8 op) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 c = (op >> 4) & 0xF;
	snprintf(cmd->operands, C166_MAX_OPT, "%s, [r%i]", c166_cc[c], op & 0xF);
	return 2;
}

static int c166_instr_cc_caddr(c166_cmd *cmd, const char *instr, ut8 op, ut16 addr) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 c = (op >> 4) & 0xF;
	snprintf(cmd->operands, C166_MAX_OPT, "%s, 0x%04x", c166_cc[c], addr);
	return 4;
}

static int c166_instr_bfld(c166_cmd *cmd, const char *instr, ut8 bitoff, ut8 opt1, ut8 opt2, bool high) {
	char tmp[16];
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	if (high) {
		snprintf(cmd->operands, C166_MAX_OPT,
			"%s, #0x%02x, #0x%02x", c166_bitoff(cmd->state, tmp, bitoff), opt2, opt1);
	} else {
		snprintf(cmd->operands, C166_MAX_OPT,
			"%s, #0x%02x, #0x%02x", c166_bitoff(cmd->state, tmp, bitoff), opt1, opt2);
	}
	return 4;
}

static int c166_instr_mov_nm(
	c166_cmd *cmd,
	const char *instr,
	const char *format,
	ut8 op,
	const char **n_map,
	const char **m_map,
	bool swap) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 n = (op >> 4) & 0xF;
	const ut8 m = op & 0xF;
	if (swap) {
		snprintf(cmd->operands, C166_MAX_OPT, format, m_map[m], n_map[n]);
	} else {
		snprintf(cmd->operands, C166_MAX_OPT, format, n_map[n], m_map[m]);
	}
	return 2;
}

static int c166_instr_mov_mem_oRw(c166_cmd *cmd, const char *instr, ut8 op, ut16 mem, bool swap) {
	snprintf(cmd->instr, C166_MAX_OPT, "%s", instr);
	const ut8 n = op & 0xF;
	char tmp[16];
	if (swap) {
		snprintf(cmd->operands, C166_MAX_OPT, "[%s], %s", c166_rw[n], c166_mem(cmd->state, tmp, mem));
	} else {
		snprintf(cmd->operands, C166_MAX_OPT, "%s, [%s]", c166_mem(cmd->state, tmp, mem), c166_rw[n]);
	}
	return 4;
}

static int c166_instr_mov_nm_data(c166_cmd *cmd, const char *instr, ut8 op, ut16 mem, const char **n_map, bool swap) {
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


int c166_decode_command(const ut8 *instr, c166_cmd *cmd, int len) {
	cmd->state = c166_get_state();
	if (!cmd->state) {
		RZ_LOG_FATAL("c166_state was NULL.");
	}
	c166_maybe_deactivate_ext(cmd->state);
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

		case C166_CMPD1_Rwn_data16:
		case C166_CMPD2_Rwn_data16:
		case C166_CMPI1_Rwn_data16:
		case C166_CMPI2_Rwn_data16:
			return c166_instr_rw_data16(cmd, c166_instr_name(instr[0]), instr[1], rz_read_at_le16(instr, 2));

		case C166_CMPD1_Rwn_mem:
		case C166_CMPD2_Rwn_mem:
		case C166_CMPI1_Rwn_mem:
		case C166_CMPI2_Rwn_mem:
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

		case C166_MOV_mem_oRwn:
			return c166_instr_mov_mem_oRw(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), false);
		case C166_MOV_oRwn_mem:
			return c166_instr_mov_mem_oRw(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), true);
		case C166_MOVB_mem_oRwn:
			return c166_instr_mov_mem_oRw(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), false);
		case C166_MOVB_oRwn_mem:
			return c166_instr_mov_mem_oRw(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), true);
		case C166_MOV_Rwn_oRwm_data16:
			return c166_instr_mov_nm_data(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), c166_rw, false);
		case C166_MOV_oRwm_data16_Rwn:
			return c166_instr_mov_nm_data(cmd, "mov", instr[1], rz_read_at_le16(instr, 2), c166_rw, true);
		case C166_MOVB_Rbn_oRwm_data16:
			return c166_instr_mov_nm_data(cmd, "movb", instr[1], rz_read_at_le16(instr, 2), c166_rb, false);
		case C166_MOVB_oRwm_data16_Rbn:
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

		case C166_EXTP_or_EXTS_pag10_or_seg8_irang2: {
			const ut8 sub_op = (instr[1] >> 6) & 0b11;
			bool seg = (sub_op == 0b00) || (sub_op == 0b10);
			return c166_instr_seg_or_pag_irang2(cmd, c166_extx_names[sub_op], instr[1], rz_read_at_le16(instr, 2), seg);
		}
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
	if (len >= 2) {
		// Two byte instructions
		switch (instr[0]) {
		case C166_ADD_Rwn_Rwm:
		case C166_ADDC_Rwn_Rwm:
		case C166_SUB_Rwn_Rwm:
		case C166_SUBC_Rwn_Rwm:
		case C166_MUL_Rwn_Rwm:
		case C166_MULU_Rwn_Rwm:
		case C166_AND_Rwn_Rwm:
		case C166_OR_Rwn_Rwm:
		case C166_XOR_Rwn_Rwm:
		case C166_PRIOR_Rwn_Rwm:
		case C166_CMP_Rwn_Rwm:
		case C166_SHL_Rwn_Rwm:
		case C166_SHR_Rwn_Rwm:
		case C166_ROL_Rwn_Rwm:
		case C166_ROR_Rwn_Rwm:
		case C166_ASHR_Rwn_Rwm:
		case C166_MOV_Rwn_Rwm:
			return c166_instr_rw_rw(cmd, c166_instr_name(instr[0]), instr[1]);
		case C166_ADDB_Rbn_Rbm:
		case C166_ADDCB_Rbn_Rbm:
		case C166_SUBB_Rbn_Rbm:
		case C166_SUBCB_Rbn_Rbm:
		case C166_ANDB_Rbn_Rbm:
		case C166_ORB_Rbn_Rbm:
		case C166_XORB_Rbn_Rbm:
		case C166_CMPB_Rbn_Rbm:
		case C166_MOVB_Rbn_Rbm:
			return c166_instr_rb_rb(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_ADD_Rwn_x:
		case C166_ADDC_Rwn_x:
		case C166_SUB_Rwn_x:
		case C166_SUBC_Rwn_x:
		case C166_CMP_Rwn_x:
		case C166_AND_Rwn_x:
		case C166_OR_Rwn_x:
		case C166_XOR_Rwn_x:
			return c166_instr_rw_x(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_ROL_Rwn_data4:
		case C166_ROR_Rwn_data4:
		case C166_SHL_Rwn_data4:
		case C166_SHR_Rwn_data4:
		case C166_CMPI1_Rwn_data4:
		case C166_CMPI2_Rwn_data4:
		case C166_CMPD1_Rwn_data4:
		case C166_CMPD2_Rwn_data4:
		case C166_ASHR_Rwn_data4:
		case C166_MOV_Rwn_data4:
			return c166_instr_rw_data4(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_MOVB_Rbn_data4:
			return c166_instr_rb_data4(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_ADDB_Rbn_x:
		case C166_ADDCB_Rbn_x:
		case C166_SUBB_Rbn_x:
		case C166_SUBCB_Rbn_x:
		case C166_CMPB_Rbn_x:
		case C166_ANDB_Rbn_x:
		case C166_ORB_Rbn_x:
		case C166_XORB_Rbn_x:
			return c166_instr_rb_x(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_DIV_Rwn:
		case C166_DIVL_Rwn:
		case C166_DIVLU_Rwn:
		case C166_DIVU_Rwn:
		case C166_NEG_Rwn:
		case C166_CPL_Rwn:
			return c166_instr_rw(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_NEGB_Rbn:
		case C166_CPLB_Rbn:
			return c166_instr_rb(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_MOVBS_Rwn_Rbm:
		case C166_MOVBZ_Rwn_Rbm:
			return c166_instr_rw_rb(cmd, c166_instr_name(instr[0]), instr[1]);

		case C166_POP_reg:
		case C166_PUSH_reg:
		case C166_RETP_reg:
			return c166_instr_reg(cmd, c166_instr_name(instr[0]), instr[1], false);
		case C166_CALLR_rel:
			return c166_instr_call_rel(cmd, "callr", instr[1]);
		case C166_CALLI_cc_Rwn:
			return c166_instr_cc_indirect(cmd, "calli", instr[1]);
		case C166_JMPI_cc_oRwn:
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

		case C166_MOV_Rwn_oRwm:
			return c166_instr_mov_nm(cmd, "mov", "%s, [%s]", instr[1], c166_rw, c166_rw, false);
		case C166_MOV_Rwn_oRwmp:
			return c166_instr_mov_nm(cmd, "mov", "%s, [%s+]", instr[1], c166_rw, c166_rw, false);
		case C166_MOV_oRwm_Rwn:
			return c166_instr_mov_nm(cmd, "mov", "[%s], %s", instr[1], c166_rw, c166_rw, true);
		case C166_MOV_noRwm_Rwn:
			return c166_instr_mov_nm(cmd, "mov", "[-%s], %s", instr[1], c166_rw, c166_rw, true);
		case C166_MOV_oRwn_oRwm:
			return c166_instr_mov_nm(cmd, "mov", "[%s], [%s]", instr[1], c166_rw, c166_rw, false);
		case C166_MOV_oRwnp_oRwm:
			return c166_instr_mov_nm(cmd, "mov", "[%s+], [%s]", instr[1], c166_rw, c166_rw, false);
		case C166_MOV_oRwn_oRwmp:
			return c166_instr_mov_nm(cmd, "mov", "[%s], [%s+]", instr[1], c166_rw, c166_rw, false);
		case C166_MOVB_Rbn_oRwm:
			return c166_instr_mov_nm(cmd, "movb", "%s, [%s]", instr[1], c166_rb, c166_rw, false);
		case C166_MOVB_Rbn_oRwmp:
			return c166_instr_mov_nm(cmd, "movb", "%s, [%s+]", instr[1], c166_rb, c166_rw, false);
		case C166_MOVB_oRwm_Rbn:
			return c166_instr_mov_nm(cmd, "movb", "[%s], %s", instr[1], c166_rb, c166_rw, true);
		case C166_MOVB_noRwm_Rbn:
			return c166_instr_mov_nm(cmd, "movb", "[-%s], %s", instr[1], c166_rb, c166_rw, true);
		case C166_MOVB_oRwn_oRwm:
			return c166_instr_mov_nm(cmd, "movb", "[%s], [%s]", instr[1], c166_rw, c166_rw, false);
		case C166_MOVB_oRwnp_oRwm:
			return c166_instr_mov_nm(cmd, "movb", "[%s+], [%s]", instr[1], c166_rw, c166_rw, false);
		case C166_MOVB_oRwn_oRwmp:
			return c166_instr_mov_nm(cmd, "movb", "[%s], [%s+]", instr[1], c166_rw, c166_rw, false);

		case C166_ATOMIC_or_EXTR_irang2: {
			const ut8 sub_op  = (instr[1] >> 6) & 0b11;
			if (sub_op == 0b00) {
				return c166_instr_irang2(cmd, "atomic", instr[1]);
			} else if (sub_op == 0b10) {
				c166_activate_ext(cmd->state, true, C166_EXT_MODE_NONE, instr[1] & 3, 0);
				return c166_instr_irang2(cmd, "extr", instr[1]);
			}
			break;
		}
		case C166_EXTP_or_EXTS_Rwm_irang2:
			return c166_instr_rw_irang2(cmd, c166_extx_names[(instr[1] >> 6) & 0b11], instr[1]);

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
	return -1;
}
