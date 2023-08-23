// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_C166_DIS_H
#define RZ_C166_DIS_H

#define C166_MAX_OPT 31

typedef enum {
	C166_EXT_MODE_NONE,
	C166_EXT_MODE_PAGE,
	C166_EXT_MODE_SEG,
} c166_ext_mode;

typedef struct {
	bool esfr;  // Extended register sequence active
	// Extended page/seq mode
	c166_ext_mode ext_mode;
	// Value of ext
	ut16 ext_value;
	// Number of unstructions remaining until state exits
	ut8 i;
} c166_state;

typedef struct {
	c166_state* state;
	char instr[32];
	char operands[32];
} c166_cmd;

extern const char *c166_rw[];
extern const char *c166_rb[];
extern const char *c166_cc[];
extern const char *c166_extx_names[];
extern const ut8 c166_opcode_sizes[];

typedef enum  {
	C166_ADD_Rwn_Rwm = 0x00,
	C166_ADDB_Rbn_Rbm = 0x01,
	C166_ADD_reg_mem = 0x02,
	C166_ADDB_reg_mem = 0x03,
	C166_ADD_mem_reg = 0x04,
	C166_ADDB_mem_reg = 0x05,
	C166_ADD_reg_data16 = 0x06,
	C166_ADDB_reg_data8 = 0x07,
	C166_ADD_Rwn_x = 0x08,
	C166_ADDB_Rbn_x = 0x09,
	C166_BFLDL_bitoff_x = 0x0A,
	C166_MUL_Rwn_Rwm = 0x0B,
	C166_ROL_Rwn_Rwm = 0x0C,
	C166_JMPR_cc_UC_rel = 0x0D,
	C166_BCLR_bitoff0 = 0x0E,
	C166_BSET_bitoff0 = 0x0F,

	C166_ADDC_Rwn_Rwm = 0x10,
	C166_ADDCB_Rbn_Rbm = 0x11,
	C166_ADDC_reg_mem = 0x12,
	C166_ADDCB_reg_mem = 0x13,
	C166_ADDC_mem_reg = 0x14,
	C166_ADDCB_mem_reg = 0x15,
	C166_ADDC_reg_data16 = 0x16,
	C166_ADDCB_reg_data8 = 0x17,
	C166_ADDC_Rwn_x = 0x18,
	C166_ADDCB_Rbn_x = 0x19,
	C166_BFLDH_bitoff_x = 0x1A,
	C166_MULU_Rwn_Rwm = 0x1B,
	C166_ROL_Rwn_data4 = 0x1C,
	C166_JMPR_cc_NET_rel = 0x1D,
	C166_BCLR_bitoff1 = 0x1E,
	C166_BSET_bitoff1 = 0x1F,

	C166_SUB_Rwn_Rwm = 0x20,
	C166_SUBB_Rbn_Rbm = 0x21,
	C166_SUB_reg_mem = 0x22,
	C166_SUBB_reg_mem = 0x23,
	C166_SUB_mem_reg = 0x24,
	C166_SUBB_mem_reg = 0x25,
	C166_SUB_reg_data16 = 0x26,
	C166_SUBB_reg_data8 = 0x27,
	C166_SUB_Rwn_x = 0x28,
	C166_SUBB_Rbn_x = 0x29,
	C166_BCMP_bitaddr_bitaddr = 0x2A,
	C166_PRIOR_Rwn_Rwm = 0x2B,
	C166_ROR_Rwn_Rwm = 0x2C,
	C166_JMPR_cc_EQ_or_Z_rel = 0x2D,
	C166_BCLR_bitoff2 = 0x2E,
	C166_BSET_bitoff2 = 0x2F,

	C166_SUBC_Rwn_Rwm = 0x30,
	C166_SUBCB_Rbn_Rbm = 0x31,
	C166_SUBC_reg_mem = 0x32,
	C166_SUBCB_reg_mem = 0x33,
	C166_SUBC_mem_reg = 0x34,
	C166_SUBCB_mem_reg = 0x35,
	C166_SUBC_reg_data16 = 0x36,
	C166_SUBCB_reg_data8 = 0x37,
	C166_SUBC_Rwn_x = 0x38,
	C166_SUBCB_Rbn_x = 0x39,
	C166_BMOVN_bitaddr_bitaddr = 0x3A,
	// 0x3B,
	C166_ROR_Rwn_data4 = 0x3C,
	C166_JMPR_cc_NE_or_NZ_rel = 0x3D,
	C166_BCLR_bitoff3 = 0x3E,
	C166_BSET_bitoff3 = 0x3F,

	C166_CMP_Rwn_Rwm = 0x40,
	C166_CMPB_Rbn_Rbm = 0x41,
	C166_CMP_reg_mem = 0x42,
	C166_CMPB_reg_mem = 0x43,
	// 0x44,
	// 0x45,
	C166_CMP_reg_data16 = 0x46,
	C166_CMPB_reg_data8 = 0x47,
	C166_CMP_Rwn_x = 0x48,
	C166_CMPB_Rbn_x = 0x49,
	C166_BMOV_bitaddr_bitaddr = 0x4A,
	C166_DIV_Rwn = 0x4B,
	C166_SHL_Rwn_Rwm = 0x4C,
	C166_JMPR_cc_V_rel = 0x4D,
	C166_BCLR_bitoff4 = 0x4E,
	C166_BSET_bitoff4 = 0x4F,

	C166_XOR_Rwn_Rwm = 0x50,
	C166_XORB_Rbn_Rbm = 0x51,
	C166_XOR_reg_mem = 0x52,
	C166_XORB_reg_mem = 0x53,
	C166_XOR_mem_reg = 0x54,
	C166_XORB_mem_reg = 0x55,
	C166_XOR_reg_data16 = 0x56,
	C166_XORB_reg_data8 = 0x57,
	C166_XOR_Rwn_x = 0x58,
	C166_XORB_Rbn_x = 0x59,
	C166_BOR_bitaddr_bitaddr = 0x5A,
	C166_DIVU_Rwn = 0x5B,
	C166_SHL_Rwn_data4 = 0x5C,
	C166_JMPR_cc_NV_rel = 0x5D,
	C166_BCLR_bitoff5 = 0x5E,
	C166_BSET_bitoff5 = 0x5F,

	C166_AND_Rwn_Rwm = 0x60,
	C166_ANDB_Rbn_Rbm = 0x61,
	C166_AND_reg_mem = 0x62,
	C166_ANDB_reg_mem = 0x63,
	C166_AND_mem_reg = 0x64,
	C166_ANDB_mem_reg = 0x65,
	C166_AND_reg_data16 = 0x66,
	C166_ANDB_reg_data8 = 0x67,
	C166_AND_Rwn_x = 0x68,
	C166_ANDB_Rbn_x = 0x69,
	C166_BAND_bitaddr_bitaddr = 0x6A,
	C166_DIVL_Rwn = 0x6B,
	C166_SHR_Rwn_Rwm = 0x6C,
	C166_JMPR_cc_N_rel = 0x6D,
	C166_BCLR_bitoff6 = 0x6E,
	C166_BSET_bitoff6 = 0x6F,

	C166_OR_Rwn_Rwm = 0x70,
	C166_ORB_Rbn_Rbm = 0x71,
	C166_OR_reg_mem = 0x72,
	C166_ORB_reg_mem = 0x73,
	C166_OR_mem_reg = 0x74,
	C166_ORB_mem_reg = 0x75,
	C166_OR_reg_data16 = 0x76,
	C166_ORB_reg_data8 = 0x77,
	C166_OR_Rwn_x = 0x78,
	C166_ORB_Rbn_x = 0x79,
	C166_BXOR_bitaddr_bitaddr = 0x7A,
	C166_DIVLU_Rwn = 0x7B,
	C166_SHR_Rwn_data4 = 0x7C,
	C166_JMPR_cc_NN_rel = 0x7D,
	C166_BCLR_bitoff7 = 0x7E,
	C166_BSET_bitoff7 = 0x7F,

	C166_CMPI1_Rwn_data4 = 0x80,
	C166_NEG_Rwn = 0x81,
	C166_CMPI1_Rwn_mem = 0x82,
	// 0x83
	C166_MOV_oRwn_mem = 0x84,
	// 0x85
	C166_CMPI1_Rwn_data16 = 0x86,
	C166_IDLE = 0x87,
	C166_MOV_noRwm_Rwn = 0x88,
	C166_MOVB_noRwm_Rbn = 0x89,
	C166_JB_bitaddr_rel = 0x8A,
	// 0x8B
	// 0x8C
	C166_JMPR_cc_C_or_ULT_rel = 0x8D,
	C166_BCLR_bitoff8 = 0x8E,
	C166_BSET_bitoff8 = 0x8F,

	C166_CMPI2_Rwn_data4 = 0x90,
	C166_CPL_Rwn = 0x91,
	C166_CMPI2_Rwn_mem = 0x92,
	// 0x93
	C166_MOV_mem_oRwn = 0x94,
	// 0x95
	C166_CMPI2_Rwn_data16 = 0x96,
	C166_PWRDN = 0x97,
	C166_MOV_Rwn_oRwmp = 0x98,
	C166_MOVB_Rbn_oRwmp = 0x99,
	C166_JNB_bitaddr_rel = 0x9A,
	C166_TRAP_trap7 = 0x9B,
	C166_JMPI_cc_oRwn = 0x9C,
	C166_JMPR_cc_NC_or_NGE_rel = 0x9D,
	C166_BCLR_bitoff9 = 0x9E,
	C166_BSET_bitoff9 = 0x9F,

	C166_CMPD1_Rwn_data4 = 0xA0,
	C166_NEGB_Rbn = 0xA1,
	C166_CMPD1_Rwn_mem = 0xA2,
	// 0xA3
	C166_MOVB_oRwn_mem = 0xA4,
	C166_DISWDT = 0xA5,
	C166_CMPD1_Rwn_data16 = 0xA6,
	C166_SRVWDT = 0xA7,
	C166_MOV_Rwn_oRwm = 0xA8,
	C166_MOVB_Rbn_oRwm = 0xA9,
	C166_JBC_bitaddr_rel = 0xAA,
	C166_CALLI_cc_Rwn = 0xAB,
	C166_ASHR_Rwn_Rwm = 0xAC,
	C166_JMPR_cc_SGT_rel = 0xAD,
	C166_BCLR_bitoff10 = 0xAE,
	C166_BSET_bitoff10 = 0xAF,

	C166_CMPD2_Rwn_data4 = 0xB0,
	C166_CPLB_Rbn = 0xB1,
	C166_CMPD2_Rwn_mem = 0xB2,
	// 0xB3,
	C166_MOVB_mem_oRwn = 0xB4,
	C166_EINIT = 0xB5,
	C166_CMPD2_Rwn_data16 = 0xB6,
	C166_SRST = 0xB7,
	C166_MOV_oRwm_Rwn = 0xB8,
	C166_MOVB_oRwm_Rbn = 0xB9,
	C166_JNBS_bitaddr_rel = 0xBA,
	C166_CALLR_rel = 0xBB,
	C166_ASHR_Rwn_data4 = 0xBC,
	C166_JMPR_cc_SLE_rel = 0xBD,
	C166_BCLR_bitoff11 = 0xBE,
	C166_BSET_bitoff11 = 0xBF,

	C166_MOVBZ_Rwn_Rbm = 0xC0,
	// 0xC1
	C166_MOVBZ_reg_mem = 0xC2,
	// 0xC3
	C166_MOV_oRwm_data16_Rwn = 0xC4,
	C166_MOVBZ_mem_reg = 0xC5,
	C166_SCXT_reg_data16 = 0xC6,
	// 0xC7
	C166_MOV_oRwn_oRwm = 0xC8,
	C166_MOVB_oRwn_oRwm = 0xC9,
	C166_CALLA_cc_caddr = 0xCA,
	C166_RET = 0xCB,
	C166_NOP = 0xCC,
	C166_JMPR_cc_SLT_rel = 0xCD,
	C166_BCLR_bitoff12 = 0xCE,
	C166_BSET_bitoff12 = 0xCF,

	C166_MOVBS_Rwn_Rbm = 0xD0,
	C166_ATOMIC_or_EXTR_irang2 = 0xD1,
	C166_MOVBS_reg_mem = 0xD2,
	// 0xD3
	C166_MOV_Rwn_oRwm_data16 = 0xD4,
	C166_MOVBS_mem_reg = 0xD5,
	C166_SCXT_reg_mem = 0xD6,
	C166_EXTP_or_EXTS_pag10_or_seg8_irang2 = 0xD7,
	C166_MOV_oRwnp_oRwm = 0xD8,
	C166_MOVB_oRwnp_oRwm = 0xD9,
	C166_CALLS_seg_caddr = 0xDA,
	C166_RETS = 0xDB,
	C166_EXTP_or_EXTS_Rwm_irang2 = 0xDC,
	C166_JMPR_cc_SGE_rel = 0xDD,
	C166_BCLR_bitoff13 = 0xDE,
	C166_BSET_bitoff13 = 0xDF,

	C166_MOV_Rwn_data4 = 0xE0,
	C166_MOVB_Rbn_data4 = 0xE1,
	C166_PCALL_reg_caddr = 0xE2,
	// 0xE3
	C166_MOVB_oRwm_data16_Rbn = 0xE4,
	// 0xE5
	C166_MOV_reg_data16 = 0xE6,
	C166_MOVB_reg_data8 = 0xE7,
	C166_MOV_oRwn_oRwmp = 0xE8,
	C166_MOVB_oRwn_oRwmp = 0xE9,
	C166_JMPA_cc_caddr = 0xEA,
	C166_RETP_reg = 0xEB,
	C166_PUSH_reg = 0xEC,
	C166_JMPR_cc_UGT_rel = 0xED,
	C166_BCLR_bitoff14 = 0xEE,
	C166_BSET_bitoff14 = 0xEF,

	C166_MOV_Rwn_Rwm = 0xF0,
	C166_MOVB_Rbn_Rbm = 0xF1,
	C166_MOV_reg_mem = 0xF2,
	C166_MOVB_reg_mem = 0xF3,
	C166_MOVB_Rbn_oRwm_data16 = 0xF4,
	// 0xF5
	C166_MOV_mem_reg = 0xF6,
	C166_MOVB_mem_reg = 0xF7,
	// 0xF8
	// 0xF9
	C166_JMPS_seg_caddr = 0xFA,
	C166_RETI = 0xFB,
	C166_POP_reg = 0xFC,
	C166_JMPR_cc_ULE_rel = 0xFD,
	C166_BCLR_bitoff15 = 0xFE,
	C166_BSET_bitoff15 = 0xFF,
} c166_opcodes;



RZ_API int c166_decode_command(const ut8 *instr, c166_cmd *cmd, int len);

RZ_API c166_state* c166_get_state();
RZ_API void c166_activate_ext(RZ_NONNULL c166_state* state, bool esfr, c166_ext_mode mode, ut8 count, ut16 value);
RZ_API void c166_maybe_deactivate_ext(RZ_NONNULL c166_state* state);


#endif /* RZ_C166_DIS_H */
