// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
// A lot of this is based on AVR's asssembler

#include <rz_types.h>
#include <rz_util.h>

#include "c166_assembler.h"
#include "c166_arch.h"

#define MAX_TOKENS 6


#define return_error(msg, ...) \
	do { \
		RZ_LOG_ERROR("[!] c166_assembler: " msg, ##__VA_ARGS__); \
		return -1; \
	} while (0)

#define return_error_if_empty_input(a, b) \
	do { \
		if (RZ_STR_ISEMPTY(a) || b < 1) { \
			RZ_LOG_ERROR("[!] c166_assembler: the input is empty.\n"); \
			return -1; \
		} \
	} while (0)

static bool is_equal(const char *a, const char *b) {
    return rz_str_casecmp(a, b) == 0 && (strlen(a) == strlen(b));
}

static bool parse_rw(ut8 *result, const char *token) {
    if (result && !RZ_STR_ISEMPTY(token)) {
        for (ut8 i = 0; i < 16; ++i) {
            if (is_equal(token, c166_rw[i])) {
                *result = i;
                return true;
            }
        }
        // TODO: If starts with r and not a match return error
    }
    return false;
}

static bool parse_rb(ut8 *result, const char *token) {
    if (result && !RZ_STR_ISEMPTY(token)) {
        for (ut8 i = 0; i < 16; ++i) {
            if (is_equal(token, c166_rb[i])) {
                *result = i;
                return true;
            }
        }
        // TODO: If starts with r, rl, or rh and not a match return error
    }
    return false;
}

static bool parse_cc(ut8 *cc, const char *token) {
    if (cc && !RZ_STR_ISEMPTY(token)) {
        for (ut8 i = 0; i < 8; ++i) {
            if (is_equal(token, c166_cc[i])) {
                *cc = i;
                return true;
            }
        }
    }
    return false;
}


static ut32 parse_number(const char *token) {
    // TODO: Is this be or le?
    if (strlen(token) > 2 && token[0] == '0' && token[1] == 'x') {
        return strtoull(token, NULL, 16);
    } else {
        return strtoull(token, NULL, 10);
    }
}


// Parse an immediate value. Must be under limit (eg 16 for data4 or 255 for data8)
static bool parse_imm(ut16 *result, const char *token, ut32 limit) {
    if (result && !RZ_STR_ISEMPTY(token) && token[0] == '#') {
        const char *tmp = token + 1;
        const ut32 i = parse_number(tmp);
        if (i < limit) {
            *result = i & 0xFFFF;
            return true;
        }
    }
    return false;
}

// Parse a mem value.
static bool parse_mem(ut16 *result, const char *token) {
    if (result && !RZ_STR_ISEMPTY(token)) {
        // TODO: Is this be or le?
        const ut32 i = parse_number(token);
        if (i <= 0xFFFF) {
            *result = i & 0xFFFF;
            return true;
        }
    }
    return false;
}

// Parse a reg value
static bool parse_reg(ut8 *result, const char *token) {
    ut8 r;
    if (result && !RZ_STR_ISEMPTY(token)) {
        // Can be a word or byte GPR
        if (parse_rw(&r, token) || parse_rb(&r, token)) {
            *result = 0xF0 | r;
            return true;
        } else {
            // Can be any SFR or ESFR
            // Must be word aligned
            const ut32 i = parse_number(token);
            if ( (i >= 0xFE00) && (i <= 0xFEEF )) {
                const ut16 sfr = (i - 0xFE00);
                if ((sfr & 1) == 0) {
                    *result = sfr / 2;
                    return true;
                }
            } else if ( (i >= 0xF000) && (i <= 0xF0EF )) {
                const ut16 esfr = (i - 0xF000);
                if ((esfr & 1) == 0) {
                    *result = esfr / 2;
                    return true;
                }
            }
        }
    }
    return false;
}

// Parse a bitoff value
static bool parse_bitoff(ut8 *result, const char *token) {
    ut8 r;
    if (result && !RZ_STR_ISEMPTY(token)) {
        // Can be a word or byte GPR
        if (parse_rw(&r, token) || parse_rb(&r, token)) {
            *result = 0xF0 + r;
            return true;
        } else {
            // Can be any SFR or ESFR
            // Must be word aligned
            const ut32 i = parse_number(token);
            if ( (i >= 0xFD00) && (i <= 0xFDFE )) {
                const ut16 sfr = (i - 0xFD00);
                if ((sfr & 1) == 0) {
                    *result = sfr / 2;
                    return true;
                }
            } else if ( (i >= 0xFF00) && (i <= 0xFFDE )) {
                const ut16 sfr = (i - 0xFF00);
                if ((sfr & 1) == 0) {
                    *result = sfr / 2 + 0x80;
                    return true;
                }
            } else if ( (i >= 0xF100) && (i <= 0xF1DE )) {
                const ut16 esfr = (i - 0xF100);
                if ((esfr & 1) == 0) {
                    *result = esfr / 2 + 0x80;
                    return true;
                }
            }
        }
    }
    return false;
}

// Parse a bitaddr.bit value.
static bool parse_bitattr_bit(ut8 *qq, ut8 *bit, const char *token) {
    bool reg_ok;
    if (qq && bit && !RZ_STR_ISEMPTY(token)) {
        // Split at dot
        const char* dot = rz_str_strchr(token, ".");
        if (dot) {
            {
                char* addr_token = rz_str_newlen(token, dot - token);
                reg_ok = parse_bitoff(qq, addr_token);
                if (addr_token) {
                    free(addr_token);
                }
            }
            if (reg_ok) {
                const char* remainder = dot+1;
                const ut32 i = strtoull(remainder, NULL, 10);
                if (i <= 0xF) {
                    *bit = i & 0xF;
                    return true;
                }
            }
        }
    }
    return false;
}


typedef int (*Encode)(const void * self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be);

typedef enum {
    C166_IFMT_NONE = 0, // Used to terminate
    C166_IFMT_Rb,
    C166_IFMT_Rb_Rb,
    C166_IFMT_Rb_data3,
    C166_IFMT_Rw,
    C166_IFMT_Rw_Rw,
    C166_IFMT_Rw_x,
    C166_IFMT_Rw_data3,
    C166_IFMT_Rw_data4,
    C166_IFMT_Rw_data16,
    C166_IFMT_Rw_mem,
    C166_IFMT_reg,
//     C166_IFMT_mem_reg,
//     C166_IFMT_reg_mem,
//     C166_IFMT_reg_data8,
//     C166_IFMT_reg_data16,
    C166_IFMT_bitaddr_bit,
//     C166_IFMT_bitaddr_bitaddr,
//
} c166_format;

typedef struct c166_format_t {
    c166_format format;
    c166_opcodes opcode;
} C166InstrFormat;

typedef struct c166_decoder_t {
	const char* name;
	ut32 mintoks; /*  required min token number */
	ut32 maxtoks; /*  required max token number */
	Encode encode;
	C166InstrFormat formats[16];
} C166Encoder;

// Try parsing a single Rw parameter (CPLB/NEGB)
static bool c166_try_op_rb(const char* n, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    if (parse_rb(&r1, n) ) {
        output[0] = opcode;
        output[1] = (r1 & 0xF) << 4;
        return true;
    }
    return false;
}

// Try parsing a Rbn, Rbm parameters
static bool c166_try_op_rb_rb(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1, r2;
    if (parse_rb(&r1, n) && parse_rb(&r2, m)) {
        output[0] = opcode;
        output[1] = ((r1 & 0xF) << 4) | (r2 & 0xF);
        return true;
    }
    return false;
}

static bool c166_try_op_rb_data3(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    ut16 data3;
    if (parse_rb(&r1, n) && parse_imm(&data3, m, 8)) {
        output[0] = opcode;
        output[1] = ((r1 & 0xF) << 4) | (data3 & 0b111);
        return true;
    }
    return false;
}

// Try parsing a single Rw parameter (CPL/NEG) or DIV/DIVL
static bool c166_try_op_rw(const char* n, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    if (parse_rw(&r1, n) ) {
        output[0] = opcode;
        switch (opcode) {
            case C166_CPL_Rwn:
            case C166_NEG_Rwn:
                output[1] = (r1 & 0xF) << 4;
                break;
            case C166_DIV_Rwn:
            case C166_DIVL_Rwn:
            case C166_DIVLU_Rwn:
            case C166_DIVU_Rwn:
                output[1] = (r1 & 0xF) << 4 | (r1 & 0xF);
                break;
            default:
                rz_warn_if_reached();
                return false;
        }

        return true;
    }
    return false;
}


// Try parsing a Rwn, Rwm parameters
static bool c166_try_op_rw_rw(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1, r2;
    if (parse_rw(&r1, n) && parse_rw(&r2, m)) {
        output[0] = opcode;
        output[1] = ((r1 & 0xF) << 4) | (r2 & 0xF);
        return true;
    }
    return false;
}


static bool c166_try_op_rw_data3(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    ut16 data3;
    if (parse_rw(&r1, n) && parse_imm(&data3, m, 8)) {
        output[0] = opcode;
        output[1] = ((r1 & 0xF) << 4) | (data3 & 0b111);
        return true;
    }
    return false;
}

static bool c166_try_op_rw_data4(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    ut16 data4;
    if (parse_rw(&r1, n) && parse_imm(&data4, m, 16)) {
        output[0] = opcode;
        output[1] = ((data4 & 0xF) << 4) | (r1 & 0xF);
        return true;
    }
    return false;
}

// CMPD1, CMPD2, CMPI1, CMPI2
static bool c166_try_op_rw_data16(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    ut16 data16;
    if (parse_rw(&r1, n) && parse_imm(&data16, m, 0x10000)) {
        output[0] = opcode;
        output[1] = 0xF0 | (r1 & 0xF);
        output[2] = data16 & 0xFF;
        output[3] = (data16 >> 8) & 0xFF;
        return true;
    }
    return false;
}

static bool c166_try_op_rw_mem(const char* n, const char* m, c166_opcodes opcode, ut8 *output) {
    ut8 r1;
    ut16 mem;
    if (parse_rw(&r1, n) && parse_mem(&mem, m)) {
        output[0] = opcode;
        output[1] = 0xF0 | (r1 & 0xF);
        output[2] = mem & 0xFF;
        output[3] = (mem >> 8) & 0xFF;
        return true;
    }
    return false;
}

static bool c166_try_op_reg(const char* n, c166_opcodes opcode, ut8 *output) {
    ut8 reg;
    if (parse_reg(&reg, n)) {
        output[0] = opcode;
        output[1] = reg;
        return true;
    }
    return false;
}

// BSET / BCLR
static bool c166_try_op_bitaddr_bit(const char* token, c166_opcodes opcode, ut8 *output) {
    ut8 bit;
    ut8 qq;
    if (parse_bitattr_bit(&qq, &bit, token)) {
        output[0] = opcode | ((bit & 0xF) << 4);
        output[1] = qq;
        return true;
    }
    return false;
}

/**
 * Assemble an in instruction by providing a list of C166InstrFormat
 * in the instruction definition.
 */
static int c166_asm_decode_fmts(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    C166Encoder *instr = (C166Encoder *) self;
    if (!instr) {
        rz_return_val_if_reached(-1);
    }
    const ut8 n = sizeof(instr->formats);
    for (ut8 i = 0; i < n; i++) {
        // NOTICE: break in switch does not break for loop
        switch (instr->formats[i].format) {
            case C166_IFMT_NONE: {
                i = n; // End for loop
                break;
            }
            case C166_IFMT_Rb: {
                rz_return_val_if_fail(ntokens >= 2, -1);
                if (c166_try_op_rb(tokens[1], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_Rb_Rb: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rb_rb(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_Rb_data3: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rb_data3(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
             case C166_IFMT_Rw: {
                rz_return_val_if_fail(ntokens >= 2, -1);
                if (c166_try_op_rw(tokens[1], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_Rw_Rw: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rw_rw(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_Rw_x: {
                break;
            }
            case C166_IFMT_Rw_data3: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rw_data3(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_Rw_data4: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rw_data4(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_Rw_data16: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rw_data16(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 4;
                }
                break;
            }
            case C166_IFMT_Rw_mem: {
                rz_return_val_if_fail(ntokens >= 3, -1);
                if (c166_try_op_rw_mem(tokens[1], tokens[2], instr->formats[i].opcode, output)) {
                    return 4;
                }
                break;
            }
            case C166_IFMT_reg: {
                rz_return_val_if_fail(ntokens >= 2, -1);
                if (c166_try_op_reg(tokens[1], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
            case C166_IFMT_bitaddr_bit: {
                rz_return_val_if_fail(ntokens >= 2, -1);
                if (c166_try_op_bitaddr_bit(tokens[1], instr->formats[i].opcode, output)) {
                    return 2;
                }
                break;
            }
        }
    }
    return_error("Invalid format for %s\n", instr->name);
}

static int c166_asm_diswdt(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xA5;
    output[1] = 0x5A;
    output[2] = 0xA5;
    output[3] = 0xA5;
    return 4;
}

static int c166_asm_einit(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xB5;
    output[1] = 0x4A;
    output[2] = 0xB5;
    output[3] = 0xB5;
    return 4;
}

static int c166_asm_ret(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xCB;
    output[1] = 0x00;
    return 2;
}

static int c166_asm_reti(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xFB;
    output[1] = 0x88;
    return 2;
}

static int c166_asm_rets(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xDB;
    output[1] = 0x00;
    return 2;
}

static int c166_asm_pwrdn(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0x97;
    output[1] = 0x68;
    output[2] = 0x97;
    output[3] = 0x97;
    return 4;
}

static int c166_asm_srst(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xB7;
    output[1] = 0x48;
    output[2] = 0xB7;
    output[3] = 0xB7;
    return 4;
}

static int c166_asm_srvwdt(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xA7;
    output[1] = 0x58;
    output[2] = 0xA7;
    output[3] = 0xA7;
    return 4;
}

static int c166_asm_idle(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0x87;
    output[1] = 0x78;
    output[2] = 0x87;
    output[3] = 0x87;
    return 4;
}

static int c166_asm_nop(const void* self, const char** tokens, ut32 ntokens, ut8 *output, ut64 pc, bool be) {
    output[0] = 0xCC;
    output[1] = 0x00;
    return 2;
}


static const C166Encoder instructions[] = {
	{ "add", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_ADD_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_ADD_Rwn_x },
    }},
    { "addc", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_ADDC_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_ADDC_Rwn_x },
    }},
    { "addb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_ADDB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_ADDB_Rbn_x },
    }},
    { "addcb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_ADDCB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_ADDCB_Rbn_x },
    }},
    { "ashr", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_ASHR_Rwn_Rwm },
        { C166_IFMT_Rw_data4, C166_ASHR_Rwn_data4 }
    }},
    { "and", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_AND_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_AND_Rwn_x },
    }},
    { "andb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_ANDB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_ANDB_Rbn_x },
    }},
    { "bclr", 2, 2, c166_asm_decode_fmts, {
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff0},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff1},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff2},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff3},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff4},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff5},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff6},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff7},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff8},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff9},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff10},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff11},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff12},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff13},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff14},
        {C166_IFMT_bitaddr_bit, C166_BCLR_bitoff15},
    }},
    { "bset", 2, 2, c166_asm_decode_fmts, {
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff0},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff1},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff2},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff3},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff4},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff5},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff6},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff7},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff8},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff9},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff10},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff11},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff12},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff13},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff14},
        {C166_IFMT_bitaddr_bit, C166_BSET_bitoff15},
    }},
    { "cpl", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rw, C166_CPL_Rwn }}},
    { "cplb", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rb, C166_CPLB_Rbn }}},
    { "cmp", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_CMP_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_CMP_Rwn_x },
    }},
    { "cmpb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_CMPB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_CMPB_Rbn_x },
    }},
    { "cmpd1", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_data4, C166_CMPD1_Rwn_data4 },
        { C166_IFMT_Rw_data16, C166_CMPD1_Rwn_data16 },
        { C166_IFMT_Rw_mem, C166_CMPD1_Rwn_mem },
    }},
    { "cmpd2", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_data4, C166_CMPD2_Rwn_data4 },
        { C166_IFMT_Rw_data16, C166_CMPD2_Rwn_data16 },
        { C166_IFMT_Rw_mem, C166_CMPD2_Rwn_mem },
    }},
    { "cmpi1", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_data4, C166_CMPI1_Rwn_data4 },
        { C166_IFMT_Rw_data16, C166_CMPI1_Rwn_data16 },
        { C166_IFMT_Rw_mem, C166_CMPI1_Rwn_mem },
    }},
    { "cmpi2", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_data4, C166_CMPI2_Rwn_data4 },
        { C166_IFMT_Rw_data16, C166_CMPI2_Rwn_data16 },
        { C166_IFMT_Rw_mem, C166_CMPI2_Rwn_mem },
    }},
    { "diswdt", 1, 1, c166_asm_diswdt, {}},
    { "div", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rw, C166_DIV_Rwn } }},
    { "divl", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rw, C166_DIVL_Rwn } }},
    { "divlu", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rw, C166_DIVLU_Rwn } }},
    { "divu", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rw, C166_DIVU_Rwn } }},
    { "einit", 1, 1, c166_asm_einit, {}},
    { "idle", 1, 1, c166_asm_idle, {}},
    { "mul", 3, 5, c166_asm_decode_fmts, {{ C166_IFMT_Rw_Rw, C166_MUL_Rwn_Rwm }}},
    { "mulu", 3, 5, c166_asm_decode_fmts, {{ C166_IFMT_Rw_Rw, C166_MULU_Rwn_Rwm }}},
    { "nop", 1, 1, c166_asm_nop, {}},
    { "or", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_OR_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_OR_Rwn_x },
    }},
    { "orb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_ORB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_ORB_Rbn_x },
    }},
    { "pop", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_reg, C166_POP_reg }}},
    { "prior", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_PRIOR_Rwn_Rwm }
    }},
    { "push", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_reg, C166_PUSH_reg }}},
    { "pwrdn", 1, 1, c166_asm_pwrdn, {}},
    { "ret", 1, 1, c166_asm_ret, {}},
    { "reti", 1, 1, c166_asm_reti, {}},
    { "retp", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_reg, C166_RETP_reg }}},
    { "rets", 1, 1, c166_asm_rets, {}},
    { "srst", 1, 1, c166_asm_srst, {}},
    { "srvwdt", 1, 1, c166_asm_srvwdt, {}},
    { "shl", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_SHL_Rwn_Rwm },
        { C166_IFMT_Rw_data4, C166_SHL_Rwn_data4 }
    }},
    { "shr", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_SHR_Rwn_Rwm },
        { C166_IFMT_Rw_data4, C166_SHR_Rwn_data4 }
    }},
    { "sub", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_SUB_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_SUB_Rwn_x },
    }},
    { "subb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_SUBB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_SUBB_Rbn_x },
    }},
    { "subc", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_SUBC_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_SUBC_Rwn_x },
    }},
    { "subcb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_SUBCB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_SUBCB_Rbn_x },
    }},
    { "rol", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_ROL_Rwn_Rwm },
        { C166_IFMT_Rw_data4, C166_ROL_Rwn_data4 }
    }},
    { "ror", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_ROR_Rwn_Rwm },
        { C166_IFMT_Rw_data4, C166_ROR_Rwn_data4 }
    }},
    { "mov", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_MOV_Rwn_Rwm },
        { C166_IFMT_Rw_data4, C166_MOV_Rwn_data4 }
    }},
    { "neg", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rw, C166_NEG_Rwn }}},
    { "negb", 2, 2, c166_asm_decode_fmts, {{ C166_IFMT_Rb, C166_NEGB_Rbn }}},

    { "xor", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rw_Rw, C166_XOR_Rwn_Rwm },
        { C166_IFMT_Rw_data3, C166_XOR_Rwn_x },
    }},
    { "xorb", 3, 5, c166_asm_decode_fmts, {
        { C166_IFMT_Rb_Rb, C166_XORB_Rbn_Rbm },
        { C166_IFMT_Rb_data3, C166_XORB_Rbn_x },
    }},
};

static void sanitize_input(char *cinput, st32 input_size) {
	for (st32 i = 0; i < input_size; ++i) {
		if (cinput[i] == ',') {
			cinput[i] = ' ';
		}
	}
}

static char *strdup_limit(const char *begin, const char *end) {
	ssize_t size = end - begin;
	if (size < 1) {
		return NULL;
	}
	char* str = malloc(size + 1);
	if (!str) {
		return NULL;
	}
	memcpy(str, begin, size);
	str[size] = 0;
	return str;
}

static char **tokens_new(const char *input, st32 input_size, ut32 *ntokens) {

	char* cinput = strdup(input);
	if (!cinput) {
		rz_warn_if_reached();
		return NULL;
	}

	sanitize_input(cinput, input_size);

	char **tokens = RZ_NEWS0(char*, MAX_TOKENS);
	if (!tokens) {
		free(cinput);
		rz_warn_if_reached();
		return NULL;
	}

	ut32 count;
	const char *start, *end;
	char* copy;

	start = rz_str_trim_head_ro(cinput);
	for (count = 0; *start && count < MAX_TOKENS; count++) {
		end = rz_str_trim_head_wp(start);

		for (ut32 i = 0; i < end - start; ++i) {
			if (start[i] == '+') {
				end = start + 1;
				break;
			}
		}

		copy = strdup_limit(start, end);
		if (!copy) {
			rz_warn_if_reached();
			break;
		}

		tokens[count] = copy;
		start = rz_str_trim_head_ro(end);
	}

	rz_warn_if_fail(count < MAX_TOKENS);

	*ntokens = count;
	free(cinput);
	return tokens;
}

static void tokens_free(char **tokens) {
	if (!tokens) {
		return;
	}
	for (ut32 i = 0; i < MAX_TOKENS; ++i) {
		free(tokens[i]);
	}
	free(tokens);
}

int c166_assemble_instruction(const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, bool be)
{
	return_error_if_empty_input(input, input_size);

	int result = -1;
	ut32 ntokens = 0;
	char** tokens = tokens_new(input, input_size, &ntokens);
	if (!tokens || ntokens < 1) {
		RZ_LOG_ERROR("[!] c166_assembler: invalid assembly.\n");
		goto c166_assembler_end;
	}

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(instructions); ++i) {
		if (is_equal(tokens[0], instructions[i].name)) {
			ut16 mintoks = instructions[i].mintoks;
			ut16 maxtoks = instructions[i].maxtoks;
			if (ntokens < mintoks || ntokens > maxtoks) {
				RZ_LOG_ERROR("[!] c166_assembler: '%s' requires %u <= ntokens <= %u, but %u tokens was provided.\n", tokens[0], mintoks, maxtoks, ntokens);
				goto c166_assembler_end;
			}
			result = instructions[i].encode(
                (void*)&instructions[i],
                (const char**)tokens, ntokens, output, pc, be
            );
			break;
		}
	}

c166_assembler_end:
	tokens_free(tokens);
	return result;
}
