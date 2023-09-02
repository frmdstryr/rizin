// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_asm.h>

#include "../arch/c166/c166_arch.h"
#include "../arch/c166/c166_assembler.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	rz_return_val_if_fail(a && op && buf, -1);
	if (len < 2) {
		return -1;
	}

	C166State *state = c166_get_state();
	if (!state) {
		RZ_LOG_FATAL("C166ExtState was NULL.");
	}
	C166Instr instr;
	ut32 addr = (ut32) a->pc;
	op->size = c166_disassemble_instruction(state, &instr, buf, len, addr);
	rz_strbuf_set(&op->buf_asm, instr.text);
	return op->size;
}


static int assemble(RzAsm *a, RzAsmOp *ao, const char *str) {
	st32 slen = strlen(str);
	ut8 buffer[16];
	int r = c166_assemble_instruction(str, slen, buffer, sizeof(buffer), a->pc, a->big_endian);

	if (r < 1) {
		return -1;
	}

	rz_strbuf_setbin(&ao->buf, (const ut8 *)&buffer, r);
    return r;
}

RzAsmPlugin rz_asm_plugin_c166 = {
	.name = "c166",
	.license = "LGPL3",
	.desc = "Bosch/Siemens C166 disassembly plugin",
	.arch = "c166",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.assemble = &assemble,
	.cpus = "c167cr"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_c166,
	.version = RZ_VERSION
};
#endif
