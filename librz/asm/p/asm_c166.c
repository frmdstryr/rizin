// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_asm.h>

#include "../arch/c166/c166_dis.h"

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	c166_cmd cmd;
	int ret = c166_decode_command(buf, &cmd, len);
	rz_strbuf_set(&op->buf_asm, sdb_fmt("%s %s", cmd.instr, cmd.operands));
	if (ret > 0) {
		rz_warn_if_fail(ret == c166_opcode_sizes[buf[0]]);
	}
	return op->size = ret;
}

RzAsmPlugin rz_asm_plugin_c166 = {
	.name = "c166",
	.license = "LGPL3",
	.desc = "Bosch/Siemens C166 disassembly plugin",
	.arch = "c166",
	.bits = 16,
	.endian = RZ_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.cpus = "c167cr"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_c166,
	.version = RZ_VERSION
};
#endif
