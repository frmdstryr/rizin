// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_util.h>
#include <rz_bin.h>

static bool check_buffer(RzBuffer *buf) {
	ut8 c = 0;
	ut8 i = 0;
	if (rz_buf_size(buf) < 64) {
		return false;
	}
	// Should point to vector table with a bunch of jmps
	while (i < 64) {
		if (!rz_buf_read8_at(buf, i, &c) || c != 0xFA) {
			return false; // Not a jmp
		}
		i += 4;
	}
	return true;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	return check_buffer(buf);
}

static void destroy(RzBinFile *bf) {
	rz_buf_free(bf->o->bin_obj);
	bf->o->bin_obj = NULL;
}

static RzBinInfo *info(RzBinFile *arch) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free(ret);
		return NULL;
	}
	ret->file = strdup(arch->file);
	ret->type = strdup("ROM");
	ret->machine = strdup("Bosch/Siemens C166");
	ret->os = strdup("c166");
	ret->arch = strdup("c166");
	ret->bits = 8;

	return ret;
}

struct rz_bin_plugin_t rz_bin_plugin_c166 = {
	.name = "c166",
	.desc = "Bosch/Siemens C166",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = NULL,
	.sections = NULL,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_c166,
	.version = RZ_VERSION
};
#endif
