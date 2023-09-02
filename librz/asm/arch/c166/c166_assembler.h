// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_C166_ASSEMBLER_H
#define RZ_ASM_C166_ASSEMBLER_H

RZ_API int c166_assemble_instruction(const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, bool be);

#endif /* RZ_ASM_C166_ASSEMBLER_H */

