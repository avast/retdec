/**
 * @file include/retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces.h
 * @brief Optimize a single x86 address spaces instruction.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X86_ADDR_SPACES_X86_ADDR_SPACES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_X86_ADDR_SPACES_X86_ADDR_SPACES_H

#include <llvm/IR/Instruction.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {
namespace x86_addr_spaces {

/**
 * Replace loads and stores from GS and FS address spaces with RetDec intrinsic
 * functions inspired by MSVC.
 *   https://msdn.microsoft.com/en-us/library/3887zk1s.aspx
 *   https://msdn.microsoft.com/en-us/library/xfh6tchw.aspx
 *   https://msdn.microsoft.com/en-us/library/htss0hyy.aspx
 *   https://msdn.microsoft.com/en-us/library/529bay7a.aspx
 *
 * We could generate these intrinsics in capstone2llvmir instead of loads and
 * stores. Then this replacement would not be needed. But then all the LLVM
 * analyses would lose semantics that these operations are loads and stores - it
 * would not be possible to optimize them.
 * To get this semantics back, they would need to know the semantics of the
 * intrinsics, which would be ugly for our passes (additional checks for
 * intrinsic calls), and impossible for stock LLVM passes.
 *
 * x86 has 6 segment registers - DS, SS, CS, ES, FS, GS.
 * DS is the default data segment.
 * Right now we optimize to intrinsics only loads/stores of FS and GS - same as
 * Hex-Rays and MSVC.
 * SS, CS, ES are interpretted the same as DS.
 * E.g.:
 *   binary  : a1 18 00 00 00
 *   assembly: mov eax, ds:0x18
 *   Hex-Rays: MEMORY[0x18];
 *
 *   binary  : 36 a1 18 00 00 00
 *   assembly: mov eax, ss:0x18
 *   Hex-Rays: MEMORY[0x18]
 *
 *   binary  : 2e a1 18 00 00 00
 *   assembly: mov eax, cs:0x18
 *   Hex-Rays: MEMORY[0x18]
 *
 *   binary  : 26 a1 18 00 00 00
 *   assembly: mov eax, es:0x18
 *   Hex-Rays: MEMORY[0x18]
 *
 *   binary  : 64 a1 18 00 00 00
 *   assembly: mov eax, fs:0x18
 *   Hex-Rays: __readfsdword(0x18u);
 *
 *   binary  : 65 a1 18 00 00 00
 *   assembly: mov eax, gs:0x18
 *   Hex-Rays: __readgsdword(0x18u);
 */
llvm::Instruction* optimize(llvm::Instruction* insn, Config* config);

/**
 * The same as \c optimize(insn,c) if \a isX86 is \c true, does nothing
 * otherwise.
 *
 * It hides condition so that it can be used as a one-liner like this:
 *   optimize(insn, c, condition)
 */
llvm::Instruction* optimize(
		llvm::Instruction* insn,
		bool isX86,
		Config* config);

} // namespace x86_addr_spaces
} // namespace bin2llvmir
} // namespace retdec

#endif
