/**
 * @file include/retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h
 * @brief Optimize a single LLVM instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPTIMIZER_INST_OPT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPTIMIZER_INST_OPT_H

#include <llvm/IR/Instruction.h>

namespace retdec {
namespace bin2llvmir {
namespace inst_opt {

bool optimize(llvm::Instruction* insn);

} // namespace inst_opt
} // namespace bin2llvmir
} // namespace retdec

#endif
