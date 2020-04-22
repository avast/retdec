/**
 * @file include/retdec/bin2llvmir/optimizations/inst_opt_rda/inst_opt_rda.h
 * @brief Optimize a single LLVM instruction using RDA.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_RDA_INST_OPT_RDA_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_INST_OPT_RDA_INST_OPT_RDA_H

#include <unordered_set>

#include <llvm/IR/Instruction.h>

namespace retdec {
namespace bin2llvmir {

class ReachingDefinitionsAnalysis;
class Abi;

namespace inst_opt_rda {

bool optimize(
		llvm::Instruction* insn,
		ReachingDefinitionsAnalysis& RDA,
		Abi* abi,
		std::unordered_set<llvm::Value*>* toRemove = nullptr);

} // namespace inst_opt_rda
} // namespace bin2llvmir
} // namespace retdec

#endif
