/**
 * @file include/retdec/bin2llvmir/optimizations/idioms/idioms_gcc.h
 * @brief GNU/GCC instruction idioms
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_GCC_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_GCC_H

#include <llvm/IR/Instruction.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
namespace bin2llvmir {

/**
 * @brief GNU/GCC instruction idioms
 */
class IdiomsGCC: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;

protected:
	llvm::Instruction * exchangeFloatNeg(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeXorMinusOne(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeSignedModuloByTwo(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCondBitShiftDiv1(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCondBitShiftDiv2(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCondBitShiftDiv3(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCopysign(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeFloatAbs(llvm::BasicBlock::iterator iter) const;

	// multi BB idioms
	int exchangeCondBitShiftDivMultiBB(llvm::Function & f, llvm::Pass * pass) const;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
