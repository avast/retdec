/**
 * @file include/retdec/bin2llvmir/optimizations/idioms/idioms_common.h
 * @brief Common compiler instruction idioms
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_COMMON_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_COMMON_H

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
namespace bin2llvmir {

/**
 * @brief Common compiler instruction idioms
 */
class IdiomsCommon: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;
protected:
	llvm::Instruction * exchangeDivByMinusTwo(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeUnsignedModulo2n(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeLessThanZero(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeGreaterEqualZero(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeBitShiftSDiv1(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeBitShiftSDiv2(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeBitShiftUDiv(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeBitShiftMul(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeSignedModulo2n(llvm::BasicBlock::iterator iter) const;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
