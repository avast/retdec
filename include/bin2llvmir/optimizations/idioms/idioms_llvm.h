/**
* @file include/bin2llvmir/optimizations/idioms/idioms_llvm.h
* @brief clang/LLVM instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_LLVM_H
#define BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_LLVM_H

#include "bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace bin2llvmir {

/**
 * @brief clang/LLVM instruction idioms
 */
class IdiomsLLVM: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;

protected:
	llvm::Instruction * exchangeIsGreaterThanMinusOne(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCompareEq(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCompareNeq(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCompareSlt(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * exchangeCompareSle(llvm::BasicBlock::iterator iter) const;
};

} // namespace bin2llvmir

#endif
