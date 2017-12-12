/**
* @file include/bin2llvmir/optimizations/idioms/idioms_vstudio.h
* @brief Visual Studio instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_VSTUDIO_H
#define BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_VSTUDIO_H

#include <llvm/IR/Instruction.h>

#include "bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace bin2llvmir {

/**
 * @brief Visual Studio instruction idioms
 */
class IdiomsVStudio: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;
protected:
	llvm::Instruction * exchangeAndZeroAssign(llvm::BasicBlock::iterator) const;
	llvm::Instruction * exchangeOrMinusOneAssign(llvm::BasicBlock::iterator) const;
};

} // namespace bin2llvmir

#endif
