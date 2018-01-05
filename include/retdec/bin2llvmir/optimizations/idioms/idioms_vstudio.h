/**
* @file include/retdec/bin2llvmir/optimizations/idioms/idioms_vstudio.h
* @brief Visual Studio instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_VSTUDIO_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_VSTUDIO_H

#include <llvm/IR/Instruction.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
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
} // namespace retdec

#endif
