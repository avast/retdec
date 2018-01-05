/**
* @file src/bin2llvmir/optimizations/idioms/idioms_vstudio.cpp
* @brief Visual Studio instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_vstudio.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Exchange X & 0 with X = 0
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
llvm::Instruction * IdiomsVStudio::exchangeAndZeroAssign(llvm::BasicBlock::iterator iter) const {
	llvm::Instruction & val = (*iter);
	llvm::Value * op0 = nullptr;
	llvm::ConstantInt *cnst = nullptr;

	// X & 0  --> X = X + 0
	if (llvm::PatternMatch::match(&val, llvm::PatternMatch::m_And(
									llvm::PatternMatch::m_Value(op0),
									llvm::PatternMatch::m_ConstantInt(cnst)))
			&& *cnst->getValue().getRawData() == 0) {
		llvm::Constant *NewCst = llvm::ConstantInt::get(op0->getType(), 0);
		return llvm::BinaryOperator::CreateAdd(NewCst, NewCst);
	}

	return nullptr;
}

/**
 * Exchange X | -1 with X = -1
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
llvm::Instruction * IdiomsVStudio::exchangeOrMinusOneAssign(llvm::BasicBlock::iterator iter) const {
	llvm::Instruction & val = (*iter);
	llvm::Value * op0 = nullptr;
	llvm::ConstantInt *cnst = nullptr;

	// X | -1  --> X = 0 + (-1)
	if (llvm::PatternMatch::match(&val, llvm::PatternMatch::m_Or(
									llvm::PatternMatch::m_Value(op0),
									llvm::PatternMatch::m_ConstantInt(cnst)))
			&& cnst->isMinusOne()) {
		llvm::Constant *NewCst = llvm::ConstantInt::get(op0->getType(), 0);
		llvm::Constant *NewCst2 = llvm::ConstantInt::get(op0->getType(), -1);
		return llvm::BinaryOperator::CreateAdd(NewCst, NewCst2);
	}

	return nullptr;
}

} // namespace bin2llvmir
} // namespace retdec
