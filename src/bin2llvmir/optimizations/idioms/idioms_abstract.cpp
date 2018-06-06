/**
 * @file src/bin2llvmir/optimizations/idioms/idioms_abstract.cpp
 * @brief Implementation of the instruction idioms analysis abstract class
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

IdiomsAbstract::IdiomsAbstract():
	m_arch(ARCH_ANY), m_compiler(CC_ANY), m_module(nullptr) {}

void IdiomsAbstract::init(llvm::Module * M, CC_compiler cc, CC_arch arch) {
	m_compiler = cc;
	m_arch = arch;
	m_module = M;
}

/**
 * Find a branch instruction in a BasicBlock
 *
 * @param br found branch instruction
 * @param bb basic block to look for br
 * @param val Value or Instruction with branch use
 */
bool IdiomsAbstract::findBranchDependingOn(llvm::BranchInst ** br, llvm::BasicBlock & bb,
		const llvm::Value * val) const {
	for (llvm::BasicBlock::iterator i = bb.begin(); i != bb.end(); ++i) {
		if ((*br = llvm::dyn_cast<llvm::BranchInst>(i)))
			if ((*br)->getNumOperands() >= 1 && (*br)->getOperand(0) == val)
				return true;
	}

	*br = nullptr;
	return false;
}

/**
 * Look for instruction by value and erase it from module.
 *
 * @param val instruction value to look for
 * @param bb BasicBlock to erase instruction from
 * @return void
 */
void IdiomsAbstract::eraseInstFromBasicBlock(llvm::Value * val, llvm::BasicBlock * bb) {
	for (llvm::BasicBlock::iterator end = bb->end(), i = bb->begin(); i != end; ++i) {
		llvm::Value * rem = static_cast<llvm::Value*>(&(*i));
		if (val == rem) {
			rem->replaceAllUsesWith(llvm::UndefValue::get(val->getType()));
			(*i).eraseFromParent();
			break;
		}
	}
}

/**
 * Is value a power of two?
 * @param x value to be check
 * @return true if value is power of two or zero
 */
bool IdiomsAbstract::isPowerOfTwo(unsigned x) {
	return ((x != 0) && ! (x & (x - 1)));
}

/**
* Is @c 2^cnst representable on the bit width of @a cnst?
*
* If you want to compute <tt>pow(2, cnst)</tt>, always ensure that @c
* isPowerOfTwoRepresentable(cnst) returns @c true.
*/
bool IdiomsAbstract::isPowerOfTwoRepresentable(const ConstantInt *cnst) {
	// When cnst has bit width X (i.e. its type is iX), representable powers
	// are up to 2^(X - 2). For example, when the type of cnst is i32,
	// representable powers are up to 2^30. 2^31 is not representable because
	// 2^31 == 2147483648, which is not representable on 32 bits when
	// considered the type to be a signed integer. Technically, it is
	// representable on 32 bits as an unsigned integer, but when considered as
	// a signed value, it is not representable.
	//
	// Consider an optimization of the following idiom:
	//
	//     %b = shl i32 %a, 31
	//
	// If we allowed 2^31 to be representable, we would end up with the
	// following replacement of the original instruction:
	//
	//     %b = mul i32 %a, -2147483648
	//
	// However, this causes -instcombine to loop/crash, which is the
	// reason why we consider 2^31 to be unrepresentable. Testing example:
	//
	//     define i32 @func(i32 %a) {
	//       %b = add i32 %a, 1
	//       %c = mul i32 %b, -2147483648
	//       ret i32 %c
	//     }
	//
	// When the above example was compiled and run, opt failed to produce a
	// result:
	//
	//     ./llvm-as func.ll && ./opt -instcombine -o func-opt.bc < func.bc
	//
	// By not allowing such optimizations, we ensure that opt does not fail.
	// And this is precisely what this function does.
	return cnst->getZExtValue() < (cnst->getBitWidth() - 1);
}

} // namespace bin2llvmir
} // namespace retdec
