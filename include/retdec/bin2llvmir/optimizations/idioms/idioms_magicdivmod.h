/**
 * @file include/retdec/bin2llvmir/optimizations/idioms/idioms_magicdivmod.h
 * @brief Magic div and modulo exchangers
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_MAGICDIVMOD_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_MAGICDIVMOD_H

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
namespace bin2llvmir {

/**
 * @brief Division and modulo using magic number
 *
 * References:
 *   GRANLUND, Torbjorn a Peter L. MONTGOMERY. Division by Invariant Integers
 *   Using Multiplication. 1994.
 *   Available online: http://gmplib.org/~tege/divcnst-pldi94.pdf
 */
class IdiomsMagicDivMod: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;

private:
	static unsigned divisorByMagicNumberUnsigned(unsigned magic_number, unsigned sh_pre, unsigned sh_post);
	static unsigned divisorByMagicNumberUnsigned2(unsigned magic_number, unsigned sh_post);
	static int      divisorByMagicNumberSigned(int magic_number, unsigned sh_post);
	static int      divisorByMagicNumberSigned2(int magic_number, unsigned sh_post);
	static unsigned divisorByMagicNumberSigned3(unsigned magic_number, unsigned shift);
	static unsigned divisorByMagicNumberSigned4(unsigned magic_number, unsigned shift);

	llvm::Instruction * magicSignedDiv7(llvm::BasicBlock::iterator iter, bool negative) const;
	llvm::Instruction * magicSignedDiv8(llvm::BasicBlock::iterator iter, bool negative) const;
protected:
	llvm::Instruction * magicUnsignedDiv1(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicUnsignedDiv2(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv1(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv2(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv3(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv4(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv5(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv6(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv7pos(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv7neg(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv8pos(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * magicSignedDiv8neg(llvm::BasicBlock::iterator iter) const;

	llvm::Instruction * signedMod1(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * signedMod2(llvm::BasicBlock::iterator iter) const;
	llvm::Instruction * unsignedMod(llvm::BasicBlock::iterator iter) const;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
