/**
 * @file src/bin2llvmir/optimizations/idioms/idioms_analysis.cpp
 * @brief Instruction idioms analysis
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/optimizations/idioms/idioms_analysis.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

/*
 * Stats of exchanged idioms.
 */
STATISTIC(NumIdioms, "Number of idioms exchanged in total");

/**
 * Analyse given BasicBlock and use instruction exchanger to transform
 * instruction idioms
 *
 * @param bb BasicBlock to analyse
 * @param exchanger instruction idiom exchanger
 * @param fname instruction idiom exchanger name (for debug purpose only)
 */
bool IdiomsAnalysis::analyse(llvm::BasicBlock & bb, llvm::Instruction * (IdiomsAnalysis::*exchanger)(llvm::BasicBlock::iterator) const, const char * fname) {
	bool change_made = false;

	for (BasicBlock::iterator iter = bb.begin(), end = bb.end(); iter != end; /**/) {
		BasicBlock::iterator insn = iter;
		++iter; // go to next instruction to use valid iterator in next loop

		// call exchanger on every instruction
		Instruction * res = (this->*exchanger)(insn);

		if (res) {
			++NumIdioms;

			change_made = true;

			(*insn).replaceAllUsesWith(res);
			print_dbg(fname, *insn);

			// Move the name to the new instruction first.
			res->takeName(&*insn);

			// Insert the new instruction into the basic block...
			BasicBlock * InstParent = (*insn).getParent();

			// If we replace a PHI with something that isn't a PHI,
			// fix up the insertion point.
			if (! isa<PHINode>(res) && isa<PHINode>(insn))
				insn = InstParent->getFirstInsertionPt();

			InstParent->getInstList().insert(insn, res);

			(*insn).eraseFromParent();
		}
	}

	return change_made;
}

/**
 * Do instruction idioms analysis pass
 *
 * @param f Function to analyse for instruction idioms
 * @param p actual pass
 * @return true whenever an exchange has been made, otherwise 0
 */
bool IdiomsAnalysis::doAnalysis(Function & f, Pass * p) {
	/*
	 * Instruction idioms are inspected in a tree of Instructions. Every
	 * instruction idiom has to be called on a basic block. Position of
	 * instruction idiom exchangers is IMPORTANT! More complicated instruction
	 * idioms have to be exchanged before simplier ones. They can consist of
	 * other instruction idioms (the simple ones), so they have to be exchanged
	 * at first place!
	 */
	bool change_made = false; // was there any exchange?

	CC_compiler cc = getCompiler();
	CC_arch arch = getArch();

	// Inspect multi-basic block idioms
	if (cc == CC_GCC || cc == CC_ANY) {
		change_made |= analyse(f, p, &IdiomsGCC::exchangeCondBitShiftDivMultiBB,
									"IdiomsGCC::exchangeCondBitShiftDivMultiBB");
	}

	// Inspect basic-block idioms
	for (Function::iterator b = f.begin(); b != f.end(); ++b) {
		BasicBlock & bb = *b;
		if (arch == ARCH_POWERPC || arch == ARCH_ARM || arch == ARCH_x86 || arch == ARCH_THUMB || arch == ARCH_ANY)
			if (cc == CC_GCC || cc == CC_Intel || cc == CC_VStudio || cc == CC_ANY) {
				change_made |= analyse(bb, &IdiomsMagicDivMod::signedMod1,
											"IdiomsMagicDivMod::signedMod1");

				change_made |= analyse(bb, &IdiomsMagicDivMod::signedMod2,
											"IdiomsMagicDivMod::signedMod2");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicUnsignedDiv2,
											"IdiomsMagicDivMod::magicUnsignedDiv2");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicUnsignedDiv1,
											"IdiomsMagicDivMod::magicUnsignedDiv1");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv1,
											"IdiomsMagicDivMod::magicSignedDiv1");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv2,
											"IdiomsMagicDivMod::magicSignedDiv2");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv3,
											"IdiomsMagicDivMod::magicSignedDiv3");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv4,
											"IdiomsMagicDivMod::magicSignedDiv4");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv5,
											"IdiomsMagicDivMod::magicSignedDiv5");

				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv6,
											"IdiomsMagicDivMod::magicSignedDiv6");

				// Found in PowerPC - div 10
				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv7pos,
											"IdiomsMagicDivMod::magicSignedDiv7pos");

				// Found in PowerPC - the same as previous, but the divisor
				// is negative, i.e. div -10
				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv7neg,
											"IdiomsMagicDivMod::magicSignedDiv7neg");

				// Found in PowerPC - div 6
				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv8pos,
											"IdiomsMagicDivMod::magicSignedDiv8pos");

				// Found in PowerPC - the same as previous, but the divisor
				// is negative, i.e. div -3
				change_made |= analyse(bb, &IdiomsMagicDivMod::magicSignedDiv8neg,
											"IdiomsMagicDivMod::magicSignedDiv8neg");

				change_made |= analyse(bb, &IdiomsMagicDivMod::unsignedMod,
											"IdiomsMagicDivMod::unsignedMod");
		}

		// all arch
		if (cc == CC_GCC || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsGCC::exchangeSignedModuloByTwo,
										"IdiomsGCC::exchangeSignedModuloByTwo");

		// PowerPC model lacks FPU and x86 uses x87.
		if (arch == ARCH_ARM || arch == ARCH_THUMB || arch == ARCH_MIPS || arch == ARCH_ANY)
			if (cc == CC_GCC || cc == CC_ANY)
				change_made |= analyse(bb, &IdiomsGCC::exchangeCopysign,
											"IdiomsGCC::exchangeCopysign");

		// PowerPC model lacks FPU and x86 uses x87.
		if (arch == ARCH_ARM || arch == ARCH_THUMB || arch == ARCH_MIPS || arch == ARCH_ANY)
			if (cc == CC_GCC || cc == CC_ANY)
				change_made |= analyse(bb, &IdiomsGCC::exchangeFloatAbs,
											"IdiomsGCC::exchangeFloatAbs");

		if (arch == ARCH_x86 || arch == ARCH_ANY)
			if (cc == CC_Intel || cc == CC_VStudio || cc == CC_ANY)
				change_made |= analyse(bb, &IdiomsVStudio::exchangeOrMinusOneAssign,
											"IdiomsVStudio::exchangeOrMinusOneAssign");

		if (arch == ARCH_x86 || arch == ARCH_ANY)
			if (cc == CC_Intel || cc == CC_VStudio || cc == CC_ANY)
				change_made |= analyse(bb, &IdiomsVStudio::exchangeAndZeroAssign,
										"IdiomsVStudio::exchangeAndZeroAssign");

		// all arch
		if (cc == CC_GCC || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsGCC::exchangeCondBitShiftDiv1,
										"IdiomsGCC::exchangeCondBitShiftDiv1");

		// all arch
		if (cc == CC_GCC || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsGCC::exchangeCondBitShiftDiv2,
										"IdiomsGCC::exchangeCondBitShiftDiv2");

		// all arch
		if (cc == CC_GCC || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsGCC::exchangeCondBitShiftDiv3,
										"IdiomsGCC::exchangeCondBitShiftDiv3");

		// all arch
		if (cc == CC_GCC || cc == CC_Intel || cc == CC_LLVM || cc == CC_VStudio || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsCommon::exchangeSignedModulo2n,
										"IdiomsCommon::exchangeSignedModulo2n");

		// all arch
		if (cc == CC_GCC || cc == CC_Intel || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsCommon::exchangeGreaterEqualZero,
										"IdiomsCommon::exchangeGreaterEqualZero");

		// all arch
		if (cc == CC_GCC || cc == CC_LLVM || cc == CC_VStudio || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsGCC::exchangeXorMinusOne,
										"IdiomsGCC::exchangeXorMinusOne");

		if (arch == ARCH_POWERPC || arch == ARCH_ARM || arch == ARCH_THUMB || arch == ARCH_MIPS || arch == ARCH_ANY)
			if (cc == CC_GCC || cc == CC_ANY)
				change_made |= analyse(bb, &IdiomsCommon::exchangeDivByMinusTwo,
											"IdiomsCommon::exchangeDivByMinusTwo");

		// all arch
		if (cc == CC_GCC || cc == CC_Intel || cc == CC_LLVM || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsCommon::exchangeLessThanZero,
										"IdiomsCommon::exchangeLessThanZero");

		// PowerPC model lacks FPU and x86 uses x87.
		if (cc == CC_GCC || cc == CC_ANY)
			if (arch == ARCH_ARM || arch == ARCH_THUMB || arch == ARCH_MIPS || arch == ARCH_ANY)
				change_made |= analyse(bb, &IdiomsGCC::exchangeFloatNeg,
											"IdiomsGCC::exchangeFloatNeg");

		// all arch
		if (cc == CC_GCC || cc == CC_ANY)
			change_made |= analyse(bb, &IdiomsCommon::exchangeUnsignedModulo2n,
										"IdiomsCommon::exchangeUnsignedModulo2n");

		// all arch
		if (cc == CC_LLVM || cc == CC_ANY)
				change_made |= analyse(bb, &IdiomsLLVM::exchangeIsGreaterThanMinusOne,
											"IdiomsLLVM::exchangeIsGreaterThanMinusOne");

		// all arch
		// all compilers
		change_made |= analyse(bb, &IdiomsCommon::exchangeBitShiftSDiv1,
									"IdiomsCommon::exchangeBitShiftSDiv1");

		// all arch
		// all compilers
		change_made |= analyse(bb, &IdiomsCommon::exchangeBitShiftSDiv2,
									"IdiomsCommon::exchangeBitShiftSDiv2");

		// all arch
		// all compilers
		change_made |= analyse(bb, &IdiomsCommon::exchangeBitShiftUDiv,
									"IdiomsCommon::exchangeBitShiftUDiv");

		// all arch
		// all compilers
		change_made |= analyse(bb, &IdiomsCommon::exchangeBitShiftMul,
									"IdiomsCommon::exchangeBitShiftMul");

		// all arch
		if (cc == CC_LLVM || cc == CC_ANY) {
			change_made |= analyse(bb, &IdiomsLLVM::exchangeIsGreaterThanMinusOne,
										"IdiomsLLVM::exchangeIsGreaterThanMinusOne");
		}

		// all arch
		if (cc == CC_LLVM || cc == CC_ANY) {
			change_made |= analyse(bb, &IdiomsLLVM::exchangeCompareEq,
										"IdiomsLLVM::exchangeCompareEq");

	#if 0
			/* We do not recognize this well */
			change_made |= analyse(bb, &IdiomsLLVM::exchangeCompareNeq,
										"IdiomsLLVM::exchangeCompareNeq");
	#endif

			change_made |= analyse(bb, &IdiomsLLVM::exchangeCompareSlt,
										"IdiomsLLVM::exchangeCompareSlt");

			change_made |= analyse(bb, &IdiomsLLVM::exchangeCompareSle,
									"IdiomsLLVM::exchangeCompareSle");
		}
	}

	return change_made;
}

/**
 * Analyse given Function and use instruction exchanger to transform
 * instruction idioms
 *
 * @param f function to visit
 * @param p actual pass
 * @param exchanger instruction idiom exchanger
 * @param fname instruction idiom exchanger name (for debug purpose only)
 * @return true whenever an exchange has been made, otherwise 0
 */
bool IdiomsAnalysis::analyse(llvm::Function & f, llvm::Pass * p, int (IdiomsAnalysis::*exchanger)(llvm::Function &, llvm::Pass *) const, const char * fname) {
	int num_idioms = 0;

	num_idioms += IdiomsGCC::exchangeCondBitShiftDivMultiBB(f, p);

	NumIdioms += num_idioms;

	return num_idioms == 0;
}

} // namespace bin2llvmir
} // namespace retdec
