/**
 * @file include/retdec/bin2llvmir/optimizations/idioms/idioms_analysis.h
 * @brief Instruction idioms analysis
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_ANALYSIS_H

#include <cstdio>

#include <llvm/ADT/Statistic.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_borland.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_common.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_gcc.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_intel.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_llvm.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_magicdivmod.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_owatcom.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_types.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_vstudio.h"
#include "retdec/bin2llvmir/providers/config.h"

#ifdef DEBUG_TYPE
#undef DEBUG_TYPE // "idioms"
#endif // DEBUG_TYPE "idioms"
#define DEBUG_TYPE "idioms"

namespace retdec {
namespace bin2llvmir {

class IdiomsAnalysis:
	public IdiomsBorland,
	public IdiomsCommon,
	public IdiomsGCC,
	public IdiomsIntel,
	public IdiomsLLVM,
	public IdiomsMagicDivMod,
	public IdiomsOWatcom,
	public IdiomsVStudio  {
public:
	IdiomsAnalysis(llvm::Module * M, CC_compiler cc, CC_arch arch)
	{
		init(M, cc, arch);
	}
	virtual bool doAnalysis(llvm::Function & f, llvm::Pass * p) override;

private:
	bool analyse(llvm::Function & f, llvm::Pass * p, int (IdiomsAnalysis::*exchanger)(llvm::Function &, llvm::Pass *) const, const char * fname);
	bool analyse(llvm::BasicBlock & bb, llvm::Instruction * (IdiomsAnalysis::*exchanger)(llvm::BasicBlock::iterator) const, const char * fname);

	void print_dbg(const char * str, const llvm::Instruction & i) const {
		DEBUG(llvm::errs() << str << " detected an idiom starting at " << i.getName() << "\n");
	}
};

} // namespace bin2llvmir
} // namespace retdec

#endif
