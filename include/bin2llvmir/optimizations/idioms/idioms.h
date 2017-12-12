/**
 * @file include/bin2llvmir/optimizations/idioms/idioms.h
 * @brief Instruction idioms analysis
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_H
#define BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_H

#include <list>

#include <llvm/IR/Function.h>
#include <llvm/Pass.h>

#include "bin2llvmir/optimizations/idioms/idioms_abstract.h"
#include "bin2llvmir/optimizations/idioms/idioms_analysis.h"
#include "bin2llvmir/optimizations/idioms/idioms_types.h"
#include "bin2llvmir/providers/config.h"

namespace bin2llvmir {

/**
 * @brief Instruction idiom analysis.
 */
class LLVM_LIBRARY_VISIBILITY Idioms: public llvm::FunctionPass {
public:
	static char ID;
	Idioms();
	virtual ~Idioms() override;

	virtual bool runOnFunction(llvm::Function & f) override;
	virtual bool doInitialization(llvm::Module & M) override;
	virtual bool doFinalization(llvm::Module & M) override;

	virtual void getAnalysisUsage(llvm::AnalysisUsage & AU) const override;
	IdiomsAnalysis * getCompilerAnalysis(llvm::Module & M);

private:
	IdiomsAnalysis * m_idioms;
	Config* m_config = nullptr;
};

} // namespace bin2llvmir

#endif
