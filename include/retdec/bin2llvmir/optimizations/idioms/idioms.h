/**
 * @file include/retdec/bin2llvmir/optimizations/idioms/idioms.h
 * @brief Instruction idioms analysis
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_H

#include <list>

#include <llvm/IR/Function.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_analysis.h"
#include "retdec/bin2llvmir/optimizations/idioms/idioms_types.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
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

	IdiomsAnalysis * getCompilerAnalysis(llvm::Module & M);

private:
	IdiomsAnalysis * m_idioms;
	Config* m_config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
