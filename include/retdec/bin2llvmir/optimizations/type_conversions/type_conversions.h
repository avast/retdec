/**
 * @file include/retdec/bin2llvmir/optimizations/type_conversions/type_conversions.h
 * @brief Removes unnecessary data type conversions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_TYPE_CONVERSIONS_TYPE_CONVERSIONS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_TYPE_CONVERSIONS_TYPE_CONVERSIONS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class TypeConversions : public llvm::ModulePass
{
	public:
		static char ID;
		TypeConversions();
		virtual bool doInitialization(llvm::Module& M) override;
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnFunction(llvm::Function& F);

	private:
		bool runInInstruction(llvm::Instruction* instr);
		bool replaceByShortcut(
				llvm::Instruction* start,
				llvm::Instruction* lastGood,
				unsigned cntr);
		bool removePtrToIntToPtr(llvm::Instruction* instr);

	private:
		llvm::Module* _module;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
