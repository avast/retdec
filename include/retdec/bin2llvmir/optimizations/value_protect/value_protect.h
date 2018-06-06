/**
* @file include/retdec/bin2llvmir/optimizations/value_protect/value_protect.h
* @brief Protect values from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VALUE_PROTECT_VALUE_PROTECT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VALUE_PROTECT_VALUE_PROTECT_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

/**
 * Generates patterns like this at functions' entry BBs:
 * \code{.ll}
 *    %1 = call i32 @__decompiler_undefined_function_X()
 *    store i32 %1, i32* XYZ
 * \endcode
 * Where XYZ are allocated variables (registers, stacks).
 *
 * This is done to protect these variables from aggressive LLVM optimizations.
 * This way, stacks are not uninitialized, and registers are not equal to
 * their initialization values.
 *
 * Every even run generates these protections.
 * Every odd run removes them
 * (partially, see https://github.com/avast-tl/retdec/issues/301).
 */
class ValueProtect : public llvm::ModulePass
{
	public:
		static char ID;
		ValueProtect();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c, Abi* abi);

	private:
		bool run();
		void protect();
		void protectStack();
		void protectRegisters();
		void unprotect();

		void protectValue(
				llvm::Value* val,
				llvm::Type* t,
				llvm::Instruction* before);

		llvm::Function* getOrCreateFunction(llvm::Type* t);
		llvm::Function* createFunction(llvm::Type* t);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		static std::map<llvm::Type*, llvm::Function*> _type2fnc;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
