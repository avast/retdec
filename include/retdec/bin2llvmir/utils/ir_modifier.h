/**
 * @file include/retdec/bin2llvmir/utils/ir_modifier.h
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H
#define RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class IrModifier
{
	public:
		using FunctionPair = std::pair<llvm::Function*, retdec::common::Function*>;
		using StackPair = std::pair<llvm::AllocaInst*, const retdec::common::Object*>;

	// Methods not using member data -> do not need instance of this class.
	// Can be used simply like this: \c IrModifier::method().
	//
	public:
		static llvm::AllocaInst* createAlloca(
				llvm::Function* fnc,
				llvm::Type* ty,
				const std::string& name = std::string());

		static llvm::Value* convertValueToType(
				llvm::Value* val,
				llvm::Type* type,
				llvm::Instruction* before);

		static llvm::Value* convertValueToTypeAfter(
				llvm::Value* val,
				llvm::Type* type,
				llvm::Instruction* after);

		static llvm::Constant* convertConstantToType(
				llvm::Constant* val,
				llvm::Type* type);

		static llvm::CallInst* modifyCallInst(
				llvm::CallInst* call,
				llvm::Type* ret,
				llvm::ArrayRef<llvm::Value*> args);

		static llvm::CallInst* modifyCallInstCallee(
				llvm::CallInst* call,
				llvm::Function* new_callee);

		static void eraseUnusedInstructionRecursive(llvm::Value* insn);
		static void eraseUnusedInstructionsRecursive(
				std::unordered_set<llvm::Value*>& insns);

	public:
		IrModifier(llvm::Module* m, Config* c);

	// Methods using member data -> need instance of this class.
	//
	public:
		FunctionPair renameFunction(
				llvm::Function* fnc,
				const std::string& fncName);

		StackPair getStackVariable(
				llvm::Function* fnc,
				int offset,
				llvm::Type* type,
				const std::string& name = std::string(),
				const std::string& realName = std::string(),
				bool fromDebug = false);

		llvm::GlobalVariable* getGlobalVariable(
				FileImage* objf,
				DebugFormat* dbgf,
				retdec::common::Address addr,
				bool strict = false,
				const std::string& name = std::string());

		llvm::Value* changeObjectType(
				FileImage* objf,
				llvm::Value* val,
				llvm::Type* toType,
				llvm::Constant* init = nullptr,
				std::unordered_set<llvm::Instruction*>* instToErase = nullptr,
				bool dbg = false,
				bool wideString = false);

		FunctionPair modifyFunction(
				llvm::Function* fnc,
				llvm::Type* ret,
				std::vector<llvm::Type*> args,
				bool isVarArg = false,
				const std::map<llvm::ReturnInst*, llvm::Value*>& rets2vals =
						std::map<llvm::ReturnInst*, llvm::Value*>(),
				const std::map<llvm::CallInst*, std::vector<llvm::Value*>>& calls2vals =
						std::map<llvm::CallInst*, std::vector<llvm::Value*>>(),
				llvm::Value* retVal = nullptr,
				const std::vector<llvm::Value*>& argStores =
						std::vector<llvm::Value*>(),
				const std::vector<std::string>& argNames = std::vector<std::string>());

		llvm::Argument* modifyFunctionArgumentType(
				llvm::Argument* arg,
				llvm::Type* type);

	protected:
		llvm::Value* changeObjectDeclarationType(
				FileImage* objf,
				llvm::Value* val,
				llvm::Type* toType,
				llvm::Constant* init = nullptr,
				bool wideString = false);

	protected:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
