/**
 * @file include/retdec/bin2llvmir/utils/ir_modifier.h
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H
#define RETDEC_BIN2LLVMIR_UTILS_IR_MODIFIER_H

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class IrModifier
{
	public:
		using FunctionPair = std::pair<llvm::Function*, retdec::config::Function*>;
		using StackPair = std::pair<llvm::AllocaInst*, retdec::config::Object*>;

	// Methods not using member data -> do not need instance of this class.
	// Can be used simply like this: \c IrModifier::method().
	//
	public:
		template<typename Container>
		static bool localize(
				llvm::Instruction* storeDefinition,
				const Container& uses,
				bool eraseDefinition = true);

		static llvm::AllocaInst* createAlloca(
				llvm::Function* fnc,
				llvm::Type* ty,
				const std::string& name = "");

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
				const std::string& name = "stack_var");

		llvm::GlobalVariable* getGlobalVariable(
				FileImage* objf,
				DebugFormat* dbgf,
				retdec::utils::Address addr,
				bool strict = false,
				std::string name = "global_var");

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

template<typename Container>
bool IrModifier::localize(
		llvm::Instruction* storeDefinition,
		const Container& uses,
		bool eraseDefinition)
{
	llvm::StoreInst* definition = llvm::dyn_cast_or_null<llvm::StoreInst>(
			storeDefinition);
	if (definition == nullptr)
	{
		return false;
	}
	auto* ptr = definition->getPointerOperand();
	auto* f = definition->getFunction();

	auto* local = new llvm::AllocaInst(ptr->getType()->getPointerElementType());
	local->insertBefore(&f->getEntryBlock().front());

	new llvm::StoreInst(definition->getValueOperand(), local, definition);
	if (eraseDefinition)
	{
		definition->eraseFromParent();
	}

	for (auto* u : uses)
	{
		reinterpret_cast<llvm::Instruction*>(u)->replaceUsesOfWith(ptr, local);
	}

	return true;
}

} // namespace bin2llvmir
} // namespace retdec

#endif
