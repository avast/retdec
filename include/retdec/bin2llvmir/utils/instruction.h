/**
 * @file include/retdec/bin2llvmir/utils/instruction.h
 * @brief LLVM instruction utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_INSTRUCTION_H
#define RETDEC_BIN2LLVMIR_UTILS_INSTRUCTION_H

#include <map>
#include <set>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class Definition;
class ReachingDefinitionsAnalysis;

std::set<llvm::Function*> getParentFuncsFor(llvm::User* user);
bool isDirectCall(const llvm::CallInst& inst);
bool isDirectCall(const llvm::CallInst* inst);
bool isIndirectCall(const llvm::CallInst& inst);
bool isIndirectCall(const llvm::CallInst* inst);
bool isFncDeclarationCall(const llvm::CallInst& inst);
bool isFncDeclarationCall(const llvm::CallInst* inst);
bool isFncDefinitionCall(const llvm::CallInst& inst);
bool isFncDefinitionCall(const llvm::CallInst* inst);

bool localizeDefinition(
		const ReachingDefinitionsAnalysis& RDA,
		const llvm::Instruction* def,
		llvm::Type* type = nullptr);
bool localizeDefinition(
		const Definition* def,
		llvm::Type* type = nullptr);

llvm::ReturnInst* modifyReturnInst(llvm::ReturnInst* ret, llvm::Value* val);

llvm::CallInst* modifyCallInst(
		llvm::CallInst* call,
		llvm::Type* ret,
		llvm::ArrayRef<llvm::Value*> args);

llvm::CallInst* modifyCallInst(
		llvm::CallInst* call,
		llvm::Type* ret);

llvm::CallInst* modifyCallInst(
		llvm::CallInst* call,
		llvm::ArrayRef<llvm::Value*> args);

llvm::CallInst* addToVariadicCallInst(
		llvm::CallInst* call,
		llvm::ArrayRef<llvm::Value*> args);

using FunctionPair = std::pair<llvm::Function*, retdec::config::Function*>;
FunctionPair modifyFunction(
		Config* config,
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
		Config* config,
		llvm::Argument* arg,
		llvm::Type* type);

llvm::Function* splitFunctionOn(
		llvm::Instruction* inst,
		const std::string& fncName = "");

void insertAtBegin(llvm::Instruction* li, llvm::BasicBlock* bb);

} // namespace bin2llvmir
} // namespace retdec

#endif
