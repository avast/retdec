/**
 * @file include/retdec/bin2llvmir/providers/config.h
 * @brief Config DB provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CONFIG_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CONFIG_H

#include <optional>

#include "retdec/config/config.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/common/address.h"
#include "retdec/utils/filesystem.h"

namespace retdec {
namespace bin2llvmir {

class Config
{
	public:
		static Config empty(llvm::Module* m);
		static Config fromConfig(llvm::Module* m, retdec::config::Config& c);

		void doFinalization();
		void tagFunctionsWithUsedCryptoGlobals();

	public:
		retdec::config::Config& getConfig();
		const retdec::config::Config& getConfig() const;

		// Function
		//
		retdec::common::Function* getConfigFunction(
				const llvm::Function* fnc);
		retdec::common::Function* getConfigFunction(
				retdec::common::Address startAddr);

		llvm::Function* getLlvmFunction(
				retdec::common::Address startAddr);

		retdec::common::Address getFunctionAddress(
				const llvm::Function* fnc);

		// Intrinsic functions.
		//
		using IntrinsicFunctionCreatorPtr = llvm::Function* (*)(llvm::Module*);
		llvm::Function* getIntrinsicFunction(IntrinsicFunctionCreatorPtr f);

		// Register
		//
		const retdec::common::Object* getConfigRegister(
				const llvm::Value* val);
		std::optional<unsigned> getConfigRegisterNumber(
				const llvm::Value* val);

		// Global
		//
		const retdec::common::Object* getConfigGlobalVariable(
				const llvm::GlobalVariable* gv);
		const retdec::common::Object* getConfigGlobalVariable(
				retdec::common::Address address);

		llvm::GlobalVariable* getLlvmGlobalVariable(
				retdec::common::Address address);
		llvm::GlobalVariable* getLlvmGlobalVariable(
				const std::string& name,
				retdec::common::Address address);

		retdec::common::Address getGlobalAddress(
				const llvm::GlobalVariable* gv);

		bool isGlobalVariable(const llvm::Value* val);

		// Local + Stack
		//
		const retdec::common::Object* getConfigLocalVariable(
				const llvm::Value* val);
		retdec::common::Object* getConfigStackVariable(
				const llvm::Value* val);

		llvm::AllocaInst* getLlvmStackVariable(
				llvm::Function* fnc,
				int offset);

		llvm::AllocaInst* getLlvmStackVariable(
				llvm::Function* fnc,
				const std::string& realName);

		bool isStackVariable(const llvm::Value* val);
		std::optional<int> getStackVariableOffset(
				const llvm::Value* val);

		// Insert
		//
		const retdec::common::Object* insertGlobalVariable(
				const llvm::GlobalVariable* gv,
				retdec::common::Address address,
				bool fromDebug = false,
				const std::string& realName = "",
				const std::string& cryptoDesc = "");

		const retdec::common::Object* insertStackVariable(
				const llvm::AllocaInst* sv,
				int offset,
				bool fromDebug = false,
				const std::string& realName = std::string());

		const retdec::common::Function* insertFunction(
				const llvm::Function* fnc,
				retdec::common::Address start = retdec::common::Address::Undefined,
				retdec::common::Address end = retdec::common::Address::Undefined,
				bool fromDebug = false);

		retdec::common::Function* renameFunction(
				retdec::common::Function* fnc,
				const std::string& name);

		// Pseudo-functions.
		//
		void setLlvmCallPseudoFunction(llvm::Function* f);
		llvm::Function* getLlvmCallPseudoFunction() const;
		bool isLlvmCallPseudoFunction(llvm::Value* f);
		llvm::CallInst* isLlvmCallPseudoFunctionCall(llvm::Value* c);

		void setLlvmReturnPseudoFunction(llvm::Function* f);
		llvm::Function* getLlvmReturnPseudoFunction() const;
		bool isLlvmReturnPseudoFunction(llvm::Value* f);
		llvm::CallInst* isLlvmReturnPseudoFunctionCall(llvm::Value* c);

		void setLlvmBranchPseudoFunction(llvm::Function* f);
		llvm::Function* getLlvmBranchPseudoFunction() const;
		bool isLlvmBranchPseudoFunction(llvm::Value* f);
		llvm::CallInst* isLlvmBranchPseudoFunctionCall(llvm::Value* c);

		void setLlvmCondBranchPseudoFunction(llvm::Function* f);
		llvm::Function* getLlvmCondBranchPseudoFunction() const;
		bool isLlvmCondBranchPseudoFunction(llvm::Value* f);
		llvm::CallInst* isLlvmCondBranchPseudoFunctionCall(llvm::Value* c);

		llvm::CallInst* isLlvmAnyBranchPseudoFunctionCall(llvm::Value* c);
		llvm::CallInst* isLlvmAnyUncondBranchPseudoFunctionCall(llvm::Value* c);

		// x86-specific pseudo-functions.
		//
		void setLlvmX87DataStorePseudoFunction(llvm::Function* f);
		llvm::Function* getLlvmX87DataStorePseudoFunction() const;
		bool isLlvmX87DataStorePseudoFunction(llvm::Value* f);
		llvm::CallInst* isLlvmX87DataStorePseudoFunctionCall(llvm::Value* c);

		void setLlvmX87DataLoadPseudoFunction(llvm::Function* f);
		llvm::Function* getLlvmX87DataLoadPseudoFunction() const;
		bool isLlvmX87DataLoadPseudoFunction(llvm::Value* f);
		llvm::CallInst* isLlvmX87DataLoadPseudoFunctionCall(llvm::Value* c);

		llvm::CallInst* isLlvmX87StorePseudoFunctionCall(llvm::Value* c);
		llvm::CallInst* isLlvmX87LoadPseudoFunctionCall(llvm::Value* c);

		// Assembly pseudo-functions.
		//
		void addPseudoAsmFunction(llvm::Function* f);
		bool isPseudoAsmFunction(llvm::Function* f);
		llvm::CallInst* isPseudoAsmFunctionCall(llvm::Value* c);

		// Other
		//
		llvm::GlobalVariable* getGlobalDummy();
		fs::path getOutputDirectory();
		bool getCryptoPattern(
				retdec::common::Address addr,
				std::string& name,
				std::string& description,
				llvm::Type*& type) const;

	private:
		Config(retdec::config::Config& c);

	public:
		llvm::Module* _module = nullptr;

	private:
		retdec::config::Config& _configDB;
		llvm::GlobalVariable* _globalDummy = nullptr;

		llvm::Function* _callFunction = nullptr;
		llvm::Function* _returnFunction = nullptr;
		llvm::Function* _branchFunction = nullptr;
		llvm::Function* _condBranchFunction = nullptr;

		llvm::Function* _x87DataStoreFunction = nullptr; // void (i3, fp80)
		llvm::Function* _x87DataLoadFunction = nullptr; // fp80 (i3)

		std::map<IntrinsicFunctionCreatorPtr, llvm::Function*> _intrinsicFunctions;
		std::set<llvm::Function*> _pseudoAsmFunctions;
};

class ConfigProvider
{
	public:
		static Config* addConfig(llvm::Module* m, retdec::config::Config& c);
		static Config* getConfig(llvm::Module* m);
		static bool getConfig(llvm::Module* m, Config*& c);
		static void doFinalization(llvm::Module* m);
		static void clear();

	private:
		static std::map<llvm::Module*, Config> _module2config;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
