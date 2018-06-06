/**
 * @file include/retdec/bin2llvmir/providers/config.h
 * @brief Config DB provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CONFIG_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CONFIG_H

#include "retdec/config/config.h"

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/utils/address.h"
#include "retdec/utils/filesystem_path.h"

namespace retdec {
namespace bin2llvmir {

class Config
{
	public:
		static Config empty(llvm::Module* m);
		static Config fromFile(llvm::Module* m, const std::string& path);
		static Config fromJsonString(llvm::Module* m, const std::string& json);

		void doFinalization();

	public:
		retdec::config::Config& getConfig();
		const retdec::config::Config& getConfig() const;

		// Function
		//
		retdec::config::Function* getConfigFunction(
				const llvm::Function* fnc);
		retdec::config::Function* getConfigFunction(
				retdec::utils::Address startAddr);

		llvm::Function* getLlvmFunction(
				retdec::utils::Address startAddr);

		retdec::utils::Address getFunctionAddress(
				const llvm::Function* fnc);

		// Register
		//
		const retdec::config::Object* getConfigRegister(
				const llvm::Value* val);
		retdec::utils::Maybe<unsigned> getConfigRegisterNumber(
				const llvm::Value* val);
		llvm::GlobalVariable* getLlvmRegister(
				const std::string& name);

		bool isRegister(const llvm::Value* val);
		bool isFlagRegister(const llvm::Value* val);
		bool isStackPointerRegister(const llvm::Value* val);
		bool isGeneralPurposeRegister(const llvm::Value* val);
		bool isFloatingPointRegister(const llvm::Value* val);

		// Global
		//
		const retdec::config::Object* getConfigGlobalVariable(
				const llvm::GlobalVariable* gv);
		const retdec::config::Object* getConfigGlobalVariable(
				retdec::utils::Address address);

		llvm::GlobalVariable* getLlvmGlobalVariable(
				retdec::utils::Address address);
		llvm::GlobalVariable* getLlvmGlobalVariable(
				const std::string& name,
				retdec::utils::Address address);

		retdec::utils::Address getGlobalAddress(
				const llvm::GlobalVariable* gv);

		bool isGlobalVariable(const llvm::Value* val);

		// Local + Stack
		//
		const retdec::config::Object* getConfigLocalVariable(
				const llvm::Value* val);
		retdec::config::Object* getConfigStackVariable(
				const llvm::Value* val);

		llvm::AllocaInst* getLlvmStackVariable(
				llvm::Function* fnc,
				int offset);

		bool isStackVariable(const llvm::Value* val);
		retdec::utils::Maybe<int> getStackVariableOffset(
				const llvm::Value* val);

		// Insert
		//
		retdec::config::Object* insertGlobalVariable(
				const llvm::GlobalVariable* gv,
				retdec::utils::Address address,
				bool fromDebug = false,
				const std::string& realName = "",
				const std::string& cryptoDesc = "");

		retdec::config::Object* insertStackVariable(
				const llvm::AllocaInst* sv,
				int offset,
				bool fromDebug = false);

		retdec::config::Function* insertFunction(
				const llvm::Function* fnc,
				retdec::utils::Address start = retdec::utils::Address::getUndef,
				retdec::utils::Address end = retdec::utils::Address::getUndef,
				bool fromDebug = false);

		retdec::config::Function* renameFunction(
				retdec::config::Function* fnc,
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

		// Other
		//
		llvm::GlobalVariable* getGlobalDummy();
		utils::FilesystemPath getOutputDirectory();
		bool getCryptoPattern(
				retdec::utils::Address addr,
				std::string& name,
				std::string& description,
				llvm::Type*& type) const;

	public:
		llvm::Module* _module = nullptr;

	private:
		retdec::config::Config _configDB;
		std::string _configPath;
		llvm::GlobalVariable* _globalDummy = nullptr;
		llvm::Function* _callFunction = nullptr;
		llvm::Function* _returnFunction = nullptr;
		llvm::Function* _branchFunction = nullptr;
		llvm::Function* _condBranchFunction = nullptr;
};

class ConfigProvider
{
	public:
		static Config* addConfigFile(llvm::Module* m, const std::string& path);
		static Config* addConfigJsonString(
				llvm::Module* m,
				const std::string& json);
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
