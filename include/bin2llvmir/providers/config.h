/**
 * @file include/bin2llvmir/providers/config.h
 * @brief Config DB provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_PROVIDERS_CONFIG_H
#define BIN2LLVMIR_PROVIDERS_CONFIG_H

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec-config/config.h"
#include "tl-cpputils/address.h"

namespace bin2llvmir {

class Config
{
	public:
		static Config empty(llvm::Module* m);
		static Config fromFile(llvm::Module* m, const std::string& path);
		static Config fromJsonString(llvm::Module* m, const std::string& json);

		void doFinalization();

	public:
		retdec_config::Config& getConfig();

		// Function
		//
		retdec_config::Function* getConfigFunction(
				const llvm::Function* fnc);
		retdec_config::Function* getConfigFunction(
				tl_cpputils::Address startAddr);

		llvm::Function* getLlvmFunction(
				tl_cpputils::Address startAddr);

		tl_cpputils::Address getFunctionAddress(
				const llvm::Function* fnc);

		bool isFrontendFunction(const llvm::Value* val);
		bool isFrontendFunctionCall(const llvm::Value* val);

		// Register
		//
		const retdec_config::Object* getConfigRegister(
				const llvm::Value* val);
		tl_cpputils::Maybe<unsigned> getConfigRegisterNumber(
				const llvm::Value* val);
		std::string getConfigRegisterClass(
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
		const retdec_config::Object* getConfigGlobalVariable(
				const llvm::GlobalVariable* gv);
		const retdec_config::Object* getConfigGlobalVariable(
				tl_cpputils::Address address);

		llvm::GlobalVariable* getLlvmGlobalVariable(
				tl_cpputils::Address address);
		llvm::GlobalVariable* getLlvmGlobalVariable(
				const std::string& name,
				tl_cpputils::Address address);

		tl_cpputils::Address getGlobalAddress(
				const llvm::GlobalVariable* gv);

		bool isGlobalVariable(const llvm::Value* val);

		// Local + Stack
		//
		const retdec_config::Object* getConfigLocalVariable(
				const llvm::Value* val);
		retdec_config::Object* getConfigStackVariable(
				const llvm::Value* val);

		llvm::AllocaInst* getLlvmStackVariable(
				llvm::Function* fnc,
				int offset);

		bool isStackVariable(const llvm::Value* val);
		tl_cpputils::Maybe<int> getStackVariableOffset(
				const llvm::Value* val);

		// Insert
		//
		retdec_config::Object* insertGlobalVariable(
				const llvm::GlobalVariable* gv,
				tl_cpputils::Address address,
				bool fromDebug = false,
				const std::string& realName = "",
				const std::string& cryptoDesc = "");

		retdec_config::Object* insertStackVariable(
				const llvm::AllocaInst* sv,
				int offset,
				bool fromDebug = false);

		retdec_config::Function* insertFunction(
				const llvm::Function* fnc,
				tl_cpputils::Address start = tl_cpputils::Address::getUndef,
				tl_cpputils::Address end = tl_cpputils::Address::getUndef,
				bool fromDebug = false);

		retdec_config::Function* renameFunction(
				retdec_config::Function* fnc,
				const std::string& name);

		// LLVM to ASM
		//
		bool isLlvmToAsmGlobalVariable(const llvm::Value* gv) const;
		bool isLlvmToAsmInstruction(const llvm::Value* inst) const;
		llvm::GlobalVariable* getLlvmToAsmGlobalVariable() const;
		void setLlvmToAsmGlobalVariable(llvm::GlobalVariable* gv);

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
		bool isPic32() const;
		bool isMipsOrPic32() const;
		llvm::GlobalVariable* getGlobalDummy();

	private:
		llvm::Module* _module = nullptr;
		retdec_config::Config _configDB;
		std::string _configPath;
		llvm::GlobalVariable* _globalDummy = nullptr;
		llvm::GlobalVariable* _asm2llvmGv = nullptr;
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

#endif
