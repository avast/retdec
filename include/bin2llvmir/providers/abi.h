/**
 * @file include/bin2llvmir/providers/abi.h
 * @brief Module provides ABI information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_PROVIDERS_ABI_H
#define BIN2LLVMIR_PROVIDERS_ABI_H

#include <llvm/IR/Module.h>

#include "retdec-config/architecture.h"
#include "retdec-config/calling_convention.h"
#include "retdec-config/tool_info.h"
#include "tl-cpputils/value.h"
#include "bin2llvmir/utils/defs.h"

namespace bin2llvmir {

class Abi
{
	public:
		static Abi armCdecl(llvm::Module* m, retdec_config::Architecture& a);
		static Abi ppcCdecl(llvm::Module* m, retdec_config::Architecture& a);
		static Abi x86Cdecl(llvm::Module* m, retdec_config::Architecture& a);
		static Abi x86Fastcall(llvm::Module* m, retdec_config::Architecture& a);
		static Abi x86Stdcall(llvm::Module* m, retdec_config::Architecture& a);
		static Abi mipsCdecl(llvm::Module* m, retdec_config::Architecture& a);
		static Abi mipsLlvmCdecl(llvm::Module* m, retdec_config::Architecture& a);
		static Abi mipsPic32Cdecl(llvm::Module* m, retdec_config::Architecture& a);
		static Abi mipsPspCdecl(llvm::Module* m, retdec_config::Architecture& a);

	public:
		const retdec_config::Architecture& getArchitecture() const;
		const retdec_config::CallingConvention& getCallingConvention() const;

		tl_cpputils::Maybe<size_t> getAlignedBitSize(llvm::Type* type) const;
		llvm::Type* getAlignedType(llvm::Type* type) const;

		bool isStackDirectionUnknown() const;
		bool isStackDirectionLeft2Right() const;
		bool isStackDirectionRight2Left() const;

		llvm::GlobalVariable* getStackPointer() const;
		tl_cpputils::Maybe<int> getParameterStartStackOffset() const;
		tl_cpputils::Maybe<int> getParameterStackAlignment() const;

		bool isReturnAddressInRegister() const;
		bool isReturnAddressOnStack() const;
		llvm::GlobalVariable* getReturnAddressRegister() const;
		tl_cpputils::Maybe<int> getReturnAddressStackOffset() const;

		bool isReturnValueInRegisters(llvm::Type* type) const;
		bool isReturnValueOnStack(llvm::Type* type) const;
		const RegisterCouple* getReturnValueRegister(llvm::Type* type) const;
		const std::pair<int, unsigned>* getReturnValueOnStack(llvm::Type* type) const;

		const std::map<llvm::Type*, std::vector<RegisterCouple>>&
				getTypeToArgumentRegs() const;
		const std::vector<RegisterCouple>* getArgumentRegs(llvm::Type* type) const;
		bool hasArgumentRegs(llvm::Type* type) const;
		bool hasArgumentRegs() const;
		int getArgumentStackOffset(llvm::Type* type) const;

	private:
		enum class eStackDirection
		{
			UNKNOWN,
			LEFT_2_RIGHT,
			RIGHT_2_LEFT
		};

	private:
		llvm::Module* _module = nullptr;
		llvm::Type* _defaultType = nullptr;
		retdec_config::Architecture _arch;
		retdec_config::CallingConvention _cc;
		llvm::Type* _defaultAlignType = nullptr;
		eStackDirection _stackDirection = eStackDirection::UNKNOWN;
		llvm::GlobalVariable* _stackPointer = nullptr;
		tl_cpputils::Maybe<int> _parameterStartOffset;
		tl_cpputils::Maybe<int> _parameterStackAlignment;
		llvm::GlobalVariable* _returnAddressReg = nullptr;
		tl_cpputils::Maybe<int> _returnAddressStackOffset;
		std::map<llvm::Type*, RegisterCouple> _typeToRetValInReg;
		std::map<llvm::Type*, std::pair<int, unsigned>> _typeToRetValOnStack;
		std::map<llvm::Type*, std::vector<RegisterCouple>> _typeToArgumentRegs;
		std::map<llvm::Type*, int> _typeToArgumentStackOffset;
};

class ModuleAbis
{
	public:
		ModuleAbis(
				llvm::Module* module,
				const retdec_config::Architecture& arch,
				const retdec_config::ToolInfoContainer& tools,
				const std::vector<std::string>& abis = std::vector<std::string>());

		Abi* getAbi(retdec_config::CallingConvention cc);
		bool getAbi(retdec_config::CallingConvention cc, Abi*& abi);

	private:
		llvm::Module* _module = nullptr;
		retdec_config::Architecture _arch;
		retdec_config::ToolInfo _tool;
		std::map<retdec_config::CallingConvention, Abi> _abis;
};

class AbiProvider
{
	public:
		static ModuleAbis* addAbis(
				llvm::Module* module,
				const retdec_config::Architecture& arch,
				const retdec_config::ToolInfoContainer& tools,
				const std::vector<std::string>& abis = std::vector<std::string>());

		static ModuleAbis* getAbis(llvm::Module* module);
		static bool getAbis(llvm::Module* module, ModuleAbis*& abis);

		static Abi* getAbi(
				llvm::Module* module,
				retdec_config::CallingConvention cc);
		static bool getAbi(
				llvm::Module* module,
				retdec_config::CallingConvention cc,
				Abi*& abi);

		static void clear();

	private:
		static std::map<llvm::Module*, ModuleAbis> _module2abis;
};

} // namespace bin2llvmir

#endif
