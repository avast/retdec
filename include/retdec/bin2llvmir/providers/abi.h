/**
 * @file include/retdec/bin2llvmir/providers/abi.h
 * @brief Module provides ABI information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_H

#include <llvm/IR/Module.h>

#include "retdec/config/architecture.h"
#include "retdec/config/calling_convention.h"
#include "retdec/config/tool_info.h"
#include "retdec/utils/value.h"
#include "retdec/bin2llvmir/utils/defs.h"

namespace retdec {
namespace bin2llvmir {

class Abi
{
	public:
		static Abi armCdecl(llvm::Module* m, retdec::config::Architecture& a);
		static Abi ppcCdecl(llvm::Module* m, retdec::config::Architecture& a);
		static Abi x86Cdecl(llvm::Module* m, retdec::config::Architecture& a);
		static Abi x86Fastcall(llvm::Module* m, retdec::config::Architecture& a);
		static Abi x86Stdcall(llvm::Module* m, retdec::config::Architecture& a);
		static Abi mipsCdecl(llvm::Module* m, retdec::config::Architecture& a);
		static Abi mipsLlvmCdecl(llvm::Module* m, retdec::config::Architecture& a);
		static Abi mipsPic32Cdecl(llvm::Module* m, retdec::config::Architecture& a);
		static Abi mipsPspCdecl(llvm::Module* m, retdec::config::Architecture& a);

	public:
		const retdec::config::Architecture& getArchitecture() const;
		const retdec::config::CallingConvention& getCallingConvention() const;

		retdec::utils::Maybe<size_t> getAlignedBitSize(llvm::Type* type) const;
		llvm::Type* getAlignedType(llvm::Type* type) const;

		bool isStackDirectionUnknown() const;
		bool isStackDirectionLeft2Right() const;
		bool isStackDirectionRight2Left() const;

		llvm::GlobalVariable* getStackPointer() const;
		retdec::utils::Maybe<int> getParameterStartStackOffset() const;
		retdec::utils::Maybe<int> getParameterStackAlignment() const;

		bool isReturnAddressInRegister() const;
		bool isReturnAddressOnStack() const;
		llvm::GlobalVariable* getReturnAddressRegister() const;
		retdec::utils::Maybe<int> getReturnAddressStackOffset() const;

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
		retdec::config::Architecture _arch;
		retdec::config::CallingConvention _cc;
		llvm::Type* _defaultAlignType = nullptr;
		eStackDirection _stackDirection = eStackDirection::UNKNOWN;
		llvm::GlobalVariable* _stackPointer = nullptr;
		retdec::utils::Maybe<int> _parameterStartOffset;
		retdec::utils::Maybe<int> _parameterStackAlignment;
		llvm::GlobalVariable* _returnAddressReg = nullptr;
		retdec::utils::Maybe<int> _returnAddressStackOffset;
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
				const retdec::config::Architecture& arch,
				const retdec::config::ToolInfoContainer& tools,
				const std::vector<std::string>& abis = std::vector<std::string>());

		Abi* getAbi(retdec::config::CallingConvention cc);
		bool getAbi(retdec::config::CallingConvention cc, Abi*& abi);

	private:
		llvm::Module* _module = nullptr;
		retdec::config::Architecture _arch;
		retdec::config::ToolInfo _tool;
		std::map<retdec::config::CallingConvention, Abi> _abis;
};

class AbiProvider
{
	public:
		static ModuleAbis* addAbis(
				llvm::Module* module,
				const retdec::config::Architecture& arch,
				const retdec::config::ToolInfoContainer& tools,
				const std::vector<std::string>& abis = std::vector<std::string>());

		static ModuleAbis* getAbis(llvm::Module* module);
		static bool getAbis(llvm::Module* module, ModuleAbis*& abis);

		static Abi* getAbi(
				llvm::Module* module,
				retdec::config::CallingConvention cc);
		static bool getAbi(
				llvm::Module* module,
				retdec::config::CallingConvention cc,
				Abi*& abi);

		static void clear();

	private:
		static std::map<llvm::Module*, ModuleAbis> _module2abis;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
