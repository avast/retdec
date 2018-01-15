/**
 * @file src/bin2llvmir/providers/abi.cpp
 * @brief Module provides ABI information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  Abi
//=============================================================================
//

Abi Abi::armCdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();

	Abi ret;
	ret._module = m;
	ret._arch = a;
	ret._defaultType = getDefaultType(ret._module);
	ret._cc = retdec::config::CallingConvention::initCdecl();
	ret._defaultAlignType = ret._defaultType;
	ret._stackDirection = eStackDirection::RIGHT_2_LEFT;
	ret._stackPointer = ret._module->getNamedGlobal("sp");
	ret._parameterStartOffset = 0;
	ret._parameterStackAlignment = 4;
	ret._returnAddressReg = ret._module->getNamedGlobal("lr");
	ret._typeToRetValInReg.emplace(
			Type::getInt32Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("r0")));
	ret._typeToRetValInReg.emplace(
			Type::getInt64Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("r0"),
					ret._module->getNamedGlobal("r1")));

	std::vector<RegisterCouple> i32Args =
	{
			RegisterCouple(ret._module->getNamedGlobal("r0")),
			RegisterCouple(ret._module->getNamedGlobal("r1")),
			RegisterCouple(ret._module->getNamedGlobal("r2")),
			RegisterCouple(ret._module->getNamedGlobal("r3")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getInt32Ty(ctx),
			i32Args);

	std::vector<RegisterCouple> floatArgs = i32Args;
	ret._typeToArgumentRegs.emplace(
			Type::getFloatTy(ctx),
			floatArgs);

	std::vector<RegisterCouple> doubleArgs =
	{
			RegisterCouple(
					ret._module->getNamedGlobal("r0"),
					ret._module->getNamedGlobal("r1")),
			RegisterCouple(
					ret._module->getNamedGlobal("r2"),
					ret._module->getNamedGlobal("r3"))
	};
	ret._typeToArgumentRegs.emplace(
			Type::getDoubleTy(ctx),
			doubleArgs);

	assert(ret._stackPointer);
	assert(ret._returnAddressReg);

	return ret;
}

Abi Abi::ppcCdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();

	Abi ret;
	ret._module = m;
	ret._arch = a;
	ret._defaultType = getDefaultType(ret._module);
	ret._cc = retdec::config::CallingConvention::initCdecl();
	ret._defaultAlignType = ret._defaultType;
	ret._stackDirection = eStackDirection::RIGHT_2_LEFT;
	ret._stackPointer = ret._module->getNamedGlobal("r1");
	ret._parameterStartOffset = 0;
	ret._parameterStackAlignment = 4;
	ret._returnAddressReg = ret._module->getNamedGlobal("r0");
	ret._typeToRetValInReg.emplace(
			Type::getInt32Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("r3")));
	ret._typeToRetValInReg.emplace(
			Type::getInt64Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("r3"),
					ret._module->getNamedGlobal("r4")));

	std::vector<RegisterCouple> i32Args =
	{
			RegisterCouple(ret._module->getNamedGlobal("r3")),
			RegisterCouple(ret._module->getNamedGlobal("r4")),
			RegisterCouple(ret._module->getNamedGlobal("r5")),
			RegisterCouple(ret._module->getNamedGlobal("r6")),
			RegisterCouple(ret._module->getNamedGlobal("r7")),
			RegisterCouple(ret._module->getNamedGlobal("r8")),
			RegisterCouple(ret._module->getNamedGlobal("r9")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getInt32Ty(ctx),
			i32Args);

	std::vector<RegisterCouple> floatArgs = i32Args;
	ret._typeToArgumentRegs.emplace(
			Type::getFloatTy(ctx),
			floatArgs);

	assert(ret._stackPointer);
	assert(ret._returnAddressReg);

	return ret;
}

Abi Abi::x86Cdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();

	Abi ret;
	ret._module = m;
	ret._arch = a;
	ret._defaultType = getDefaultType(ret._module);
	ret._cc = retdec::config::CallingConvention::initCdecl();
	ret._defaultAlignType = ret._defaultType;
	ret._stackDirection = eStackDirection::RIGHT_2_LEFT;
	ret._stackPointer = ret._module->getNamedGlobal("esp");
	ret._parameterStartOffset = 0;
	ret._parameterStackAlignment = 4;
	ret._returnAddressStackOffset = 0;
	ret._typeToRetValInReg.emplace(
			Type::getInt32Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("eax")));
	ret._typeToRetValInReg.emplace(
			Type::getFloatTy(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("eax")));
	ret._typeToRetValInReg.emplace(
			Type::getDoubleTy(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("eax")));
	ret._typeToRetValInReg.emplace(
			Type::getInt64Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("eax"),
					ret._module->getNamedGlobal("ecx")));

	assert(ret._stackPointer);

	return ret;
}

Abi Abi::x86Fastcall(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();
	auto ret = x86Cdecl(m, a);

	ret._cc = retdec::config::CallingConvention::initFastcall();

	std::vector<RegisterCouple> i32Args =
	{
			RegisterCouple(ret._module->getNamedGlobal("ecx")),
			RegisterCouple(ret._module->getNamedGlobal("edx")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getInt32Ty(ctx),
			i32Args);

	return ret;
}

Abi Abi::x86Stdcall(llvm::Module* m, retdec::config::Architecture& a)
{
	auto ret = x86Cdecl(m, a);
	ret._cc = retdec::config::CallingConvention::initStdcall();
	return ret;
}

Abi Abi::mipsCdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();

	Abi ret;
	ret._module = m;
	ret._arch = a;
	ret._defaultType = getDefaultType(ret._module);
	ret._cc = retdec::config::CallingConvention::initCdecl();
	ret._defaultAlignType = ret._defaultType;
	ret._stackDirection = eStackDirection::RIGHT_2_LEFT;
	ret._stackPointer = ret._module->getNamedGlobal("sp");
	ret._parameterStartOffset = 0;
	ret._parameterStackAlignment = 4;
	ret._returnAddressReg = ret._module->getNamedGlobal("ra");
	ret._typeToRetValInReg.emplace(
			Type::getInt32Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("v0")));
	ret._typeToRetValInReg.emplace(
			Type::getInt64Ty(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("v0"),
					ret._module->getNamedGlobal("v1")));
	ret._typeToRetValInReg.emplace(
			Type::getFloatTy(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("f0")));
	ret._typeToRetValInReg.emplace(
			Type::getDoubleTy(ctx),
			RegisterCouple(
					ret._module->getNamedGlobal("fd0")));

	std::vector<RegisterCouple> i32Args =
	{
			RegisterCouple(ret._module->getNamedGlobal("a0")),
			RegisterCouple(ret._module->getNamedGlobal("a1")),
			RegisterCouple(ret._module->getNamedGlobal("a2")),
			RegisterCouple(ret._module->getNamedGlobal("a3")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getInt32Ty(ctx),
			i32Args);

	std::vector<RegisterCouple> floatArgs =
	{
			RegisterCouple(
					ret._module->getNamedGlobal("f12"),
					ret._module->getNamedGlobal("f13")),
			RegisterCouple(
					ret._module->getNamedGlobal("f14"),
					ret._module->getNamedGlobal("f15"))
	};
	ret._typeToArgumentRegs.emplace(
			Type::getFloatTy(ctx),
			floatArgs);

	std::vector<RegisterCouple> doubleArgs =
	{
			RegisterCouple(
					ret._module->getNamedGlobal("fd0"),
					ret._module->getNamedGlobal("fd1")),
			RegisterCouple(
					ret._module->getNamedGlobal("fd3"),
					ret._module->getNamedGlobal("fd4"))
	};
	ret._typeToArgumentRegs.emplace(
			Type::getDoubleTy(ctx),
			doubleArgs);

	assert(ret._stackPointer);
	assert(ret._returnAddressReg);

	return ret;
}

Abi Abi::mipsLlvmCdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();
	auto ret = mipsCdecl(m, a);
	ret._typeToArgumentStackOffset.emplace(Type::getInt32Ty(ctx), 16);
	ret._typeToArgumentStackOffset.emplace(Type::getFloatTy(ctx), 16);
	ret._typeToArgumentStackOffset.emplace(Type::getDoubleTy(ctx), 16);
	return ret;
}

Abi Abi::mipsPic32Cdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	return mipsLlvmCdecl(m, a);
}

Abi Abi::mipsPspCdecl(llvm::Module* m, retdec::config::Architecture& a)
{
	auto& ctx = m->getContext();
	auto ret = mipsCdecl(m, a);

	std::vector<RegisterCouple> i32Args =
	{
			RegisterCouple(ret._module->getNamedGlobal("a0")),
			RegisterCouple(ret._module->getNamedGlobal("a1")),
			RegisterCouple(ret._module->getNamedGlobal("a2")),
			RegisterCouple(ret._module->getNamedGlobal("a3")),
			RegisterCouple(ret._module->getNamedGlobal("t0")),
			RegisterCouple(ret._module->getNamedGlobal("t1")),
			RegisterCouple(ret._module->getNamedGlobal("t2")),
			RegisterCouple(ret._module->getNamedGlobal("t3")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getInt32Ty(ctx),
			i32Args);

	std::vector<RegisterCouple> floatArgs =
	{
			RegisterCouple(
					ret._module->getNamedGlobal("f12"),
					ret._module->getNamedGlobal("f13")),
			RegisterCouple(
					ret._module->getNamedGlobal("f14"),
					ret._module->getNamedGlobal("f15")),
			RegisterCouple(
					ret._module->getNamedGlobal("f16"),
					ret._module->getNamedGlobal("f17")),
			RegisterCouple(
					ret._module->getNamedGlobal("f18"),
					ret._module->getNamedGlobal("f19")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getFloatTy(ctx),
			floatArgs);

	std::vector<RegisterCouple> doubleArgs =
	{
			RegisterCouple(
					ret._module->getNamedGlobal("fd12"),
					ret._module->getNamedGlobal("fd13")),
			RegisterCouple(
					ret._module->getNamedGlobal("fd14"),
					ret._module->getNamedGlobal("fd15")),
			RegisterCouple(
					ret._module->getNamedGlobal("fd16"),
					ret._module->getNamedGlobal("fd17")),
			RegisterCouple(
					ret._module->getNamedGlobal("fd18"),
					ret._module->getNamedGlobal("fd19")),
	};
	ret._typeToArgumentRegs.emplace(
			Type::getDoubleTy(ctx),
			doubleArgs);

	return ret;
}

const retdec::config::Architecture& Abi::getArchitecture() const
{
	return _arch;
}

const retdec::config::CallingConvention& Abi::getCallingConvention() const
{
	return _cc;
}

retdec::utils::Maybe<size_t> Abi::getAlignedBitSize(llvm::Type* type) const
{
	if (type->getPrimitiveSizeInBits() > _defaultType->getPrimitiveSizeInBits())
	{
		return type->getPrimitiveSizeInBits();
	}
	else
	{
		return _defaultType->getPrimitiveSizeInBits();
	}
}

llvm::Type* Abi::getAlignedType(llvm::Type* type) const
{
	if (type->getPrimitiveSizeInBits() > _defaultType->getPrimitiveSizeInBits())
	{
		return type;
	}
	else
	{
		return _defaultType;
	}
}

bool Abi::isStackDirectionUnknown() const
{
	return _stackDirection == eStackDirection::UNKNOWN;
}

bool Abi::isStackDirectionLeft2Right() const
{
	return _stackDirection == eStackDirection::LEFT_2_RIGHT;
}

bool Abi::isStackDirectionRight2Left() const
{
	return _stackDirection == eStackDirection::RIGHT_2_LEFT;
}

/**
 * @return Stack pointer register. @c Nullptr if it is not known, but it always
 *         should be.
 */
llvm::GlobalVariable* Abi::getStackPointer() const
{
	return _stackPointer;
}

/**
 * @return Stack offset where function's parameters start.
 */
retdec::utils::Maybe<int> Abi::getParameterStartStackOffset() const
{
	return _parameterStartOffset;
}

/**
 * @return Alignment of function's parameters on stack.
 */
retdec::utils::Maybe<int> Abi::getParameterStackAlignment() const
{
	return _parameterStackAlignment;
}

/**
 * @return @c True if function's return address is in register,
 *         @c false otherwise.
 */
bool Abi::isReturnAddressInRegister() const
{
	return getReturnAddressRegister() != nullptr;
}

/**
 * @return @c True if function's return address is on stack, @c false otherwise.
 */
bool Abi::isReturnAddressOnStack() const
{
	return getReturnAddressStackOffset().isDefined();
}

/**
 * @return Register where function's return address is stored. @c Nullptr if
 *         return address is not stored in register.
 */
llvm::GlobalVariable* Abi::getReturnAddressRegister() const
{
	return _returnAddressReg;
}

/**
 * @return @c Offset on stack where function's return address is stored.
 *         This may net be set -- check @c Maybe before use.
 */
retdec::utils::Maybe<int> Abi::getReturnAddressStackOffset() const
{
	return _returnAddressStackOffset;
}

/**
 * @return @c True if value of the given type @ type is returned from function
 *         in register. @c False otherwise.
 */
bool Abi::isReturnValueInRegisters(llvm::Type* type) const
{
	return getReturnValueRegister(type) != nullptr;
}

/**
 * @return @c True if value of the given type @ type is returned from function
 *         on stack. @c False otherwise.
 */
bool Abi::isReturnValueOnStack(llvm::Type* type) const
{
	return getReturnValueOnStack(type) != nullptr;
}

/**
 * @return Register where value of type @a type is returned from function.
 *         @c Nullptr if such value is not returned in register.
 */
const RegisterCouple* Abi::getReturnValueRegister(llvm::Type* type) const
{
	auto f = _typeToRetValInReg.find(type);
	if (f != _typeToRetValInReg.end())
	{
		return &f->second;
	}
	f = _typeToRetValInReg.find(_defaultType);
	return f != _typeToRetValInReg.end() ? &f->second : nullptr;
}

/**
 * @return TODO: i have no idea what this is supposed to be.
 */
const std::pair<int, unsigned>* Abi::getReturnValueOnStack(llvm::Type* type) const
{
	auto f = _typeToRetValOnStack.find(type);
	return f != _typeToRetValOnStack.end() ? &f->second : nullptr;
}

/**
 * @return All information about function argument passing in registers.
 */
const std::map<llvm::Type*, std::vector<RegisterCouple>>&
		Abi::getTypeToArgumentRegs() const
{
	return _typeToArgumentRegs;
}

/**
 * @return Vector of registers which are used to pass arguments of the given
 *         @c type. @c Nullptr if arguments of this type are not passed in
 *         registers at all.
 */
const std::vector<RegisterCouple>* Abi::getArgumentRegs(llvm::Type* type) const
{
	auto f = _typeToArgumentRegs.find(type);
	return f != _typeToArgumentRegs.end() ? &f->second : nullptr;
}

/**
 * @return @c True if some function arguments of the type @c type is passed
 *         by register, @c false if all arguments of this type are always
 *         passed on stack.
 */
bool Abi::hasArgumentRegs(llvm::Type* type) const
{
	auto f = _typeToArgumentRegs.find(type);
	return f != _typeToArgumentRegs.end();
}

/**
 * @return @c True if some type of function arguments is passed by register,
 *         @c false if all arguments are always passed on stack.
 */
bool Abi::hasArgumentRegs() const
{
	return !_typeToArgumentRegs.empty();
}

/**
 * @return Start stack offset for the function arguments of the given @a type.
 *         Default value is zero -- it is returned if we have no info.
 */
int Abi::getArgumentStackOffset(llvm::Type* type) const
{
	auto f = _typeToArgumentStackOffset.find(type);
	return f != _typeToArgumentStackOffset.end() ? f->second : 0;
}

//
//=============================================================================
//  ModuleAbis
//=============================================================================
//

ModuleAbis::ModuleAbis(
		llvm::Module* module,
		const retdec::config::Architecture& arch,
		const retdec::config::ToolInfoContainer& tools,
		const std::vector<std::string>& abis)
{
	_module = module;
	_arch = arch;

	assert(abis.empty() && "loading ABIs from files is not implemented");

	if (_arch.isX86())
	{
		_abis.emplace(
				retdec::config::CallingConvention::initCdecl(),
				Abi::x86Cdecl(_module, _arch));
		_abis.emplace(
				retdec::config::CallingConvention::initFastcall(),
				Abi::x86Fastcall(_module, _arch));
		_abis.emplace(
				retdec::config::CallingConvention::initStdcall(),
				Abi::x86Stdcall(_module, _arch));
	}
	else if (_arch.isArmOrThumb())
	{
		_abis.emplace(
				retdec::config::CallingConvention::initCdecl(),
				Abi::armCdecl(_module, _arch));
	}
	else if (_arch.isPpc())
	{
		_abis.emplace(
				retdec::config::CallingConvention::initCdecl(),
				Abi::ppcCdecl(_module, _arch));
	}
	else if (_arch.isMipsOrPic32() || tools.isPic32())
	{
		if (tools.isPspGcc())
		{
			_abis.emplace(
					retdec::config::CallingConvention::initCdecl(),
					Abi::mipsPspCdecl(_module, _arch));
		}
		else if (tools.isLlvm())
		{
			_abis.emplace(
					retdec::config::CallingConvention::initCdecl(),
					Abi::mipsLlvmCdecl(_module, _arch));
		}
		else if (arch.isPic32() || tools.isPic32())
		{
			_abis.emplace(
					retdec::config::CallingConvention::initCdecl(),
					Abi::mipsPic32Cdecl(_module, _arch));
		}
		else
		{
			_abis.emplace(
					retdec::config::CallingConvention::initCdecl(),
					Abi::mipsCdecl(_module, _arch));
		}
	}
}

Abi* ModuleAbis::getAbi(retdec::config::CallingConvention cc)
{
	auto f = _abis.find(cc);
	return f != _abis.end() ? &f->second : nullptr;
}

bool ModuleAbis::getAbi(retdec::config::CallingConvention cc, Abi*& abi)
{
	abi = getAbi(cc);
	return abi != nullptr;
}

//
//=============================================================================
//  AbiProvider
//=============================================================================
//

std::map<llvm::Module*, ModuleAbis> AbiProvider::_module2abis;

ModuleAbis* AbiProvider::addAbis(
		llvm::Module* module,
		const retdec::config::Architecture& arch,
		const retdec::config::ToolInfoContainer& tools,
		const std::vector<std::string>& abis)
{
	auto p = _module2abis.emplace(module, ModuleAbis(module, arch, tools, abis));
	return &p.first->second;
}

/**
 * @return This might return @c nullptr if ABIs for @a module does not exist.
 *         Caller must check the value before using it.
 */
ModuleAbis* AbiProvider::getAbis(llvm::Module* module)
{
	auto f = _module2abis.find(module);
	return f != _module2abis.end() ? &f->second : nullptr;
}

/**
 * @param[in]  module Module for which to get ABIs.
 * @param[out] abis   Pointer is set to ABIs if they were added.
 *             If not, pointer is not changed.
 * @return @c True if ABIs were added and can be used.
 *         @c False otherwise.
 */
bool AbiProvider::getAbis(llvm::Module* module, ModuleAbis*& abis)
{
	abis = getAbis(module);
	return abis != nullptr;
}

/**
 * @return This might return @c nullptr if ABI for @a module and @a cc call
 *         convention does not exist. Caller must check the value before
 *         using it.
 */
Abi* AbiProvider::getAbi(
		llvm::Module* module,
		retdec::config::CallingConvention cc)
{
	auto* ma = getAbis(module);
	return ma ? ma->getAbi(cc) : nullptr;
}

/**
 * @param[in]  module Module for which to get ABI.
 * @param[in]  cc     Calling convention for which to get ABI.
 * @param[out] abi    Pointer is set to ABI if it was added.
 *             If not, pointer is not changed.
 * @return @c True if ABI was added and can be used.
 *         @c False otherwise.
 */
bool AbiProvider::getAbi(
		llvm::Module* module,
		retdec::config::CallingConvention cc,
		Abi*& abi)
{
	abi = getAbi(module, cc);
	return abi != nullptr;
}

/**
 * Clear all stored data.
 */
void AbiProvider::clear()
{
	_module2abis.clear();
}

} // namespace bin2llvmir
} // namespace retdec
