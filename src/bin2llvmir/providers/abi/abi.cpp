/**
 * @file src/bin2llvmir/providers/abi/abi.cpp
 * @brief ABI information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/abi/arm.h"
#include "retdec/bin2llvmir/providers/abi/arm64.h"
#include "retdec/bin2llvmir/providers/abi/mips.h"
#include "retdec/bin2llvmir/providers/abi/ms_x64.h"
#include "retdec/bin2llvmir/providers/abi/powerpc.h"
#include "retdec/bin2llvmir/providers/abi/x86.h"
#include "retdec/bin2llvmir/providers/abi/x64.h"
#include "retdec/bin2llvmir/providers/abi/pic32.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// Abi
//==============================================================================
//

const uint32_t Abi::REG_INVALID = 0;
const unsigned Abi::DEFAULT_ADDR_SPACE = 0;

Abi::Abi(llvm::Module* m, Config* c) :
		_module(m),
		_config(c)
{

}

Abi::~Abi()
{

}

bool Abi::isRegister(const llvm::Value* val) const
{
	return _regs2id.count(val);
}

bool Abi::isRegister(const llvm::Value* val, uint32_t r) const
{
	return getRegister(r) == val;
}

bool Abi::isFlagRegister(const llvm::Value* val)
{
	return isRegister(val)
			&& val->getType()->getPointerElementType()->isIntegerTy(1);
}

bool Abi::isStackPointerRegister(const llvm::Value* val) const
{
	return getStackPointerRegister() == val;
}

bool Abi::isZeroRegister(const llvm::Value* val)
{
	return getZeroRegister() == val;
}

/**
 * \param r   Register ID to get.
 *            Warning! We are using Capstone register IDs which overlaps.
 *            E.g. MIPS_REG_0 has the same ID as X86_REG_AL.
 * \param use Should the register be really got.
 *            This solves the problem with overlapping IDs when used like this:
 *            Abi::getRegister(MIPS_REG_GP, Abi::isMips())
 */
llvm::GlobalVariable* Abi::getRegister(uint32_t r, bool use) const
{
	if (!use)
	{
		return nullptr;
	}
	assert(r < _id2regs.size());
	return _id2regs[r];
}

uint32_t Abi::getRegisterId(const llvm::Value* r) const
{
	auto it = _regs2id.find(r);
	return it != _regs2id.end() ? it->second : Abi::REG_INVALID;
}

const std::vector<llvm::GlobalVariable*>& Abi::getRegisters() const
{
	return _regs;
}

llvm::GlobalVariable* Abi::getStackPointerRegister() const
{
	return getRegister(_regStackPointerId);
}

llvm::GlobalVariable* Abi::getZeroRegister() const
{
	return getRegister(_regZeroReg);
}

std::size_t Abi::getRegisterByteSize(uint32_t reg) const
{
	auto r = getRegister(reg);
	assert(r);

	if (auto* p = dyn_cast<PointerType>(r->getType()))
	{
		return getTypeByteSize(p->getElementType());
	}

	return getTypeByteSize(r->getType());
}

void Abi::addRegister(uint32_t id, llvm::GlobalVariable* reg)
{
	if (id >= _id2regs.size())
	{
		_id2regs.resize(id+1, nullptr);
	}
	_regs.emplace_back(reg);
	_id2regs[id] = reg;
	_regs2id.emplace(reg, id);
}

llvm::GlobalVariable* Abi::getSyscallIdRegister()
{
	return getRegister(_regSyscallId);
}

llvm::GlobalVariable* Abi::getSyscallReturnRegister()
{
	return getRegister(_regSyscallReturn);
}

llvm::GlobalVariable* Abi::getSyscallArgumentRegister(unsigned n)
{
	return n < _syscallRegs.size() ? getRegister(_syscallRegs[n]) : nullptr;
}

bool Abi::isStackVariable(const Value* val) const
{
	return _config->isStackVariable(val);
}

bool Abi::isNopInstruction(AsmInstruction ai)
{
	return isNopInstruction(ai.getCapstoneInsn());
}

std::size_t Abi::getTypeByteSize(llvm::Type* t) const
{
	return Abi::getTypeByteSize(_module, t);
}

std::size_t Abi::getTypeBitSize(llvm::Type* t) const
{
	return Abi::getTypeBitSize(_module, t);
}

llvm::IntegerType* Abi::getDefaultType() const
{
	return Abi::getDefaultType(_module);
}

llvm::PointerType* Abi::getDefaultPointerType() const
{
	return Abi::getDefaultPointerType(_module);
}

std::size_t Abi::getWordSize() const
{
	return _config->getConfig().architecture.getBitSize() / 8;
}

std::size_t Abi::getTypeByteSize(llvm::Module* m, llvm::Type* t)
{
	assert(m);
	assert(t->isSized());

	return m->getDataLayout().getTypeStoreSize(t);
}

std::size_t Abi::getTypeBitSize(llvm::Module* m, llvm::Type* t)
{
	assert(m);
	assert(t->isSized());

	return m->getDataLayout().getTypeSizeInBits(t);
}

llvm::IntegerType* Abi::getDefaultType(llvm::Module* m)
{
	assert(m);
	unsigned s = m->getDataLayout().getPointerSize(0) * 8;
	return Type::getIntNTy(m->getContext(), s);
}

llvm::Type* Abi::getDefaultFPType(llvm::Module* m)
{
	assert(m);
	return Type::getFloatTy(m->getContext());
}

llvm::PointerType* Abi::getDefaultPointerType(llvm::Module* m)
{
	assert(m);
	return PointerType::get(Abi::getDefaultType(m), 0);
}

std::size_t Abi::getWordSize(llvm::Module* m)
{
	return m->getDataLayout().getPointerSize(0);
}

bool Abi::isMips() const
{
	return _config->getConfig().architecture.isMipsOrPic32();
}

bool Abi::isMips64() const
{
	return _config->getConfig().architecture.isMips64();
}

bool Abi::isArm() const
{
	return _config->getConfig().architecture.isArm32OrThumb();
}

bool Abi::isArm64() const
{
	return _config->getConfig().architecture.isArm64();
}

bool Abi::isX86() const
{
	return _config->getConfig().architecture.isX86();
}

bool Abi::isX64() const
{
	return _config->getConfig().architecture.isX86_64();
}

bool Abi::isPowerPC() const
{
	return _config->getConfig().architecture.isPpc();
}

bool Abi::isPowerPC64() const
{
	return _config->getConfig().architecture.isPpc64();
}

bool Abi::isPic32() const
{
	return _config->getConfig().architecture.isPic32();
}

CallingConvention* Abi::getDefaultCallingConvention()
{
	return getCallingConvention(_defcc);
}

CallingConvention* Abi::getCallingConvention(
			const CallingConvention::ID& cc)
{
	if (_id2cc.find(cc) == _id2cc.end())
	{
		auto provider = CallingConventionProvider::getProvider();
		_id2cc[cc] = provider->createCallingConvention(cc, this);
	}

	return _id2cc[cc].get();
}

Config* Abi::getConfig() const
{
	return _config;
}

//
//==============================================================================
// AbiProvider
//==============================================================================
//

std::map<llvm::Module*, std::unique_ptr<Abi>> AbiProvider::_module2abi;

Abi* AbiProvider::addAbi(
		llvm::Module* m,
		Config* c)
{
	if (m == nullptr || c == nullptr)
	{
		return nullptr;
	}

	if (c->getConfig().architecture.isArm32OrThumb())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiArm>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isArm64())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiArm64>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isMips())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiMips>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isPic32())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiPic32>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isPpc())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiPowerpc>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isX86_64())
	{
		bool isMinGW = c->getConfig().tools.isGcc()
				&& c->getConfig().fileFormat.isPe();

		if (isMinGW || c->getConfig().tools.isMsvc())
		{
			auto p = _module2abi.emplace(m, std::make_unique<AbiMS_X64>(m, c));
			return p.first->second.get();
		}

		auto p = _module2abi.emplace(m, std::make_unique<AbiX64>(m, c));
		return p.first->second.get();
	}
	else if (c->getConfig().architecture.isX86())
	{
		auto p = _module2abi.emplace(m, std::make_unique<AbiX86>(m, c));
		return p.first->second.get();
	}
	// ...

	return nullptr;
}

Abi* AbiProvider::getAbi(llvm::Module* m)
{
	auto f = _module2abi.find(m);
	return f != _module2abi.end() ? f->second.get() : nullptr;
}

bool AbiProvider::getAbi(llvm::Module* m, Abi*& abi)
{
	abi = getAbi(m);
	return abi != nullptr;
}

void AbiProvider::clear()
{
	_module2abi.clear();
}

} // namespace bin2llvmir
} // namespace retdec
