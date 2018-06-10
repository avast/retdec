/**
 * @file src/capstone2llvmir/capstone2llvmir.cpp
 * @brief Converts bytes to Capstone representation, and Capstone representation
 *        to LLVM IR.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "capstone2llvmir/capstone2llvmir_impl.h"

namespace retdec {
namespace capstone2llvmir {

template <typename CInsn, typename CInsnOp>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::Capstone2LlvmIrTranslator_impl(
		cs_arch a,
		cs_mode basic,
		cs_mode extra,
		llvm::Module* m)
		:
		_arch(a),
		_basicMode(basic),
		_extraMode(extra),
		_origBasicMode(basic),
		_module(m)
{
	// Do not call anything here, especially virtual methods.
}

template <typename CInsn, typename CInsnOp>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::~Capstone2LlvmIrTranslator_impl()
{
	closeHandle();
}

//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::modifyBasicMode(cs_mode m)
{
	if (!isAllowedBasicMode(m))
	{
		throw Capstone2LlvmIrModeError(
				_arch,
				m,
				Capstone2LlvmIrModeError::eType::BASIC_MODE);
	}

	if (cs_option(_handle, CS_OPT_MODE, m + _extraMode) != CS_ERR_OK)
	{
		throw CapstoneError(cs_errno(_handle));
	}

	_basicMode = m;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::modifyExtraMode(cs_mode m)
{
	if (!isAllowedExtraMode(m))
	{
		throw Capstone2LlvmIrModeError(
				_arch,
				m,
				Capstone2LlvmIrModeError::eType::EXTRA_MODE);
	}

	if (cs_option(_handle, CS_OPT_MODE, m + _basicMode) != CS_ERR_OK)
	{
		throw CapstoneError(cs_errno(_handle));
	}

	_extraMode = m;
}

template <typename CInsn, typename CInsnOp>
uint32_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getArchBitSize()
{
	return getArchByteSize() * 8;
}

//
//==============================================================================
// Translation methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

// TODO: Optimize -- to make generation easier and nicer, some things
// can be generated suboptimally. We should inspect every generated
// ASM insruction and optimize some known patterns:
//
// 1. Load propagation:
// a = load r
// ... use a, not change r, no fnc call, etc.
// b = load r
// ... use b -> replace by a, remove b
//
// 2. Conversions:
// a = cast b
// ... use a
// c = cast b
// ... use c -> replace by a, remove c
//
// 3. Unused values (e.g. from loadOpBinary() where only one op used):
// a = load x
// ... a unused
//
// 4. Values used only for their type (e.g. op0 load in translateMov()):
// a = load x
// b = load y
// c = convert b to a.type
// store c x
//
// etc.

template <typename CInsn, typename CInsnOp>
typename Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::TranslationResult
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translate(
		const uint8_t* bytes,
		std::size_t size,
		retdec::utils::Address a,
		llvm::IRBuilder<>& irb,
		std::size_t count,
		bool stopOnBranch)
{
	TranslationResult res;

	// We want to keep all Capstone instructions -> alloc a new one each time.
	cs_insn* insn = cs_malloc(_handle);

	uint64_t address = a;

	_branchGenerated = nullptr;
	_inCondition = false;

	// TODO: hack, solve better.
	bool disasmRes = cs_disasm_iter(_handle, &bytes, &size, &address, insn);
	if (!disasmRes && _arch == CS_ARCH_MIPS && _basicMode == CS_MODE_MIPS32)
	{
		modifyBasicMode(CS_MODE_MIPS64);
		disasmRes = cs_disasm_iter(_handle, &bytes, &size, &address, insn);
		modifyBasicMode(CS_MODE_MIPS32);
	}

	while (disasmRes)
	{
		auto* a2l = generateSpecialAsm2LlvmInstr(irb, insn);

		res.insns.push_back(std::make_pair(a2l, insn));
		res.size = (insn->address + insn->size) - a;

		translateInstruction(insn, irb);

		++res.count;
		if (count && count == res.count)
		{
			return res;
		}

		if (_branchGenerated && stopOnBranch)
		{
			res.branchCall = _branchGenerated;
			res.inCondition = _inCondition;
			return res;
		}

		insn = cs_malloc(_handle);

		// TODO: hack, solve better.
		disasmRes = cs_disasm_iter(_handle, &bytes, &size, &address, insn);
		if (!disasmRes && _arch == CS_ARCH_MIPS && _basicMode == CS_MODE_MIPS32)
		{
			modifyBasicMode(CS_MODE_MIPS64);
			disasmRes = cs_disasm_iter(_handle, &bytes, &size, &address, insn);
			modifyBasicMode(CS_MODE_MIPS32);
		}
	}

	cs_free(insn, 1);

	return res;
}

template <typename CInsn, typename CInsnOp>
typename Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::TranslationResultOne
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translateOne(
		const uint8_t*& bytes,
		std::size_t& size,
		retdec::utils::Address& a,
		llvm::IRBuilder<>& irb)
{
	TranslationResultOne res;

	// We want to keep all Capstone instructions -> alloc a new one each time.
	cs_insn* insn = cs_malloc(_handle);

	uint64_t address = a;
	_branchGenerated = nullptr;
	_inCondition = false;

	// TODO: hack, solve better.
	bool disasmRes = cs_disasm_iter(_handle, &bytes, &size, &address, insn);
	if (!disasmRes && _arch == CS_ARCH_MIPS && _basicMode == CS_MODE_MIPS32)
	{
		modifyBasicMode(CS_MODE_MIPS64);
		disasmRes = cs_disasm_iter(_handle, &bytes, &size, &address, insn);
		modifyBasicMode(CS_MODE_MIPS32);
	}

	if (disasmRes)
	{
		auto* a2l = generateSpecialAsm2LlvmInstr(irb, insn);
		translateInstruction(insn, irb);

		res.llvmInsn = a2l;
		res.capstoneInsn = insn;
		res.size = insn->size;
		res.branchCall = _branchGenerated;
		res.inCondition = _inCondition;

		a = address;
	}
	else
	{
		cs_free(insn, 1);
	}

	return res;
}

//
//==============================================================================
// Capstone related getters - from Capstone2LlvmIrTranslator.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
const csh& Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getCapstoneEngine() const
{
	return _handle;
}

template <typename CInsn, typename CInsnOp>
cs_arch Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getArchitecture() const
{
	return _arch;
}

template <typename CInsn, typename CInsnOp>
cs_mode Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getBasicMode() const
{
	return _basicMode;
}

template <typename CInsn, typename CInsnOp>
cs_mode Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getExtraMode() const
{
	return _extraMode;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::hasDelaySlot(uint32_t id) const
{
	return false;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::hasDelaySlotTypical(uint32_t id) const
{
	return false;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::hasDelaySlotLikely(uint32_t id) const
{
	return false;
}

template <typename CInsn, typename CInsnOp>
std::size_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getDelaySlot(uint32_t id) const
{
	return 0;
}

template <typename CInsn, typename CInsnOp>
llvm::GlobalVariable* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getRegister(uint32_t r)
{
	// This could be optimized using cache.
	auto rn = getRegisterName(r);
	return _module->getNamedGlobal(rn);
}

template <typename CInsn, typename CInsnOp>
std::string Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getRegisterName(uint32_t r) const
{
	auto fIt = _reg2name.find(r);
	if (fIt == _reg2name.end())
	{
		if (auto* n = cs_reg_name(_handle, r))
		{
			return n;
		}
		else
		{
			throw Capstone2LlvmIrError(
					"Missing name for register number: " + std::to_string(r));
		}
	}
	else
	{
		return fIt->second;
	}
}

template <typename CInsn, typename CInsnOp>
uint32_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getRegisterBitSize(uint32_t r) const
{
	auto* rt = getRegisterType(r);
	if (auto* it = llvm::dyn_cast<llvm::IntegerType>(rt))
	{
		return it->getBitWidth();
	}
	else if (rt->isHalfTy())
	{
		return 16;
	}
	else if (rt->isFloatTy())
	{
		return 32;
	}
	else if (rt->isDoubleTy())
	{
		return 64;
	}
	else if (rt->isX86_FP80Ty())
	{
		return 80;
	}
	else if (rt->isFP128Ty())
	{
		return 128;
	}
	else
	{
		throw Capstone2LlvmIrError(
				"Unhandled type of register number: " + std::to_string(r));
	}
}

template <typename CInsn, typename CInsnOp>
uint32_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getRegisterByteSize(
		uint32_t r) const
{
	return getRegisterBitSize(r) / 8;
}

template <typename CInsn, typename CInsnOp>
llvm::Type* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getRegisterType(
		uint32_t r) const
{
	auto fIt = _reg2type.find(r);
	if (fIt == _reg2type.end())
	{
		assert(false);
		throw Capstone2LlvmIrError(
				"Missing type for register number: " + std::to_string(r));
	}
	return fIt->second;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isControlFlowInstruction(
		cs_insn& i) const
{
	return _controlFlowInsnIds.count(i.id)
			|| isCallInstruction(i)
			|| isReturnInstruction(i)
			|| isBranchInstruction(i)
			|| isCondBranchInstruction(i);
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isCallInstruction(
		cs_insn& i) const
{
	return _callInsnIds.count(i.id);
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isReturnInstruction(
		cs_insn& i) const
{
	return _returnInsnIds.count(i.id);
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isBranchInstruction(
		cs_insn& i) const
{
	return _branchInsnIds.count(i.id);
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isCondBranchInstruction(
		cs_insn& i) const
{
	return _condBranchInsnIds.count(i.id);
}

//
//==============================================================================
// LLVM related getters and query methods.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
llvm::BranchInst*
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getCondBranchForInsnInIfThen(
		llvm::Instruction* i) const
{
	// Asm to LLVM mapping instruction is not in BB where call is.
	auto* prev = i->getPrevNode();
	while (prev)
	{
		if (isSpecialAsm2LlvmInstr(prev))
		{
			return nullptr;
		}
		prev = prev->getPrevNode();
	}

	auto* prevBb = i->getParent()->getPrevNode();
	auto* term = prevBb ? prevBb->getTerminator() : nullptr;
	auto* br = llvm::dyn_cast_or_null<llvm::BranchInst>(term);
	if (prevBb == nullptr
			|| br == nullptr
			|| !br->isConditional()
			|| br->getSuccessor(0) != i->getParent())
	{
		return nullptr;
	}

	return br;
}

template <typename CInsn, typename CInsnOp>
llvm::Module* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getModule() const
{
	return _module;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isSpecialAsm2LlvmMapGlobal(
		llvm::Value* v) const
{
	return _asm2llvmGv == v;
}

template <typename CInsn, typename CInsnOp>
llvm::StoreInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isSpecialAsm2LlvmInstr(
		llvm::Value* v) const
{
	if (auto* s = llvm::dyn_cast<llvm::StoreInst>(v))
	{
		if (isSpecialAsm2LlvmMapGlobal(s->getPointerOperand()))
		{
			return s;
		}
	}
	return nullptr;
}

template <typename CInsn, typename CInsnOp>
llvm::GlobalVariable* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getAsm2LlvmMapGlobalVariable() const
{
	return _asm2llvmGv;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isCallFunction(llvm::Function* f) const
{
	return f == _callFunction;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isCallFunctionCall(llvm::CallInst* c) const
{
	return c ? isCallFunction(c->getCalledFunction()) : false;
}

template <typename CInsn, typename CInsnOp>
llvm::BranchInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isInConditionCallFunctionCall(llvm::CallInst* c) const
{
	return isCallFunctionCall(c) ? getCondBranchForInsnInIfThen(c) : nullptr;
}

template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getCallFunction() const
{
	return _callFunction;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isReturnFunction(llvm::Function* f) const
{
	return f == _returnFunction;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isReturnFunctionCall(
		llvm::CallInst* c) const
{
	return c ? isReturnFunction(c->getCalledFunction()) : false;
}

template <typename CInsn, typename CInsnOp>
llvm::BranchInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isInConditionReturnFunctionCall(llvm::CallInst* c) const
{
	return isReturnFunctionCall(c) ? getCondBranchForInsnInIfThen(c) : nullptr;
}

template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getReturnFunction() const
{
	return _returnFunction;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isBranchFunction(llvm::Function* f) const
{
	return _branchFunction == f;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isBranchFunctionCall(
		llvm::CallInst* c) const
{
	return c ? isBranchFunction(c->getCalledFunction()) : false;
}

template <typename CInsn, typename CInsnOp>
llvm::BranchInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isInConditionBranchFunctionCall(llvm::CallInst* c) const
{
	return isBranchFunctionCall(c) ? getCondBranchForInsnInIfThen(c) : nullptr;
}

template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getBranchFunction() const
{
	return _branchFunction;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isCondBranchFunction(
		llvm::Function* f) const
{
	return _condBranchFunction == f;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isCondBranchFunctionCall(
		llvm::CallInst* c) const
{
	return c ? isCondBranchFunction(c->getCalledFunction()) : false;
}

template <typename CInsn, typename CInsnOp>
llvm::BranchInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isInConditionCondBranchFunctionCall(llvm::CallInst* c) const
{
	return isCondBranchFunctionCall(c) ? getCondBranchForInsnInIfThen(c) : nullptr;
}

template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getCondBranchFunction() const
{
	return _condBranchFunction;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isAnyPseudoFunction(
		llvm::Function* f) const
{
	return isCallFunction(f)
			|| isReturnFunction(f)
			|| isBranchFunction(f)
			|| isCondBranchFunction(f);
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isAnyPseudoFunctionCall(
		llvm::CallInst* c) const
{
	return isCallFunctionCall(c)
			|| isReturnFunctionCall(c)
			|| isBranchFunctionCall(c)
			|| isCondBranchFunctionCall(c);
}

template <typename CInsn, typename CInsnOp>
llvm::GlobalVariable* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isRegister(
		llvm::Value* v) const
{
	auto it = _allLlvmRegs.find(llvm::dyn_cast_or_null<llvm::GlobalVariable>(v));
	return it != _allLlvmRegs.end() ? it->first : nullptr;
}

template <typename CInsn, typename CInsnOp>
uint32_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getCapstoneRegister(
		llvm::GlobalVariable* gv) const
{
	auto it = _allLlvmRegs.find(gv);
	return it != _allLlvmRegs.end() ? it->second : 0;
}

//
//==============================================================================
//
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::initialize()
{
	if (!isAllowedBasicMode(_basicMode))
	{
		throw Capstone2LlvmIrModeError(
				_arch,
				_basicMode,
				Capstone2LlvmIrModeError::eType::BASIC_MODE);
	}
	if (!isAllowedExtraMode(_extraMode))
	{
		throw Capstone2LlvmIrModeError(
				_arch,
				_extraMode,
				Capstone2LlvmIrModeError::eType::EXTRA_MODE);
	}

	openHandle(); // Sets both _basicMode and _extraMode.
	configureHandle();

	initializeRegNameMap();
	initializeRegTypeMap();
	initializePseudoCallInstructionIDs();
	initializeArchSpecific();

	generateEnvironment();
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::openHandle()
{
	cs_mode finalMode = static_cast<cs_mode>(_basicMode + _extraMode);
	if (cs_open(_arch, finalMode, &_handle) != CS_ERR_OK)
	{
		throw CapstoneError(cs_errno(_handle));
	}
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::configureHandle()
{
	if (cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	{
		throw CapstoneError(cs_errno(_handle));
	}
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::closeHandle()
{
	if (_handle != 0)
	{
		if (cs_close(&_handle) != CS_ERR_OK)
		{
			throw CapstoneError(cs_errno(_handle));
		}
	}
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateEnvironment()
{
	generateSpecialAsm2LlvmMapGlobal();
	generateCallFunction();
	generateReturnFunction();
	generateBranchFunction();
	generateCondBranchFunction();

	generateEnvironmentArchSpecific();
	generateRegisters();
	generateDataLayout();
}

/**
 * The generated global variable is unnamed. capstone2llvmir library does not
 * allow to specify or set its name. Users can however get the variable with
 * @c getAsm2LlvmMapGlobalVariable() and do whatever they want with it
 * (e.g. rename).
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateSpecialAsm2LlvmMapGlobal()
{
	llvm::GlobalValue::LinkageTypes lt = llvm::GlobalValue::InternalLinkage;
	llvm::Constant* initializer = nullptr;
	auto* t = llvm::IntegerType::getInt64Ty(_module->getContext());
	if (initializer == nullptr
			&& lt != llvm::GlobalValue::LinkageTypes::ExternalLinkage)
	{
		initializer = llvm::ConstantInt::get(t, 0);
	}

	_asm2llvmGv = new llvm::GlobalVariable(
			*_module,
			t,
			false, // isConstant
			lt,
			initializer);
}

template <typename CInsn, typename CInsnOp>
llvm::StoreInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateSpecialAsm2LlvmInstr(
		llvm::IRBuilder<>& irb,
		cs_insn* i)
{
	retdec::utils::Address a = i->address;
	auto* gv = getAsm2LlvmMapGlobalVariable();
	auto* ci = llvm::ConstantInt::get(gv->getValueType(), a, false);
	auto* s = irb.CreateStore(ci, gv, true);
	return s;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCallFunction()
{
	auto* ft = llvm::FunctionType::get(
			llvm::Type::getVoidTy(_module->getContext()),
			{llvm::Type::getIntNTy(_module->getContext(), getArchBitSize())},
			false);
	_callFunction = llvm::Function::Create(
			ft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);
}

template <typename CInsn, typename CInsnOp>
llvm::CallInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCallFunctionCall(
		llvm::IRBuilder<>& irb,
		llvm::Value* t)
{
	auto* a1t = _callFunction->getArgumentList().front().getType();
	t = irb.CreateSExtOrTrunc(t, a1t);
	_branchGenerated = irb.CreateCall(_callFunction, {t});
	return _branchGenerated;
}

template <typename CInsn, typename CInsnOp>
llvm::CallInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCondCallFunctionCall(
		llvm::IRBuilder<>& irb,
		llvm::Value* cond,
		llvm::Value* t)
{
	auto bodyIrb = generateIfThen(cond, irb);

	auto* a1t = _callFunction->getArgumentList().front().getType();
	t = bodyIrb.CreateSExtOrTrunc(t, a1t);
	_branchGenerated = bodyIrb.CreateCall(_callFunction, {t});
	_inCondition = true;
	return _branchGenerated;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateReturnFunction()
{
	auto* ft = llvm::FunctionType::get(
			llvm::Type::getVoidTy(_module->getContext()),
			{llvm::Type::getIntNTy(_module->getContext(), getArchBitSize())},
			false);
	_returnFunction = llvm::Function::Create(
			ft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);
}

template <typename CInsn, typename CInsnOp>
llvm::CallInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateReturnFunctionCall(
		llvm::IRBuilder<>& irb,
		llvm::Value* t)
{
	auto* a1t = _returnFunction->getArgumentList().front().getType();
	t = irb.CreateSExtOrTrunc(t, a1t);
	_branchGenerated = irb.CreateCall(_returnFunction, {t});
	return _branchGenerated;
}

template <typename CInsn, typename CInsnOp>
llvm::CallInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCondReturnFunctionCall(
		llvm::IRBuilder<>& irb,
		llvm::Value* cond,
		llvm::Value* t)
{
	auto bodyIrb = generateIfThen(cond, irb);

	auto* a1t = _returnFunction->getArgumentList().front().getType();
	t = bodyIrb.CreateSExtOrTrunc(t, a1t);
	_branchGenerated = bodyIrb.CreateCall(_returnFunction, {t});
	_inCondition = true;
	return _branchGenerated;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateBranchFunction()
{
	auto* ft = llvm::FunctionType::get(
			llvm::Type::getVoidTy(_module->getContext()),
			{llvm::Type::getIntNTy(_module->getContext(), getArchBitSize())},
			false);
	_branchFunction = llvm::Function::Create(
			ft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);
}

template <typename CInsn, typename CInsnOp>
llvm::CallInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateBranchFunctionCall(
		llvm::IRBuilder<>& irb,
		llvm::Value* t)
{
	auto* a1t = _branchFunction->getArgumentList().front().getType();
	t = irb.CreateSExtOrTrunc(t, a1t);
	_branchGenerated = irb.CreateCall(_branchFunction, {t});
	return _branchGenerated;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCondBranchFunction()
{
	std::vector<llvm::Type*> params = {
			llvm::Type::getInt1Ty(_module->getContext()),
			llvm::Type::getIntNTy(_module->getContext(), getArchBitSize())};
	auto* ft = llvm::FunctionType::get(
			llvm::Type::getVoidTy(_module->getContext()),
			params,
			false);
	_condBranchFunction = llvm::Function::Create(
			ft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);
}

template <typename CInsn, typename CInsnOp>
llvm::CallInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCondBranchFunctionCall(
		llvm::IRBuilder<>& irb,
		llvm::Value* cond,
		llvm::Value* t)
{
	auto* a1t = _condBranchFunction->getArgumentList().back().getType();
	t = irb.CreateSExtOrTrunc(t, a1t);
	_branchGenerated = irb.CreateCall(_condBranchFunction, {cond, t});
	return _branchGenerated;
}

template <typename CInsn, typename CInsnOp>
llvm::GlobalVariable* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::createRegister(
		uint32_t r,
		llvm::GlobalValue::LinkageTypes lt,
		llvm::Constant* initializer)
{
	auto* rt = getRegisterType(r);
	if (initializer == nullptr
			&& lt != llvm::GlobalValue::LinkageTypes::ExternalLinkage)
	{
		if (auto* it = llvm::dyn_cast<llvm::IntegerType>(rt))
		{
			initializer = llvm::ConstantInt::get(it, 0);
		}
		else if (rt->isFloatingPointTy())
		{
			initializer = llvm::ConstantFP::get(rt, 0);
		}
		else
		{
			throw Capstone2LlvmIrError("Unhandled register type.");
		}
	}

	auto* gv = new llvm::GlobalVariable(
			*_module,
			rt,
			false, // isConstant
			lt,
			initializer,
			getRegisterName(r));

	if (gv == nullptr)
	{
		throw Capstone2LlvmIrError("Memory allocation error.");
	}

	_allLlvmRegs[gv] = r;

	return gv;
}

//
//==============================================================================
// Load/store methods.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpUnary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct,
		llvm::Type* loadType)
{
	if (ci->op_count != 1)
	{
		throw Capstone2LlvmIrError("This is not an unary instruction.");
	}

	auto* op = loadOp(ci->operands[0], irb, loadType);
	op = generateTypeConversion(irb, op, dstType, ct);
	return op;
}

template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (ci->op_count != 2)
	{
		throw Capstone2LlvmIrError("This is not a binary instruction.");
	}

	auto* op0 = loadOp(ci->operands[0], irb);
	auto* op1 = loadOp(ci->operands[1], irb);
	if (op0 == nullptr || op1 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}
	op1 = generateTypeConversion(irb, op1, op0->getType(), ct);

	return std::make_pair(op0, op1);
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinaryOp0(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty)
{
	if (ci->op_count != 2)
	{
		throw Capstone2LlvmIrError("This is not a binary instruction.");
	}

	return loadOp(ci->operands[0], irb, ty);
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinaryOp1(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty)
{
	if (ci->op_count != 2)
	{
		throw Capstone2LlvmIrError("This is not a binary instruction.");
	}

	return loadOp(ci->operands[1], irb, ty);
}

template <typename CInsn, typename CInsnOp>
std::tuple<llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpTernary(
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	if (ci->op_count != 3)
	{
		throw Capstone2LlvmIrError("This is not a ternary instruction.");
	}

	auto* op0 = loadOp(ci->operands[0], irb);
	auto* op1 = loadOp(ci->operands[1], irb);
	auto* op2 = loadOp(ci->operands[2], irb);
	if (op0 == nullptr || op1 == nullptr || op2 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}

	return std::make_tuple(op0, op1, op2);
}

template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpTernaryOp1Op2(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	llvm::Value* op1 = nullptr;
	llvm::Value* op2 = nullptr;

//	if (mi->op_count != 3)
//	{
//		throw Capstone2LlvmIrError("This is not a ternary instruction.");
//	}

	if (ci->op_count == 3)
	{
		op1 = loadOp(ci->operands[1], irb);
		op2 = loadOp(ci->operands[2], irb);
	}
	// TODO: Is this desirable here? Maybe special function with this behaviour?
	else if (ci->op_count == 2)
	{
		op1 = loadOp(ci->operands[0], irb);
		op2 = loadOp(ci->operands[1], irb);
	}
	// TODO: "00 21 08 22" = "andhs r2, r8, #0, #2"
	// No idea what this is, we just want to ignore it somehow, when throwing
	// and silent catching is done, this hack can be removed.
	//
	else if (ci->op_count > 3)
	{
		op1 = loadOp(ci->operands[1], irb);
		op2 = loadOp(ci->operands[2], irb);
	}
	else
	{
		throw Capstone2LlvmIrError("This is not a ternary instruction.");
	}
	if (op1 == nullptr || op2 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}
	op2 = generateTypeConversion(irb, op2, op1->getType(), ct);

	return std::make_pair(op1, op2);
}

template <typename CInsn, typename CInsnOp>
std::tuple<llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpQuaternaryOp1Op2Op3(
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	if (ci->op_count != 4)
	{
		throw Capstone2LlvmIrError("This is not a ternary instruction.");
	}

	auto* op1 = loadOp(ci->operands[1], irb);
	auto* op2 = loadOp(ci->operands[2], irb);
	auto* op3 = loadOp(ci->operands[3], irb);
	if (op1 == nullptr || op2 == nullptr || op3 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}

	return std::make_tuple(op1, op2, op3);
}

//
//==============================================================================
// Carry/overflow/borrow add/sub generation routines.
//==============================================================================
//

/**
 * carry_add()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCarryAdd(
		llvm::Value* add,
		llvm::Value* op0,
		llvm::IRBuilder<>& irb)
{
	return irb.CreateICmpULT(add, op0);
}

/**
 * carry_add_c()
 *
 * If @p cf is not passed, default cf register is used. Why pass it?
 * - Pass cf if you want to generate nicer code - prevent second cf load if
 *   it is already loaded by caller. This should however be taken care of by
 *   after generation optimizations.
 * - Use a different value as cf.
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCarryAddC(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	auto* add1 = irb.CreateAdd(op0, op1);
	if (cf == nullptr)
	{
		cf = loadRegister(getCarryRegister(), irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, add1->getType());
	auto* add2 = irb.CreateAdd(add1, cfc);
	auto* icmp1 = irb.CreateICmpULE(add2, op0);
	auto* icmp2 = irb.CreateICmpULT(add1, op0);
	auto* cff = irb.CreateZExtOrTrunc(cf, irb.getInt1Ty());
	return irb.CreateSelect(cff, icmp1, icmp2);
}

/**
 * carry_add_int4()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCarryAddInt4(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	auto* ci15 = llvm::ConstantInt::get(op0->getType(), 15);
	auto* and0 = irb.CreateAnd(op0, ci15);
	auto* and1 = irb.CreateAnd(op1, ci15);
	auto* add = irb.CreateAdd(and0, and1);
	return irb.CreateICmpUGT(add, ci15);
}

/**
 * carry_add_c_int4()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateCarryAddCInt4(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	auto* ci15 = llvm::ConstantInt::get(op0->getType(), 15);
	auto* and0 = irb.CreateAnd(op0, ci15);
	auto* and1 = irb.CreateAnd(op1, ci15);
	auto* a = irb.CreateAdd(and0, and1);
	if (cf == nullptr)
	{
		cf = loadRegister(
				getCarryRegister(),
				irb,
				a->getType(),
				eOpConv::ZEXT_TRUNC);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, a->getType());
	auto* add = irb.CreateAdd(a, cfc);
	return irb.CreateICmpUGT(add, ci15);
}

/**
 * overflow_add()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateOverflowAdd(
		llvm::Value* add,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	auto* xor0 = irb.CreateXor(op0, add);
	auto* xor1 = irb.CreateXor(op1, add);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(
			ofAnd,
			llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * overflow_add_c()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateOverflowAddC(
		llvm::Value* add,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	if (cf == nullptr)
	{
		cf = loadRegister(getCarryRegister(), irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, add->getType());
	auto* ofAdd = irb.CreateAdd(add, cfc);
	auto* xor0 = irb.CreateXor(op0, ofAdd);
	auto* xor1 = irb.CreateXor(op1, ofAdd);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(ofAnd, llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * overflow_sub()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateOverflowSub(
		llvm::Value* sub,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	auto* xor0 = irb.CreateXor(op0, op1);
	auto* xor1 = irb.CreateXor(op0, sub);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(
			ofAnd,
			llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * overflow_sub_c()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateOverflowSubC(
		llvm::Value* sub,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	if (cf == nullptr)
	{
		cf = loadRegister(getCarryRegister(), irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, sub->getType());
	auto* ofSub = irb.CreateSub(sub, cfc);
	auto* xor0 = irb.CreateXor(op0, op1);
	auto* xor1 = irb.CreateXor(op0, ofSub);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(
			ofAnd,
			llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * borrow_sub()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateBorrowSub(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	return irb.CreateICmpULT(op0, op1);
}

/**
 * borrow_sub_c()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateBorrowSubC(
		llvm::Value* sub,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	if (cf == nullptr)
	{
		cf = loadRegister(getCarryRegister(), irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, sub->getType());
	auto* cfSub = irb.CreateSub(sub, cfc);
	auto* cfIcmp1 = irb.CreateICmpULT(op0, cfSub);
	auto* negOne = llvm::ConstantInt::getSigned(op1->getType(), -1);
	auto* cfIcmp2 = irb.CreateICmpULT(op1, negOne);
	auto* cfOr = irb.CreateOr(cfIcmp1, cfIcmp2);
	auto* cfIcmp3 = irb.CreateICmpULT(op0, op1);
	auto* cff = irb.CreateZExtOrTrunc(cf, irb.getInt1Ty());
	return irb.CreateSelect(cff, cfOr, cfIcmp3);
}

/**
 * borrow_sub_int4()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateBorrowSubInt4(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	auto* ci15 = llvm::ConstantInt::get(op0->getType(), 15);
	auto* and0 = irb.CreateAnd(op0, ci15);
	auto* and1 = irb.CreateAnd(op1, ci15);
	auto* afSub = irb.CreateSub(and0, and1);
	return irb.CreateICmpUGT(afSub, ci15);
}

/**
 * borrow_sub_c_int4()
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateBorrowSubCInt4(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	auto* ci15 = llvm::ConstantInt::get(op0->getType(), 15);
	auto* and0 = irb.CreateAnd(op0, ci15);
	auto* and1 = irb.CreateAnd(op1, ci15);
	auto* sub = irb.CreateSub(and0, and1);
	if (cf == nullptr)
	{
		cf = loadRegister(getCarryRegister(), irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, sub->getType());
	auto* add = irb.CreateAdd(sub, cfc);
	return irb.CreateICmpUGT(add, ci15);
}

//
//==============================================================================
// Non-virtual helper methods.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
llvm::IntegerType* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getDefaultType()
{
	return getIntegerTypeFromByteSize(_module, getArchByteSize());
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getThisInsnAddress(cs_insn* i)
{
	return llvm::ConstantInt::get(getDefaultType(), i->address);
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getNextInsnAddress(cs_insn* i)
{
	return llvm::ConstantInt::get(getDefaultType(), i->address + i->size);
}

/**
 * @return Asm function associated with @p name, or @c nullptr if there is
 *         no such function.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getAsmFunction(
		const std::string& name) const
{
	auto fIt = _asmFunctions.find(name);
	return fIt != _asmFunctions.end() ? fIt->second : nullptr;
}

/**
 * Get already existing asm functions associated with @p name, or if there
 * is no such function, create it using @p name and @p type, add it to asm
 * functions and return it.
 * @return Functions associated with @p insnId.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getOrCreateAsmFunction(
		std::size_t insnId,
		const std::string& name,
		llvm::FunctionType* type)
{
	llvm::Function* fnc = getAsmFunction(name);
	if (fnc == nullptr)
	{
		fnc = llvm::Function::Create(
				type,
				llvm::GlobalValue::LinkageTypes::ExternalLinkage,
				name,
				_module);
		_asmFunctions[name] = fnc;
	}
	return fnc;
}

/**
 * The same as @c getOrCreateAsmFunction(std::size_t,std::string&, llvm::FunctionType*),
 * but function is created with zero parameters and @p retType return type.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getOrCreateAsmFunction(
		std::size_t insnId,
		const std::string& name,
		llvm::Type* retType)
{
	return getOrCreateAsmFunction(
			insnId,
			name,
			llvm::FunctionType::get(retType, false));
}

/**
 * The same as @c getOrCreateAsmFunction(std::size_t,std::string&, llvm::FunctionType*),
 * but function is created with void return type and @p params parameters.
 *
 * TODO: This is not ideal, when used with only one argument (e.g. {i32}),
 * the llvm::Type* retType variant is used instead of this method.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getOrCreateAsmFunction(
		std::size_t insnId,
		const std::string& name,
		llvm::ArrayRef<llvm::Type*> params)
{
	return getOrCreateAsmFunction(
			insnId,
			name,
			llvm::FunctionType::get(
					llvm::Type::getVoidTy(_module->getContext()),
					params,
					false));
}

/**
 * The same as @c getOrCreateAsmFunction(std::size_t,std::string&, llvm::FunctionType*),
 * but function type is created by this variant.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getOrCreateAsmFunction(
		std::size_t insnId,
		const std::string& name,
		llvm::Type* retType,
		llvm::ArrayRef<llvm::Type*> params)
{
	return getOrCreateAsmFunction(
			insnId,
			name,
			llvm::FunctionType::get(retType, params, false));
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateTypeConversion(
		llvm::IRBuilder<>& irb,
		llvm::Value* from,
		llvm::Type* to,
		eOpConv ct)
{
	if (from == nullptr)
	{
		std::cout << "shit" << std::endl;
		exit(1);
	}

	if (to == nullptr || from->getType() == to)
	{
		return from;
	}

	llvm::Value* ret = nullptr;

	switch (ct)
	{
		case eOpConv::SEXT_TRUNC:
		{
			if (from->getType()->isFloatingPointTy())
			{
				ret = irb.CreateFPCast(from, to);
			}
			else
			{
				ret = irb.CreateSExtOrTrunc(from, to);
			}
			break;
		}
		case eOpConv::ZEXT_TRUNC:
		{
			ret = irb.CreateZExtOrTrunc(from, to);
			break;
		}
		case eOpConv::FP_CAST:
		{
			ret = irb.CreateFPCast(from, to);
			break;
		}
		case eOpConv::SITOFP:
		{
			ret = irb.CreateSIToFP(from, to);
			break;
		}
		case eOpConv::UITOFP:
		{
			ret = irb.CreateUIToFP(from, to);
			break;
		}
		case eOpConv::NOTHING:
		{
			ret = from;
			break;
		}
		case eOpConv::THROW:
		default:
		{
			throw Capstone2LlvmIrError("Unhandled eOpConv type.");
		}
	}

	return ret;
}

template class Capstone2LlvmIrTranslator_impl<cs_arm, cs_arm_op>;
template class Capstone2LlvmIrTranslator_impl<cs_mips, cs_mips_op>;
template class Capstone2LlvmIrTranslator_impl<cs_ppc, cs_ppc_op>;
template class Capstone2LlvmIrTranslator_impl<cs_x86, cs_x86_op>;

} // namespace capstone2llvmir
} // namespace retdec
