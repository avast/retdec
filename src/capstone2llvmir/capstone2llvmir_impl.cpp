/**
 * @file src/capstone2llvmir/capstone2llvmir.cpp
 * @brief Converts bytes to Capstone representation, and Capstone representation
 *        to LLVM IR.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>

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
// Translator configuration methods.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::setIgnoreUnexpectedOperands(bool f)
{
	_ignoreUnexpectedOperands = f;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::setIgnoreUnhandledInstructions(bool f)
{
	_ignoreUnhandledInstructions = f;
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::setGeneratePseudoAsmFunctions(bool f)
{
	_generatePseudoAsmFunctions = f;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isIgnoreUnexpectedOperands() const
{
	return _ignoreUnexpectedOperands;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isIgnoreUnhandledInstructions() const
{
	return _ignoreUnhandledInstructions;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isGeneratePseudoAsmFunctions() const
{
	return _generatePseudoAsmFunctions;
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
		throw ModeSettingError(
				_arch,
				m,
				ModeSettingError::eType::BASIC_MODE);
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
		throw ModeSettingError(
				_arch,
				m,
				ModeSettingError::eType::EXTRA_MODE);
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
		retdec::common::Address a,
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
		retdec::common::Address& a,
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
	auto fIt = _capstone2LlvmRegs.find(r);
	return fIt != _capstone2LlvmRegs.end() ? fIt->second : nullptr;
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
			throw GenericError(
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
		throw GenericError(
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
		throw GenericError(
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
llvm::BranchInst* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isInConditionCondBranchFunctionCall(
		llvm::CallInst* c) const
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
	auto it = _llvm2CapstoneRegs.find(llvm::dyn_cast_or_null<llvm::GlobalVariable>(v));
	return it != _llvm2CapstoneRegs.end() ? it->first : nullptr;
}

template <typename CInsn, typename CInsnOp>
uint32_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getCapstoneRegister(
		llvm::GlobalVariable* gv) const
{
	auto it = _llvm2CapstoneRegs.find(gv);
	return it != _llvm2CapstoneRegs.end() ? it->second : 0;
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isPseudoAsmFunction(
		llvm::Function* f) const
{
	return _asmFunctions.count(f);
}

template <typename CInsn, typename CInsnOp>
bool Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::isPseudoAsmFunctionCall(
		llvm::CallInst* c) const
{
	return c ? isPseudoAsmFunction(c->getCalledFunction()) : false;
}

template <typename CInsn, typename CInsnOp>
const std::set<llvm::Function*>& Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getPseudoAsmFunctions() const
{
	return _asmFunctions;
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
		throw ModeSettingError(
				_arch,
				_basicMode,
				ModeSettingError::eType::BASIC_MODE);
	}
	if (!isAllowedExtraMode(_extraMode))
	{
		throw ModeSettingError(
				_arch,
				_extraMode,
				ModeSettingError::eType::EXTRA_MODE);
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
	retdec::common::Address a = i->address;
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
	auto* a1t = _callFunction->arg_begin()->getType();
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

	auto* a1t = _callFunction->arg_begin()->getType();
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
	auto* a1t = _returnFunction->arg_begin()->getType();
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

	auto* a1t = _returnFunction->arg_begin()->getType();
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
	auto* a1t = _branchFunction->arg_begin()->getType();
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
	auto aIt = _condBranchFunction->arg_begin();
	++aIt;
	auto* a1t = aIt->getType();
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
			throw GenericError("Unhandled register type.");
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
		throw GenericError("Memory allocation error.");
	}

	_llvm2CapstoneRegs[gv] = r;
	_capstone2LlvmRegs[r] = gv;

	return gv;
}

//
//==============================================================================
// Load/store methods.
//==============================================================================
//

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOp(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		std::size_t idx,
		llvm::Type* loadType,
		llvm::Type* dstType,
		eOpConv ct)
{
	if (ci->op_count <= idx)
	{
		throw GenericError(
				"Idx out of bounds: "+std::to_string(idx)
				+"/"+std::to_string(ci->op_count));
	}

	auto* op = loadOp(ci->operands[idx], irb, loadType);
	if (op == nullptr)
	{
		throw GenericError("Operand loading failed.");
	}

	if (dstType == nullptr)
	{
		return op;
	}

	return generateTypeConversion(irb, op, dstType, ct);
}

template <typename CInsn, typename CInsnOp>
std::vector<llvm::Value*> Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::_loadOps(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		std::size_t opCnt,
		bool strict,
		llvm::Type* loadType,
		llvm::Type* dstType,
		eOpConv ct)
{
	if ((strict && (ci->op_count != opCnt)) || (ci->op_count < opCnt))
	{
		throw GenericError(
				"Trying to load "
				+std::to_string(opCnt)
				+" operands from instruction with"
				+std::to_string(ci->op_count)
				+" opernads.");
	}

	std::size_t startOp = ci->op_count - opCnt;

	std::vector<llvm::Value*> operands;

	// If no destination type specified, use type of first operand.
	if (dstType == nullptr)
	{
		auto* op0 = loadOp(ci, irb, startOp, loadType, dstType, ct);
		dstType = op0->getType();
		dstType = _checkTypeConversion(irb, dstType, ct);
		op0 = generateTypeConversion(irb, op0, dstType, ct);
		startOp++;
		operands.push_back(op0);
	}
	else
	{
		auto* type = _checkTypeConversion(irb, dstType, ct);
		if (type != dstType)
		{
			throw GenericError(
				"Invalid combination of destination type and conversion type.");
		}
	}

	for (; startOp < ci->op_count; startOp++) {
		auto* op = loadOp(ci, irb, startOp, loadType, dstType, ct);
		operands.push_back(op);
	}

	return operands;
}

template <typename CInsn, typename CInsnOp>
std::vector<llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::_loadOpsUniversal(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		std::size_t opCnt,
		bool strict,
		eOpConv ict,
		eOpConv fct)
{
	if ((strict && (ci->op_count != opCnt)) || (ci->op_count < opCnt))
	{
		throw GenericError(
				"Trying to load "
				+std::to_string(opCnt)
				+" operands from instruction with"
				+std::to_string(ci->op_count)
				+" opernads.");
	}

	auto op0 = loadOp(ci, irb, ci->op_count - opCnt);
	if (op0->getType()->isIntegerTy())
	{
		auto operands = _loadOps(ci, irb, opCnt-1, false, nullptr, op0->getType(), ict);
		operands.insert(operands.begin(), op0);
		return operands;
	}

	auto operands = _loadOps(ci, irb, opCnt-1, false, nullptr, op0->getType(), fct);
	operands.insert(operands.begin(), op0);
	return operands;
}

/**
 * Throws if op_count != 1.
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpUnary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* loadType,
		llvm::Type* dstType,
		eOpConv ct)
{
	return _loadOps(ci, irb, 1, true, loadType, dstType, ct)[0];
}

/**
 * Throws if op_count != 2.
 */
template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	auto operands = _loadOps(ci, irb, 2, true, nullptr, nullptr, ct);
	return std::make_pair(operands[0], operands[1]);
}

/**
 * Throws if op_count != 2.
 */
template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ict,
		eOpConv fct)
{
	auto operands = _loadOpsUniversal(ci, irb, 2, true, ict, fct);
	return std::make_pair(operands[0], operands[1]);
}

template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* loadType,
		llvm::Type* dstType,
		eOpConv ct)
{
	auto operands = _loadOps(ci, irb, 2, true, loadType, dstType, ct);
	return std::make_pair(operands[0], operands[1]);
}

/**
 * Throws if op_count != 2.
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinaryOp0(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty)
{
	auto operand = loadOp(ci, irb, 0, ty);
	return operand;
}

/**
 * Throws if op_count != 2.
 */
template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinaryOp1(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty)
{
	auto operand = loadOp(ci, irb, 1, ty);
	return operand;
}

/**
 * Throws if op_count != 3.
 */
template <typename CInsn, typename CInsnOp>
std::tuple<llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpTernary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	auto operands = _loadOps(ci, irb, 3, true, nullptr, nullptr, ct);
	return std::make_tuple(operands[0], operands[1], operands[2]);
}

/**
 * Throws if op_count != 3.
 */
template <typename CInsn, typename CInsnOp>
std::tuple<llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpTernary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ict,
		eOpConv fct)
{
	auto operands = _loadOpsUniversal(ci, irb, 3, true, ict, fct);
	return std::make_tuple(operands[0], operands[1], operands[2]);
}

/**
 * Throws if op_count != 3.
 */
template <typename CInsn, typename CInsnOp>
std::tuple<llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpTernary(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		llvm::Type* loadType,
		llvm::Type* dstType,
		eOpConv ct)
{
	auto operands = _loadOps(ci, irb, 3, true, loadType, dstType, ct);
	return std::make_tuple(operands[0], operands[1], operands[2]);
}

/**
 * Throws if op_count not in {2, 3}.
 */
template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinaryOrTernaryOp1Op2(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	auto operands = _loadOps(ci, irb, 2, false, nullptr, nullptr, ct);
	return std::make_pair(operands[0], operands[1]);
}

/**
 * Throws if op_count not in {2, 3}.
 */
template <typename CInsn, typename CInsnOp>
std::pair<llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpBinaryOrTernaryOp1Op2(
		CInsn* ci,
		llvm::IRBuilder<>& irb,
		eOpConv ict,
		eOpConv fct)
{
	auto operands = _loadOpsUniversal(ci, irb, 2, false, ict, fct);
	return std::make_pair(operands[0], operands[1]);
}

/**
 * Throws if op_count != 4.
 */
template <typename CInsn, typename CInsnOp>
std::tuple<llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::loadOpQuaternaryOp1Op2Op3(
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	auto operands = _loadOps(ci, irb, 3, false);
	return std::make_tuple(operands[0], operands[1], operands[2]);
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
				eOpConv::ZEXT_TRUNC_OR_BITCAST);
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
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getThisInsnAddress(
		cs_insn* i)
{
	return llvm::ConstantInt::get(getDefaultType(), i->address);
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getNextInsnAddress(
		cs_insn* i)
{
	return llvm::ConstantInt::get(getDefaultType(), i->address + i->size);
}

/**
 * Generate pseudo assembly function name from the given instruction @a insn.
 */
template <typename CInsn, typename CInsnOp>
std::string Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getPseudoAsmFunctionName(
		cs_insn* insn)
{
	return "__asm_" + std::string(insn->mnemonic);
}

/**
 * Get already existing asm functions associated with @p name, or if there
 * is no such function, create it using @p name and @p type, add it to asm
 * functions and return it.
 * @return Functions associated with @p insnId.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getPseudoAsmFunction(
		cs_insn* insn,
		llvm::FunctionType* type,
		const std::string& name)
{
	auto n = name.empty() ? getPseudoAsmFunctionName(insn) : name;
	auto p = std::make_pair(n, type);
	auto fIt = _insn2asmFunctions.find(p);
	if (fIt == _insn2asmFunctions.end())
	{
		auto* fnc = llvm::Function::Create(
				type,
				llvm::GlobalValue::LinkageTypes::ExternalLinkage,
				n,
				_module);
		_insn2asmFunctions[p] = fnc;
		_asmFunctions.insert(fnc);
		return fnc;
	}
	else
	{
		return fIt->second;
	}
}

/**
 * The same as @c getPseudoAsmFunction(std::size_t,std::string&, llvm::FunctionType*),
 * but function type is created by this variant.
 */
template <typename CInsn, typename CInsnOp>
llvm::Function* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getPseudoAsmFunction(
		cs_insn* insn,
		llvm::Type* retType,
		llvm::ArrayRef<llvm::Type*> params,
		const std::string& name)
{
	return getPseudoAsmFunction(
			insn,
			llvm::FunctionType::get(retType, params, false),
			name);
}

template <typename CInsn, typename CInsnOp>
llvm::Value* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::generateTypeConversion(
		llvm::IRBuilder<>& irb,
		llvm::Value* from,
		llvm::Type* to,
		eOpConv ct)
{
	if (to == nullptr || from->getType() == to)
	{
		return from;
	}

	llvm::Value* ret = nullptr;

	switch (ct)
	{
		case eOpConv::SEXT_TRUNC_OR_BITCAST:
		{
			if (!to->isIntegerTy())
			{
				throw GenericError("Invalid combination of conversion method and destination type");
			}

			if (from->getType()->isIntegerTy())
			{
				ret = irb.CreateSExtOrTrunc(from, to);
			}
			else
			{
				auto size = _module->getDataLayout().getTypeStoreSizeInBits(from->getType());
				auto intTy = irb.getIntNTy(size);
				ret = irb.CreateBitCast(from, intTy);
				ret = irb.CreateZExtOrTrunc(ret, to);
			}
			break;
		}
		case eOpConv::ZEXT_TRUNC_OR_BITCAST:
		{
			if (!to->isIntegerTy())
			{
				throw GenericError("Invalid combination of conversion method and destination type");
			}

			if (from->getType()->isIntegerTy())
			{
				ret = irb.CreateZExtOrTrunc(from, to);
			}
			else
			{
				auto size = _module->getDataLayout().getTypeStoreSizeInBits(from->getType());
				auto intTy = irb.getIntNTy(size);
				ret = irb.CreateBitCast(from, intTy);
				ret = irb.CreateZExtOrTrunc(ret, to);
			}
			break;
		}
		case eOpConv::FPCAST_OR_BITCAST:
		{
			if (!to->isFloatingPointTy())
			{
				throw GenericError("Invalid combination of conversion method and destination type");
			}

			if (from->getType()->isFloatingPointTy())
			{
				ret = irb.CreateFPCast(from, to);
			}
			else
			{
				auto isize = _module->getDataLayout().getTypeStoreSizeInBits(from->getType());
				auto dsize = _module->getDataLayout().getTypeStoreSizeInBits(irb.getDoubleTy());
				auto fsize = _module->getDataLayout().getTypeStoreSizeInBits(irb.getFloatTy());
				auto lsize = _module->getDataLayout().getTypeStoreSizeInBits(llvm::Type::getFP128Ty(_module->getContext()));

				if (isize == fsize)
				{
					from = irb.CreateBitCast(from, irb.getFloatTy());
				}
				else if (isize == dsize)
				{
					from = irb.CreateBitCast(from, irb.getDoubleTy());
				}
				else if (isize == lsize)
				{
					from = irb.CreateBitCast(from, llvm::Type::getFP128Ty(_module->getContext()));
				}
				else
				{
					throw GenericError("Unable to create bitcast to floating point type.");
				}

				ret = irb.CreateFPCast(from, to);
			}
			break;
		}
		case eOpConv::SITOFP_OR_FPCAST:
		{
			if (!to->isFloatingPointTy())
			{
				throw GenericError("Invalid combination of conversion method and destination type");
			}
			if (from->getType()->isFloatingPointTy())
			{
				ret = irb.CreateFPCast(from, to);
			}
			else
			{
				ret = irb.CreateSIToFP(from, to);
			}
			break;
		}
		case eOpConv::UITOFP_OR_FPCAST:
		{
			if (!to->isFloatingPointTy())
			{
				throw GenericError("Invalid combination of conversion method and destination type");
			}
			if (from->getType()->isFloatingPointTy())
			{
				ret = irb.CreateFPCast(from, to);
			}
			else
			{
				ret = irb.CreateUIToFP(from, to);
			}
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
			throw GenericError("Unhandled eOpConv type.");
		}
	}

	return ret;
}

template <typename CInsn, typename CInsnOp>
llvm::Type* Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::_checkTypeConversion(
		llvm::IRBuilder<>& irb,
		llvm::Type* to,
		eOpConv ct)
{
	switch (ct)
	{
		case eOpConv::ZEXT_TRUNC_OR_BITCAST:
		case eOpConv::SEXT_TRUNC_OR_BITCAST:
		{
			if (!to->isIntegerTy())
			{
				auto size = _module->getDataLayout().getTypeStoreSizeInBits(to);
				return irb.getIntNTy(size);
			}
			break;
		}
		case eOpConv::FPCAST_OR_BITCAST:
		case eOpConv::SITOFP_OR_FPCAST:
		case eOpConv::UITOFP_OR_FPCAST:
		{
			if (!to->isFloatingPointTy())
			{
				auto flSize = _module->getDataLayout().getTypeStoreSizeInBits(
							irb.getFloatTy());
				auto size = _module->getDataLayout().getTypeStoreSizeInBits(to);
				if (size <= flSize)
				{
					return irb.getFloatTy();
				}

				return irb.getDoubleTy();
			}
			break;
		}
		default:
		{
			return to;
		}
	}

	return to;
}

/**
 * op0 = __asm_<mnem>()
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0Fnc(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ci, irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			getDefaultType(),
			llvm::ArrayRef<llvm::Type*>{});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{});

	storeOp(ci->operands[0], c, irb);
}

/**
 * __asm_<mnem>(op0)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmFncOp0(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			irb.getVoidTy(),
			llvm::ArrayRef<llvm::Type*>{op0->getType()});

	irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0});
}

/**
 * op0 = __asm_<mnem>(op0)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp0(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			op0->getType(),
			llvm::ArrayRef<llvm::Type*>{op0->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0});

	storeOp(ci->operands[0], c, irb);
}

/**
 * __asm_<mnem>(op0, op1)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmFncOp0Op1(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			irb.getVoidTy(),
			llvm::ArrayRef<llvm::Type*>{op0->getType(), op1->getType()});

	irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1});
}

/**
 * op0 = __asm_<mnem>(op1)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp1(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ci, irb);

	op1 = loadOp(ci->operands[1], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			op1->getType(),
			llvm::ArrayRef<llvm::Type*>{op1->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op1});

	storeOp(ci->operands[0], c, irb);
}

/**
 * op0 = __asm_<mnem>(op0, op1)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp0Op1(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			op0->getType(),
			llvm::ArrayRef<llvm::Type*>{op0->getType(), op1->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1});

	storeOp(ci->operands[0], c, irb);
}

/**
 * __asm_<mnem>(op0, op1, op2)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmFncOp0Op1Op2(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			irb.getVoidTy(),
			llvm::ArrayRef<llvm::Type*>{
					op0->getType(),
					op1->getType(),
					op2->getType()});

	irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1, op2});
}

/**
 * op0 = __asm_<mnem>(op1, op2)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp1Op2(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ci, irb);

	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			getDefaultType(),
			llvm::ArrayRef<llvm::Type*>{
					op1->getType(),
					op2->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op1, op2});

	storeOp(ci->operands[0], c, irb);
}

/**
 * op0 = __asm_<mnem>(op0, op1, op2)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp0Op1Op2(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			op0->getType(),
			llvm::ArrayRef<llvm::Type*>{
					op0->getType(),
					op1->getType(),
					op2->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1, op2});

	storeOp(ci->operands[0], c, irb);
}

/**
 * __asm_<mnem>(op0, op1, op2, op3)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmFncOp0Op1Op2Op3(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);
	op3 = loadOp(ci->operands[3], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			irb.getVoidTy(),
			llvm::ArrayRef<llvm::Type*>{
					op0->getType(),
					op1->getType(),
					op2->getType(),
					op3->getType()});

	irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1, op2, op3});
}

/**
 * op0 = __asm_<mnem>(op1, op2, op3)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp1Op2Op3(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ci, irb);

	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);
	op3 = loadOp(ci->operands[3], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			getDefaultType(),
			llvm::ArrayRef<llvm::Type*>{
					op1->getType(),
					op2->getType(),
					op3->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op1, op2, op3});

	storeOp(ci->operands[0], c, irb);
}

/**
 * op0 = __asm_<mnem>(op0, op1, op2, op3)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0FncOp0Op1Op2Op3(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);
	op3 = loadOp(ci->operands[3], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			op0->getType(),
			llvm::ArrayRef<llvm::Type*>{
					op0->getType(),
					op1->getType(),
					op2->getType(),
					op3->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1, op2, op3});

	storeOp(ci->operands[0], c, irb);
}

/**
 * op0, op1 = __asm_<mnem>(op0, op1, op2, op3)
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmOp0Op1FncOp0Op1Op2Op3(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ci, irb);

	op0 = loadOp(ci->operands[0], irb);
	op1 = loadOp(ci->operands[1], irb);
	op2 = loadOp(ci->operands[2], irb);
	op3 = loadOp(ci->operands[3], irb);

	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			llvm::StructType::create(llvm::ArrayRef<llvm::Type*>{
					op0->getType(),
					op1->getType()}),
			llvm::ArrayRef<llvm::Type*>{
					op0->getType(),
					op1->getType(),
					op2->getType(),
					op3->getType()});

	auto* c = irb.CreateCall(fnc, llvm::ArrayRef<llvm::Value*>{op0, op1, op2, op3});

	storeOp(ci->operands[0], irb.CreateExtractValue(c, {0}), irb);
	storeOp(ci->operands[1], irb.CreateExtractValue(c, {1}), irb);
}

/**
 * Some architectures do not have this info in operands.
 * Return default value: CS_AC_INVALID.
 */
template <typename CInsn, typename CInsnOp>
uint8_t Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::getOperandAccess(CInsnOp&)
{
	return CS_AC_INVALID;
}

/**
 * Generate pseudo asm call using information provided by Capstone.
 */
template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::translatePseudoAsmGeneric(
		cs_insn* i,
		CInsn* ci,
		llvm::IRBuilder<>& irb)
{
	std::vector<llvm::Value*> vals;
	std::vector<llvm::Type*> types;

	unsigned writeCnt = 0;
	llvm::Type* writeType = getDefaultType();
	bool writesOp = false;
	for (std::size_t j = 0; j < ci->op_count; ++j)
	{
		auto& op = ci->operands[j];
		auto access = getOperandAccess(op);
		if (access == CS_AC_INVALID || (access & CS_AC_READ))
		{
			auto* o = loadOp(op, irb);
			vals.push_back(o);
			types.push_back(o->getType());
		}

		if (access & CS_AC_WRITE)
		{
			writesOp = true;
			++writeCnt;

			if (isOperandRegister(op))
			{
				auto* t = getRegisterType(op.reg);
				if (writeCnt == 1 || writeType == t)
				{
					writeType = t;
				}
				else
				{
					writeType = getDefaultType();
				}
			}
			else
			{
				writeType = getDefaultType();
			}
		}
	}

	if (vals.empty())
	{
		// All registers must be ok, or don't use them at all.
		std::vector<uint32_t> readRegs;
		readRegs.reserve(i->detail->regs_read_count);
		for (std::size_t j = 0; j < i->detail->regs_read_count; ++j)
		{
			auto r = i->detail->regs_read[j];
			if (getRegister(r))
			{
				readRegs.push_back(r);
			}
			else
			{
				readRegs.clear();
				break;
			}
		}

		for (auto r : readRegs)
		{
			auto* op = loadRegister(r, irb);
			vals.push_back(op);
			types.push_back(op->getType());
		}
	}

	auto* retType = writesOp ? writeType : irb.getVoidTy();
	llvm::Function* fnc = getPseudoAsmFunction(
			i,
			retType,
			types);

	auto* c = irb.CreateCall(fnc, vals);

	std::set<uint32_t> writtenRegs;
	if (retType)
	{
		for (std::size_t j = 0; j < ci->op_count; ++j)
		{
			auto& op = ci->operands[j];
			if (getOperandAccess(op) & CS_AC_WRITE)
			{
				storeOp(op, c, irb);

				if (isOperandRegister(op))
				{
					writtenRegs.insert(op.reg);
				}
			}
		}
	}

	// All registers must be ok, or don't use them at all.
	std::vector<uint32_t> writeRegs;
	writeRegs.reserve(i->detail->regs_write_count);
	for (std::size_t j = 0; j < i->detail->regs_write_count; ++j)
	{
		auto r = i->detail->regs_write[j];
		if (writtenRegs.count(r))
		{
			// silently ignore
		}
		else if (getRegister(r))
		{
			writeRegs.push_back(r);
		}
		else
		{
			writeRegs.clear();
			break;
		}
	}

	for (auto r : writeRegs)
	{
		llvm::Value* val = retType->isVoidTy()
				? llvm::cast<llvm::Value>(
						llvm::UndefValue::get(getRegisterType(r)))
				: llvm::cast<llvm::Value>(c);
		storeRegister(r, val, irb);
	}
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::throwUnexpectedOperands(
		cs_insn* i,
		const std::string comment)
{
	if (!isIgnoreUnexpectedOperands())
	{
		throw UnexpectedOperandsError(i, comment);
	}
}

template <typename CInsn, typename CInsnOp>
void Capstone2LlvmIrTranslator_impl<CInsn, CInsnOp>::throwUnhandledInstructions(
		cs_insn* i,
		const std::string comment)
{
	if (!isIgnoreUnhandledInstructions())
	{
		throw UnhandledInstructionError(i, comment);
	}
}

template class Capstone2LlvmIrTranslator_impl<cs_arm, cs_arm_op>;
template class Capstone2LlvmIrTranslator_impl<cs_arm64, cs_arm64_op>;
template class Capstone2LlvmIrTranslator_impl<cs_mips, cs_mips_op>;
template class Capstone2LlvmIrTranslator_impl<cs_ppc, cs_ppc_op>;
template class Capstone2LlvmIrTranslator_impl<cs_x86, cs_x86_op>;

} // namespace capstone2llvmir
} // namespace retdec
