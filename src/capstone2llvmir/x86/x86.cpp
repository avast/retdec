/**
 * @file src/capstone2llvmir/x86/x86.cpp
 * @brief X86 implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "retdec/capstone2llvmir/x86/x86.h"

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorX86::Capstone2LlvmIrTranslatorX86(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator(CS_ARCH_X86, basic, extra, m),
		_origBasicMode(basic),
		_reg2parentMap(X86_REG_ENDING, X86_REG_INVALID)
{
	// This needs to be called from concrete's class ctor, not abstract's
	// class ctor, so that virtual table is properly initialized.
	initialize();
}

Capstone2LlvmIrTranslatorX86::~Capstone2LlvmIrTranslatorX86()
{
	// Nothing specific to x86.
}

/**
 * x86 is special. When this returns @c true, mode can be used to initialize
 * x86 translator, but it does not have to be possible to modify translator
 * with this mode later. See @c modifyBasicMode().
 */
bool Capstone2LlvmIrTranslatorX86::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_16 || m == CS_MODE_32 || m == CS_MODE_64;
}

bool Capstone2LlvmIrTranslatorX86::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN || m == CS_MODE_BIG_ENDIAN;
}

/**
 * x86 allows to change basic mode only to modes lower than the original
 * initialization mode an back to original mode (CS_MODE_16 < CS_MODE_32
 * < CS_MODE_64). This is because the original mode is used to initialize
 * module's environment with registers and other specific features. It is
 * possible to simulate lower modes in environments created for higher modes
 * (e.g. get ax register from eax), but not the other way around (e.g. get
 * rax from eax).
 */
void Capstone2LlvmIrTranslatorX86::modifyBasicMode(cs_mode m)
{
	if (!isAllowedBasicMode(m))
	{
		throw Capstone2LlvmIrModeError(
				_arch,
				m,
				Capstone2LlvmIrModeError::eType::BASIC_MODE);
	}

	if ((_origBasicMode == CS_MODE_16)
			|| (_origBasicMode == CS_MODE_32 && m == CS_MODE_64))
	{
		throw Capstone2LlvmIrModeError(
				_arch,
				m,
				Capstone2LlvmIrModeError::eType::BASIC_MODE_CHANGE);
	}

	if (cs_option(_handle, CS_OPT_MODE, m + _extraMode) != CS_ERR_OK)
	{
		throw CapstoneError(cs_errno(_handle));
	}

	_basicMode = m;
}

/**
 * It does not really make sense to change extra mode (little <-> big endian)
 * for x86 architecture, but it should not crash or anything, so whatever.
 */
void Capstone2LlvmIrTranslatorX86::modifyExtraMode(cs_mode m)
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

void Capstone2LlvmIrTranslatorX86::generateEnvironmentArchSpecific()
{
	generateX87RegLoadStoreFunctions();
}

void Capstone2LlvmIrTranslatorX86::generateDataLayout()
{
	switch (_origBasicMode)
	{
		case CS_MODE_16:
		{
			_module->setDataLayout("e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"); // clang -m16
			break;
		}
		case CS_MODE_32:
		{
			_module->setDataLayout("e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"); // clang -m32
			break;
		}
		case CS_MODE_64:
		{
			_module->setDataLayout("e-m:e-i64:64-f80:128-n8:16:32:64-S128"); // clang
			break;
		}
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in getStackPointerRegister().");
			break;
		}
	}
}

void Capstone2LlvmIrTranslatorX86::generateX87RegLoadStoreFunctions()
{
	std::vector<llvm::Type*> dsp = {
			llvm::Type::getIntNTy(_module->getContext(), 3),
			llvm::Type::getX86_FP80Ty(_module->getContext())};
	auto* dsft = llvm::FunctionType::get(
			llvm::Type::getVoidTy(_module->getContext()),
			dsp,
			false);
	_x87DataStoreFunction = llvm::Function::Create(
			dsft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);

	std::vector<llvm::Type*> tsp = {
			llvm::Type::getIntNTy(_module->getContext(), 3),
			llvm::Type::getIntNTy(_module->getContext(), 2)};
	auto* tsft = llvm::FunctionType::get(
			llvm::Type::getVoidTy(_module->getContext()),
			tsp,
			false);
	_x87TagStoreFunction = llvm::Function::Create(
			tsft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);

	auto* dlft = llvm::FunctionType::get(
			llvm::Type::getX86_FP80Ty(_module->getContext()),
			{llvm::Type::getIntNTy(_module->getContext(), 3)},
			false);
	_x87DataLoadFunction = llvm::Function::Create(
			dlft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);

	auto* tlft = llvm::FunctionType::get(
			llvm::Type::getIntNTy(_module->getContext(), 2),
			{llvm::Type::getIntNTy(_module->getContext(), 3)},
			false);
	_x87TagLoadFunction = llvm::Function::Create(
			tlft,
			llvm::GlobalValue::LinkageTypes::ExternalLinkage,
			"",
			_module);
}

llvm::Function* Capstone2LlvmIrTranslatorX86::getX87DataStoreFunction()
{
	return _x87DataStoreFunction;
}

llvm::Function* Capstone2LlvmIrTranslatorX86::getX87TagStoreFunction()
{
	return _x87TagStoreFunction;
}

llvm::Function* Capstone2LlvmIrTranslatorX86::getX87DataLoadFunction()
{
	return _x87DataLoadFunction;
}

llvm::Function* Capstone2LlvmIrTranslatorX86::getX87TagLoadFunction()
{
	return _x87TagLoadFunction;
}

/**
 * All registers from the original Capstone @c x86_reg should be
 * in @c _reg2parentMap. Our added registers are not there, but all of them
 * should map to themselves, i.e. if register not in map, we return its number.
 */
uint32_t Capstone2LlvmIrTranslatorX86::getParentRegister(uint32_t r)
{
	return r < _reg2parentMap.size() ? _reg2parentMap[r] : r;
}

uint32_t Capstone2LlvmIrTranslatorX86::getAccumulatorRegister(std::size_t size)
{
	switch (size)
	{
		case 1: return X86_REG_AL;
		case 2: return X86_REG_AX;
		case 4: return X86_REG_EAX;
		case 8: return X86_REG_RAX;
		default: throw Capstone2LlvmIrError("Unhandled accumulator register.");
	}
}

uint32_t Capstone2LlvmIrTranslatorX86::getStackPointerRegister()
{
	switch (_origBasicMode)
	{
		case CS_MODE_16: return X86_REG_SP;
		case CS_MODE_32: return X86_REG_ESP;
		case CS_MODE_64: return X86_REG_RSP;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in getStackPointerRegister().");
			break;
		}
	}
}

uint32_t Capstone2LlvmIrTranslatorX86::getBasePointerRegister()
{
	switch (_origBasicMode)
	{
		case CS_MODE_16: return X86_REG_BP;
		case CS_MODE_32: return X86_REG_EBP;
		case CS_MODE_64: return X86_REG_RBP;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in getBasePointerRegister().");
			break;
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorX86::getCurrentPc(cs_insn* i)
{
	return llvm::ConstantInt::get(
			getIntegerTypeFromByteSize(getArchByteSize()),
			i->address + i->size);
}

uint32_t Capstone2LlvmIrTranslatorX86::getArchByteSize()
{
	switch (_origBasicMode)
	{
		case CS_MODE_16: return 2;
		case CS_MODE_32: return 4;
		case CS_MODE_64: return 8;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in getArchByteSize().");
			break;
		}
	}
}

uint32_t Capstone2LlvmIrTranslatorX86::getArchBitSize()
{
	return getArchByteSize() * 8;
}

void Capstone2LlvmIrTranslatorX86::generateRegisters()
{
	generateRegistersCommon();

	switch (_origBasicMode)
	{
		case CS_MODE_16: generateRegisters16(); break;
		case CS_MODE_32: generateRegisters32(); break;
		case CS_MODE_64: generateRegisters64(); break;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in generateRegisters().");
			break;
		}
	}
}

void Capstone2LlvmIrTranslatorX86::generateRegistersCommon()
{
	// Flag registers (x86_reg_rflags).
	//
	createRegister(X86_REG_CF, _regLt);
	createRegister(X86_REG_PF, _regLt);
	createRegister(X86_REG_AF, _regLt);
	createRegister(X86_REG_ZF, _regLt);
	createRegister(X86_REG_SF, _regLt);
	createRegister(X86_REG_TF, _regLt);
	createRegister(X86_REG_IF, _regLt);
	createRegister(X86_REG_DF, _regLt);
	createRegister(X86_REG_OF, _regLt);
	createRegister(X86_REG_IOPL, _regLt);
	createRegister(X86_REG_NT, _regLt);
	createRegister(X86_REG_RF, _regLt);
	createRegister(X86_REG_VM, _regLt);
	createRegister(X86_REG_AC, _regLt);
	createRegister(X86_REG_VIF, _regLt);
	createRegister(X86_REG_VIP, _regLt);
	createRegister(X86_REG_ID, _regLt);

	// Segment registers.
	//
	createRegister(X86_REG_SS, _regLt);
	createRegister(X86_REG_CS, _regLt);
	createRegister(X86_REG_DS, _regLt);
	createRegister(X86_REG_ES, _regLt);
	createRegister(X86_REG_FS, _regLt);
	createRegister(X86_REG_GS, _regLt);

	// x87 FPU data registers.
	//
	createRegister(X86_REG_ST0, _regLt);
	createRegister(X86_REG_ST1, _regLt);
	createRegister(X86_REG_ST2, _regLt);
	createRegister(X86_REG_ST3, _regLt);
	createRegister(X86_REG_ST4, _regLt);
	createRegister(X86_REG_ST5, _regLt);
	createRegister(X86_REG_ST6, _regLt);
	createRegister(X86_REG_ST7, _regLt);

	// x87 FPU status registers (x87_reg_status).
	//
	createRegister(X87_REG_IE, _regLt);
	createRegister(X87_REG_DE, _regLt);
	createRegister(X87_REG_ZE, _regLt);
	createRegister(X87_REG_OE, _regLt);
	createRegister(X87_REG_UE, _regLt);
	createRegister(X87_REG_PE, _regLt);
	createRegister(X87_REG_SF, _regLt);
	createRegister(X87_REG_ES, _regLt);
	createRegister(X87_REG_C0, _regLt);
	createRegister(X87_REG_C1, _regLt);
	createRegister(X87_REG_C2, _regLt);
	createRegister(X87_REG_C3, _regLt);
	createRegister(X87_REG_TOP, _regLt);
	createRegister(X87_REG_B, _regLt);

	// x87 FPU control registers (x87_reg_control).
	//
	createRegister(X87_REG_IM, _regLt);
	createRegister(X87_REG_DM, _regLt);
	createRegister(X87_REG_ZM, _regLt);
	createRegister(X87_REG_OM, _regLt);
	createRegister(X87_REG_UM, _regLt);
	createRegister(X87_REG_PM, _regLt);
	createRegister(X87_REG_PC, _regLt);
	createRegister(X87_REG_RC, _regLt);
	createRegister(X87_REG_X, _regLt);

	// x87 FPU tag registers (x87_reg_tag).
	//
	createRegister(X87_REG_TAG0, _regLt);
	createRegister(X87_REG_TAG1, _regLt);
	createRegister(X87_REG_TAG2, _regLt);
	createRegister(X87_REG_TAG3, _regLt);
	createRegister(X87_REG_TAG4, _regLt);
	createRegister(X87_REG_TAG5, _regLt);
	createRegister(X87_REG_TAG6, _regLt);
	createRegister(X87_REG_TAG7, _regLt);

	// Debug registers.
	//
	createRegister(X86_REG_DR0, _regLt);
	createRegister(X86_REG_DR1, _regLt);
	createRegister(X86_REG_DR2, _regLt);
	createRegister(X86_REG_DR3, _regLt);
	createRegister(X86_REG_DR4, _regLt);
	createRegister(X86_REG_DR5, _regLt);
	createRegister(X86_REG_DR6, _regLt);
	createRegister(X86_REG_DR7, _regLt);

	// Control registers.
	//
	createRegister(X86_REG_CR0, _regLt);
	createRegister(X86_REG_CR1, _regLt);
	createRegister(X86_REG_CR2, _regLt);
	createRegister(X86_REG_CR3, _regLt);
	createRegister(X86_REG_CR4, _regLt);
	createRegister(X86_REG_CR5, _regLt);
	createRegister(X86_REG_CR6, _regLt);
	createRegister(X86_REG_CR7, _regLt);
	createRegister(X86_REG_CR8, _regLt);
	createRegister(X86_REG_CR9, _regLt);
	createRegister(X86_REG_CR10, _regLt);
	createRegister(X86_REG_CR11, _regLt);
	createRegister(X86_REG_CR12, _regLt);
	createRegister(X86_REG_CR13, _regLt);
	createRegister(X86_REG_CR14, _regLt);
	createRegister(X86_REG_CR15, _regLt);
}

void Capstone2LlvmIrTranslatorX86::generateRegisters16()
{
	// General-purpose registers.
	//
	createRegister(X86_REG_AX, _regLt);
	createRegister(X86_REG_CX, _regLt);
	createRegister(X86_REG_DX, _regLt);
	createRegister(X86_REG_BX, _regLt);
	createRegister(X86_REG_SP, _regLt);
	createRegister(X86_REG_BP, _regLt);
	createRegister(X86_REG_SI, _regLt);
	createRegister(X86_REG_DI, _regLt);

	// Instruction pointer register.
	//
	createRegister(X86_REG_IP, _regLt);
}

void Capstone2LlvmIrTranslatorX86::generateRegisters32()
{
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());
	auto* i32Zero = llvm::ConstantInt::get(i32, 0);

	// General-purpose registers.
	//
	createRegister(X86_REG_EAX, _regLt);
	createRegister(X86_REG_ECX, _regLt);
	createRegister(X86_REG_EDX, _regLt);
	createRegister(X86_REG_EBX, _regLt);
	createRegister(X86_REG_ESP, _regLt);
	createRegister(X86_REG_EBP, _regLt);
	createRegister(X86_REG_ESI, _regLt);
	createRegister(X86_REG_EDI, _regLt);

	// Instruction pointer register.
	//
	createRegister(X86_REG_EIP, _regLt);

	// Other.
	//
	// Pseudo register eval to 0.
	createRegister(X86_REG_EIZ, _regLt, i32Zero);
}

void Capstone2LlvmIrTranslatorX86::generateRegisters64()
{
	auto* i64 = llvm::IntegerType::getInt64Ty(_module->getContext());
	auto* i64Zero = llvm::ConstantInt::get(i64, 0);

	// General-purpose registers.
	//
	// bits               64                  8,    8,   16,   32
	createRegister(X86_REG_RAX, _regLt); //   ah,   al,   ax,  eax
	createRegister(X86_REG_RCX, _regLt); //   ch,   cl,   cx,  ecx
	createRegister(X86_REG_RDX, _regLt); //   dh,   dl,   dx,  edx
	createRegister(X86_REG_RBX, _regLt); //   bh,   bl,   bx,  ebx
	createRegister(X86_REG_RSP, _regLt); // ----,  spl,   sp,  esp
	createRegister(X86_REG_RBP, _regLt); // ----,  bpl,   bp,  ebp
	createRegister(X86_REG_RSI, _regLt); // ----,  sil,   si,  esi
	createRegister(X86_REG_RDI, _regLt); // ----,  dil,   di,  edi
	createRegister(X86_REG_R8, _regLt);  // ----,  r8b,  r8w,  r8d
	createRegister(X86_REG_R9, _regLt);  // ----,  r9b,  r9w,  r9d
	createRegister(X86_REG_R10, _regLt); // ----, r10b, r10w, r10d
	createRegister(X86_REG_R11, _regLt); // ----, r11b, r11w, r11d
	createRegister(X86_REG_R12, _regLt); // ----, r12b, r12w, r12d
	createRegister(X86_REG_R13, _regLt); // ----, r13b, r13w, r13d
	createRegister(X86_REG_R14, _regLt); // ----, r14b, r14w, r14d
	createRegister(X86_REG_R15, _regLt); // ----, r15b, r15w, r15d

	// Instruction pointer register.
	//
	createRegister(X86_REG_RIP, _regLt); // ----, ----,   ip,  eip

	// Other.
	//
	// Pseudo register eval to 0.
	createRegister(X86_REG_RIZ, _regLt, i64Zero); // ----, ----, ----,  eiz
}

void Capstone2LlvmIrTranslatorX86::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	_insn = i;

	cs_detail* d = i->detail;
	cs_x86* xi = &d->x86;

	// At the moment, we want to notice these instruction and check if we
	// can translate them without any special handling.
	// There are more internals in cs_x86 (e.g. sib, sicp), but Capstone
	// uses them to interpret instruction operands and we do not have to do
	// it ourselves.
	// It is likely that the situation will be the same for these, but we
	// still want to manually check.
	//

	// REP @ INS, OUTS, MOVS, LODS, STOS
	// REPE/REPZ @ CMPS, SCAS
	// REPNE/REPNZ @ CMPS, SCAS
	//
	// X86_PREFIX_REP == X86_PREFIX_REPE
	//
	static std::set<unsigned> handledReps =
	{
		// X86_PREFIX_REP
		X86_INS_OUTSB, X86_INS_OUTSD, X86_INS_OUTSW,
		X86_INS_INSB, X86_INS_INSD, X86_INS_INSW,
		X86_INS_STOSB, X86_INS_STOSD, X86_INS_STOSQ, X86_INS_STOSW,
		X86_INS_MOVSB, X86_INS_MOVSW, X86_INS_MOVSD, X86_INS_MOVSQ,
		X86_INS_LODSB, X86_INS_LODSW, X86_INS_LODSD, X86_INS_LODSQ,
		// X86_PREFIX_REPE
		X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ,
		X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ
	};
	static std::set<unsigned> handledRepnes =
	{
		// X86_PREFIX_REPNE
		X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ,
		X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ,
		// BND prefix == X86_PREFIX_REPNE
		// Some total bullshit, ignore it for all of these instructions:
		X86_INS_CALL, X86_INS_LCALL, X86_INS_RET, X86_INS_JMP,
		X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JE, X86_INS_JGE,
		X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JNE, X86_INS_JNO,
		X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JS
	};
	if (xi->prefix[0])
	{
		if (xi->prefix[0] == X86_PREFIX_REP
				&& handledReps.find(i->id) == handledReps.end())
		{
//std::cout << "prefix[0] == X86_PREFIX_REP @ " << std::hex << i->address << std::endl;
//exit(1);
//			assert(false && "rep prefix not handled");
			return;
		}
		else if (xi->prefix[0] == X86_PREFIX_REP)
		{
			// Nothing, REP should be handled.
		}
		else if (xi->prefix[0] == X86_PREFIX_REPNE
				&& handledRepnes.find(i->id) == handledRepnes.end())
		{
//std::cout << "prefix[0] == X86_PREFIX_REPNE @ " << std::hex << i->address << std::endl;
//std::cout << i->mnemonic << " " << i->op_str << std::endl;
//exit(1);
//			assert(false && "repne prefix not handled");
			return;
		}
		else if (xi->prefix[0] == X86_PREFIX_REPNE)
		{
			// Nothing, REPNE should be handled.
		}
		else if (xi->prefix[0] == X86_PREFIX_LOCK)
		{
			// Nothing, LOCK does not matter for decompilation.
		}
	}

//	assert(!xi->sse_cc);
//	assert(!xi->avx_cc);
//	assert(!xi->avx_sae);
//	assert(!xi->avx_rm);

	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;
//std::cout << std::hex << i->address << " @ " << i->mnemonic << " " << i->op_str << std::endl;
		(this->*f)(i, xi, irb);
	}
	else
	{
		bool silentSkip = true;
		for (unsigned j = 0; j < d->groups_count; ++j)
		{
			static std::set<uint8_t> ignoredGroups =
			{
					X86_GRP_3DNOW,
					X86_GRP_AES,
					X86_GRP_ADX,
					X86_GRP_AVX,
					X86_GRP_AVX2,
					X86_GRP_AVX512,
					X86_GRP_MMX,
					X86_GRP_SHA,
					X86_GRP_SSE1,
					X86_GRP_SSE2,
					X86_GRP_SSE3,
					X86_GRP_SSE41,
					X86_GRP_SSE42,
					X86_GRP_SSE4A,
					X86_GRP_SSSE3,
			};
			uint32_t g = d->groups[j];
			if (ignoredGroups.count(g))
			{
				silentSkip = true;
				break;
			}
		}

		if (!silentSkip)
		{
			std::stringstream msg;
			msg << "Translation of unhandled instruction: " << i->id << " ("
					<< i->mnemonic << " " << i->op_str << ") @ " << std::hex
					<< i->address << "\n";
//std::cout << msg.str() << std::endl;
//exit(1);
			throw Capstone2LlvmIrError(msg.str());
		}
	}
}

//
//==============================================================================
// Translation helper methods.
//==============================================================================
//

llvm::Type* Capstone2LlvmIrTranslatorX86::getDefaultType()
{
	auto& ctx = _module->getContext();
	switch (_origBasicMode)
	{
		case CS_MODE_16: return llvm::Type::getInt16Ty(ctx);
		case CS_MODE_32: return llvm::Type::getInt32Ty(ctx);
		case CS_MODE_64: return llvm::Type::getInt64Ty(ctx);
		default: throw Capstone2LlvmIrError("Unhandled original mode.");
	}
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadRegister(
		uint32_t r,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct)
{
	if (r == X86_REG_INVALID)
	{
		return nullptr;
	}

	auto* rt = getRegisterType(r);
	auto pr = getParentRegister(r);
	auto* reg = getRegister(pr);
	if (reg == nullptr)
	{
		throw Capstone2LlvmIrError("Capstone2LlvmIrTranslatorX86() unhandled reg.");
	}


	llvm::Value* ret = nullptr;
	if (pr == X86_REG_RIP
			|| pr == X86_REG_EIP
			|| pr == X86_REG_IP)
	{
		ret = getCurrentPc(_insn);
	}
	else
	{
		ret = irb.CreateLoad(reg);

		if (r != pr)
// TODO: We want to do this for register storing, but probably not here?
//				&& getRegisterBitSize(pr) != 64) // Do not trunc for 64-bit target regs.
		{
			// Special handling - we need a right shift to get bits 8..15 to 0..7.
			//
			if (r == X86_REG_AH
					|| r == X86_REG_CH
					|| r == X86_REG_DH
					|| r == X86_REG_BH)
			{
				ret = irb.CreateLShr(ret, 8);
			}

			ret = irb.CreateTrunc(ret, rt);
		}
	}

	if (dstType == nullptr || dstType == ret->getType())
	{
		return ret;
	}

	switch (ct)
	{
		case eOpConv::ZEXT_TRUNC:
		{
			ret = irb.CreateZExtOrTrunc(ret, dstType);
			break;
		}
		case eOpConv::NOTHING:
		{
			break;
		}
		case eOpConv::THROW:
		default:
		{
			throw Capstone2LlvmIrError("Type of reg load not equal dst type.");
		}
	}

	return ret;
}

llvm::StoreInst* Capstone2LlvmIrTranslatorX86::storeRegister(
		uint32_t r,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	auto* rt = getRegisterType(r);
	auto pr = getParentRegister(r);
	auto* reg = getRegister(pr);
	if (reg == nullptr)
	{
		throw Capstone2LlvmIrError("Capstone2LlvmIrTranslatorX86() unhandled reg.");
	}

	llvm::StoreInst* ret = nullptr;

	// We probably want to do this for all conversion variants.
	//
	if (rt->isIntegerTy())
	{
		assert(val->getType()->isIntegerTy());

		auto* valT = llvm::cast<llvm::IntegerType>(val->getType());
		if (valT->getBitWidth() > getRegisterBitSize(r))
		{
			val = irb.CreateTrunc(val, rt);
		}
	}
	else if (rt->isFloatingPointTy())
	{
		// nothing?
	}
	else
	{
		throw Capstone2LlvmIrError("Unhandled register type.");
	}

	if (val->getType() != reg->getValueType())
	{
		switch (ct)
		{
			case eOpConv::SEXT_TRUNC:
				val = irb.CreateSExtOrTrunc(val, reg->getValueType());
				break;
			case eOpConv::FP_CAST:
				val = irb.CreateFPCast(val, reg->getValueType());
				break;
			case eOpConv::ZEXT_TRUNC:
			// We do the zero extend as default (even for THROW).
			// Problem: e.g. 64-bit mov instruction - operands should be the
			// same size, and they are in Capstone (eax, mem, size 4).
			// But we can not store to 4 byte eax, we need to store to 8 byte
			// rax, so we need to extend.
			default:
				val = irb.CreateZExt(val, reg->getValueType());
				break;
		}
	}
	assert(val->getType() == reg->getValueType());

	if (r == pr
			// Zext for 64-bit target regs & 32-bit source regs.
			|| (getRegisterBitSize(pr) == 64 && getRegisterBitSize(r) == 32))
	{
		ret = irb.CreateStore(val, reg);
	}
	else
	{
		llvm::Value* l = irb.CreateLoad(reg);
		if (!(l->getType()->isIntegerTy(16)
				|| l->getType()->isIntegerTy(32)
				|| l->getType()->isIntegerTy(64)))
		{
			throw Capstone2LlvmIrError("Unexpected parent type.");
		}

		llvm::Value* andC = nullptr;
		if (r == X86_REG_AH
				|| r == X86_REG_CH
				|| r == X86_REG_DH
				|| r == X86_REG_BH)
		{
			if (l->getType()->isIntegerTy(16))
			{
				andC = irb.getInt16(0x00ff);
			}
			else if (l->getType()->isIntegerTy(32))
			{
				andC = irb.getInt32(0xffff00ff);
			}
			else if (l->getType()->isIntegerTy(64))
			{
				andC = irb.getInt64(0xffffffffffff00ff);
			}

			val = irb.CreateShl(val, 8);
		}
		else if (rt->isIntegerTy(8))
		{
			if (l->getType()->isIntegerTy(16))
			{
				andC = irb.getInt16(0xff00);
			}
			else if (l->getType()->isIntegerTy(32))
			{
				andC = irb.getInt32(0xffffff00);
			}
			else if (l->getType()->isIntegerTy(64))
			{
				andC = irb.getInt64(0xffffffffffffff00);
			}
		}
		else if (rt->isIntegerTy(16))
		{
			if (l->getType()->isIntegerTy(32))
			{
				andC = irb.getInt32(0xffff0000);
			}
			else if (l->getType()->isIntegerTy(64))
			{
				andC = irb.getInt64(0xffffffffffff0000);
			}
		}
		else if (rt->isIntegerTy(32))
		{
			if (l->getType()->isIntegerTy(64))
			{
				andC = irb.getInt64(0xffffffff00000000);
			}
		}
		assert(andC);
		l = irb.CreateAnd(l, andC);

		auto* o = irb.CreateOr(l, val);
		ret = irb.CreateStore(o, reg);
	}

	return ret;
}

void Capstone2LlvmIrTranslatorX86::storeRegisters(
		llvm::IRBuilder<>& irb,
		const std::vector<std::pair<uint32_t, llvm::Value*>>& regs)
{
	for (auto& p : regs)
	{
		storeRegister(p.first, p.second, irb);
	}
}

void Capstone2LlvmIrTranslatorX86::storeRegistersPlusSflags(
		llvm::IRBuilder<>& irb,
		llvm::Value* sflagsVal,
		const std::vector<std::pair<uint32_t, llvm::Value*>>& regs)
{
	storeRegisters(irb, regs);
	storeRegister(X86_REG_ZF, genZeroFlag(sflagsVal, irb), irb);
	storeRegister(X86_REG_SF, genSignFlag(sflagsVal, irb), irb);
	storeRegister(X86_REG_PF, genParityFlag(sflagsVal, irb), irb);
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadX87Top(llvm::IRBuilder<>& irb)
{
	return loadRegister(X87_REG_TOP, irb);
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadX87TopDec(llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	return irb.CreateSub(top, llvm::ConstantInt::get(top->getType(), 1));
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadX87TopInc(llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	return irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), 1));
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadX87TopDecStore(
		llvm::IRBuilder<>& irb)
{
	auto* top = loadX87TopDec(irb);
	storeRegister(X87_REG_TOP, top, irb);
	return top;
}

/**
 * This returns TOP value before the incrementation.
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::loadX87TopIncStore(
		llvm::IRBuilder<>& irb)
{
//	auto* top = loadX87TopInc(irb);
	auto* top = loadX87Top(irb);
	auto* inc = irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), 1));
	storeRegister(X87_REG_TOP, inc, irb);
	return top;
}

llvm::Value* Capstone2LlvmIrTranslatorX86::x87IncTop(
		llvm::IRBuilder<>& irb,
		llvm::Value* top)
{
	top = top == nullptr ? loadX87Top(irb) : top;
	auto* inc = irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), 1));
	storeRegister(X87_REG_TOP, inc, irb);
	return inc;
}

llvm::Value* Capstone2LlvmIrTranslatorX86::x87DecTop(
		llvm::IRBuilder<>& irb,
		llvm::Value* top)
{
	top = top == nullptr ? loadX87Top(irb) : top;
	auto* dec = irb.CreateSub(top, llvm::ConstantInt::get(top->getType(), 1));
	storeRegister(X87_REG_TOP, dec, irb);
	return dec;
}

llvm::CallInst* Capstone2LlvmIrTranslatorX86::storeX87DataReg(
		llvm::IRBuilder<>& irb,
		llvm::Value* rNum,
		llvm::Value* val)
{
	assert(rNum->getType()->isIntegerTy(3));
	assert(val->getType()->isX86_FP80Ty());

	auto* i2 = irb.getIntNTy(2);
	auto* isZero = irb.CreateFCmpOEQ(val, llvm::ConstantFP::get(val->getType(), 0));
	auto* tmp = llvm::ConstantInt::get(i2, 0); // TODO: this is not complete
	auto* tagVal = irb.CreateSelect(
			isZero,
			llvm::ConstantInt::get(i2, 1), // 01 - zero
			tmp);                          // 00 - valid
	storeX87TagReg(irb, rNum, tagVal);

	std::vector<llvm::Value*> ps = {rNum, val};
	return irb.CreateCall(getX87DataStoreFunction(), ps);
}

/**
 * 00 - valid
 * 01 - zero
 * 10 - special, invalid (Nan, unsupported), infinity, denormal
 * 11 - empty
 */
llvm::CallInst* Capstone2LlvmIrTranslatorX86::storeX87TagReg(
		llvm::IRBuilder<>& irb,
		llvm::Value* rNum,
		llvm::Value* val)
{
	assert(rNum->getType()->isIntegerTy(3));
	assert(val->getType()->isIntegerTy(2));

	std::vector<llvm::Value*> ps = {rNum, val};
	return irb.CreateCall(getX87TagStoreFunction(), ps);
}

llvm::CallInst* Capstone2LlvmIrTranslatorX86::clearX87TagReg(
		llvm::IRBuilder<>& irb,
		llvm::Value* rNum)
{
	return storeX87TagReg(
			irb,
			rNum,
			llvm::ConstantInt::get(irb.getIntNTy(2), -1, true)); // 11 - empty
}

llvm::CallInst* Capstone2LlvmIrTranslatorX86::loadX87DataReg(
		llvm::IRBuilder<>& irb,
		llvm::Value* rNum)
{
	assert(rNum->getType()->isIntegerTy(3));

	std::vector<llvm::Value*> ps = {rNum};
	return irb.CreateCall(getX87DataLoadFunction(), ps);
}

llvm::CallInst* Capstone2LlvmIrTranslatorX86::loadX87TagReg(
		llvm::IRBuilder<>& irb,
		llvm::Value* rNum)
{
	assert(rNum->getType()->isIntegerTy(3));

	std::vector<llvm::Value*> ps = {rNum};
	return irb.CreateCall(getX87TagLoadFunction(), ps);
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadOp(
		cs_x86_op& op,
		llvm::IRBuilder<>& irb,
		bool lea,
		bool fp)
{
	switch (op.type)
	{
		case X86_OP_REG:
		{
			return loadRegister(op.reg, irb);
		}
		case X86_OP_IMM:
		{
			auto* t = getIntegerTypeFromByteSize(op.size);
			return llvm::ConstantInt::get(t, op.imm, false);
		}
		case X86_OP_MEM:
		{
// TODO: what to do with this?
//			auto* segR = loadRegister(op.mem.segment, irb);
//			assert(segR == nullptr);

			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = baseR ? baseR->getType() : getDefaultType();
			llvm::Value* disp = op.mem.disp
					? llvm::ConstantInt::get(t, op.mem.disp)
					: nullptr;

			auto* idxR = loadRegister(op.mem.index, irb);
			if (idxR)
			{
				auto* scale = llvm::ConstantInt::get(
						idxR->getType(),
						op.mem.scale);
				idxR = irb.CreateMul(idxR, scale);
			}

			llvm::Value* addr = nullptr;
			if (baseR && disp == nullptr)
			{
				addr = baseR;
			}
			else if (disp && baseR == nullptr)
			{
				addr = disp;
			}
			else if (baseR && disp)
			{
				disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
				addr = irb.CreateAdd(baseR, disp);
			}
			else if (idxR)
			{
				addr = idxR;
			}
			// Possible, e.g. lea edi, dword ptr [ecx*4] (8d 3c 8d 00 00 00 00).
			//
			else
			{
				addr = llvm::ConstantInt::get(getDefaultType(), 0);
			}

			if (idxR && addr != idxR)
			{
				idxR = irb.CreateZExtOrTrunc(idxR, addr->getType());
				addr = irb.CreateAdd(addr, idxR);
			}

			if (lea)
			{
				return addr;
			}
			else
			{
				llvm::Type* t = fp
						? getFloatTypeFromByteSize(op.size)
						: getIntegerTypeFromByteSize(op.size);
				auto* pt = llvm::PointerType::get(t, 0);
				addr = irb.CreateIntToPtr(addr, pt);
				return irb.CreateLoad(addr);
			}
		}
		case X86_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadOpUnary(
		cs_x86* xi,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct,
		bool fp)
{
	if (xi->op_count != 1)
	{
		throw Capstone2LlvmIrError("This is not an unary instruction.");
	}

	auto* op = loadOp(xi->operands[0], irb, false, fp);
	if (dstType == nullptr || op->getType() == dstType)
	{
		return op;
	}

	switch (ct)
	{
		case eOpConv::ZEXT_TRUNC:
		{
			op = irb.CreateZExtOrTrunc(op, dstType);
			break;
		}
		case eOpConv::FP_CAST:
		{
			op = irb.CreateFPCast(op, dstType);
			break;
		}
		case eOpConv::SITOFP:
		{
			op = irb.CreateSIToFP(op, dstType);
			break;
		}
		case eOpConv::UITOFP:
		{
			op = irb.CreateUIToFP(op, dstType);
			break;
		}
		case eOpConv::NOTHING:
		{
			break;
		}
		case eOpConv::THROW:
		default:
		{
			throw Capstone2LlvmIrError("Type of reg load not equal dst type.");
		}
	}

	return op;
}

llvm::Value* Capstone2LlvmIrTranslatorX86::loadOpUnaryFloat(
		cs_x86* xi,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct)
{
	return loadOpUnary(xi, irb, dstType, ct, true);
}

std::pair<llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorX86::loadOpBinary(
		cs_x86* xi,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (xi->op_count != 2)
	{
		throw Capstone2LlvmIrError("This is not a binary instruction.");
	}

	auto* op0 = loadOp(xi->operands[0], irb);
	auto* op1 = loadOp(xi->operands[1], irb);
	if (op0 == nullptr || op1 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}

	if (op0->getType() == op1->getType())
	{
		return {op0, op1};
	}

	switch (ct)
	{
		case eOpConv::SECOND_SEXT:
		{
			op1 = irb.CreateSExtOrTrunc(op1, op0->getType());
			break;
		}
		case eOpConv::SECOND_ZEXT:
		{
			op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
			break;
		}
		case eOpConv::NOTHING:
		{
			break;
		}
		default:
		case eOpConv::THROW:
		{
			throw Capstone2LlvmIrError("Binary operands' types not equal.");
		}
	}

	return {op0, op1};
}

std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorX86::loadOpTernary(
		cs_x86* xi,
		llvm::IRBuilder<>& irb)
{
	if (xi->op_count != 3)
	{
		throw Capstone2LlvmIrError("This is not a binary instruction.");
	}

	auto* op0 = loadOp(xi->operands[0], irb);
	auto* op1 = loadOp(xi->operands[1], irb);
	auto* op2 = loadOp(xi->operands[2], irb);
	if (op0 == nullptr || op1 == nullptr || op2 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}

	return std::make_tuple(op0, op1, op2);
}

llvm::Instruction* Capstone2LlvmIrTranslatorX86::setOp(
		cs_x86_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct,
		bool fp)
{
	switch (op.type)
	{
		case X86_OP_REG:
		{
			return storeRegister(op.reg, val, irb, ct);
		}
		case X86_OP_MEM:
		{
// TODO: what to do with this?
//			auto* segR = loadRegister(op.mem.segment, irb);
//			assert(segR == nullptr);

			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = baseR ? baseR->getType() : getDefaultType();
			llvm::Value* disp = op.mem.disp
					? llvm::ConstantInt::get(t, op.mem.disp)
					: nullptr;

			auto* idxR = loadRegister(op.mem.index, irb);
			if (idxR)
			{
				auto* scale = llvm::ConstantInt::get(idxR->getType(), op.mem.scale);
				idxR = irb.CreateMul(idxR, scale);
			}

			llvm::Value* addr = nullptr;
			if (baseR && disp == nullptr)
			{
				addr = baseR;
			}
			else if (disp && baseR == nullptr)
			{
				addr = disp;
			}
			else if (baseR && disp)
			{
				disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
				addr = irb.CreateAdd(baseR, disp);
			}
			else if (idxR)
			{
				addr = idxR;
			}
			// Possible, e.g. lea edi, dword ptr [ecx*4] (8d 3c 8d 00 00 00 00).
			//
			else
			{
				addr = llvm::ConstantInt::get(getDefaultType(), 0);
			}

			if (idxR && addr != idxR)
			{
				idxR = irb.CreateZExtOrTrunc(idxR, addr->getType());
				addr = irb.CreateAdd(addr, idxR);
			}

			auto* tt = fp
					? getFloatTypeFromByteSize(op.size)
					: getIntegerTypeFromByteSize(op.size);

			if (val->getType() != tt)
			{
				switch (ct)
				{
					case eOpConv::ZEXT_TRUNC:
						val = irb.CreateZExtOrTrunc(val, tt);
						break;
					case eOpConv::SEXT_TRUNC:
						val = irb.CreateSExtOrTrunc(val, tt);
						break;
					case eOpConv::FP_CAST:
						val = irb.CreateFPCast(val, tt);
						break;
					default:
						throw Capstone2LlvmIrError("Conversion unsupported by setOp()");

				}
			}

			auto* pt = llvm::PointerType::get(tt, 0);
			addr = irb.CreateIntToPtr(addr, pt);
			return irb.CreateStore(val, addr);
		}
		case X86_OP_IMM:
		case X86_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

llvm::Instruction* Capstone2LlvmIrTranslatorX86::setOpFloat(
		cs_x86_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	return setOp(op, val, irb, ct, true);
}

/**
 * carry_add_int4()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCarryAddInt4(
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
llvm::Value* Capstone2LlvmIrTranslatorX86::genCarryAddCInt4(
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
		cf = loadRegister(X86_REG_CF, irb, a->getType(), eOpConv::ZEXT_TRUNC);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, a->getType());
	auto* add = irb.CreateAdd(a, cfc);
	return irb.CreateICmpUGT(add, ci15);
}

/**
 * carry_add()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCarryAdd(
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
 * - Use a different value as cf - see adcx/adox.
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCarryAddC(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	auto* add1 = irb.CreateAdd(op0, op1);
	if (cf == nullptr)
	{
		cf = loadRegister(X86_REG_CF, irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, add1->getType());
	auto* add2 = irb.CreateAdd(add1, cfc);
	auto* icmp1 = irb.CreateICmpULE(add2, op0);
	auto* icmp2 = irb.CreateICmpULT(add1, op0);
	auto* cff = irb.CreateZExtOrTrunc(cf, irb.getInt1Ty());
	return irb.CreateSelect(cff, icmp1, icmp2);
}

/**
 * overflow_add()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genOverflowAdd(
		llvm::Value* add,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	auto* xor0 = irb.CreateXor(op0, add);
	auto* xor1 = irb.CreateXor(op1, add);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(ofAnd, llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * overflow_add_c()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genOverflowAddC(
		llvm::Value* add,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	if (cf == nullptr)
	{
		cf = loadRegister(X86_REG_CF, irb, add->getType(), eOpConv::ZEXT_TRUNC);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, add->getType());
	auto* ofAdd = irb.CreateAdd(add, cfc);
	auto* xor0 = irb.CreateXor(op0, ofAdd);
	auto* xor1 = irb.CreateXor(op1, ofAdd);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(ofAnd, llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * borrow_sub_int4()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genBorrowSubInt4(
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
llvm::Value* Capstone2LlvmIrTranslatorX86::genBorrowSubCInt4(
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
		cf = loadRegister(X86_REG_CF, irb, sub->getType(), eOpConv::ZEXT_TRUNC);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, sub->getType());
	auto* add = irb.CreateAdd(sub, cfc);
	return irb.CreateICmpUGT(add, ci15);
}

/**
 * borrow_sub()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genBorrowSub(
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	return irb.CreateICmpULT(op0, op1);
}

/**
 * borrow_sub_c()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genBorrowSubC(
		llvm::Value* sub,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	if (cf == nullptr)
	{
		cf = loadRegister(X86_REG_CF, irb);
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
 * overflow_sub()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genOverflowSub(
		llvm::Value* sub,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb)
{
	auto* xor0 = irb.CreateXor(op0, op1);
	auto* xor1 = irb.CreateXor(op0, sub);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(ofAnd, llvm::ConstantInt::get(ofAnd->getType(), 0));
}

/**
 * overflow_sub_c()
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genOverflowSubC(
		llvm::Value* sub,
		llvm::Value* op0,
		llvm::Value* op1,
		llvm::IRBuilder<>& irb,
		llvm::Value* cf)
{
	if (cf == nullptr)
	{
		cf = loadRegister(X86_REG_CF, irb);
	}
	auto* cfc = irb.CreateZExtOrTrunc(cf, sub->getType());
	auto* ofSub = irb.CreateSub(sub, cfc);
	auto* xor0 = irb.CreateXor(op0, op1);
	auto* xor1 = irb.CreateXor(op0, ofSub);
	auto* ofAnd = irb.CreateAnd(xor0, xor1);
	return irb.CreateICmpSLT(ofAnd, llvm::ConstantInt::get(ofAnd->getType(), 0));
}

llvm::Value* Capstone2LlvmIrTranslatorX86::genZeroFlag(
		llvm::Value* val,
		llvm::IRBuilder<>& irb)
{
	auto* zero = llvm::ConstantInt::get(val->getType(), 0);
	return irb.CreateICmpEQ(val, zero);
}

llvm::Value* Capstone2LlvmIrTranslatorX86::genSignFlag(
		llvm::Value* val,
		llvm::IRBuilder<>& irb)
{
	auto* zero = llvm::ConstantInt::get(val->getType(), 0);
	return irb.CreateICmpSLT(val, zero);
}

/**
 * The parity flag reflects the parity only of the least significant byte of
 * the result, and is set if the number of set bits of ones is even.
 *
 * (val & 1) (== 1) -> odd
 * (val & 1) == 0   -> even
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genParityFlag(
		llvm::Value* val,
		llvm::IRBuilder<>& irb)
{
	auto* i8t = irb.getInt8Ty();
	auto* trunc = irb.CreateTrunc(val, i8t);
	auto* f = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::ctpop, i8t);
	auto* c = irb.CreateCall(f, {trunc});
	auto* a = irb.CreateAnd(c, llvm::ConstantInt::get(c->getType(), 1));
	return irb.CreateICmpEQ(a, llvm::ConstantInt::get(a->getType(), 0));
}

/**
 * SET_SFLAGS()
 */
void Capstone2LlvmIrTranslatorX86::genSetSflags(
		llvm::Value* val,
		llvm::IRBuilder<>& irb)
{
	storeRegister(X86_REG_ZF, genZeroFlag(val, irb), irb);
	storeRegister(X86_REG_SF, genSignFlag(val, irb), irb);
	storeRegister(X86_REG_PF, genParityFlag(val, irb), irb);
}

/**
 * CF == 0
 * AE - above or equal
 * NB - not below
 * NC - not carry
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcAE(llvm::IRBuilder<>& irb)
{
	auto* cf = loadRegister(X86_REG_CF, irb);
	return irb.CreateICmpEQ(cf, irb.getInt1(false));
}

/**
 * CF == 0 && ZF == 0
 * A - above
 * NBE - not below or equal
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcA(llvm::IRBuilder<>& irb)
{
	auto* cf = loadRegister(X86_REG_CF, irb);
	auto* zf = loadRegister(X86_REG_ZF, irb);
	auto* orr = irb.CreateOr(cf, zf);
	return irb.CreateXor(orr, irb.getInt1(true));
}

/**
 * CF == 1 or ZF == 1
 * BE - below or equal
 * NA - not above
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcBE(llvm::IRBuilder<>& irb)
{
	auto* cf = loadRegister(X86_REG_CF, irb);
	auto* zf = loadRegister(X86_REG_ZF, irb);
	return irb.CreateOr(cf, zf);
}

/**
 * CF == 1
 * B - below
 * C - carry
 * NAE - not above or equal
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcB(llvm::IRBuilder<>& irb)
{
	return loadRegister(X86_REG_CF, irb);
}

/**
 * ZF == 1
 * E - equal
 * Z - zero
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcE(llvm::IRBuilder<>& irb)
{
	return loadRegister(X86_REG_ZF, irb);
}

/**
 * SF == OF
 * GE - greater or equal
 * NL - not less
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcGE(llvm::IRBuilder<>& irb)
{
	auto* sf = loadRegister(X86_REG_SF, irb);
	auto* of = loadRegister(X86_REG_OF, irb);
	return irb.CreateICmpEQ(sf, of);
}

/**
 * ZF == 0 and SF == OF
 * G - greater
 * NLE - not less or equal
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcG(llvm::IRBuilder<>& irb)
{
	auto* zf = loadRegister(X86_REG_ZF, irb);
	auto* sf = loadRegister(X86_REG_SF, irb);
	auto* of = loadRegister(X86_REG_OF, irb);
	auto* sfOfEq = irb.CreateICmpEQ(sf, of);
	auto* zfZero = irb.CreateICmpEQ(zf, irb.getInt1(false));
	return irb.CreateAnd(sfOfEq, zfZero);
}

/**
 * ZF == 1 or SF != OF
 * LE - less or equal
 * NG - not greater
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcLE(llvm::IRBuilder<>& irb)
{
	auto* zf = loadRegister(X86_REG_ZF, irb);
	auto* sf = loadRegister(X86_REG_SF, irb);
	auto* of = loadRegister(X86_REG_OF, irb);
	auto* sfOfNe = irb.CreateICmpNE(sf, of);
	return irb.CreateOr(zf, sfOfNe);
}

/**
 * SF != OF
 * L - less
 * NGE - not greater or equal
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcL(llvm::IRBuilder<>& irb)
{
	auto* sf = loadRegister(X86_REG_SF, irb);
	auto* of = loadRegister(X86_REG_OF, irb);
	return irb.CreateICmpNE(sf, of);
}

/**
 * ZF == 0
 * NE - not equal
 * NZ - not zero
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcNE(llvm::IRBuilder<>& irb)
{
	auto* zf = loadRegister(X86_REG_ZF, irb);
	return irb.CreateICmpEQ(zf, irb.getInt1(false));
}

/**
 * OF == 0
 * NO - not overflow
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcNO(llvm::IRBuilder<>& irb)
{
	auto* of = loadRegister(X86_REG_OF, irb);
	return irb.CreateICmpEQ(of, irb.getInt1(false));
}

/**
 * PF == 0
 * NP - not parity
 * PO - parity odd
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcNP(llvm::IRBuilder<>& irb)
{
	auto* pf = loadRegister(X86_REG_PF, irb);
	return irb.CreateICmpEQ(pf, irb.getInt1(false));
}

/**
 * SF == 0
 * NS - not sign
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcNS(llvm::IRBuilder<>& irb)
{
	auto* sf = loadRegister(X86_REG_SF, irb);
	return irb.CreateICmpEQ(sf, irb.getInt1(false));
}

/**
 * OF == 1
 * O - overflow
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcO(llvm::IRBuilder<>& irb)
{
	return loadRegister(X86_REG_OF, irb);
}

/**
 * PF == 1
 * P - parity
 * PE - parity even
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcP(llvm::IRBuilder<>& irb)
{
	return loadRegister(X86_REG_PF, irb);
}

/**
 * SF == 1
 * S - sign
 */
llvm::Value* Capstone2LlvmIrTranslatorX86::genCcS(llvm::IRBuilder<>& irb)
{
	return loadRegister(X86_REG_SF, irb);
}

//
//==============================================================================
// Instruction translation methods.
//==============================================================================
//

/**
 * X86_INS_AAA, X86_INS_AAS
 */
void Capstone2LlvmIrTranslatorX86::translateAaa(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* al = loadRegister(X86_REG_AL, irb);
	auto* ah = loadRegister(X86_REG_AH, irb);
	auto* af = loadRegister(X86_REG_AF, irb);

	auto* ala = irb.CreateAnd(al, irb.getInt8(0xf));
	auto* alUgt = irb.CreateICmpUGT(ala, irb.getInt8(9));
	auto* cond = irb.CreateOr(alUgt, af);

	auto* aladd = i->id == X86_INS_AAA
			? irb.CreateAdd(al, irb.getInt8(6))  // X86_INS_AAA
			: irb.CreateSub(al, irb.getInt8(6)); // X86_INS_AAS
	auto* ahadd = i->id == X86_INS_AAA
			? irb.CreateAdd(ah, irb.getInt8(1))  // X86_INS_AAA
			: irb.CreateSub(ah, irb.getInt8(1)); // X86_INS_AAS

	auto* alv = irb.CreateSelect(cond, aladd, al);
	auto* ahv = irb.CreateSelect(cond, ahadd, ah);
	auto* afv = irb.CreateSelect(cond, irb.getInt1(true), irb.getInt1(false));
	auto* cfv = irb.CreateSelect(cond, irb.getInt1(true), irb.getInt1(false));

	alv = irb.CreateAnd(alv, irb.getInt8(0xf));

	storeRegisters(irb, {
			{X86_REG_AL, alv},
			{X86_REG_AH, ahv},
			{X86_REG_AF, afv},
			{X86_REG_CF, cfv}});
}

/**
 * X86_INS_DAA, X86_INS_DAS
 */
void Capstone2LlvmIrTranslatorX86::translateDaaDas(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* al = loadRegister(X86_REG_AL, irb);
	auto* af = loadRegister(X86_REG_AF, irb);
	auto* cf = loadRegister(X86_REG_CF, irb);

	auto* alAnd = irb.CreateAnd(al, llvm::ConstantInt::get(al->getType(), 0xf));
	auto* alIcmp = irb.CreateICmpUGT(alAnd, llvm::ConstantInt::get(alAnd->getType(), 9));
	auto* cnd = irb.CreateOr(alIcmp, af);

	auto irbP = generateIfThenElse(cnd, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	{
		auto* alAdd = i->id == X86_INS_DAA
				? bodyIf.CreateAdd(al, llvm::ConstantInt::get(al->getType(), 6))    // X86_INS_DAA
				: bodyIf.CreateAdd(al, llvm::ConstantInt::get(al->getType(), 250)); // X86_INS_DAS, => +250 == -6
		auto* alUgt = bodyIf.CreateICmpUGT(al, llvm::ConstantInt::get(al->getType(), 153));
		auto* cfOr = bodyIf.CreateOr(alUgt, cf);
		auto* alAdd96 = i->id == X86_INS_DAA
				? bodyIf.CreateAdd(alAdd, llvm::ConstantInt::get(al->getType(), 96))  // X86_INS_DAA
				: bodyIf.CreateSub(alAdd, llvm::ConstantInt::get(al->getType(), 96)); // X86_INS_DAS
		auto* alSel = bodyIf.CreateSelect(cfOr, alAdd96, alAdd);
		storeRegistersPlusSflags(bodyIf, alSel, {
				{X86_REG_CF, cfOr},
				{X86_REG_AF, bodyIf.getInt1(true)},
				{X86_REG_AL, alSel}});
	}

	{
		auto* alUgt = bodyElse.CreateICmpUGT(al, llvm::ConstantInt::get(al->getType(), 153));
		auto* cfOr = bodyElse.CreateOr(alUgt, cf);
		auto* alAdd96 = i->id == X86_INS_DAA
				? bodyElse.CreateAdd(al, llvm::ConstantInt::get(al->getType(), 96))  // X86_INS_DAA
				: bodyElse.CreateSub(al, llvm::ConstantInt::get(al->getType(), 96)); // X86_INS_DAS
		auto* alSel = bodyElse.CreateSelect(cfOr, alAdd96, al);

		storeRegistersPlusSflags(bodyElse, alSel, {
				{X86_REG_CF, cfOr},
				{X86_REG_AF, bodyElse.getInt1(false)},
				{X86_REG_AL, alSel}});
	}
}

/**
 * X86_INS_AAD
 * According to Ollydbg, CF, OF, and possibly AF are also set (undef in specs).
 */
void Capstone2LlvmIrTranslatorX86::translateAad(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* al = loadRegister(X86_REG_AL, irb);
	auto* ah = loadRegister(X86_REG_AH, irb);
	if (xi->op_count == 0)
	{
		op0 = llvm::ConstantInt::get(ah->getType(), 10);
	}
	else
	{
		op0 = loadOpUnary(xi, irb, ah->getType(), eOpConv::ZEXT_TRUNC);
	}

	auto* mul = irb.CreateMul(ah, op0);
	auto* add = irb.CreateAdd(al, mul);
	// There is & 0xFF in specification, but I think LLVM's arithmetic on i8
	// will take care of this.

	storeRegistersPlusSflags(irb, add, {
			{X86_REG_AL, add},
			{X86_REG_AH, llvm::ConstantInt::get(ah->getType(), 0)}});
}

/**
 * X86_INS_AAM
 */
void Capstone2LlvmIrTranslatorX86::translateAam(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* al = loadRegister(X86_REG_AL, irb);
	if (xi->op_count == 0)
	{
		op0 = llvm::ConstantInt::get(al->getType(), 10);
	}
	else
	{
		op0 = loadOpUnary(xi, irb, al->getType(), eOpConv::ZEXT_TRUNC);
	}

	auto* div = irb.CreateUDiv(al, op0);
	auto* rem = irb.CreateURem(al, op0);

	storeRegistersPlusSflags(irb, rem, {
			{X86_REG_AL, rem},
			{X86_REG_AH, div}});
}

/**
 * X86_INS_ADC, X86_INS_ADCX, X86_INS_ADOX
 * http://stackoverflow.com/questions/29747508/what-is-the-difference-between-the-adc-and-adcx-instructions-on-ia32-ia64
 * X86_INS_ADC == X86_INS_ADCX : carry-in/out == CF
 * X86_INS_ADOX : carry-in/out == OF
 */
void Capstone2LlvmIrTranslatorX86::translateAdc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);
	uint32_t cfReg = X86_REG_CF; // X86_INS_ADC || X86_INS_ADCX
	if (i->id == X86_INS_ADOX)
	{
		cfReg = X86_REG_OF;
	}
	auto* cf = loadRegister(cfReg, irb, op0->getType(), eOpConv::ZEXT_TRUNC);

	auto* add1 = irb.CreateAdd(op0, op1);
	auto* add = irb.CreateAdd(add1, cf);

	if (i->id == X86_INS_ADC)
	{
		storeRegistersPlusSflags(irb, add, {
				{X86_REG_AF, genCarryAddCInt4(op0, op1, irb, cf)},
				{X86_REG_OF, genOverflowAddC(add, op0, op1, irb, cf)}});
	}
	storeRegister(cfReg, genCarryAddC(op0, op1, irb, cf), irb);
	setOp(xi->operands[0], add, irb);
}

/**
 * X86_INS_ADD, X86_INS_XADD
 */
void Capstone2LlvmIrTranslatorX86::translateAdd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);

	auto* add = irb.CreateAdd(op0, op1);

	storeRegistersPlusSflags(irb, add, {
			{X86_REG_AF, genCarryAddInt4(op0, op1, irb)},
			{X86_REG_CF, genCarryAdd(add, op0, irb)},
			{X86_REG_OF, genOverflowAdd(add, op0, op1, irb)}});
	setOp(xi->operands[0], add, irb);
	if (i->id == X86_INS_XADD)
	{
		setOp(xi->operands[1], op0, irb);
	}
}

/**
 * X86_INS_TEST, X86_INS_AND
 */
void Capstone2LlvmIrTranslatorX86::translateAnd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);

	auto* andOp = irb.CreateAnd(op0, op1);

	storeRegistersPlusSflags(irb, andOp, {
			{X86_REG_AF, irb.getInt1(false)},   // undef
			{X86_REG_CF, irb.getInt1(false)},   // cleared
			{X86_REG_OF, irb.getInt1(false)}}); // cleared
	if (i->id == X86_INS_AND)
	{
		setOp(xi->operands[0], andOp, irb);
	}
}

/**
 * X86_INS_BSF, X86_INS_BSR
 */
void Capstone2LlvmIrTranslatorX86::translateBsf(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::THROW);
	auto fnc = i->id == X86_INS_BSF ? llvm::Intrinsic::cttz : llvm::Intrinsic::ctlz;
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			fnc,
			op1->getType());

	llvm::Value* c = irb.CreateCall(f, {op1, irb.getTrue()});
	if (i->id == X86_INS_BSR)
	{
		auto* op1T = llvm::cast<llvm::IntegerType>(op1->getType());
		auto* w = llvm::ConstantInt::get(c->getType(), op1T->getBitWidth() - 1);
		c = irb.CreateSub(w, c);
	}
	auto* eqz = irb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 0));
	auto* zf = irb.CreateSelect(eqz, irb.getInt1(true), irb.getInt1(false));
	auto* rv = irb.CreateSelect(eqz, op0, c); // true => undef

	storeRegister(X86_REG_ZF, zf, irb);
	setOp(xi->operands[0], rv, irb);
}

/**
 * X86_INS_BSWAP
 */
void Capstone2LlvmIrTranslatorX86::translateBswap(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			llvm::Intrinsic::bswap,
			op0->getType());

	auto* c = irb.CreateCall(f, {op0});

	setOp(xi->operands[0], c, irb);
}

/**
 * X86_INS_BT
 */
void Capstone2LlvmIrTranslatorX86::translateBt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	op1 = irb.CreateAnd(op1, llvm::ConstantInt::get(op1->getType(), op0BitW - 1));
	auto* shl = irb.CreateShl(llvm::ConstantInt::get(op1->getType(), 1), op1);
	auto* andd = irb.CreateAnd(shl, op0);
	auto* icmp = irb.CreateICmpNE(andd, llvm::ConstantInt::get(andd->getType(), 0));
	storeRegister(X86_REG_CF, icmp, irb);
}

/**
 * X86_INS_BTC
 */
void Capstone2LlvmIrTranslatorX86::translateBtc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	op1 = irb.CreateAnd(op1, llvm::ConstantInt::get(op1->getType(), op0BitW - 1));

	auto* srl = irb.CreateLShr(op0, op1);
	auto* and1 = irb.CreateAnd(srl, llvm::ConstantInt::get(srl->getType(), 1));
	auto* icmp = irb.CreateICmpNE(and1, llvm::ConstantInt::get(and1->getType(), 0));
	storeRegister(X86_REG_CF, icmp, irb);

	auto* shl = irb.CreateShl(llvm::ConstantInt::get(op1->getType(), 1), op1);
	auto* xor1 = irb.CreateXor(shl, llvm::ConstantInt::get(shl->getType(), -1, true));
	auto* and2 = irb.CreateAnd(op0, xor1);
	auto* xor2 = irb.CreateXor(and1, llvm::ConstantInt::get(and1->getType(), 1));
	auto* shl2 = irb.CreateShl(xor2, op1);
	auto* or1 = irb.CreateOr(shl2, and2);
	setOp(xi->operands[0], or1, irb);
}

/**
 * X86_INS_BTR
 */
void Capstone2LlvmIrTranslatorX86::translateBtr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	op1 = irb.CreateAnd(op1, llvm::ConstantInt::get(op1->getType(), op0BitW - 1));
	auto* shl = irb.CreateShl(llvm::ConstantInt::get(op1->getType(), 1), op1);
	auto* andd = irb.CreateAnd(shl, op0);
	auto* icmp = irb.CreateICmpNE(andd, llvm::ConstantInt::get(andd->getType(), 0));
	storeRegister(X86_REG_CF, icmp, irb);

	auto* xor1 = irb.CreateXor(shl, llvm::ConstantInt::get(shl->getType(), -1, true));
	auto* and2 = irb.CreateAnd(op0, xor1);
	setOp(xi->operands[0], and2, irb);
}

/**
 * X86_INS_BTS
 */
void Capstone2LlvmIrTranslatorX86::translateBts(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	op1 = irb.CreateAnd(op1, llvm::ConstantInt::get(op1->getType(), op0BitW - 1));
	auto* shl = irb.CreateShl(llvm::ConstantInt::get(op1->getType(), 1), op1);
	auto* andd = irb.CreateAnd(shl, op0);
	auto* icmp = irb.CreateICmpNE(andd, llvm::ConstantInt::get(andd->getType(), 0));
	storeRegister(X86_REG_CF, icmp, irb);

	auto* or1 = irb.CreateOr(shl, op0);
	setOp(xi->operands[0], or1, irb);
}

/**
 * X86_INS_CBW
 */
void Capstone2LlvmIrTranslatorX86::translateCbw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadRegister(X86_REG_AL, irb);
	auto* e = irb.CreateSExt(op0, getRegisterType(X86_REG_AX));
	storeRegister(X86_REG_AX, e, irb);
}

/**
 * X86_INS_CWDE
 */
void Capstone2LlvmIrTranslatorX86::translateCwde(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadRegister(X86_REG_AX, irb);
	auto* e = irb.CreateSExt(op0, getRegisterType(X86_REG_EAX));
	storeRegister(X86_REG_EAX, e, irb);
}

/**
 * X86_INS_CDQE
 */
void Capstone2LlvmIrTranslatorX86::translateCdqe(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadRegister(X86_REG_EAX, irb);
	auto* e = irb.CreateSExt(op0, getRegisterType(X86_REG_RAX));
	storeRegister(X86_REG_RAX, e, irb);
}

/**
 * X86_INS_CWD
 */
void Capstone2LlvmIrTranslatorX86::translateCwd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadRegister(X86_REG_AX, irb);
	auto* e = irb.CreateAShr(op0, getRegisterBitSize(X86_REG_AX) - 1);
	storeRegister(X86_REG_DX, e, irb);
}

/**
 * X86_INS_CDQ
 */
void Capstone2LlvmIrTranslatorX86::translateCdq(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadRegister(X86_REG_EAX, irb);
	auto* e = irb.CreateAShr(op0, getRegisterBitSize(X86_REG_EAX) - 1);
	storeRegister(X86_REG_EDX, e, irb);
}

/**
 * X86_INS_CQO
 */
void Capstone2LlvmIrTranslatorX86::translateCqo(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadRegister(X86_REG_RAX, irb);
	auto* e = irb.CreateAShr(op0, getRegisterBitSize(X86_REG_RAX) - 1);
	storeRegister(X86_REG_RDX, e, irb);
}

/**
 * X86_INS_CLC
 */
void Capstone2LlvmIrTranslatorX86::translateClc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	storeRegister(X86_REG_CF, irb.getInt1(false), irb);
}

/**
 * X86_INS_CLD
 */
void Capstone2LlvmIrTranslatorX86::translateCld(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	storeRegister(X86_REG_DF, irb.getInt1(false), irb);
}

/**
 * X86_INS_CLI
 */
void Capstone2LlvmIrTranslatorX86::translateCli(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	storeRegister(X86_REG_IF, irb.getInt1(false), irb);
}

/**
 * X86_INS_CMC
 */
void Capstone2LlvmIrTranslatorX86::translateCmc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* cf = loadRegister(X86_REG_CF, irb);
	auto* xorOp = irb.CreateXor(cf, llvm::ConstantInt::get(cf->getType(), 1));
	storeRegister(X86_REG_CF, xorOp, irb);
}

/**
 * X86_INS_CMPXCHG
 * cmpxchg accum={al, ax, eax}, op0, op1
 * if (accum == op0) then op0 <- op1 else accum <- op0
 */
void Capstone2LlvmIrTranslatorX86::translateCmpxchg(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);
	auto* accum = loadRegister(getAccumulatorRegister(xi->operands[0].size), irb);

	auto* sub = irb.CreateSub(accum, op0);

	storeRegistersPlusSflags(irb, sub, {
			{X86_REG_AF, genBorrowSubInt4(accum, op0, irb)},
			{X86_REG_CF, genBorrowSub(accum, op0, irb)},
			{X86_REG_OF, genOverflowSub(sub, accum, op1, irb)}});
	// If-then-else construction could be used here for more straightforward
	// code, but that would create BBs inside ASM instruction, which should be
	// avoided whenever possible.
	// if (accum == op1) then op0 <- op1, accum <- accum
	//                   else op0 <- op0, accum <- op0
	// (accum == op1) <=> (zf == 1)
	auto* zf = loadRegister(X86_REG_ZF, irb);
	auto* op0Val = irb.CreateSelect(zf, op1, op0);
	auto* accumVal = irb.CreateSelect(zf, accum, op0);
	setOp(xi->operands[0], op0Val, irb);
	storeRegister(getAccumulatorRegister(xi->operands[0].size), accumVal, irb);
}

/**
 * X86_INS_CMPXCHG8B
 */
void Capstone2LlvmIrTranslatorX86::translateCmpxchg8b(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	auto* eax = loadRegister(X86_REG_EAX, irb, op0->getType(), eOpConv::ZEXT_TRUNC);
	auto* edx = loadRegister(X86_REG_EDX, irb, op0->getType(), eOpConv::ZEXT_TRUNC);
	edx = irb.CreateShl(edx, 32);
	auto* rval = irb.CreateOr(edx, eax);
	auto* cnd = irb.CreateICmpEQ(op0, rval);

	auto irbP = generateIfThenElse(cnd, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(X86_REG_ZF, bodyIf.getInt1(true), bodyIf);
	auto* ecx = loadRegister(X86_REG_ECX, bodyIf, op0->getType(), eOpConv::ZEXT_TRUNC);
	auto* ebx = loadRegister(X86_REG_EBX, bodyIf, op0->getType(), eOpConv::ZEXT_TRUNC);
	ecx = bodyIf.CreateShl(ecx, 32);
	auto* res = bodyIf.CreateOr(ecx, ebx);
	setOp(xi->operands[0], res, bodyIf);

	storeRegister(X86_REG_ZF, bodyElse.getInt1(false), bodyElse);
	auto* low = bodyElse.CreateTrunc(op0, eax->getType());
	auto* high = bodyElse.CreateTrunc(bodyElse.CreateLShr(op0, 32), edx->getType());
	storeRegister(X86_REG_EAX, low, bodyElse);
	storeRegister(X86_REG_EDX, high, bodyElse);
}

/**
 * X86_INS_CMPXCHG16B
 */
void Capstone2LlvmIrTranslatorX86::translateCmpxchg16b(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	auto* rax = loadRegister(X86_REG_RAX, irb, op0->getType(), eOpConv::ZEXT_TRUNC);
	auto* rdx = loadRegister(X86_REG_RDX, irb, op0->getType(), eOpConv::ZEXT_TRUNC);
	rdx = irb.CreateShl(rdx, 64);
	auto* rval = irb.CreateOr(rdx, rax);
	auto* cnd = irb.CreateICmpEQ(op0, rval);

	auto irbP = generateIfThenElse(cnd, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(X86_REG_ZF, bodyIf.getInt1(true), bodyIf);
	auto* rcx = loadRegister(X86_REG_RCX, bodyIf, op0->getType(), eOpConv::ZEXT_TRUNC);
	auto* rbx = loadRegister(X86_REG_RBX, bodyIf, op0->getType(), eOpConv::ZEXT_TRUNC);
	rcx = bodyIf.CreateShl(rcx, 64);
	auto* res = bodyIf.CreateOr(rcx, rbx);
	setOp(xi->operands[0], res, bodyIf);

	storeRegister(X86_REG_ZF, bodyElse.getInt1(false), bodyElse);
	auto* low = bodyElse.CreateTrunc(op0, rax->getType());
	auto* high = bodyElse.CreateTrunc(bodyElse.CreateLShr(op0, 64), rdx->getType());
	storeRegister(X86_REG_RAX, low, bodyElse);
	storeRegister(X86_REG_RDX, high, bodyElse);
}

/**
 * X86_INS_DEC
 */
void Capstone2LlvmIrTranslatorX86::translateDec(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	op1 = llvm::ConstantInt::get(op0->getType(), 1);

	auto* sub = irb.CreateSub(op0, op1);

	storeRegistersPlusSflags(irb, sub, {
			{X86_REG_AF, genBorrowSubInt4(op0, op1, irb)},
			// CF not changed.
			{X86_REG_OF, genOverflowSub(sub, op0, op1, irb)}});
	setOp(xi->operands[0], sub, irb);
}

/**
 * X86_INS_IMUL
 */
void Capstone2LlvmIrTranslatorX86::translateImul(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	if (xi->op_count == 1)
	{
		translateMul(i, xi, irb);
	}
	else if (xi->op_count == 2)
	{
		std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);

		auto* origType = op0->getType();
		unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
		auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);

		op0 = irb.CreateSExt(op0, doubleT);
		op1 = irb.CreateSExt(op1, doubleT);
		auto* mul = irb.CreateMul(op0, op1);
		setOp(xi->operands[0], mul, irb);

		auto* trunc = irb.CreateTrunc(mul, origType);
		auto* sext = irb.CreateSExt(trunc, doubleT);
		auto* f = irb.CreateICmpNE(mul, sext);
		storeRegister(X86_REG_OF, f, irb);
		storeRegister(X86_REG_CF, f, irb);
	}
	else if (xi->op_count == 3)
	{
		std::tie(op0, op1, op2) = loadOpTernary(xi, irb);

		unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
		auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);

		op1 = irb.CreateSExt(op1, doubleT);
		op2 = irb.CreateSExt(op2, doubleT);
		auto* mul = irb.CreateMul(op1, op2);
		setOp(xi->operands[0], mul, irb);

		auto* trunc = irb.CreateTrunc(mul, op0->getType());
		auto* sext = irb.CreateSExt(trunc, doubleT);
		auto* f = irb.CreateICmpNE(mul, sext);
		storeRegister(X86_REG_OF, f, irb);
		storeRegister(X86_REG_CF, f, irb);
	}
	else
	{
		assert(false && "X86_INS_IMUL unhandled num of operands");
	}
}

/**
 * X86_INS_INC
 */
void Capstone2LlvmIrTranslatorX86::translateInc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	op1 = llvm::ConstantInt::get(op0->getType(), 1);

	auto* add = irb.CreateAdd(op0, op1);

	storeRegistersPlusSflags(irb, add, {
			{X86_REG_AF, genCarryAddInt4(op0, op1, irb)},
			// CF not changed.
			{X86_REG_OF, genOverflowAdd(add, op0, op1, irb)}});
	setOp(xi->operands[0], add, irb);
}

/**
 * X86_INS_DIV, X86_INS_IDIV
 */
void Capstone2LlvmIrTranslatorX86::translateDiv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpUnary(xi, irb);
	uint32_t op0l = X86_REG_INVALID;
	uint32_t op0h = X86_REG_INVALID;
	uint32_t divR = X86_REG_INVALID;
	uint32_t remR = X86_REG_INVALID;
	llvm::IntegerType* divT = nullptr;
	llvm::IntegerType* resT = nullptr;

	switch (xi->operands[0].size)
	{
		case 1:
		{
			op0l = X86_REG_AX;
			op0h = X86_REG_INVALID;
			divR = X86_REG_AL;
			remR = X86_REG_AH;
			divT = irb.getInt16Ty();
			resT = irb.getInt8Ty();
			break;
		}
		case 2:
		{
			op0l = X86_REG_AX;
			op0h = X86_REG_DX;
			divR = X86_REG_AX;
			remR = X86_REG_DX;
			divT = irb.getInt32Ty();
			resT = irb.getInt16Ty();
			break;
		}
		case 4:
		{
			op0l = X86_REG_EAX;
			op0h = X86_REG_EDX;
			divR = X86_REG_EAX;
			remR = X86_REG_EDX;
			divT = irb.getInt64Ty();
			resT = irb.getInt32Ty();
			break;
		}
		case 8:
		{
			op0l = X86_REG_RAX;
			op0h = X86_REG_RDX;
			divR = X86_REG_RAX;
			remR = X86_REG_RDX;
			divT = irb.getInt128Ty();
			resT = irb.getInt64Ty();
			break;
		}
		default:
		{
			throw Capstone2LlvmIrError("Unhandled op size in translateDiv().");
		}
	}

	if (op0h == X86_REG_INVALID)
	{
		op0 = loadRegister(op0l, irb); // already i16
	}
	else
	{
		auto* op0ll = irb.CreateZExt(loadRegister(op0l, irb), divT);
		auto* op0hl = irb.CreateZExt(loadRegister(op0h, irb), divT);
		op0hl = irb.CreateShl(op0hl, resT->getBitWidth());
		op0 = irb.CreateOr(op0hl, op0ll);
	}
	op1 = irb.CreateZExt(op1, op0->getType());

	auto* div = i->id == X86_INS_IDIV
			? irb.CreateSDiv(op0, op1)  // X86_INS_IDIV - signed.
			: irb.CreateUDiv(op0, op1); // X86_INS_DIV  - unsigned.
	div = irb.CreateTrunc(div, resT);
	storeRegister(divR, div, irb);

	auto* rem = i->id == X86_INS_IDIV
			? irb.CreateSRem(op0, op1)  // X86_INS_IDIV - signed.
			: irb.CreateURem(op0, op1); // X86_INS_DIV  - unsigned.
	rem = irb.CreateTrunc(rem, resT);
	storeRegister(remR, rem, irb);
}

/**
 * X86_INS_JMP
 */
void Capstone2LlvmIrTranslatorX86::translateJmp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	generateBranchFunctionCall(irb, op0);
}

/**
 * X86_INS_LJMP
 */
void Capstone2LlvmIrTranslatorX86::translateLjmp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	if (xi->op_count == 1)
	{
		// Same/similar to translateLoadFarPtr().
		op0 = loadOp(xi->operands[0], irb, true);

		auto* it1 = getIntegerTypeFromByteSize(xi->operands[0].size);
		auto* pt1 = llvm::PointerType::get(it1, 0);
		auto* addr1 = irb.CreateIntToPtr(op0, pt1);
		auto* l1 = irb.CreateLoad(addr1);

		auto* it2 = irb.getInt16Ty();
		auto* pt2 = llvm::PointerType::get(it2, 0);
		auto* addC = llvm::ConstantInt::get(op0->getType(), xi->operands[0].size);
		auto* addr2 = irb.CreateAdd(op0, addC);
		addr2 = irb.CreateIntToPtr(addr2, pt2);
		auto* l2 = irb.CreateLoad(addr2);

		op0 = l2; // segment selector
		op1 = l1; // address
	}
	else if (xi->op_count == 2)
	{
		std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::NOTHING);
	}
	else
	{
		throw Capstone2LlvmIrError("Unhandled op count in translateLjmp().");
	}

	// What to do with segment selector (op0)?
	// Store it to segment register (used now)?
	// Create a different kind of brach function call that also takes segment
	// selector value as parameter?
	storeRegister(X86_REG_CS, op0, irb);
	generateBranchFunctionCall(irb, op1);
}

/**
 * X86_INS_CALL
 */
void Capstone2LlvmIrTranslatorX86::translateCall(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* pc = getCurrentPc(i);
	auto* sp = loadRegister(getStackPointerRegister(), irb);
	auto* ci = llvm::ConstantInt::get(sp->getType(), getArchByteSize());
	auto* sub = irb.CreateSub(sp, ci);
	auto* pt = llvm::PointerType::get(pc->getType(), 0);
	auto* addr = irb.CreateIntToPtr(sub, pt);
	irb.CreateStore(pc, addr);
	storeRegister(getStackPointerRegister(), sub, irb);

	op0 = loadOpUnary(xi, irb);
	generateCallFunctionCall(irb, op0);
}

/**
 * X86_INS_LCALL
 * e.g. lcall ptr [ecx + 0x78563412]
 */
void Capstone2LlvmIrTranslatorX86::translateLcall(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* pc = getCurrentPc(i);
	auto* cs = loadRegister(X86_REG_CS, irb);
	auto* sp = loadRegister(getStackPointerRegister(), irb);

	auto* ci1 = llvm::ConstantInt::get(sp->getType(), getArchByteSize());
	auto* sub1 = irb.CreateSub(sp, ci1);
	auto* pt1 = llvm::PointerType::get(cs->getType(), 0);
	auto* addr1 = irb.CreateIntToPtr(sub1, pt1);
	irb.CreateStore(cs, addr1);

	auto* ci2 = llvm::ConstantInt::get(sp->getType(), getArchByteSize()*2);
	auto* sub2 = irb.CreateSub(sp, ci2);
	auto* pt2 = llvm::PointerType::get(pc->getType(), 0);
	auto* addr2 = irb.CreateIntToPtr(sub2, pt2);
	irb.CreateStore(pc, addr2);

	storeRegister(getStackPointerRegister(), sub2, irb);

	if (xi->op_count == 1)
	{
		op0 = loadOpUnary(xi, irb);
	}
	// binary e.g.: lcall 7:0
	else
	{
		std::tie(op1, op0) = loadOpBinary(xi, irb, eOpConv::NOTHING);
	}

	generateCallFunctionCall(irb, op0);
}

/**
 * X86_INS_LAHF
 */
void Capstone2LlvmIrTranslatorX86::translateLahf(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* i8t = irb.getInt8Ty();
	auto* cf = irb.CreateZExt(loadRegister(X86_REG_CF, irb), i8t);
	auto* pf = irb.CreateZExt(loadRegister(X86_REG_PF, irb), i8t);
	auto* af = irb.CreateZExt(loadRegister(X86_REG_AF, irb), i8t);
	auto* zf = irb.CreateZExt(loadRegister(X86_REG_ZF, irb), i8t);
	auto* sf = irb.CreateZExt(loadRegister(X86_REG_SF, irb), i8t);
	auto* zero = irb.getInt8(0);
	auto* one = irb.getInt8(1);

	llvm::Value* val = zero;
	val = irb.CreateOr(val, cf);
	val = irb.CreateOr(val, irb.CreateShl(one, 1));
	val = irb.CreateOr(val, irb.CreateShl(pf, 2));
	val = irb.CreateOr(val, irb.CreateShl(af, 4));
	val = irb.CreateOr(val, irb.CreateShl(zf, 6));
	val = irb.CreateOr(val, irb.CreateShl(sf, 7));
	storeRegister(X86_REG_AH, val, irb);
}

/**
 * X86_INS_LEA
 */
void Capstone2LlvmIrTranslatorX86::translateLea(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op1 = loadOp(xi->operands[1], irb, true);
	// In specification, there are op size/addr size tables of actions based on
	// different bit sizes -- zero extends, truncates.
	// I think setOp() -> storeRegister() will take of it automatically.
	setOp(xi->operands[0], op1, irb);
}

/**
 * X86_INS_ENTER
 */
void Capstone2LlvmIrTranslatorX86::translateEnter(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::NOTHING);
	auto* sp = loadRegister(getStackPointerRegister(), irb);
	auto* bp = loadRegister(getBasePointerRegister(), irb);

//	auto* nestingLevel = irb.CreateURem(op1, llvm::ConstantInt::get(op1->getType(), 32));

	auto* ci = llvm::ConstantInt::get(sp->getType(), xi->addr_size);
	auto* sub = irb.CreateSub(sp, ci);
	auto* pt = llvm::PointerType::get(bp->getType(), 0);
	auto* addr = irb.CreateIntToPtr(sub, pt);
	irb.CreateStore(bp, addr);  // push BP
	storeRegister(getStackPointerRegister(), sub, irb);

	auto* frameTemp = sub; // SP

	// TODO: nestingLevel != 0

	// Continue:
	//
	storeRegister(getBasePointerRegister(), frameTemp, irb);
	op0 = irb.CreateZExtOrTrunc(op0, frameTemp->getType());
	auto* spSub = irb.CreateSub(frameTemp, op0);
	storeRegister(getStackPointerRegister(), spSub, irb);
}

/**
 * X86_INS_LEAVE
 */
void Capstone2LlvmIrTranslatorX86::translateLeave(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* bp = loadRegister(getBasePointerRegister(), irb);
	auto* pt = llvm::PointerType::get(bp->getType(), 0);
	auto* addr = irb.CreateIntToPtr(bp, pt);
	auto* l = irb.CreateLoad(addr);
	auto* c = llvm::ConstantInt::get(bp->getType(), getArchByteSize());
	auto* add = irb.CreateAdd(bp, c);

	storeRegister(getBasePointerRegister(), l, irb);
	storeRegister(getStackPointerRegister(), add, irb);
}

/**
 * X86_INS_LDS, X86_INS_LES, X86_INS_LFS, X86_INS_LGS, X86_INS_LSS
 * There is some more shit going on when instruction executed in protected mode.
 */
void Capstone2LlvmIrTranslatorX86::translateLoadFarPtr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 2);
	op1 = loadOp(xi->operands[1], irb, true);

	auto* it1 = getIntegerTypeFromByteSize(xi->operands[1].size);
	auto* pt1 = llvm::PointerType::get(it1, 0);
	auto* addr1 = irb.CreateIntToPtr(op1, pt1);
	auto* l1 = irb.CreateLoad(addr1);

	auto* it2 = irb.getInt16Ty();
	auto* pt2 = llvm::PointerType::get(it2, 0);
	auto* addC = llvm::ConstantInt::get(op1->getType(), xi->operands[1].size);
	auto* addr2 = irb.CreateAdd(op1, addC);
	addr2 = irb.CreateIntToPtr(addr2, pt2);
	auto* l2 = irb.CreateLoad(addr2);

	uint32_t segR = X86_REG_INVALID;
	switch (i->id)
	{
		case X86_INS_LDS: segR = X86_REG_DS; break;
		case X86_INS_LES: segR = X86_REG_ES; break;
		case X86_INS_LFS: segR = X86_REG_FS; break;
		case X86_INS_LGS: segR = X86_REG_GS; break;
		case X86_INS_LSS: segR = X86_REG_SS; break;
		default: throw Capstone2LlvmIrError("Unhandled insn ID in translateLoadFarPtr().");
	}

	storeRegister(segR, l2, irb);
	setOp(xi->operands[0], l1, irb);
}

/**
 * X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVSXD, X86_INS_MOVZX, X86_INS_MOVABS
 */
void Capstone2LlvmIrTranslatorX86::translateMov(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
//	if (xi->op_count != 2)
//	{
//		std::cout << " @ " << std::hex << i->address << std::endl;
//		exit(1);
//	}

	assert(xi->op_count == 2);
	op1 = loadOp(xi->operands[1], irb);
	switch (i->id)
	{
		case X86_INS_MOV:
		case X86_INS_MOVABS:
//			setOp(xi->operands[0], op1, irb, eOpConv::THROW);
			setOp(xi->operands[0], op1, irb, eOpConv::ZEXT_TRUNC);
			break;
		case X86_INS_MOVSX:
		case X86_INS_MOVSXD:
			setOp(xi->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
			break;
		case X86_INS_MOVZX:
			setOp(xi->operands[0], op1, irb, eOpConv::ZEXT_TRUNC);
			break;
		default:
			throw Capstone2LlvmIrError("Unhandle instr ID in translateMov().");
	}
}

/**
 * X86_INS_MUL, X86_INS_IMUL (only unary form)
 */
void Capstone2LlvmIrTranslatorX86::translateMul(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	op1 = loadRegister(getAccumulatorRegister(xi->operands[0].size), irb);

	llvm::IntegerType* halfT = nullptr;
	llvm::IntegerType* mulT = nullptr;
	uint32_t lowR = X86_REG_INVALID;
	uint32_t highR = X86_REG_INVALID;
	switch (xi->operands[0].size)
	{
		case 1:
		{
			halfT = irb.getInt8Ty();
			mulT = irb.getInt16Ty();
			lowR = X86_REG_AX;
			highR = X86_REG_INVALID;
			break;
		}
		case 2:
		{
			halfT = irb.getInt16Ty();
			mulT = irb.getInt32Ty();
			lowR = X86_REG_AX;
			highR = X86_REG_DX;
			break;
		}
		case 4:
		{
			halfT = irb.getInt32Ty();
			mulT = irb.getInt64Ty();
			lowR = X86_REG_EAX;
			highR = X86_REG_EDX;
			break;
		}
		case 8:
		{
			halfT = irb.getInt64Ty();
			mulT = irb.getInt128Ty();
			lowR = X86_REG_RAX;
			highR = X86_REG_RDX;
			break;
		}
		default:
		{
			throw Capstone2LlvmIrError("Unhandled op size in translateMul().");
		}
	}

	op0 = i->id == X86_INS_MUL ? irb.CreateZExt(op0, mulT) : irb.CreateSExt(op0, mulT);
	op1 = i->id == X86_INS_MUL ? irb.CreateZExt(op1, mulT) : irb.CreateSExt(op1, mulT);
	auto* mul = irb.CreateMul(op0, op1);
	auto* l = irb.CreateTrunc(mul, halfT);
	auto* h = irb.CreateTrunc(irb.CreateLShr(mul, halfT->getBitWidth()), halfT);
	auto* f = irb.CreateICmpNE(h, llvm::ConstantInt::get(h->getType(), 0));
	if (highR == X86_REG_INVALID)
	{
		storeRegister(lowR, mul, irb);
	}
	else
	{
		storeRegister(lowR, l, irb);
		storeRegister(highR, h, irb);
	}
	if (i->id == X86_INS_IMUL)
	{
		auto* f1 = irb.CreateICmpNE(h, llvm::ConstantInt::get(h->getType(), -1, true));
		f = irb.CreateAnd(f, f1);
	}
	storeRegister(X86_REG_OF, f, irb);
	storeRegister(X86_REG_CF, f, irb);
}

/**
 * X86_INS_NEG
 */
void Capstone2LlvmIrTranslatorX86::translateNeg(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	auto* zero = llvm::ConstantInt::get(op0->getType(), 0);

	auto* sub = irb.CreateSub(zero, op0);

	storeRegistersPlusSflags(irb, sub, {
			{X86_REG_AF, genBorrowSubInt4(zero, op0, irb)},
			{X86_REG_CF, irb.CreateICmpNE(op0, zero)},
			{X86_REG_OF, zero}});
	setOp(xi->operands[0], sub, irb);
}

/**
 * X86_INS_NOP, X86_INS_UD2, X86_INS_UD2B, X86_INS_FNOP, X86_INS_FDISI8087_NOP,
 * X86_INS_FENI8087_NOP
 *
 * Complete list from the old semantics:
 * IRETD, IRET, STI, CLI, VERR, VERW, LMSW, LTR,
 * SMSW, CLTS, INVD, LOCK, RSM, RDMSR, WRMSR, RDPMC, SYSENTER,
 * SYSEXIT, XGETBV, LAR, LSL, INVPCID, SLDT, LLDT, SGDT, SIDT, LGDT, LIDT,
 * XSAVE, XRSTOR, XSAVEOPT, INVLPG, FBLD, FBSTP, FLDENV, FRSTOR, FNSAVE, FFREE,
 * FCMOVE, FCMOVNE, FCMOVB, FCMOVNB, FCMOVBE, FCMOVNBE, FCMOVU, FCMOVNU, ARPL,
 * STR, FPREM, FPREM1, FSCALE, FXTRACT, FPTAN, FPATAN, F2XM1, FYL2X,
 * FYL2XP1, FNCLEX, FWAIT, FNOP
 */
void Capstone2LlvmIrTranslatorX86::translateNop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// nothing

	// X86_INS_NOP -> true nop
	// X86_INS_UD2 -> undefined
	// X86_INS_UD2B -> undefined
	// X86_INS_FNOP -> FPU nop
}

/**
 * X86_INS_FNINIT
 * This was modeled as empty (nop) instruction in an old semantics, but it
 * does set some values. Not all of the set objects are represented in our
 * current environment, and therefore we are not able to set them all.
 */
void Capstone2LlvmIrTranslatorX86::translateFninit(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* zero = irb.getFalse();
	auto* one = irb.getTrue();
	auto* i2Set = llvm::ConstantInt::get(irb.getIntNTy(2), 3); // 0b11

	// FPUControlWord = 0x37F; (0x37F = 00000011 01111111)
	storeRegister(X87_REG_IM, one, irb);
	storeRegister(X87_REG_DM, one, irb);
	storeRegister(X87_REG_ZM, one, irb);
	storeRegister(X87_REG_OM, one, irb);
	storeRegister(X87_REG_UM, one, irb);
	storeRegister(X87_REG_PM, one, irb);
	storeRegister(X87_REG_PC, i2Set, irb);
	storeRegister(X87_REG_RC, zero, irb);
	storeRegister(X87_REG_X, zero, irb);
	// FPUStatusWord = 0;
	storeRegister(X87_REG_IE, zero, irb);
	storeRegister(X87_REG_DE, zero, irb);
	storeRegister(X87_REG_ZE, zero, irb);
	storeRegister(X87_REG_OE, zero, irb);
	storeRegister(X87_REG_UE, zero, irb);
	storeRegister(X87_REG_PE, zero, irb);
	storeRegister(X87_REG_SF, zero, irb);
	storeRegister(X87_REG_ES, zero, irb);
	storeRegister(X87_REG_C0, zero, irb);
	storeRegister(X87_REG_C1, zero, irb);
	storeRegister(X87_REG_C2, zero, irb);
	storeRegister(X87_REG_C3, zero, irb);
	storeRegister(X87_REG_TOP, zero, irb);
	storeRegister(X87_REG_B, zero, irb);
	// FPUTagWord = 0xFFFF;
	storeRegister(X87_REG_TAG0, i2Set, irb);
	storeRegister(X87_REG_TAG1, i2Set, irb);
	storeRegister(X87_REG_TAG2, i2Set, irb);
	storeRegister(X87_REG_TAG3, i2Set, irb);
	storeRegister(X87_REG_TAG4, i2Set, irb);
	storeRegister(X87_REG_TAG5, i2Set, irb);
	storeRegister(X87_REG_TAG6, i2Set, irb);
	storeRegister(X87_REG_TAG7, i2Set, irb);
	// FPUDataPointer = 0;
	// FPUInstructionPointer = 0;
	// FPULastInstructionOpcode = 0;
}

/**
 * X86_INS_NOT
 */
void Capstone2LlvmIrTranslatorX86::translateNot(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	auto* negativeOne = llvm::ConstantInt::getSigned(op0->getType(), -1);

	auto* xorOp = irb.CreateXor(op0, negativeOne);

	setOp(xi->operands[0], xorOp, irb);
}

/**
 * X86_INS_OR
 */
void Capstone2LlvmIrTranslatorX86::translateOr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);

	auto* orOp = irb.CreateOr(op0, op1);

	storeRegistersPlusSflags(irb, orOp, {
			{X86_REG_AF, irb.getInt1(false)},   // undef
			{X86_REG_CF, irb.getInt1(false)},   // cleared
			{X86_REG_OF, irb.getInt1(false)}}); // cleared
	setOp(xi->operands[0], orOp, irb);
}

/**
 * X86_INS_POP
 */
void Capstone2LlvmIrTranslatorX86::translatePop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 1);
	auto* sp = loadRegister(getStackPointerRegister(), irb);

	auto* it = getIntegerTypeFromByteSize(xi->operands[0].size);
	auto* pt = llvm::PointerType::get(it, 0);
	auto* addr = irb.CreateIntToPtr(sp, pt);
	auto* l = irb.CreateLoad(addr);
	setOp(xi->operands[0], l, irb);

	auto* ci = llvm::ConstantInt::get(sp->getType(), xi->operands[0].size);
	auto* add = irb.CreateAdd(sp, ci);
	storeRegister(getStackPointerRegister(), add, irb);
}

/**
 * X86_INS_POPAL == POPAD (32-bit), X86_INS_POPAW == POPA (16-bit)
 */
void Capstone2LlvmIrTranslatorX86::translatePopa(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* sp = loadRegister(getStackPointerRegister(), irb);
	auto* t = getIntegerTypeFromByteSize(xi->addr_size);
	auto* pt = llvm::PointerType::get(t, 0);
	auto* c = llvm::ConstantInt::get(sp->getType(), xi->addr_size);

	auto* a1 = sp;
	auto* a2 = irb.CreateAdd(a1, c);
	auto* a3 = irb.CreateAdd(a2, c);
	auto* a4 = irb.CreateAdd(a3, c); // unused
	auto* a5 = irb.CreateAdd(a4, c);
	auto* a6 = irb.CreateAdd(a5, c);
	auto* a7 = irb.CreateAdd(a6, c);
	auto* a8 = irb.CreateAdd(a7, c);
	auto* a9 = irb.CreateAdd(a8, c);

	// 67 61 = popal with addr size == 2 -> probbaly behaves like popaw
	//
	if (i->id == X86_INS_POPAL && xi->addr_size == 4)
	{
		storeRegisters(irb, {
			{X86_REG_EDI, irb.CreateLoad(irb.CreateIntToPtr(a1, pt))},
			{X86_REG_ESI, irb.CreateLoad(irb.CreateIntToPtr(a2, pt))},
			{X86_REG_EBP, irb.CreateLoad(irb.CreateIntToPtr(a3, pt))},
			{X86_REG_EBX, irb.CreateLoad(irb.CreateIntToPtr(a5, pt))},
			{X86_REG_EDX, irb.CreateLoad(irb.CreateIntToPtr(a6, pt))},
			{X86_REG_ECX, irb.CreateLoad(irb.CreateIntToPtr(a7, pt))},
			{X86_REG_EAX, irb.CreateLoad(irb.CreateIntToPtr(a8, pt))},
			{getStackPointerRegister(), a9}});
	}
	else if (i->id == X86_INS_POPAW ||
			(i->id == X86_INS_POPAL && xi->addr_size == 2))
	{
		assert(xi->addr_size == 2 || xi->addr_size == 4);
		storeRegisters(irb, {
			{X86_REG_DI, irb.CreateLoad(irb.CreateIntToPtr(a1, pt))},
			{X86_REG_SI, irb.CreateLoad(irb.CreateIntToPtr(a2, pt))},
			{X86_REG_BP, irb.CreateLoad(irb.CreateIntToPtr(a3, pt))},
			{X86_REG_BX, irb.CreateLoad(irb.CreateIntToPtr(a5, pt))},
			{X86_REG_DX, irb.CreateLoad(irb.CreateIntToPtr(a6, pt))},
			{X86_REG_CX, irb.CreateLoad(irb.CreateIntToPtr(a7, pt))},
			{X86_REG_AX, irb.CreateLoad(irb.CreateIntToPtr(a8, pt))},
			{getStackPointerRegister(), a9}});
	}
	else
	{
		assert(false && "unhandled combination");
	}
}

/**
 * X86_INS_POPF, X86_INS_POPFD, X86_INS_POPFQ
 * This currently does only what original model did.
 * The operations are more complicated, setting of some flags is conditoned by
 * some runtime CPU modes. I don't know if we can/need to solve this.
 */
void Capstone2LlvmIrTranslatorX86::translatePopEflags(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* sp = loadRegister(getStackPointerRegister(), irb);
	auto* it = getIntegerTypeFromByteSize(xi->addr_size);
	auto* pt = llvm::PointerType::get(it, 0);
	auto* addr = irb.CreateIntToPtr(sp, pt);
	auto* l = irb.CreateLoad(addr);

	auto* ci = llvm::ConstantInt::get(sp->getType(), xi->addr_size);
	auto* add = irb.CreateAdd(sp, ci);
	storeRegister(getStackPointerRegister(), add, irb);

	auto* zero = llvm::ConstantInt::get(l->getType(), 0);
	auto* cf = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 0));
	// reserved
	auto* pf = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 2));
	// reserved
	auto* af = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 4));
	// reserved
	auto* zf = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 6));
	auto* sf = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 7));
	auto* tf = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 8));
	auto* iff = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 9));
	auto* df = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 10));
	auto* of = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 11));
//	auto* iopl = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), (1 << 12) + (1 << 13)));
	auto* nt = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 14));

	storeRegisters(irb, {
		{X86_REG_CF, irb.CreateICmpNE(cf, zero)},
		{X86_REG_PF, irb.CreateICmpNE(pf, zero)},
		{X86_REG_AF, irb.CreateICmpNE(af, zero)},
		{X86_REG_ZF, irb.CreateICmpNE(zf, zero)},
		{X86_REG_SF, irb.CreateICmpNE(sf, zero)},
		{X86_REG_TF, irb.CreateICmpNE(tf, zero)},
		{X86_REG_IF, irb.CreateICmpNE(iff, zero)},
		{X86_REG_DF, irb.CreateICmpNE(df, zero)},
		{X86_REG_OF, irb.CreateICmpNE(of, zero)},
//		{X86_REG_IOPL, irb.CreateICmpNE(iopl, zero)},
		{X86_REG_NT, irb.CreateICmpNE(nt, zero)}});

	if (i->id == X86_INS_POPFD || i->id == X86_INS_POPFQ)
	{
		// reserved
		auto* rf = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 16));
//		auto* vm = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 17));
		auto* ac = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 18));
//		auto* vif = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 19));
//		auto* vip = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 20));
		auto* id = irb.CreateAnd(l, llvm::ConstantInt::get(l->getType(), 1 << 21));

		storeRegisters(irb, {
			{X86_REG_RF, irb.CreateICmpNE(rf, zero)},
//			{X86_REG_VM, irb.CreateICmpNE(vm, zero)},
			{X86_REG_AC, irb.CreateICmpNE(ac, zero)},
//			{X86_REG_VIF, irb.CreateICmpNE(vif, zero)},
//			{X86_REG_VIP, irb.CreateICmpNE(vip, zero)},
			{X86_REG_ID, irb.CreateICmpNE(id, zero)}});
	}
}

/**
 * X86_INS_PUSH
 */
void Capstone2LlvmIrTranslatorX86::translatePush(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(xi, irb);
	auto* sp = loadRegister(getStackPointerRegister(), irb);

	auto* ci = llvm::ConstantInt::get(sp->getType(), xi->operands[0].size);
	auto* sub = irb.CreateSub(sp, ci);
	auto* pt = llvm::PointerType::get(op0->getType(), 0);
	auto* addr = irb.CreateIntToPtr(sub, pt);

	irb.CreateStore(op0, addr);
	storeRegister(getStackPointerRegister(), sub, irb);
}

/**
 * X86_INS_PUSHAL = PUSHAD (32-bit), X86_INS_PUSHAW = PUSHA (16-bit)
 */
void Capstone2LlvmIrTranslatorX86::translatePusha(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* sp = loadRegister(getStackPointerRegister(), irb);
	llvm::Type* t = nullptr; // getIntegerTypeFromByteSize(xi->addr_size);
	std::size_t bsz = 0;
	if (i->id == X86_INS_PUSHAL)
	{
		t = irb.getInt32Ty();
		bsz = 4;
	}
	else if (i->id == X86_INS_PUSHAW)
	{
		t = irb.getInt16Ty();
		bsz = 2;
	}
	auto* pt = llvm::PointerType::get(t, 0);
	auto* c = llvm::ConstantInt::get(sp->getType(), bsz);

	auto* a1 = irb.CreateSub(sp, c);
	auto* a2 = irb.CreateSub(a1, c);
	auto* a3 = irb.CreateSub(a2, c);
	auto* a4 = irb.CreateSub(a3, c);
	auto* a5 = irb.CreateSub(a4, c);
	auto* a6 = irb.CreateSub(a5, c);
	auto* a7 = irb.CreateSub(a6, c);
	auto* a8 = irb.CreateSub(a7, c);

	if (i->id == X86_INS_PUSHAL)
	{
//		assert(xi->addr_size == 4);
		irb.CreateStore(loadRegister(X86_REG_EAX, irb), irb.CreateIntToPtr(a1, pt));
		irb.CreateStore(loadRegister(X86_REG_ECX, irb), irb.CreateIntToPtr(a2, pt));
		irb.CreateStore(loadRegister(X86_REG_EDX, irb), irb.CreateIntToPtr(a3, pt));
		irb.CreateStore(loadRegister(X86_REG_EBX, irb), irb.CreateIntToPtr(a4, pt));
		irb.CreateStore(irb.CreateZExtOrTrunc(sp, t), irb.CreateIntToPtr(a5, pt));
		irb.CreateStore(loadRegister(X86_REG_EBP, irb), irb.CreateIntToPtr(a6, pt));
		irb.CreateStore(loadRegister(X86_REG_ESI, irb), irb.CreateIntToPtr(a7, pt));
		irb.CreateStore(loadRegister(X86_REG_EDI, irb), irb.CreateIntToPtr(a8, pt));
		storeRegister(getStackPointerRegister(), a8, irb);
	}
	else if (i->id == X86_INS_PUSHAW)
	{
//		assert(xi->addr_size == 2); // this does not have to be true, this is commonly 4, should we still push words?
		irb.CreateStore(loadRegister(X86_REG_AX, irb), irb.CreateIntToPtr(a1, pt));
		irb.CreateStore(loadRegister(X86_REG_CX, irb), irb.CreateIntToPtr(a2, pt));
		irb.CreateStore(loadRegister(X86_REG_DX, irb), irb.CreateIntToPtr(a3, pt));
		irb.CreateStore(loadRegister(X86_REG_BX, irb), irb.CreateIntToPtr(a4, pt));
		irb.CreateStore(irb.CreateZExtOrTrunc(sp, t), irb.CreateIntToPtr(a5, pt));
		irb.CreateStore(loadRegister(X86_REG_BP, irb), irb.CreateIntToPtr(a6, pt));
		irb.CreateStore(loadRegister(X86_REG_SI, irb), irb.CreateIntToPtr(a7, pt));
		irb.CreateStore(loadRegister(X86_REG_DI, irb), irb.CreateIntToPtr(a8, pt));
		storeRegister(getStackPointerRegister(), a8, irb);
	}
}

/**
 * X86_INS_PUSHF, X86_INS_PUSHFD, X86_INS_PUSHFQ
 * See @c translatePopEflags() comment.
 */
void Capstone2LlvmIrTranslatorX86::translatePushEflags(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* it = getIntegerTypeFromByteSize(xi->addr_size);

	auto* cf = irb.CreateZExt(loadRegister(X86_REG_CF, irb), it);
	// reserved
	auto* pf = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_PF, irb), it), 2);
	// reserved
	auto* af = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_AF, irb), it), 4);
	// reserved
	auto* zf = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_ZF, irb), it), 6);
	auto* sf = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_SF, irb), it), 7);
	auto* tf = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_TF, irb), it), 8);
	auto* iff = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_IF, irb), it), 9);
	auto* df = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_DF, irb), it), 10);
	auto* of = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_OF, irb), it), 11);
//	auto* iopl = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_IOPL, irb), it), 13);
	auto* nt = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_NT, irb), it), 14);
	// reserved

	auto* val = cf;
	// This was in original model, but I did not find a reason for it.
	val = irb.CreateOr(val, llvm::ConstantInt::get(val->getType(), 2));
	val = irb.CreateOr(val, pf);
	val = irb.CreateOr(val, af);
	val = irb.CreateOr(val, zf);
	val = irb.CreateOr(val, sf);
	val = irb.CreateOr(val, tf);
	val = irb.CreateOr(val, iff);
	val = irb.CreateOr(val, df);
	val = irb.CreateOr(val, of);
	val = irb.CreateOr(val, nt);

	if (i->id == X86_INS_POPFD || i->id == X86_INS_POPFQ)
	{
//		auto* rf = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_RF, irb), it), 16);
//		auto* vm = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_VM, irb), it), 17);
		auto* ac = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_AC, irb), it), 18);
//		auto* vif = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_VIF, irb), it), 19);
//		auto* vip = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_VIP, irb), it), 20);
		auto* id = irb.CreateShl(irb.CreateZExt(loadRegister(X86_REG_ID, irb), it), 21);

		val = irb.CreateOr(val, ac);
		val = irb.CreateOr(val, id);
	}

	auto* sp = loadRegister(getStackPointerRegister(), irb);
	auto* ci = llvm::ConstantInt::get(sp->getType(), xi->addr_size);
	auto* sub = irb.CreateSub(sp, ci);
	auto* pt = llvm::PointerType::get(val->getType(), 0);
	auto* addr = irb.CreateIntToPtr(sub, pt);

	irb.CreateStore(val, addr);
	storeRegister(getStackPointerRegister(), sub, irb);
}

/**
 * X86_INS_RET, X86_INS_RETF, X86_INS_RETFQ
 */
void Capstone2LlvmIrTranslatorX86::translateRet(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	bool far = i->id != X86_INS_RET;
	auto* sp = loadRegister(getStackPointerRegister(), irb);
	auto sz = 0;
	switch (_origBasicMode)
	{
		case CS_MODE_16:
			sz = xi->prefix[2] == X86_PREFIX_OPSIZE ? 4 : 2;
			break;
		case CS_MODE_32:
			sz = xi->prefix[2] == X86_PREFIX_OPSIZE ? 2 : 4;
			break;
		case CS_MODE_64:
			sz = xi->prefix[2] == X86_PREFIX_OPSIZE ? 4 : 8;
			break;
		default:
			throw Capstone2LlvmIrError("Unhandled mode in translateRet().");
	}
	assert(sz);
	op0 = nullptr;
	if (xi->op_count == 1)
	{
		op0 = loadOpUnary(xi, irb);
	}

	auto* it = getIntegerTypeFromByteSize(sz);
	auto* pt = llvm::PointerType::get(it, 0);
	auto* addr = irb.CreateIntToPtr(sp, pt);
	auto* l = irb.CreateLoad(addr);

	auto* ci = llvm::ConstantInt::get(sp->getType(), sz);
	auto* add = irb.CreateAdd(sp, ci);

	if (far)
	{
		auto* addr2 = irb.CreateIntToPtr(add, pt);
		auto* l2 = irb.CreateLoad(addr2);
		storeRegister(X86_REG_CS, l2, irb);
		add = irb.CreateAdd(add, ci);
	}
	if (op0)
	{
		op0 = irb.CreateZExtOrTrunc(op0, add->getType());
		add = irb.CreateAdd(add, op0);
	}

	storeRegister(getStackPointerRegister(), add, irb);

	generateReturnFunctionCall(irb, l);
}

/**
 * X86_INS_SAHF
 */
void Capstone2LlvmIrTranslatorX86::translateSahf(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* ah = loadRegister(X86_REG_AH, irb);
	auto* t = ah->getType();
	auto* zero = irb.getInt8(0);

	storeRegister(X86_REG_CF, irb.CreateAnd(ah, llvm::ConstantInt::get(t, 1 << 0)), irb);
	// Bit 1 of RFLAGS is set to 1, but we have no way of setting it.
	storeRegister(X86_REG_PF, irb.CreateICmpNE(
			irb.CreateAnd(ah, llvm::ConstantInt::get(t, 1 << 2)), zero), irb);
	// Bit 3 of RFLAGS is set to 0, but we have no way of setting it.
	storeRegister(X86_REG_AF, irb.CreateICmpNE(
			irb.CreateAnd(ah, llvm::ConstantInt::get(t, 1 << 4)), zero), irb);
	// Bit 5 of RFLAGS is set to 0, but we have no way of setting it.
	storeRegister(X86_REG_ZF, irb.CreateICmpNE(
			irb.CreateAnd(ah, llvm::ConstantInt::get(t, 1 << 6)), zero), irb);
	storeRegister(X86_REG_SF, irb.CreateICmpNE(
			irb.CreateAnd(ah, llvm::ConstantInt::get(t, 1 << 7)), zero), irb);
}

/**
 * X86_INS_SALC
 */
void Capstone2LlvmIrTranslatorX86::translateSalc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	auto* cf = loadRegister(X86_REG_CF, irb);
	auto* icmp = irb.CreateICmpEQ(cf, irb.getInt1(false));
	auto* v = irb.CreateSelect(icmp, irb.getInt8(0), irb.getInt8(0xff));

	storeRegister(X86_REG_AL, v, irb);
}

/**
 * X86_INS_SBB
 */
void Capstone2LlvmIrTranslatorX86::translateSbb(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);
	auto* cf = loadRegister(X86_REG_CF, irb, op0->getType(), eOpConv::ZEXT_TRUNC);

	auto* sub1 = irb.CreateSub(op0, op1);
	auto* sub = irb.CreateAdd(sub1, cf); // Yes, this really is add.

	storeRegistersPlusSflags(irb, sub, {
			{X86_REG_AF, genBorrowSubCInt4(op0, op1, irb)},
			{X86_REG_CF, genBorrowSubC(sub1, op0, op1, irb)}, // Really sub1.
			{X86_REG_OF, genOverflowSubC(sub1, op0, op1, irb)}}); // Really sub1.
	setOp(xi->operands[0], sub, irb);
}

/**
 * X86_INS_SHL == X86_INS_SAL
 */
void Capstone2LlvmIrTranslatorX86::translateShiftLeft(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOp(xi->operands[0], irb);
	if (xi->op_count == 2)
	{
		op1 = loadOp(xi->operands[1], irb);
		op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
	}
	else
	{
		op1 = llvm::ConstantInt::get(op0->getType(), 1);
	}
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op1->getType(), maskC);
	op1 = irb.CreateAnd(op1, mask);
	auto* of = llvm::cast<llvm::Instruction>(loadRegister(X86_REG_OF, irb));
	auto* op1Zero = irb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 0));

	// Sometimes (most of the times, not for op1 = CL) LLVM can eval cond brach
	// cond on-the-fly. Then this pattern creates stuff like:
	// br i1 false, x, y
	// It is not a big deal, because it will be optimized, but with a bit better
	// code here, we could generate much simpler customized translations.
	//
	auto bodyIrb = generateIfNotThen(op1Zero, irb);

	auto* shl = bodyIrb.CreateShl(op0, op1);
	genSetSflags(shl, bodyIrb);
	setOp(xi->operands[0], shl, bodyIrb);

	auto* cfOp1 = bodyIrb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* cfShl = bodyIrb.CreateShl(op0, cfOp1);
	auto* cfIntT = llvm::cast<llvm::IntegerType>(cfShl->getType());
	auto* cfRightCount = llvm::ConstantInt::get(cfIntT, cfIntT->getBitWidth() - 1);
	auto* cfLow = bodyIrb.CreateLShr(cfShl, cfRightCount);
	storeRegister(X86_REG_CF, cfLow, bodyIrb);

	auto* ofLow = bodyIrb.CreateLShr(shl, cfRightCount);
	auto* ofIcmp = bodyIrb.CreateICmpNE(ofLow, cfLow);
	auto* ofIs1 = bodyIrb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* ofV = bodyIrb.CreateSelect(ofIs1, ofIcmp, of);
	storeRegister(X86_REG_OF, ofV, bodyIrb);
}

/**
 * X86_INS_SHR, X86_INS_SAR
 */
void Capstone2LlvmIrTranslatorX86::translateShiftRight(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	op0 = loadOp(xi->operands[0], irb);
	if (xi->op_count == 2)
	{
		op1 = loadOp(xi->operands[1], irb);
		op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
	}
	else
	{
		op1 = llvm::ConstantInt::get(op0->getType(), 1);
	}
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op1->getType(), maskC);
	op1 = irb.CreateAnd(op1, mask);
	auto* of = llvm::cast<llvm::Instruction>(loadRegister(X86_REG_OF, irb));
	auto* op1Zero = irb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 0));
	auto bodyIrb = generateIfNotThen(op1Zero, irb);

	llvm::Value* shift = i->id == X86_INS_SHR
			? bodyIrb.CreateLShr(op0, op1)  // X86_INS_SHR
			: bodyIrb.CreateAShr(op0, op1); // X86_INS_SAR
	genSetSflags(shift, bodyIrb);
	setOp(xi->operands[0], shift, bodyIrb);
	auto* cfOp1 = bodyIrb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* cfShl = bodyIrb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
	auto* cfAnd = bodyIrb.CreateAnd(cfShl, op0);
	auto* cfIcmp = bodyIrb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
	storeRegister(X86_REG_CF, cfIcmp, bodyIrb);
	auto* ofIs1 = bodyIrb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 1));
	llvm::Value* ofVal = nullptr;
	if (i->id == X86_INS_SHR)
	{
		ofVal = bodyIrb.CreateICmpSLT(op0, llvm::ConstantInt::get(op0->getType(), 0));
	}
	else if (i->id == X86_INS_SAR)
	{
		ofVal = bodyIrb.getInt1(false);
	}
	storeRegister(X86_REG_OF, bodyIrb.CreateSelect(ofIs1, ofVal, of), bodyIrb);
}

/**
 * X86_INS_SHLD
 */
void Capstone2LlvmIrTranslatorX86::translateShld(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(getBasicMode() == CS_MODE_32);
	std::tie(op0, op1, op2) = loadOpTernary(xi, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op0->getType());
	auto* of = loadRegister(X86_REG_OF, irb);

	if (getBasicMode() == CS_MODE_32)
	{
		op2 = irb.CreateSRem(op2, llvm::ConstantInt::get(op2->getType(), 32));
	}
	else if (getBasicMode() == CS_MODE_64) // && REX.W prefix.
	{
		op2 = irb.CreateSRem(op2, llvm::ConstantInt::get(op2->getType(), 64));
	}

	auto* op2Zero = irb.CreateICmpEQ(op2, llvm::ConstantInt::get(op2->getType(), 0));
	auto bodyIrb = generateIfNotThen(op2Zero, irb);

	auto* shl = bodyIrb.CreateShl(op0, op2);
	auto* it = llvm::cast<llvm::IntegerType>(shl->getType());
	auto* sub = bodyIrb.CreateSub(llvm::ConstantInt::get(it, it->getBitWidth()), op2);
	auto* srl = bodyIrb.CreateLShr(op1, sub);
	auto* orr = bodyIrb.CreateOr(srl, shl);
	genSetSflags(orr, bodyIrb);
	setOp(xi->operands[0], orr, bodyIrb);

	auto* subCf = bodyIrb.CreateSub(op2, llvm::ConstantInt::get(op2->getType(), 1));
	auto* shlCf = bodyIrb.CreateShl(op0, subCf);
	auto* icmpCf = bodyIrb.CreateICmpSLT(shlCf, llvm::ConstantInt::getSigned(shlCf->getType(), 0));
	storeRegister(X86_REG_CF, icmpCf, bodyIrb);

	auto* icmpOf = bodyIrb.CreateICmpEQ(op2, llvm::ConstantInt::get(op2->getType(), 1));
	auto* xorOf = bodyIrb.CreateXor(orr, shlCf);
	auto* icmpOfV = bodyIrb.CreateICmpSLT(xorOf, llvm::ConstantInt::getSigned(xorOf->getType(), 0));
	auto* ofV = bodyIrb.CreateSelect(icmpOf, icmpOfV, of);
	storeRegister(X86_REG_OF, ofV, bodyIrb);
}

/**
 * X86_INS_SHRD
 */
void Capstone2LlvmIrTranslatorX86::translateShrd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(getBasicMode() == CS_MODE_32);
	std::tie(op0, op1, op2) = loadOpTernary(xi, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op0->getType());
	auto* of = loadRegister(X86_REG_OF, irb);

	if (getBasicMode() == CS_MODE_32)
	{
		op2 = irb.CreateSRem(op2, llvm::ConstantInt::get(op2->getType(), 32));
	}
	else if (getBasicMode() == CS_MODE_64) // && REX.W prefix.
	{
		op2 = irb.CreateSRem(op2, llvm::ConstantInt::get(op2->getType(), 64));
	}

	auto* op2Zero = irb.CreateICmpEQ(op2, llvm::ConstantInt::get(op2->getType(), 0));
	auto bodyIrb = generateIfNotThen(op2Zero, irb);

	auto* lshr = bodyIrb.CreateLShr(op0, op2);
	auto* it = llvm::cast<llvm::IntegerType>(op2->getType());
	auto* sub = bodyIrb.CreateSub(llvm::ConstantInt::get(it, it->getBitWidth()), op2);
	auto* shl = bodyIrb.CreateShl(op1, sub);
	auto* orr = bodyIrb.CreateOr(shl, lshr);
	genSetSflags(orr, bodyIrb);
	setOp(xi->operands[0], orr, bodyIrb);

	auto* subCf = bodyIrb.CreateSub(op2, llvm::ConstantInt::get(op2->getType(), 1));
	auto* shlCf = bodyIrb.CreateShl(llvm::ConstantInt::get(subCf->getType(), 1), subCf);
	auto* andCf = bodyIrb.CreateAnd(shlCf, op0);
	auto* icmpCf = bodyIrb.CreateICmpNE(andCf, llvm::ConstantInt::get(andCf->getType(), 0));
	storeRegister(X86_REG_CF, icmpCf, bodyIrb);

	auto* icmpOf = bodyIrb.CreateICmpEQ(op2, llvm::ConstantInt::get(op2->getType(), 1));
	auto* xorOf = bodyIrb.CreateXor(orr, op0);
	auto* icmpOfV = bodyIrb.CreateICmpSLT(xorOf, llvm::ConstantInt::getSigned(xorOf->getType(), 0));
	auto* ofV = bodyIrb.CreateSelect(icmpOf, icmpOfV, of);
	storeRegister(X86_REG_OF, ofV, bodyIrb);
}

/**
 * X86_INS_RCR
 */
void Capstone2LlvmIrTranslatorX86::translateRcr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op1->getType(), maskC);
	op1 = irb.CreateAnd(op1, mask);
	auto* op1NotZero = irb.CreateICmpNE(op1, llvm::ConstantInt::get(op1->getType(), 0));

	auto bodyIrb = generateIfThen(op1NotZero, irb);

	auto* cf = loadRegister(X86_REG_CF, bodyIrb, op0->getType(), eOpConv::ZEXT_TRUNC);

	auto* srl = bodyIrb.CreateLShr(op0, op1);
	auto* srlZext = bodyIrb.CreateZExt(srl, doubleT);
	auto* op0Zext = bodyIrb.CreateZExt(op0, doubleT);
	auto* sub = bodyIrb.CreateSub(llvm::ConstantInt::get(op1->getType(), op0BitW + 1), op1);
	auto* subZext = bodyIrb.CreateZExt(sub, doubleT);
	auto* shl = bodyIrb.CreateShl(op0Zext, subZext);
	auto* sub2 = bodyIrb.CreateSub(llvm::ConstantInt::get(op1->getType(), op0BitW), op1);
	auto* shl2 = bodyIrb.CreateShl(cf, sub2);
	auto* shl2Zext = bodyIrb.CreateZExt(shl2, doubleT);
	auto* or1 = bodyIrb.CreateOr(shl, srlZext);
	auto* or2 = bodyIrb.CreateOr(or1, shl2Zext);
	auto* or2Trunc = bodyIrb.CreateTrunc(or2, op0->getType());
	setOp(xi->operands[0], or2Trunc, bodyIrb);

	auto* sub3 = bodyIrb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* shl3 = bodyIrb.CreateShl(llvm::ConstantInt::get(sub3->getType(), 1), sub3);
	auto* and1 = bodyIrb.CreateAnd(shl3, op0);
	auto* cfIcmp = bodyIrb.CreateICmpNE(and1, llvm::ConstantInt::get(and1->getType(), 0));
	storeRegister(X86_REG_CF, cfIcmp, bodyIrb);

	auto* of = loadRegister(X86_REG_OF, bodyIrb);
	auto* ofSrl = bodyIrb.CreateLShr(op0, llvm::ConstantInt::get(op0->getType(), op0BitW - 1));
	auto* ofIcmp = bodyIrb.CreateICmpNE(ofSrl, cf);
	auto* op1Eq1 = bodyIrb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* ofVal = bodyIrb.CreateSelect(op1Eq1, ofIcmp, of);
	storeRegister(X86_REG_OF, ofVal, bodyIrb);
}

/**
 * X86_INS_RCL
 */
void Capstone2LlvmIrTranslatorX86::translateRcl(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op1->getType(), maskC);
	op1 = irb.CreateAnd(op1, mask);
	auto* op1NotZero = irb.CreateICmpNE(op1, llvm::ConstantInt::get(op1->getType(), 0));

	auto bodyIrb = generateIfThen(op1NotZero, irb);

	auto* cf = loadRegister(X86_REG_CF, bodyIrb, op0->getType(), eOpConv::ZEXT_TRUNC);

	auto* shl = bodyIrb.CreateShl(op0, op1);
	auto* shlZext = bodyIrb.CreateZExt(shl, doubleT);
	auto* op0Zext = bodyIrb.CreateZExt(op0, doubleT);
	auto* sub = bodyIrb.CreateSub(llvm::ConstantInt::get(op1->getType(), op0BitW + 1), op1);
	auto* subZext = bodyIrb.CreateZExt(sub, doubleT);
	auto* srl = bodyIrb.CreateLShr(op0Zext, subZext);
	auto* sub2 = bodyIrb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* shl2 = bodyIrb.CreateShl(cf, sub2);
	auto* shl2Zext = bodyIrb.CreateZExt(shl2, doubleT);
	auto* or1 = bodyIrb.CreateOr(srl, shlZext);
	auto* or2 = bodyIrb.CreateOr(or1, shl2Zext);
	auto* or2Trunc = bodyIrb.CreateTrunc(or2, op0->getType());
	setOp(xi->operands[0], or2Trunc, bodyIrb);

	auto* shl3 = bodyIrb.CreateShl(op0, sub2);
	auto* srl2 = bodyIrb.CreateLShr(shl3, llvm::ConstantInt::get(shl3->getType(), op0BitW - 1));
	auto* cfIcmp = bodyIrb.CreateICmpNE(srl2, llvm::ConstantInt::get(srl2->getType(), 0));
	storeRegister(X86_REG_CF, cfIcmp, bodyIrb);

	auto* of = loadRegister(X86_REG_OF, bodyIrb);
	auto* ofSrl = bodyIrb.CreateLShr(or2Trunc, llvm::ConstantInt::get(or2Trunc->getType(), op0BitW - 1));
	auto* ofIcmp = bodyIrb.CreateICmpNE(ofSrl, srl2);
	auto* op1Eq1 = bodyIrb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* ofVal = bodyIrb.CreateSelect(op1Eq1, ofIcmp, of);
	storeRegister(X86_REG_OF, ofVal, bodyIrb);
}

/**
 * X86_INS_ROL
 */
void Capstone2LlvmIrTranslatorX86::translateRol(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op1->getType(), maskC);
	op1 = irb.CreateAnd(op1, mask);
	auto* op1NotZero = irb.CreateICmpNE(op1, llvm::ConstantInt::get(op1->getType(), 0));

	auto bodyIrb = generateIfThen(op1NotZero, irb);

	auto* shl = bodyIrb.CreateShl(op0, op1);
	auto* sub = bodyIrb.CreateSub(llvm::ConstantInt::get(op1->getType(), op0BitW), op1);
	auto* srl = bodyIrb.CreateLShr(op0, sub);
	auto* orr = bodyIrb.CreateOr(srl, shl);

	setOp(xi->operands[0], orr, bodyIrb);

	auto* and1 = bodyIrb.CreateAnd(orr, llvm::ConstantInt::get(orr->getType(), 1));
	auto* cfIcmp = bodyIrb.CreateICmpNE(and1, llvm::ConstantInt::get(orr->getType(), 0));
	storeRegister(X86_REG_CF, cfIcmp, bodyIrb);

	auto* of = loadRegister(X86_REG_OF, bodyIrb);
	auto* ofSrl = bodyIrb.CreateLShr(orr, llvm::ConstantInt::get(orr->getType(), op0BitW - 1));
	auto* ofIcmp = bodyIrb.CreateICmpNE(ofSrl, and1);
	auto* op1Eq1 = bodyIrb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* ofVal = bodyIrb.CreateSelect(op1Eq1, ofIcmp, of);
	storeRegister(X86_REG_OF, ofVal, bodyIrb);
}

/**
 * X86_INS_ROR
 */
void Capstone2LlvmIrTranslatorX86::translateRor(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_ZEXT);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op0->getType())->getBitWidth();
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op1->getType(), maskC);
	op1 = irb.CreateAnd(op1, mask);
	auto* op1NotZero = irb.CreateICmpNE(op1, llvm::ConstantInt::get(op1->getType(), 0));

	auto bodyIrb = generateIfThen(op1NotZero, irb);

	auto* srl = bodyIrb.CreateLShr(op0, op1);
	auto* sub = bodyIrb.CreateSub(llvm::ConstantInt::get(op1->getType(), op0BitW), op1);
	auto* shl = bodyIrb.CreateShl(op0, sub);
	auto* orr = bodyIrb.CreateOr(srl, shl);
	setOp(xi->operands[0], orr, bodyIrb);

	auto* cfSrl = bodyIrb.CreateLShr(orr, llvm::ConstantInt::get(orr->getType(), op0BitW - 1));
	auto* cfIcmp = bodyIrb.CreateICmpNE(cfSrl, llvm::ConstantInt::get(cfSrl->getType(), 0));
	storeRegister(X86_REG_CF, cfIcmp, bodyIrb);

	auto* of = loadRegister(X86_REG_OF, bodyIrb);
	auto* ofSrl = bodyIrb.CreateLShr(orr, llvm::ConstantInt::get(orr->getType(), op0BitW - 2));
	auto* ofAnd = bodyIrb.CreateAnd(ofSrl, llvm::ConstantInt::get(ofSrl->getType(), 1));
	auto* ofIcmp = bodyIrb.CreateICmpNE(cfSrl, ofAnd);
	auto* op1Eq1 = bodyIrb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 1));
	auto* ofVal = bodyIrb.CreateSelect(op1Eq1, ofIcmp, of);
	storeRegister(X86_REG_OF, ofVal, bodyIrb);
}

/**
 * X86_INS_STC
 */
void Capstone2LlvmIrTranslatorX86::translateStc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	storeRegister(X86_REG_CF, irb.getInt1(true), irb);
}

/**
 * X86_INS_STD
 */
void Capstone2LlvmIrTranslatorX86::translateStd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);
	storeRegister(X86_REG_DF, irb.getInt1(true), irb);
}

/**
 * X86_INS_SUB, X86_INS_CMP
 */
void Capstone2LlvmIrTranslatorX86::translateSub(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);

	auto* sub = irb.CreateSub(op0, op1);

	storeRegistersPlusSflags(irb, sub, {
			{X86_REG_AF, genBorrowSubInt4(op0, op1, irb)},
			{X86_REG_CF, genBorrowSub(op0, op1, irb)},
			{X86_REG_OF, genOverflowSub(sub, op0, op1, irb)}});
	if (i->id == X86_INS_SUB)
	{
		setOp(xi->operands[0], sub, irb);
	}
}

/**
 * X86_INS_XCHG
 */
void Capstone2LlvmIrTranslatorX86::translateXchg(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::NOTHING);
	// TODO:
	// Capstone may generate something like this:
	// "xchg eax, bp" at 0x1100107b in x86-pe-df4c5b7cdbb714f30fe958236c745d50
	// That should not be a valid instructions. Right now, we skip translation
	// of such case, but we could use this to detect that we are decoding bad
	// data -> instead of ignore or throw, we should behave as if capstone
	// decoding failed (might be implemented as throw catched by captone2llvm).
	//
	// However, that address should not even be translated.
	//
	if (op0->getType() != op1->getType())
	{
		return;
	}

	setOp(xi->operands[0], op1, irb);
	setOp(xi->operands[1], op0, irb);
}

/**
 * X86_INS_XLATB
 */
void Capstone2LlvmIrTranslatorX86::translateXlatb(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* al = loadRegister(X86_REG_AL, irb);
	llvm::Value* ebx = nullptr;
	switch (xi->addr_size)
	{
		case 2: ebx = loadRegister(X86_REG_BX, irb); break;  // Maybe DS:BX?
		case 4: ebx = loadRegister(X86_REG_EBX, irb); break; // Maybe DS:EBX?
		case 8: ebx = loadRegister(X86_REG_RBX, irb); break; // Only RBX.
		default: throw Capstone2LlvmIrError("Unhandled address size in XLATB.");
	}

	al = irb.CreateZExt(al, ebx->getType());
	auto* add = irb.CreateAdd(ebx, al);
	auto* ptrT = llvm::PointerType::get(irb.getInt8Ty(), 0);
	auto* addr = irb.CreateIntToPtr(add, ptrT);
	auto* l = irb.CreateLoad(addr);

	storeRegister(X86_REG_AL, l, irb);
}

/**
 * X86_INS_XOR
 */
void Capstone2LlvmIrTranslatorX86::translateXor(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::SECOND_SEXT);

	auto* xorOp = irb.CreateXor(op0, op1);

	storeRegistersPlusSflags(irb, xorOp, {
			{X86_REG_AF, irb.getInt1(false)},   // undef
			{X86_REG_CF, irb.getInt1(false)},   // cleared
			{X86_REG_OF, irb.getInt1(false)}}); // cleared

	setOp(xi->operands[0], xorOp, irb);
}

/**
 * X86_INS_LODSB, X86_INS_LODSW, X86_INS_LODSD, X86_INS_LODSQ
 * + REP prefix variants
 */
void Capstone2LlvmIrTranslatorX86::translateLoadString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 2);

	// REP prefix.
	//
	bool isRepPrefix = xi->prefix[0] == X86_PREFIX_REP;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isRepPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isRepPrefix ? irbP.second : irb;
	if (isRepPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	op1 = loadOp(xi->operands[1], body);
	setOp(xi->operands[0], op1, body);

	// We need to modify SI/ESI/RSI, it should be base register in memory op1.
	cs_x86_op& o1 = xi->operands[1];
	assert(o1.type == X86_OP_MEM);
	uint32_t siN = o1.mem.base;
	auto* si = loadRegister(siN, body);
	assert(si);
	auto* df = loadRegister(X86_REG_DF, body);

	llvm::Value* v1 = llvm::ConstantInt::getSigned(si->getType(), -o1.size);
	llvm::Value* v2 = llvm::ConstantInt::getSigned(si->getType(), o1.size);
	auto* val = body.CreateSelect(df, v1, v2);
	auto* add = body.CreateAdd(si, val);

	storeRegister(siN, add, body);

	// REP prefix.
	//
	if (isRepPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);
	}
}

/**
 * X86_INS_STOSB, X86_INS_STOSW, X86_INS_STOSD, X86_INS_STOSQ
 * + REP prefix variants
 */
void Capstone2LlvmIrTranslatorX86::translateStoreString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 2);

	// REP prefix.
	//
	bool isRepPrefix = xi->prefix[0] == X86_PREFIX_REP;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isRepPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isRepPrefix ? irbP.second : irb;
	if (isRepPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	op1 = loadOp(xi->operands[1], body);
	setOp(xi->operands[0], op1, body);

	// We need to modify DI/EDI/RDI, it should be base register in memory op0.
	cs_x86_op& o0 = xi->operands[0];
	assert(o0.type == X86_OP_MEM);
	uint32_t diN = o0.mem.base;
	auto* di = loadRegister(diN, body);
	assert(di);
	auto* df = loadRegister(X86_REG_DF, body);

	llvm::Value* v1 = llvm::ConstantInt::getSigned(di->getType(), -o0.size);
	llvm::Value* v2 = llvm::ConstantInt::getSigned(di->getType(), o0.size);
	auto* val = body.CreateSelect(df, v1, v2);
	auto* add = body.CreateAdd(di, val);

	storeRegister(diN, add, body);

	// REP prefix.
	//
	if (isRepPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);
	}
}

/**
 * X86_INS_MOVSB, X86_INS_MOVSW, X86_INS_MOVSD, X86_INS_MOVSQ
 * + REP prefix variants
 */
void Capstone2LlvmIrTranslatorX86::translateMoveString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: 10003351 @ movsd xmm0, qword ptr [edi + 8] in x86-pe-00d062fd23f36fbcdda3ae372f3dd975
	// even ida says:
	// .text:10003351                 movsd   xmm0, qword ptr [edi+8]
	//
	if (xi->op_count != 2
		|| xi->operands[0].type != X86_OP_MEM
		|| xi->operands[1].type != X86_OP_MEM)
	{
		return; // ignore
	}

	assert(xi->op_count == 2);
	assert(xi->operands[0].type == X86_OP_MEM);
	assert(xi->operands[1].type == X86_OP_MEM);

	// REP prefix.
	//
	bool isRepPrefix = xi->prefix[0] == X86_PREFIX_REP;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isRepPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isRepPrefix ? irbP.second : irb;
	if (isRepPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	op1 = loadOp(xi->operands[1], body);
	setOp(xi->operands[0], op1, body);

	// We need to modify DI/EDI/RDI, it should be base register in memory op0.
	cs_x86_op& o0 = xi->operands[0];
	uint32_t diN = o0.mem.base;
	auto* di = loadRegister(diN, body);
	assert(di);
	// We need to modify SI/ESI/RSI, it should be base register in memory op1.
	cs_x86_op& o1 = xi->operands[1];
	uint32_t siN = o1.mem.base;
	auto* si = loadRegister(siN, body);
	assert(si);

	auto* df = loadRegister(X86_REG_DF, body);
	assert(o0.size == o1.size);
	llvm::Value* v1 = llvm::ConstantInt::getSigned(di->getType(), -o0.size);
	llvm::Value* v2 = llvm::ConstantInt::getSigned(di->getType(), o0.size);
	auto* val = body.CreateSelect(df, v1, v2);
	auto* addDi = body.CreateAdd(di, val);
	auto* addSi = body.CreateAdd(si, val);

	storeRegister(diN, addDi, body);
	storeRegister(siN, addSi, body);

	// REP prefix.
	//
	if (isRepPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);
	}
}

/**
 * X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ
 */
void Capstone2LlvmIrTranslatorX86::translateScanString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// REPE/REPNE prefix.
	//
	bool isRepePrefix = xi->prefix[0] == X86_PREFIX_REPE;
	bool isRepnePrefix = xi->prefix[0] == X86_PREFIX_REPNE;
	bool isPrefix = isRepePrefix || isRepnePrefix;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isPrefix ? irbP.second : irb;
	if (isPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	std::tie(op0, op1) = loadOpBinary(xi, body, eOpConv::THROW);

	auto* sub = body.CreateSub(op0, op1);

	storeRegistersPlusSflags(body, sub, {
			{X86_REG_AF, genBorrowSubInt4(op0, op1, body)},
			{X86_REG_CF, genBorrowSub(op0, op1, body)},
			{X86_REG_OF, genOverflowSub(sub, op0, op1, body)}});

	// We need to modify DI/EDI/RDI, it should be base register in memory op1.
	cs_x86_op& o1 = xi->operands[1];
	uint32_t diN = o1.mem.base;
	auto* di = loadRegister(diN, body);
	assert(di);

	auto* df = loadRegister(X86_REG_DF, body);
	llvm::Value* v1 = llvm::ConstantInt::getSigned(di->getType(), -o1.size);
	llvm::Value* v2 = llvm::ConstantInt::getSigned(di->getType(), o1.size);
	auto* val = body.CreateSelect(df, v1, v2);
	auto* add = body.CreateAdd(di, val);

	storeRegister(diN, add, body);

	// REP/REPNE prefix.
	//
	if (isPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);

		auto* zf = loadRegister(X86_REG_ZF, body);
		if (isRepnePrefix)
		{
			llvm::BranchInst::Create(
					irb.GetInsertBlock(),        // zf == true -> break
					irbP.first.GetInsertBlock(),
					zf,
					body.GetInsertBlock()->getTerminator());
		}
		else if (isRepePrefix)
		{
			llvm::BranchInst::Create(
					irbP.first.GetInsertBlock(), // zf == true -> continue
					irb.GetInsertBlock(),
					zf,
					body.GetInsertBlock()->getTerminator());
		}
		body.GetInsertBlock()->getTerminator()->eraseFromParent();
	}
}

/**
 * X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ
 */
void Capstone2LlvmIrTranslatorX86::translateCompareString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 2);
	assert(xi->operands[0].type == X86_OP_MEM);
	assert(xi->operands[1].type == X86_OP_MEM);

	// REPE/REPNE prefix.
	//
	bool isRepePrefix = xi->prefix[0] == X86_PREFIX_REPE;
	bool isRepnePrefix = xi->prefix[0] == X86_PREFIX_REPNE;
	bool isPrefix = isRepePrefix || isRepnePrefix;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isPrefix ? irbP.second : irb;
	if (isPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	std::tie(op0, op1) = loadOpBinary(xi, body, eOpConv::THROW);

	auto* sub = body.CreateSub(op0, op1);

	storeRegistersPlusSflags(body, sub, {
			{X86_REG_AF, genBorrowSubInt4(op0, op1, body)},
			{X86_REG_CF, genBorrowSub(op0, op1, body)},
			{X86_REG_OF, genOverflowSub(sub, op0, op1, body)}});

	// We need to modify SI/ESI/RSI, it should be base register in memory op0.
	cs_x86_op& o0 = xi->operands[0];
	uint32_t siN = o0.mem.base;
	auto* si = loadRegister(siN, body);
	assert(si);
	// We need to modify DI/EDI/RDI, it should be base register in memory op1.
	cs_x86_op& o1 = xi->operands[1];
	uint32_t diN = o1.mem.base;
	auto* di = loadRegister(diN, body);
	assert(di);

	auto* df = loadRegister(X86_REG_DF, body);
	assert(o0.size == o1.size);
	llvm::Value* v1 = llvm::ConstantInt::getSigned(si->getType(), -o0.size);
	llvm::Value* v2 = llvm::ConstantInt::getSigned(si->getType(), o0.size);
	auto* val = body.CreateSelect(df, v1, v2);
	auto* addDi = body.CreateAdd(di, val);
	auto* addSi = body.CreateAdd(si, val);

	storeRegister(diN, addDi, body);
	storeRegister(siN, addSi, body);

	// REP/REPNE prefix.
	//
	if (isPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);

		auto* zf = loadRegister(X86_REG_ZF, body);
		if (isRepnePrefix)
		{
			llvm::BranchInst::Create(
					irb.GetInsertBlock(),        // zf == true -> break
					irbP.first.GetInsertBlock(),
					zf,
					body.GetInsertBlock()->getTerminator());
		}
		else if (isRepePrefix)
		{
			llvm::BranchInst::Create(
					irbP.first.GetInsertBlock(), // zf == true -> continue
					irb.GetInsertBlock(),
					zf,
					body.GetInsertBlock()->getTerminator());
		}
		body.GetInsertBlock()->getTerminator()->eraseFromParent();
	}
}

/**
 * X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JRCXZ
 */
void Capstone2LlvmIrTranslatorX86::translateJecxz(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	llvm::Value* ecx = nullptr;
	switch (xi->addr_size)
	{
		case 2: ecx = loadRegister(X86_REG_CX, irb); break;
		case 4: ecx = loadRegister(X86_REG_ECX, irb); break;
		case 8: ecx = loadRegister(X86_REG_RCX, irb); break;
		default: throw Capstone2LlvmIrError("Unhandled addr size in translateJecxz().");
	}

	auto* eqZ = irb.CreateICmpEQ(ecx, llvm::ConstantInt::get(ecx->getType(), 0));
	op0 = loadOpUnary(xi, irb);
	generateCondBranchFunctionCall(irb, eqZ, op0);
}

/**
 * X86_INS_LOOP, X86_INS_LOOPE (LOOPZ), X86_INS_LOOPNE (LOOPNZ)
 */
void Capstone2LlvmIrTranslatorX86::translateLoop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	uint32_t ecxN = X86_REG_INVALID;
	switch (xi->addr_size)
	{
		case 2: ecxN = X86_REG_CX; break;
		case 4: ecxN = X86_REG_ECX; break;
		case 8: ecxN = X86_REG_RCX; break;
		default: throw Capstone2LlvmIrError("Unhandled addr size in translateLoop().");
	}
	llvm::Value* ecx = loadRegister(ecxN, irb);

	auto* sub = irb.CreateSub(ecx, llvm::ConstantInt::get(ecx->getType(), 1));
	storeRegister(ecxN, sub, irb);

	llvm::Value* cnd = nullptr;
	switch (i->id)
	{
		case X86_INS_LOOP:
		{
			cnd = irb.CreateICmpNE(sub, llvm::ConstantInt::get(sub->getType(), 0));
			break;
		}
		case X86_INS_LOOPE:
		{
			auto* neZ = irb.CreateICmpNE(sub, llvm::ConstantInt::get(sub->getType(), 0));
			auto* zf = loadRegister(X86_REG_ZF, irb);
			cnd = irb.CreateAnd(neZ, zf);
			break;
		}
		case X86_INS_LOOPNE:
		{
			auto* eqZ = irb.CreateICmpEQ(sub, llvm::ConstantInt::get(sub->getType(), 0));
			auto* zf = loadRegister(X86_REG_ZF, irb);
			auto* orr = irb.CreateOr(eqZ, zf);
			cnd = irb.CreateXor(orr, irb.getInt1(true));
			break;
		}
		default:
		{
			throw Capstone2LlvmIrError("Unhandled insn ID in translateLoop().");
		}
	}

	op0 = loadOpUnary(xi, irb);
	generateCondBranchFunctionCall(irb, cnd, op0);
}

/**
 * X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JE, X86_INS_JGE,
 * X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JNE, X86_INS_JNO,
 * X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JS
 */
void Capstone2LlvmIrTranslatorX86::translateJCc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	llvm::Value* cond = nullptr;
	switch (i->id)
	{
		case X86_INS_JAE: cond = genCcAE(irb); break;
		case X86_INS_JA:  cond = genCcA(irb); break;
		case X86_INS_JBE: cond = genCcBE(irb); break;
		case X86_INS_JB:  cond = genCcB(irb); break;
		case X86_INS_JE:  cond = genCcE(irb); break;
		case X86_INS_JGE: cond = genCcGE(irb); break;
		case X86_INS_JG:  cond = genCcG(irb); break;
		case X86_INS_JLE: cond = genCcLE(irb); break;
		case X86_INS_JL:  cond = genCcL(irb); break;
		case X86_INS_JNE: cond = genCcNE(irb); break;
		case X86_INS_JNO: cond = genCcNO(irb); break;
		case X86_INS_JNP: cond = genCcNP(irb); break;
		case X86_INS_JNS: cond = genCcNS(irb); break;
		case X86_INS_JO:  cond = genCcO(irb); break;
		case X86_INS_JP:  cond = genCcP(irb); break;
		case X86_INS_JS:  cond = genCcS(irb); break;
		default: throw Capstone2LlvmIrError("Unhandled insn ID in translateJCc().");
	}

	op0 = loadOpUnary(xi, irb);
	generateCondBranchFunctionCall(irb, cond, op0);
}

/**
 * X86_INS_SETAE, X86_INS_SETA, X86_INS_SETBE, X86_INS_SETB, X86_INS_SETE,
 * X86_INS_SETGE, X86_INS_SETG, X86_INS_SETLE, X86_INS_SETL, X86_INS_SETNE,
 * X86_INS_SETNO, X86_INS_SETNP, X86_INS_SETNS, X86_INS_SETO, X86_INS_SETP,
 * X86_INS_SETS
 */
void Capstone2LlvmIrTranslatorX86::translateSetCc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 1);
	assert(xi->operands[0].size == 1); // This insn should always set byte.

	llvm::Value* cond = nullptr;
	switch (i->id)
	{
		case X86_INS_SETAE: cond = genCcAE(irb); break;
		case X86_INS_SETA:  cond = genCcA(irb); break;
		case X86_INS_SETBE: cond = genCcBE(irb); break;
		case X86_INS_SETB:  cond = genCcB(irb); break;
		case X86_INS_SETE:  cond = genCcE(irb); break;
		case X86_INS_SETGE: cond = genCcGE(irb); break;
		case X86_INS_SETG:  cond = genCcG(irb); break;
		case X86_INS_SETLE: cond = genCcLE(irb); break;
		case X86_INS_SETL:  cond = genCcL(irb); break;
		case X86_INS_SETNE: cond = genCcNE(irb); break;
		case X86_INS_SETNO: cond = genCcNO(irb); break;
		case X86_INS_SETNP: cond = genCcNP(irb); break;
		case X86_INS_SETNS: cond = genCcNS(irb); break;
		case X86_INS_SETO:  cond = genCcO(irb); break;
		case X86_INS_SETP:  cond = genCcP(irb); break;
		case X86_INS_SETS:  cond = genCcS(irb); break;
		default: throw Capstone2LlvmIrError("Unhandled insn ID in translateSetCc().");
	}

	// This should be done by setOp(), but we make sure here anyway.
	auto* val = irb.CreateZExtOrTrunc(cond, irb.getInt8Ty());

	setOp(xi->operands[0], val, irb);
}

/**
 * X86_INS_CMOVAE, X86_INS_CMOVA, X86_INS_CMOVBE, X86_INS_CMOVB, X86_INS_CMOVE,
 * X86_INS_CMOVGE, X86_INS_CMOVG, X86_INS_CMOVLE, X86_INS_CMOVL, X86_INS_CMOVNE,
 * X86_INS_CMOVNO, X86_INS_CMOVNP, X86_INS_CMOVNS, X86_INS_CMOVO, X86_INS_CMOVP,
 * X86_INS_CMOVS
 */
void Capstone2LlvmIrTranslatorX86::translateCMovCc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	llvm::Value* cond = nullptr;
	switch (i->id)
	{
		case X86_INS_CMOVAE: cond = genCcAE(irb); break;
		case X86_INS_CMOVA:  cond = genCcA(irb); break;
		case X86_INS_CMOVBE: cond = genCcBE(irb); break;
		case X86_INS_CMOVB:  cond = genCcB(irb); break;
		case X86_INS_CMOVE:  cond = genCcE(irb); break;
		case X86_INS_CMOVGE: cond = genCcGE(irb); break;
		case X86_INS_CMOVG:  cond = genCcG(irb); break;
		case X86_INS_CMOVLE: cond = genCcLE(irb); break;
		case X86_INS_CMOVL:  cond = genCcL(irb); break;
		case X86_INS_CMOVNE: cond = genCcNE(irb); break;
		case X86_INS_CMOVNO: cond = genCcNO(irb); break;
		case X86_INS_CMOVNP: cond = genCcNP(irb); break;
		case X86_INS_CMOVNS: cond = genCcNS(irb); break;
		case X86_INS_CMOVO:  cond = genCcO(irb); break;
		case X86_INS_CMOVP:  cond = genCcP(irb); break;
		case X86_INS_CMOVS:  cond = genCcS(irb); break;
		default: throw Capstone2LlvmIrError("Unhandled insn ID in translateSetCc().");
	}

	std::tie(op0, op1) = loadOpBinary(xi, irb, eOpConv::THROW);
	auto* val = irb.CreateSelect(cond, op1, op0);
	setOp(xi->operands[0], val, irb);
}

/**
 * X86_INS_FLD, X86_INS_FILD
 */
void Capstone2LlvmIrTranslatorX86::translateFld(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	if (i->id == X86_INS_FLD)
	{
		op0 = loadOpUnaryFloat(xi, irb, llvm::Type::getX86_FP80Ty(_module->getContext()), eOpConv::FP_CAST);
	}
	else
	{
		op0 = loadOpUnary(xi, irb, llvm::Type::getX86_FP80Ty(_module->getContext()), eOpConv::SITOFP);
	}
	auto* top = loadX87TopDec(irb);

	storeX87DataReg(irb, top, op0);
	storeRegister(X87_REG_TOP, top, irb);
}

/**
 * X86_INS_FLD1, X86_INS_FLDL2T, X86_INS_FLDL2E, X86_INS_FLDPI, X86_INS_FLDLG2,
 * X86_INS_FLDLN2, X86_INS_FLDZ
 */
void Capstone2LlvmIrTranslatorX86::translateFloadConstant(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87TopDec(irb);

	auto* fp80 = llvm::Type::getX86_FP80Ty(_module->getContext());
	llvm::Value* val = nullptr;
	switch (i->id)
	{
		case X86_INS_FLD1:
		{
			val = llvm::ConstantFP::get(fp80, 1.0);
			break;
		}
		case X86_INS_FLDL2T:
		{
			static double l2t = std::log2(10.0L);
			val = llvm::ConstantFP::get(fp80, l2t);
			break;
		}
		case X86_INS_FLDL2E:
		{
			static double l2e = std::log2(std::exp(1.0L));
			val = llvm::ConstantFP::get(fp80, l2e);
			break;
		}
		case X86_INS_FLDPI:
		{
			static double pi = 3.14159265358979323846;
			val = llvm::ConstantFP::get(fp80, pi);
			break;
		}
		case X86_INS_FLDLG2:
		{
			static double lg2 = std::log10(2.0L);
			val = llvm::ConstantFP::get(fp80, lg2);
			break;
		}
		case X86_INS_FLDLN2:
		{
			static double ln2 = std::log(2.0L);
			val = llvm::ConstantFP::get(fp80, ln2);
			break;
		}
		case X86_INS_FLDZ:
		{
			val = llvm::ConstantFP::get(fp80, 0.0);
			break;
		}
		default:
		{
			assert(false && "unhandled instruction ID");
			return;
		}
	}

	storeX87DataReg(irb, top, val);
	storeRegister(X87_REG_TOP, top, irb);
}

/**
 * X86_INS_FST, X86_INS_FSTP
 */
void Capstone2LlvmIrTranslatorX86::translateFst(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	llvm::Value* src = loadX87DataReg(irb, top);

	setOpFloat(xi->operands[0], src, irb);

	if (i->id == X86_INS_FSTP)
	{
		storeX87TagReg(irb, top, llvm::ConstantInt::get(irb.getIntNTy(2), 3)); // 0b11
		x87IncTop(irb, top);
	}
}

std::tuple<llvm::Value*, llvm::Value*, llvm::Value*, llvm::Value*>
Capstone2LlvmIrTranslatorX86::loadOpFloatingUnaryTop(
		cs_insn* i,
		cs_x86* xi,
		llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0 || xi->op_count == 1 || xi->op_count == 2);

	llvm::Value* top = loadX87Top(irb);
	llvm::Value* op0 = nullptr;
	llvm::Value* op1 = nullptr;
	llvm::Value* idx = nullptr;

	if (xi->op_count == 0)
	{
		idx = irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), 1));

		op0 = loadX87DataReg(irb, idx);
		op1 = loadX87DataReg(irb, top);
	}
	else if (xi->op_count == 2)
	{
		auto reg1 = xi->operands[0].reg;
		assert(X86_REG_ST0 <= reg1 && reg1 <= X86_REG_ST7);
		if (reg1 == X86_REG_ST0)
		{
			op0 = loadX87DataReg(irb, top);
			idx = top;
		}
		else
		{
			unsigned regOff = reg1 - X86_REG_ST0;
			idx = irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), regOff));
			op0 = loadX87DataReg(irb, idx);
		}

		auto reg2 = xi->operands[1].reg;
		assert(X86_REG_ST0 <= reg2 && reg2 <= X86_REG_ST7);
		if (reg2 == X86_REG_ST0)
		{
			op1 = loadX87DataReg(irb, top);
		}
		else
		{
			unsigned regOff = reg2 - X86_REG_ST0;
			auto* idx2 = irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), regOff));
			op1 = loadX87DataReg(irb, idx2);
		}
	}
	else if (xi->operands[0].type == X86_OP_REG)
	{
		auto reg = xi->operands[0].reg;
		assert(X86_REG_ST0 <= reg && reg <= X86_REG_ST7);
		unsigned regOff = reg - X86_REG_ST0;
		idx = irb.CreateAdd(top, llvm::ConstantInt::get(top->getType(), regOff));

		op0 = loadX87DataReg(irb, idx);
		op1 = loadX87DataReg(irb, top);
	}
	else if (xi->operands[0].type == X86_OP_MEM)
	{
		if (i->id == X86_INS_FIADD
				|| i->id == X86_INS_FIMUL
				|| i->id == X86_INS_FIDIV
				|| i->id == X86_INS_FIDIVR
				|| i->id == X86_INS_FISUB
				|| i->id == X86_INS_FISUBR)
		{
			op1 = loadOpUnary(xi, irb, llvm::Type::getX86_FP80Ty(_module->getContext()), eOpConv::SITOFP);
			op0 = loadX87DataReg(irb, top);
		}
		else if ( i->id == X86_INS_FICOM
				|| i->id == X86_INS_FICOMP)
		{
			op0 = loadOpUnary(xi, irb, llvm::Type::getX86_FP80Ty(_module->getContext()), eOpConv::UITOFP);
			op1 = loadX87DataReg(irb, top);
		}
		else
		{
			op0 = loadOpUnaryFloat(xi, irb, llvm::Type::getX86_FP80Ty(_module->getContext()), eOpConv::FP_CAST);
			op1 = loadX87DataReg(irb, top);
		}
		idx = top;
	}
	else
	{
		assert(false && "unhandled");
	}

	return std::make_tuple(op0, op1, top, idx);;
}

/**
 * X86_INS_FMUL, X86_INS_FMULP, X86_INS_FIMUL
 */
void Capstone2LlvmIrTranslatorX86::translateFmul(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	auto* fmul = irb.CreateFMul(op0, op1);

	storeX87DataReg(irb, idx, fmul);
	if (i->id == X86_INS_FMULP)
	{
		clearX87TagReg(irb, top); // pop
		x87IncTop(irb, top);
	}
}

/**
 * X86_INS_FADD, X86_INS_FADDP, X86_INS_FIADD
 */
void Capstone2LlvmIrTranslatorX86::translateFadd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	auto* fadd = irb.CreateFAdd(op0, op1);

	storeX87DataReg(irb, idx, fadd);
	if (i->id == X86_INS_FADDP)
	{
		clearX87TagReg(irb, top); // pop
		x87IncTop(irb, top);
	}
}

/**
 * X86_INS_FDIV, X86_INS_FDIVP, X86_INS_FIDIV
 */
void Capstone2LlvmIrTranslatorX86::translateFdiv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	auto* fdiv = irb.CreateFDiv(op0, op1); // or op1, op0?

	storeX87DataReg(irb, idx, fdiv);
	if (i->id == X86_INS_FDIVP)
	{
		clearX87TagReg(irb, top); // pop
		x87IncTop(irb, top);
	}
}

/**
 * X86_INS_FDIVR, X86_INS_FDIVRP, X86_INS_FIDIVR
 */
void Capstone2LlvmIrTranslatorX86::translateFdivr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	auto* fdiv = irb.CreateFDiv(op1, op0); // or op0, op1?

	storeX87DataReg(irb, idx, fdiv);
	if (i->id == X86_INS_FDIVRP)
	{
		clearX87TagReg(irb, top); // pop
		x87IncTop(irb, top);
	}
}

/**
 * X86_INS_FSUB, X86_INS_FSUBP, X86_INS_FISUB
 */
void Capstone2LlvmIrTranslatorX86::translateFsub(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	auto* fsub = irb.CreateFSub(op0, op1); // or op1, op0?

	storeX87DataReg(irb, idx, fsub);
	if (i->id == X86_INS_FSUBP)
	{
		clearX87TagReg(irb, top); // pop
		x87IncTop(irb, top);
	}
}

/**
 * X86_INS_FSUBR, X86_INS_FSUBRP, X86_INS_FISUBR
 */
void Capstone2LlvmIrTranslatorX86::translateFsubr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	//        op, top
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	auto* fsub = irb.CreateFSub(op0, op1); // or op1, op0?

	storeX87DataReg(irb, idx, fsub);
	if (i->id == X86_INS_FSUBRP)
	{
		clearX87TagReg(irb, top); // pop
		x87IncTop(irb, top);
	}
}

/**
 * X86_INS_FABS
 */
void Capstone2LlvmIrTranslatorX86::translateFabs(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	op0 = loadX87DataReg(irb, top);
	auto* f = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::fabs, op0->getType());
	auto* fabs = irb.CreateCall(f, {op0});

	storeX87DataReg(irb, top, fabs);
}

/**
 * X86_INS_FCHS
 */
void Capstone2LlvmIrTranslatorX86::translateFchs(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	op0 = loadX87DataReg(irb, top);
	auto* res = irb.CreateFSub(llvm::ConstantFP::getZeroValueForNegation(op0->getType()), op0);

	storeX87DataReg(irb, top, res);
}

/**
 * X86_INS_FSQRT
 */
void Capstone2LlvmIrTranslatorX86::translateFsqrt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	op0 = loadX87DataReg(irb, top);
	auto* f = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::sqrt, op0->getType());
	auto* fabs = irb.CreateCall(f, {op0});

	storeX87DataReg(irb, top, fabs);
}

/**
 * X86_INS_FXCH
 */
void Capstone2LlvmIrTranslatorX86::translateFxch(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	storeX87DataReg(irb, top, op0);
	storeX87DataReg(irb, idx, op1);
}

/**
 * X86_INS_FXAM
 */
void Capstone2LlvmIrTranslatorX86::translateFxam(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
}

/**
 * X86_INS_FNSTCW
 */
void Capstone2LlvmIrTranslatorX86::translateFnstcw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
}

/**
 * X86_INS_FNSTSW
 */
void Capstone2LlvmIrTranslatorX86::translateFnstsw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
}

/**
 * X86_INS_FNSTENV
 */
void Capstone2LlvmIrTranslatorX86::translateFnstenv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
}

/**
 * X86_INS_FLDCW
 */
void Capstone2LlvmIrTranslatorX86::translateFldcw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
}

/**
 * X86_INS_FLDENV
 */
void Capstone2LlvmIrTranslatorX86::translateFldenv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO
}

/**
 * X86_INS_FCOS
 */
void Capstone2LlvmIrTranslatorX86::translateFcos(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	op0 = loadX87DataReg(irb, top);
	auto* fabs = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::fabs, op0->getType());
	auto* absCall = irb.CreateCall(fabs, {op0});
	auto* fc = llvm::ConstantFP::get(absCall->getType(), 9223372036854775808.0); // 1 << 63
	auto* olt = irb.CreateFCmpOLT(absCall, fc);

	auto irbP = generateIfThenElse(olt, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(X87_REG_C2, bodyIf.getFalse(), bodyIf);
	auto* cos = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::cos, op0->getType());
	auto* cosCall = bodyIf.CreateCall(cos, {op0});
	storeX87DataReg(bodyIf, top, cosCall);

	storeRegister(X87_REG_C2, bodyElse.getTrue(), bodyElse);
}

/**
 * X86_INS_FSINCOS
 */
void Capstone2LlvmIrTranslatorX86::translateFsincos(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	op0 = loadX87DataReg(irb, top);
	auto* fabs = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::fabs, op0->getType());
	auto* absCall = irb.CreateCall(fabs, {op0});
	auto* fc = llvm::ConstantFP::get(absCall->getType(), 9223372036854775808.0); // 1 << 63
	auto* olt = irb.CreateFCmpOLT(absCall, fc);

	auto irbP = generateIfThenElse(olt, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(X87_REG_C2, bodyIf.getFalse(), bodyIf);
	auto* sin = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::sin, op0->getType());
	auto* sinCall = bodyIf.CreateCall(sin, {op0});
	storeX87DataReg(bodyIf, top, sinCall);

	auto* cos = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::cos, op0->getType());
	auto* cosCall = bodyIf.CreateCall(cos, {op0});
	auto* nTop = x87DecTop(bodyIf, top);
	storeX87DataReg(bodyIf, nTop, cosCall);

	storeRegister(X87_REG_C2, bodyElse.getTrue(), bodyElse);
}

/**
 * X86_INS_FSIN
 */
void Capstone2LlvmIrTranslatorX86::translateFsin(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* top = loadX87Top(irb);
	op0 = loadX87DataReg(irb, top);
	auto* fabs = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::fabs, op0->getType());
	auto* absCall = irb.CreateCall(fabs, {op0});
	auto* fc = llvm::ConstantFP::get(absCall->getType(), 9223372036854775808.0); // 1 << 63
	auto* olt = irb.CreateFCmpOLT(absCall, fc);

	auto irbP = generateIfThenElse(olt, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(X87_REG_C2, bodyIf.getFalse(), bodyIf);
	auto* sin = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::sin, op0->getType());
	auto* sinCall = bodyIf.CreateCall(sin, {op0});
	storeX87DataReg(bodyIf, top, sinCall);

	storeRegister(X87_REG_C2, bodyElse.getTrue(), bodyElse);
}

/**
 * X86_INS_FINCSTP
 */
void Capstone2LlvmIrTranslatorX86::translateFincstp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	x87IncTop(irb);
	storeRegister(X87_REG_C1, irb.getFalse(), irb);
}

/**
 * X86_INS_FDECSTP
 */
void Capstone2LlvmIrTranslatorX86::translateFdecstp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	x87DecTop(irb);
	storeRegister(X87_REG_C1, irb.getFalse(), irb);
}

/**
 * X86_INS_FUCOM, X86_INS_FUCOMP, X86_INS_FUCOMPP
 * X86_INS_FCOM, X86_INS_FCOMP, X86_INS_FCOMPP
 * X86_INS_FUCOMI, X86_INS_FUCOMIP
 * X86_INS_FCOMI, X86_INS_FCOMIP
 * X86_INS_FTST
 * X86_INS_FICOM, X86_INS_FICOMP
 */
void Capstone2LlvmIrTranslatorX86::translateFucomPop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	bool doublePop = i->id == X86_INS_FUCOMPP || i->id == X86_INS_FCOMPP;
	bool pop = i->id == X86_INS_FUCOMP || i->id == X86_INS_FCOMP
			|| i->id == X86_INS_FUCOMIP || i->id == X86_INS_FCOMIP
			|| i->id == X86_INS_FICOMP || doublePop;

	uint32_t r1 = X87_REG_C0;
	uint32_t r2 = X87_REG_C2;
	uint32_t r3 = X87_REG_C3;
	if (i->id == X86_INS_FUCOMI
			|| i->id == X86_INS_FUCOMIP
			|| i->id == X86_INS_FCOMI
			|| i->id == X86_INS_FCOMIP)
	{
		r1 = X86_REG_CF;
		r2 = X86_REG_PF;
		r3 = X86_REG_ZF;
	}

	// op1 == top
	std::tie(op0, op1, top, idx) = loadOpFloatingUnaryTop(i, xi, irb);

	if (i->id == X86_INS_FTST)
	{
		op0 = llvm::ConstantFP::get(op1->getType(), 0.0);
	}

	auto* fcmpOgt = irb.CreateFCmpOGT(op1, op0);
	auto irbP = generateIfThenElse(fcmpOgt, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(r1, bodyIf.getFalse(), bodyIf);
	storeRegister(r2, bodyIf.getFalse(), bodyIf);
	storeRegister(r3, bodyIf.getFalse(), bodyIf);
	if (pop)
	{
		clearX87TagReg(bodyIf, top); // pop
		auto* top1 = x87IncTop(bodyIf, top);
		if (doublePop)
		{
			clearX87TagReg(bodyIf, top1); // pop
			x87IncTop(bodyIf, top1);
		}
	}

	auto* fcmpOlt = bodyElse.CreateFCmpOLT(op1, op0);
	auto irbP1 = generateIfThenElse(fcmpOlt, bodyElse);
	llvm::IRBuilder<>& bodyIf1(irbP1.first), bodyElse1(irbP1.second);

	storeRegister(r1, bodyIf1.getTrue(), bodyIf1);
	storeRegister(r2, bodyIf1.getFalse(), bodyIf1);
	storeRegister(r3, bodyIf1.getFalse(), bodyIf1);
	if (pop)
	{
		clearX87TagReg(bodyIf1, top); // pop
		auto* top1 = x87IncTop(bodyIf1, top);
		if (doublePop)
		{
			clearX87TagReg(bodyIf1, top1); // pop
			x87IncTop(bodyIf1, top1);
		}
	}

	auto* fcmpOeq = bodyElse1.CreateFCmpOEQ(op1, op0);
	storeRegister(r3, bodyElse1.getTrue(), bodyElse1);
	auto irbP2 = generateIfThenElse(fcmpOeq, bodyElse1);
	llvm::IRBuilder<>& bodyIf2(irbP2.first), bodyElse2(irbP2.second);

	storeRegister(r1, bodyIf2.getFalse(), bodyIf2);
	storeRegister(r2, bodyIf2.getFalse(), bodyIf2);
	if (pop)
	{
		clearX87TagReg(bodyIf2, top); // pop
		auto* top1 = x87IncTop(bodyIf2, top);
		if (doublePop)
		{
			clearX87TagReg(bodyIf2, top1); // pop
			x87IncTop(bodyIf2, top1);
		}
	}

	storeRegister(r1, bodyElse2.getTrue(), bodyElse2);
	storeRegister(r2, bodyElse2.getTrue(), bodyElse2);
	if (pop)
	{
		clearX87TagReg(bodyElse2, top); // pop
		auto* top1 = x87IncTop(bodyElse2, top);
		if (doublePop)
		{
			clearX87TagReg(bodyElse2, top1); // pop
			x87IncTop(bodyElse2, top1);
		}
	}
}

/**
 * X86_INS_FIST, X86_INS_FISTP
 */
void Capstone2LlvmIrTranslatorX86::translateFist(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 1);

	auto* topNum = loadX87Top(irb);
	auto* top = loadX87DataReg(irb, topNum);
	auto* t = getIntegerTypeFromByteSize(xi->operands[0].size);
	auto* fptosi = irb.CreateFPToSI(top, t);
	setOp(xi->operands[0], fptosi, irb);

	if (i->id == X86_INS_FISTP)
	{
		clearX87TagReg(irb, topNum); // pop
		x87IncTop(irb, topNum);
	}
}

/**
 * X86_INS_FRNDINT
 */
void Capstone2LlvmIrTranslatorX86::translateFrndint(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	assert(xi->op_count == 0);

	auto* top = loadX87Top(irb);
	llvm::Value* src = loadX87DataReg(irb, top);
	auto* f = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::round, src->getType());
	auto* val = irb.CreateCall(f, {src});
	storeX87DataReg(irb, top, val);
}

/**
 * X86_INS_CPUID
 */
void Capstone2LlvmIrTranslatorX86::translateCpuid(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	llvm::Type* i32 = irb.getInt32Ty();
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_cpuid",
			llvm::StructType::create({i32, i32, i32, i32}),
			{i32});

	auto* eax = loadRegister(X86_REG_EAX, irb);
	auto* c = irb.CreateCall(fnc, {eax});
	storeRegister(X86_REG_EAX, irb.CreateExtractValue(c, {0}), irb);
	storeRegister(X86_REG_EBX, irb.CreateExtractValue(c, {1}), irb);
	storeRegister(X86_REG_ECX, irb.CreateExtractValue(c, {2}), irb);
	storeRegister(X86_REG_EDX, irb.CreateExtractValue(c, {3}), irb);
}

/**
 * X86_INS_OUTSB, X86_INS_OUTSD, X86_INS_OUTSW
 */
void Capstone2LlvmIrTranslatorX86::translateOuts(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::string name;
	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case X86_INS_OUTSB: name = "__asm_outsb"; ty = irb.getInt8Ty(); break;
		case X86_INS_OUTSW: name = "__asm_outsw"; ty = irb.getInt16Ty(); break;
		case X86_INS_OUTSD: name = "__asm_outsd"; ty = irb.getInt32Ty(); break;
		default: throw Capstone2LlvmIrError("Unhandled insn ID.");
	}
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			name,
			{irb.getInt16Ty(), ty});

	// REP prefix.
	//
	bool isRepPrefix = xi->prefix[0] == X86_PREFIX_REP;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isRepPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isRepPrefix ? irbP.second : irb;
	if (isRepPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	std::tie(op0, op1) = loadOpBinary(xi, body, eOpConv::NOTHING);
	auto* dx = body.CreateZExtOrTrunc(op0, body.getInt16Ty());
	auto* val = body.CreateZExtOrTrunc(op1, ty);
	body.CreateCall(fnc, {dx, val});

	// REP prefix.
	//
	if (isRepPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);
	}
}

/**
 * X86_INS_INSB, X86_INS_INSW, X86_INS_INSD
 */
void Capstone2LlvmIrTranslatorX86::translateIns(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	std::string name;
	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case X86_INS_INSB: name = "__asm_insb"; ty = irb.getInt8Ty(); break;
		case X86_INS_INSW: name = "__asm_insw"; ty = irb.getInt16Ty(); break;
		case X86_INS_INSD: name = "__asm_insd"; ty = irb.getInt32Ty(); break;
		default: throw Capstone2LlvmIrError("Unhandled insn ID.");
	}
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			name,
			ty,
			{irb.getInt16Ty()});

	// REP prefix.
	//
	bool isRepPrefix = xi->prefix[0] == X86_PREFIX_REP;
	llvm::BranchInst* branch = nullptr;
	llvm::Value* cntr = nullptr;
	auto irbP = isRepPrefix ? generateWhile(branch, irb) : std::make_pair(irb, irb);
	llvm::IRBuilder<>& body = isRepPrefix ? irbP.second : irb;
	if (isRepPrefix)
	{
		llvm::IRBuilder<>& before = irbP.first;
		cntr = loadRegister(getParentRegister(X86_REG_CX), before);
		auto* cond = before.CreateICmpNE(cntr, llvm::ConstantInt::get(cntr->getType(), 0));
		branch->setCondition(cond);
	}

	// Body.
	//
	auto* dx = loadRegister(X86_REG_DX, body);
	auto* c = body.CreateCall(fnc, {dx});
	setOp(xi->operands[0], c, body);

	// REP prefix.
	//
	if (isRepPrefix)
	{
		auto* sub = body.CreateSub(cntr, llvm::ConstantInt::get(cntr->getType(), 1));
		storeRegister(getParentRegister(X86_REG_CX), sub, body);
	}
}

/**
 * X86_INS_RDTSC
 */
void Capstone2LlvmIrTranslatorX86::translateRdtsc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_rdtsc",
			llvm::StructType::create({irb.getInt32Ty(), irb.getInt32Ty()}));

	auto* c = irb.CreateCall(fnc);
	storeRegister(X86_REG_EDX, irb.CreateExtractValue(c, {0}), irb);
	storeRegister(X86_REG_EAX, irb.CreateExtractValue(c, {1}), irb);
}

/**
 * X86_INS_RDTSCP
 */
void Capstone2LlvmIrTranslatorX86::translateRdtscp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	auto* i32 = irb.getInt32Ty();
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_rdtscp",
			llvm::StructType::create({i32, i32, i32}));

	auto* c = irb.CreateCall(fnc);
	storeRegister(X86_REG_EDX, irb.CreateExtractValue(c, {0}), irb);
	storeRegister(X86_REG_EAX, irb.CreateExtractValue(c, {1}), irb);
	storeRegister(X86_REG_ECX, irb.CreateExtractValue(c, {2}), irb);
}

/**
 * X86_INS_INT
 */
void Capstone2LlvmIrTranslatorX86::translateInt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

/**
 * X86_INS_INT1
 */
void Capstone2LlvmIrTranslatorX86::translateInt1(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

/**
 * X86_INS_INT3
 */
void Capstone2LlvmIrTranslatorX86::translateInt3(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

/**
 * X86_INS_INTO
 */
void Capstone2LlvmIrTranslatorX86::translateInto(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

/**
 * X86_INS_HLT
 */
void Capstone2LlvmIrTranslatorX86::translateHlt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

/**
 * X86_INS_WAIT
 */
void Capstone2LlvmIrTranslatorX86::translateWait(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

/**
 * X86_INS_BOUND
 */
void Capstone2LlvmIrTranslatorX86::translateBound(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb)
{
	// TODO: generate ASM pseudo function
}

} // namespace capstone2llvmir
} // namespace retdec
