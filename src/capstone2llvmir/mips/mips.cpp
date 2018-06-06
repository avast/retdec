/**
 * @file src/capstone2llvmir/mips/mips.cpp
 * @brief MIPS implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "capstone2llvmir/mips/mips_impl.h"

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorMips_impl::Capstone2LlvmIrTranslatorMips_impl(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator_impl(CS_ARCH_MIPS, basic, extra, m)
{
	// This needs to be called from concrete's class ctor, not abstract's
	// class ctor, so that virtual table is properly initialized.
	initialize();
}

Capstone2LlvmIrTranslatorMips_impl::~Capstone2LlvmIrTranslatorMips_impl()
{
	// Nothing specific to MIPS.
}

//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

bool Capstone2LlvmIrTranslatorMips_impl::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_MIPS32
			|| m == CS_MODE_MIPS64
			|| m == CS_MODE_MIPS3
			|| m == CS_MODE_MIPS32R6;
}

bool Capstone2LlvmIrTranslatorMips_impl::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN
			|| m == CS_MODE_BIG_ENDIAN
			|| m == CS_MODE_MICRO;
}

uint32_t Capstone2LlvmIrTranslatorMips_impl::getArchByteSize()
{
	switch (_origBasicMode)
	{
		case CS_MODE_MIPS32:
		case CS_MODE_MIPS32R6:
		case CS_MODE_MIPS3:
			return 4;
		case CS_MODE_MIPS64:
			return 8;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in getArchByteSize().");
			break;
		}
	}
}

//
//==============================================================================
// Capstone related getters - from Capstone2LlvmIrTranslator.
//==============================================================================
//

bool Capstone2LlvmIrTranslatorMips_impl::hasDelaySlot(uint32_t id) const
{
	return getDelaySlot(id);
}

bool Capstone2LlvmIrTranslatorMips_impl::hasDelaySlotTypical(uint32_t id) const
{
	return getDelaySlot(id) && !hasDelaySlotLikely(id);
}

bool Capstone2LlvmIrTranslatorMips_impl::hasDelaySlotLikely(uint32_t id) const
{
	static std::set<uint32_t> set =
	{
			MIPS_INS_BC1FL, MIPS_INS_BC1TL, MIPS_INS_BEQL, MIPS_INS_BNEL,
			MIPS_INS_BLEZL, MIPS_INS_BGTZL, MIPS_INS_BLTZL, MIPS_INS_BGEZL,
			MIPS_INS_BGEZALL, MIPS_INS_BLTZALL
	};
	return set.count(id);
}

/**
 * At the moment, all instructions here have delay slot of size 1.
 * If there are some instructions with different sized slots, we will need map.
 */
std::size_t Capstone2LlvmIrTranslatorMips_impl::getDelaySlot(uint32_t id) const
{
	static std::set<uint32_t> set =
	{
			// cond branch
			MIPS_INS_BC1F, MIPS_INS_BC1FL, MIPS_INS_BC1T, MIPS_INS_BC1TL,
			MIPS_INS_BEQ, MIPS_INS_BEQL, MIPS_INS_BNE, MIPS_INS_BNEL,
			MIPS_INS_BLEZ, MIPS_INS_BLEZL, MIPS_INS_BGTZ, MIPS_INS_BGTZL,
			MIPS_INS_BLTZ, MIPS_INS_BLTZL, MIPS_INS_BGEZ, MIPS_INS_BGEZL,
			MIPS_INS_BEQZ, MIPS_INS_BNEZ,
			// call
			MIPS_INS_BGEZAL, MIPS_INS_BGEZALL, MIPS_INS_BLTZAL,
			MIPS_INS_BLTZALL, MIPS_INS_JAL, MIPS_INS_JALR,
			MIPS_INS_BAL,
			// branch
			MIPS_INS_J, MIPS_INS_JR,
			MIPS_INS_B,
	};
	return set.count(id);
}

//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorMips_impl::generateEnvironmentArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorMips_impl::generateDataLayout()
{
	switch (_basicMode)
	{
		case CS_MODE_MIPS32:
		case CS_MODE_MIPS32R6:
		case CS_MODE_MIPS3:
			// clang -m32 -> this will screw up few tests, some LLVM passes
			// (e.g. -instcombine) behaves differently, e.g. generates really
			// stupid loads from float registers:
			// "load i32, i32* bitcast (float* @f0 to i32*), align 4"
			//
//			_module->setDataLayout("E-m:m-p:32:32-i8:8:32-i16:16:32-i64:64-n32-S64");
			// original, works ok
			_module->setDataLayout("e-p:32:32:32-f80:32:32");
			break;
		case CS_MODE_MIPS64:
			// TODO: This may have the same problems as the 32-bit version.
			_module->setDataLayout("E-m:m-i8:8:32-i16:16:32-i64:64-n32:64-S128"); // clang -m64
			break;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in generateDataLayout().");
			break;
		}
	}
}

void Capstone2LlvmIrTranslatorMips_impl::generateRegisters()
{
	// Program counter.
	//
	createRegister(MIPS_REG_PC, _regLt);

	// Multiply and divide registers.
	//
	createRegister(MIPS_REG_HI, _regLt);
	createRegister(MIPS_REG_LO, _regLt);

	// General purpose registers.
	//
	createRegister(MIPS_REG_0, _regLt);
	createRegister(MIPS_REG_1, _regLt);
	createRegister(MIPS_REG_2, _regLt);
	createRegister(MIPS_REG_3, _regLt);
	createRegister(MIPS_REG_4, _regLt);
	createRegister(MIPS_REG_5, _regLt);
	createRegister(MIPS_REG_6, _regLt);
	createRegister(MIPS_REG_7, _regLt);
	createRegister(MIPS_REG_8, _regLt);
	createRegister(MIPS_REG_9, _regLt);
	createRegister(MIPS_REG_10, _regLt);
	createRegister(MIPS_REG_11, _regLt);
	createRegister(MIPS_REG_12, _regLt);
	createRegister(MIPS_REG_13, _regLt);
	createRegister(MIPS_REG_14, _regLt);
	createRegister(MIPS_REG_15, _regLt);
	createRegister(MIPS_REG_16, _regLt);
	createRegister(MIPS_REG_17, _regLt);
	createRegister(MIPS_REG_18, _regLt);
	createRegister(MIPS_REG_19, _regLt);
	createRegister(MIPS_REG_20, _regLt);
	createRegister(MIPS_REG_21, _regLt);
	createRegister(MIPS_REG_22, _regLt);
	createRegister(MIPS_REG_23, _regLt);
	createRegister(MIPS_REG_24, _regLt);
	createRegister(MIPS_REG_25, _regLt);
	createRegister(MIPS_REG_26, _regLt);
	createRegister(MIPS_REG_27, _regLt);
	createRegister(MIPS_REG_28, _regLt);
	createRegister(MIPS_REG_29, _regLt);
	createRegister(MIPS_REG_30, _regLt);
	createRegister(MIPS_REG_31, _regLt);

	// FPU registers.
	//
	createRegister(MIPS_REG_F0, _regLt);
	createRegister(MIPS_REG_F1, _regLt);
	createRegister(MIPS_REG_F2, _regLt);
	createRegister(MIPS_REG_F3, _regLt);
	createRegister(MIPS_REG_F4, _regLt);
	createRegister(MIPS_REG_F5, _regLt);
	createRegister(MIPS_REG_F6, _regLt);
	createRegister(MIPS_REG_F7, _regLt);
	createRegister(MIPS_REG_F8, _regLt);
	createRegister(MIPS_REG_F9, _regLt);
	createRegister(MIPS_REG_F10, _regLt);
	createRegister(MIPS_REG_F11, _regLt);
	createRegister(MIPS_REG_F12, _regLt);
	createRegister(MIPS_REG_F13, _regLt);
	createRegister(MIPS_REG_F14, _regLt);
	createRegister(MIPS_REG_F15, _regLt);
	createRegister(MIPS_REG_F16, _regLt);
	createRegister(MIPS_REG_F17, _regLt);
	createRegister(MIPS_REG_F18, _regLt);
	createRegister(MIPS_REG_F19, _regLt);
	createRegister(MIPS_REG_F20, _regLt);
	createRegister(MIPS_REG_F21, _regLt);
	createRegister(MIPS_REG_F22, _regLt);
	createRegister(MIPS_REG_F23, _regLt);
	createRegister(MIPS_REG_F24, _regLt);
	createRegister(MIPS_REG_F25, _regLt);
	createRegister(MIPS_REG_F26, _regLt);
	createRegister(MIPS_REG_F27, _regLt);
	createRegister(MIPS_REG_F28, _regLt);
	createRegister(MIPS_REG_F29, _regLt);
	createRegister(MIPS_REG_F30, _regLt);
	createRegister(MIPS_REG_F31, _regLt);

	if (getRegisterType(MIPS_REG_F0)->isFloatTy())
	{
		createRegister(MIPS_REG_FD0, _regLt);
		createRegister(MIPS_REG_FD2, _regLt);
		createRegister(MIPS_REG_FD4, _regLt);
		createRegister(MIPS_REG_FD6, _regLt);
		createRegister(MIPS_REG_FD8, _regLt);
		createRegister(MIPS_REG_FD10, _regLt);
		createRegister(MIPS_REG_FD12, _regLt);
		createRegister(MIPS_REG_FD14, _regLt);
		createRegister(MIPS_REG_FD16, _regLt);
		createRegister(MIPS_REG_FD18, _regLt);
		createRegister(MIPS_REG_FD20, _regLt);
		createRegister(MIPS_REG_FD22, _regLt);
		createRegister(MIPS_REG_FD24, _regLt);
		createRegister(MIPS_REG_FD26, _regLt);
		createRegister(MIPS_REG_FD28, _regLt);
		createRegister(MIPS_REG_FD30, _regLt);
	}

	createRegister(MIPS_REG_FCC0, _regLt);
	createRegister(MIPS_REG_FCC1, _regLt);
	createRegister(MIPS_REG_FCC2, _regLt);
	createRegister(MIPS_REG_FCC3, _regLt);
	createRegister(MIPS_REG_FCC4, _regLt);
	createRegister(MIPS_REG_FCC5, _regLt);
	createRegister(MIPS_REG_FCC6, _regLt);
	createRegister(MIPS_REG_FCC7, _regLt);

	createRegister(MIPS_REG_W0, _regLt);
	createRegister(MIPS_REG_W1, _regLt);
	createRegister(MIPS_REG_W2, _regLt);
	createRegister(MIPS_REG_W3, _regLt);
	createRegister(MIPS_REG_W4, _regLt);
	createRegister(MIPS_REG_W5, _regLt);
	createRegister(MIPS_REG_W6, _regLt);
	createRegister(MIPS_REG_W7, _regLt);
	createRegister(MIPS_REG_W8, _regLt);
	createRegister(MIPS_REG_W9, _regLt);
	createRegister(MIPS_REG_W10, _regLt);
	createRegister(MIPS_REG_W11, _regLt);
	createRegister(MIPS_REG_W12, _regLt);
	createRegister(MIPS_REG_W13, _regLt);
	createRegister(MIPS_REG_W14, _regLt);
	createRegister(MIPS_REG_W15, _regLt);
	createRegister(MIPS_REG_W16, _regLt);
	createRegister(MIPS_REG_W17, _regLt);
	createRegister(MIPS_REG_W18, _regLt);
	createRegister(MIPS_REG_W19, _regLt);
	createRegister(MIPS_REG_W20, _regLt);
	createRegister(MIPS_REG_W21, _regLt);
	createRegister(MIPS_REG_W22, _regLt);
	createRegister(MIPS_REG_W23, _regLt);
	createRegister(MIPS_REG_W24, _regLt);
	createRegister(MIPS_REG_W25, _regLt);
	createRegister(MIPS_REG_W26, _regLt);
	createRegister(MIPS_REG_W27, _regLt);
	createRegister(MIPS_REG_W28, _regLt);
	createRegister(MIPS_REG_W29, _regLt);
	createRegister(MIPS_REG_W30, _regLt);
	createRegister(MIPS_REG_W31, _regLt);

	createRegister(MIPS_REG_AC0, _regLt);
	createRegister(MIPS_REG_AC1, _regLt);
	createRegister(MIPS_REG_AC2, _regLt);
	createRegister(MIPS_REG_AC3, _regLt);

	createRegister(MIPS_REG_CC0, _regLt);
	createRegister(MIPS_REG_CC1, _regLt);
	createRegister(MIPS_REG_CC2, _regLt);
	createRegister(MIPS_REG_CC3, _regLt);
	createRegister(MIPS_REG_CC4, _regLt);
	createRegister(MIPS_REG_CC5, _regLt);
	createRegister(MIPS_REG_CC6, _regLt);
	createRegister(MIPS_REG_CC7, _regLt);

	createRegister(MIPS_REG_P0, _regLt);
	createRegister(MIPS_REG_P1, _regLt);
	createRegister(MIPS_REG_P2, _regLt);

	createRegister(MIPS_REG_MPL0, _regLt);
	createRegister(MIPS_REG_MPL1, _regLt);
	createRegister(MIPS_REG_MPL2, _regLt);
}

uint32_t Capstone2LlvmIrTranslatorMips_impl::getCarryRegister()
{
	return MIPS_REG_INVALID;
}

void Capstone2LlvmIrTranslatorMips_impl::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	_insn = i;

	cs_detail* d = i->detail;
	cs_mips* mi = &d->mips;

	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;
		(this->*f)(i, mi, irb);
	}
	else
	{
		// TODO: Automatically generate pseudo asm call.
	}
}

//
//==============================================================================
// MIPS-specific methods.
//==============================================================================
//

/**
 * TODO: Maybe move this to the abstract class level? If all (most) archs
 * compute the current pc the same -- address of the next instruction.
 * TODO: Is current PC on MIPS address of the next instruction?
 */
llvm::Value* Capstone2LlvmIrTranslatorMips_impl::getCurrentPc(cs_insn* i)
{
	return getNextInsnAddress(i);
}

/**
 * MIPS specifications often says something like:
 * "The return link is the address of the second instruction following the,
 * branch, at which location execution continues after a procedure call."
 * This method returns this address as an LLVM @c ConstantInt.
 */
llvm::Value* Capstone2LlvmIrTranslatorMips_impl::getNextNextInsnAddress(cs_insn* i)
{
	return llvm::ConstantInt::get(getDefaultType(), i->address + (2 * i->size));
}

/**
 * @return @c Nullptr -- there is no value.
 *
 * @c Nullptr will cause all the consumers like @c storeRegisterUnpredictable()
 * not to generate any code that depends on unpredictable value.
 *
 * MIPS specifications says:
 * "... Software can never depend on results that are UNPREDICTABLE.
 * UNPREDICTABLE operations may cause a result to be generated or not. ..."
 *
 * Right now, we choose not to generate it. This may change in future.
 */
llvm::Value* Capstone2LlvmIrTranslatorMips_impl::getUnpredictableValue()
{
	return nullptr;
}

uint32_t Capstone2LlvmIrTranslatorMips_impl::singlePrecisionToDoublePrecisionFpRegister(
		uint32_t r) const
{
	// Working with odd double reg (e.g. sdc1 $f21, -0x7ba3($v1)) may happen.
	// I have no idea why, and if this is ok, or it is simply caused by decoding
	// data. But it is a real example from real binary, IDA has the same thing.
	// Right now, we map odd numbers to even ones. But we would be able to
	// create their own double registers very easily.
	switch (r)
	{
		case MIPS_REG_F0: return MIPS_REG_FD0;
		case MIPS_REG_F1: return MIPS_REG_FD0;
		case MIPS_REG_F2: return MIPS_REG_FD2;
		case MIPS_REG_F3: return MIPS_REG_FD2;
		case MIPS_REG_F4: return MIPS_REG_FD4;
		case MIPS_REG_F5: return MIPS_REG_FD4;
		case MIPS_REG_F6: return MIPS_REG_FD6;
		case MIPS_REG_F7: return MIPS_REG_FD6;
		case MIPS_REG_F8: return MIPS_REG_FD8;
		case MIPS_REG_F9: return MIPS_REG_FD8;
		case MIPS_REG_F10: return MIPS_REG_FD10;
		case MIPS_REG_F11: return MIPS_REG_FD10;
		case MIPS_REG_F12: return MIPS_REG_FD12;
		case MIPS_REG_F13: return MIPS_REG_FD12;
		case MIPS_REG_F14: return MIPS_REG_FD14;
		case MIPS_REG_F15: return MIPS_REG_FD14;
		case MIPS_REG_F16: return MIPS_REG_FD16;
		case MIPS_REG_F17: return MIPS_REG_FD16;
		case MIPS_REG_F18: return MIPS_REG_FD18;
		case MIPS_REG_F19: return MIPS_REG_FD18;
		case MIPS_REG_F20: return MIPS_REG_FD20;
		case MIPS_REG_F21: return MIPS_REG_FD20;
		case MIPS_REG_F22: return MIPS_REG_FD22;
		case MIPS_REG_F23: return MIPS_REG_FD22;
		case MIPS_REG_F24: return MIPS_REG_FD24;
		case MIPS_REG_F25: return MIPS_REG_FD24;
		case MIPS_REG_F26: return MIPS_REG_FD26;
		case MIPS_REG_F27: return MIPS_REG_FD26;
		case MIPS_REG_F28: return MIPS_REG_FD28;
		case MIPS_REG_F29: return MIPS_REG_FD28;
		case MIPS_REG_F30: return MIPS_REG_FD30;
		case MIPS_REG_F31: return MIPS_REG_FD30;
		default:
			throw Capstone2LlvmIrError("Can not convert to double precision "
					"register.");
	}
}

llvm::Value* Capstone2LlvmIrTranslatorMips_impl::loadRegister(
		uint32_t r,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct)
{
	if (r == MIPS_REG_INVALID)
	{
		return nullptr;
	}

	if (r == MIPS_REG_PC)
	{
		return getCurrentPc(_insn);
	}

	if (r == MIPS_REG_ZERO)
	{
		return llvm::ConstantInt::getSigned(getDefaultType(), 0);
	}

	if (cs_insn_group(_handle, _insn, MIPS_GRP_NOTFP64BIT)
			&& MIPS_REG_F0 <= r
			&& r <= MIPS_REG_F31)
	{
		r = singlePrecisionToDoublePrecisionFpRegister(r);
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("loadRegister() unhandled reg.");
	}

	// TODO: do type conversion

	return irb.CreateLoad(llvmReg);
}

llvm::Value* Capstone2LlvmIrTranslatorMips_impl::loadOp(
		cs_mips_op& op,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty,
		bool lea) // TODO: implement lea
{
	switch (op.type)
	{
		case MIPS_OP_REG:
		{
			return loadRegister(op.reg, irb);
		}
		case MIPS_OP_IMM:
		{
			// TODO: Maybe this will cause problems.
			// In 32-bit MIPS, imms are 16 bits (always?).
			// What if number will be negative on 16 bits, but because we
			// take it here and create 32 bit, it loses it negativity?
			// The same in 64-bit MIPS.
			// However, maybe it will be ok, because cs_mips_op.imm is signed
			// int64_t, so if Capstone interprets it ok for us, then we probably
			// do not need to bother with it.
			return llvm::ConstantInt::getSigned(getDefaultType(), op.imm);
		}
		case MIPS_OP_MEM:
		{
			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = getDefaultType();
			llvm::Value* disp = llvm::ConstantInt::getSigned(t, op.mem.disp);

			llvm::Value* addr = nullptr;
			if (baseR == nullptr)
			{
				addr = disp;
			}
			else
			{
				if (op.mem.disp == 0)
				{
					addr = baseR;
				}
				else
				{
					disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
					addr = irb.CreateAdd(baseR, disp);
				}
			}

			auto* lty = ty ? ty : t;
			auto* pt = llvm::PointerType::get(lty, 0);
			addr = irb.CreateIntToPtr(addr, pt);
			return irb.CreateLoad(addr);
		}
		case MIPS_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

llvm::StoreInst* Capstone2LlvmIrTranslatorMips_impl::storeRegister(
		uint32_t r,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (r == MIPS_REG_INVALID)
	{
		return nullptr;
	}
	// These registers should not be stored, or their store has no effect.
	//
	if (r == MIPS_REG_PC
			|| r == MIPS_REG_ZERO)
	{
		return nullptr;
	}

	if (cs_insn_group(_handle, _insn, MIPS_GRP_NOTFP64BIT)
			&& MIPS_REG_F0 <= r
			&& r <= MIPS_REG_F31)
	{
		r = singlePrecisionToDoublePrecisionFpRegister(r);
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("storeRegister() unhandled reg.");
	}
	val = generateTypeConversion(irb, val, llvmReg->getValueType(), ct);

	return irb.CreateStore(val, llvmReg);
}

/**
 * Store unpredictable value to register @a r.
 * No store is generated if unpredictable value is set to @c nullptr (see
 * @c getUnpredictableValue()).
 */
llvm::StoreInst* Capstone2LlvmIrTranslatorMips_impl::storeRegisterUnpredictable(
		uint32_t r,
		llvm::IRBuilder<>& irb)
{
	auto* u = getUnpredictableValue();
	return u ? storeRegister(r, u, irb) : nullptr;
}

/**
 * @a ct is used when storing a value to register with a different type.
 * When storing to memory, value type is used -- therefore it needs to be
 * converted to the desired type prior to @c storeOp() call.
 */
llvm::Instruction* Capstone2LlvmIrTranslatorMips_impl::storeOp(
		cs_mips_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct) // TODO: use this, instead of default sext for registers.
{
	switch (op.type)
	{
		case MIPS_OP_REG:
		{
			return storeRegister(op.reg, val, irb, ct);
		}
		case MIPS_OP_MEM:
		{
			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = getDefaultType();
			llvm::Value* disp = llvm::ConstantInt::getSigned(t, op.mem.disp);

			llvm::Value* addr = nullptr;
			if (baseR == nullptr)
			{
				addr = disp;
			}
			else
			{
				if (op.mem.disp == 0)
				{
					addr = baseR;
				}
				else
				{
					disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
					addr = irb.CreateAdd(baseR, disp);
				}
			}

			auto* pt = llvm::PointerType::get(val->getType(), 0);
			addr = irb.CreateIntToPtr(addr, pt);
			return irb.CreateStore(val, addr);
		}
		case MIPS_OP_IMM:
		case MIPS_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

bool Capstone2LlvmIrTranslatorMips_impl::isFpInstructionVariant(cs_insn* i)
{
	auto& mi = i->detail->mips;
	return mi.op_count > 0
			&& mi.operands[0].type == MIPS_OP_REG
			&& MIPS_REG_F0 <= mi.operands[0].reg
			&& mi.operands[0].reg <= MIPS_REG_F31;
}

//
//==============================================================================
// MIPS instruction translation methods.
//==============================================================================
//

/**
 * MIPS_INS_ADDI, MIPS_INS_ADDIU, MIPS_INS_ADD, MIPS_INS_ADDU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateAdd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::SEXT_TRUNC);
	auto* add = op1->getType()->isFloatingPointTy()
			? irb.CreateFAdd(op1, op2)
			: irb.CreateAdd(op1, op2);
	storeOp(mi->operands[0], add, irb);
}

/**
 * MIPS_INS_AND, MIPS_INS_ANDI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateAnd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* a = irb.CreateAnd(op1, op2);
	storeOp(mi->operands[0], a, irb);
}

/**
 * MIPS_INS_BC1F, MIPS_INS_BC1FL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateBc1f(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count == 1)
	{
		op0 = loadRegister(MIPS_REG_FCC0, irb); // implied operand
		op1 = loadOpUnary(mi, irb);
	}
	else if (mi->op_count == 2)
	{
		std::tie(op0, op1) = loadOpBinary(mi, irb);
	}
	else
	{
		assert(false && "unhandled number of operands");
		return;
	}

	auto* c = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
	generateCondBranchFunctionCall(irb, c, op1);
}

/**
 * MIPS_INS_BC1T, MIPS_INS_BC1TL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateBc1t(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count == 1)
	{
		op0 = loadRegister(MIPS_REG_FCC0, irb); // implied operand
		op1 = loadOpUnary(mi, irb);
	}
	else if (mi->op_count == 2)
	{
		std::tie(op0, op1) = loadOpBinary(mi, irb);
	}
	else
	{
		assert(false && "unhandled number of operands");
		return;
	}

	auto* c = irb.CreateICmpNE(op0, llvm::ConstantInt::get(op0->getType(), 0));
	generateCondBranchFunctionCall(irb, c, op1);
}

/**
 * MIPS_INS_BGEZAL (and link), MIPS_INS_BGEZALL (and link likely -- executes
 * the delay slot only if the branch is taken).
 * Bodies are the same, but delay slot eecution differs:
 * - MIPS_INS_BGEZAL: delay slot always executed -> should be moved before jump.
 * - MIPS_INS_BGEZALL: delay slot execution only if jump taken -> should be
 *   moved to branch target.
 *
 * The same for:
 * MIPS_INS_BLTZAL, MIPS_INS_BLTZALL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateBcondal(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(mi, irb);
	auto* zero = llvm::ConstantInt::get(op0->getType(), 0);
	llvm::Value* cond = nullptr;
	switch (i->id)
	{
		case MIPS_INS_BGEZAL:
		case MIPS_INS_BGEZALL:
			cond = irb.CreateICmpSGE(op0, zero);
			break;
		case MIPS_INS_BLTZAL:
		case MIPS_INS_BLTZALL:
			cond = irb.CreateICmpSLT(op0, zero);
			break;
		default:
			throw Capstone2LlvmIrError("Unhandled insn ID in translateBcondal().");
	}

	auto bodyIrb = generateIfThen(cond, irb);

	storeRegister(MIPS_REG_RA, getNextNextInsnAddress(i), bodyIrb);
	generateCallFunctionCall(bodyIrb, op1);
}

/**
 * MIPS_INS_ROUND, MIPS_INS_ABS, MIPS_INS_NEG, MIPS_INS_SQRT, MIPS_INS_FLOOR,
 * MIPS_INS_CEIL, MIPS_INS_TRUNC
 * MIPS_INS_CFC1 -- op1 is GPR holding a value (not FPU control reg).
 *                  Complicated decision what to do based on this value.
 */
void Capstone2LlvmIrTranslatorMips_impl::translateBinaryPseudoAsm(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);

	std::string tyStr;
	llvm::raw_string_ostream rso(tyStr);
	op1->getType()->print(rso);

	// TODO: Here, and in all other places, function name could also contain
	// types of arguments, to make sure, correct functions are called.
	// Or, there should be op1 casts to function argument types.
	//
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic) + "." + rso.str(),
			op1->getType(),
			{op1->getType()});

	auto* c = irb.CreateCall(fnc, {op1});
	storeOp(mi->operands[0], c, irb);
}

/**
 * MIPS_INS_CTC1
 */
void Capstone2LlvmIrTranslatorMips_impl::translateCtc1(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(mi, irb);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			irb.getVoidTy(),
			{op0->getType(), op1->getType()});

	irb.CreateCall(fnc, {op0, op1});
}

/**
 * MIPS_INS_CVT
 */
void Capstone2LlvmIrTranslatorMips_impl::translateCvt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::string mnem = i->mnemonic;
	if (mi->op_count != 2
			|| mi->operands[0].type != MIPS_OP_REG
			|| !(MIPS_REG_F0 <= mi->operands[0].reg && mi->operands[0].reg <= MIPS_REG_F31)
			|| mi->operands[1].type != MIPS_OP_REG
			|| !(MIPS_REG_F0 <= mi->operands[1].reg && mi->operands[1].reg <= MIPS_REG_F31))
	{
		assert(false && "unhandled MIPS_INS_CVT format");
		return;
	}

	auto r0 = mi->operands[0].reg;
	auto r1 = mi->operands[1].reg;

	// CVT.S.fmt
	//
	if (mnem == "cvt.s.d") // should be only on MIPS32
	{
		op1 = loadRegister(r1, irb);
		op1 = irb.CreateFPCast(op1, getRegisterType(r0));
		irb.CreateStore(op1, getRegister(r0));
	}
	else if (mnem == "cvt.s.w" // should be only on MIPS32
			|| mnem == "cvt.s.l") // should be only on MIPS64
	{
		auto* op0Ty = getRegisterType(r0);
		op1 = loadRegister(r1, irb);
		auto* iTy = op1->getType()->isDoubleTy()
				? irb.getInt64Ty()
				: irb.getInt32Ty();
		op1 = irb.CreateBitCast(op1, iTy);
		op1 = irb.CreateSIToFP(op1, op0Ty);
		irb.CreateStore(op1, getRegister(r0));
	}
	// CVT.D.fmt
	//
	else if (mnem == "cvt.d.s")
	{
		op1 = irb.CreateLoad(getRegister(r1));
		storeRegister(r0, op1, irb, eOpConv::FP_CAST);
	}
	else if (mnem == "cvt.d.w" // should be only on MIPS32
			|| mnem == "cvt.d.l") // should be only on MIPS64
	{
		op1 = irb.CreateLoad(getRegister(r1));
		auto* iTy = op1->getType()->isDoubleTy()
				? irb.getInt64Ty()
				: irb.getInt32Ty();
		op1 = irb.CreateBitCast(op1, iTy);
		op1 = irb.CreateSIToFP(op1, irb.getDoubleTy());
		storeRegister(r0, op1, irb, eOpConv::FP_CAST);
	}
	// CVT.W.fmt
	//
	else if (mnem == "cvt.w.s" // should be only on MIPS32
			|| mnem == "cvt.w.d") // should be only on MIPS64
	{
		op1 = loadRegister(r1, irb);
		auto* iTy = op1->getType()->isDoubleTy()
				? irb.getInt64Ty()
				: irb.getInt32Ty();
		op1 = irb.CreateFPToSI(op1, iTy);
		auto* iTy2 = getRegisterType(r0)->isDoubleTy()
				? irb.getInt64Ty()
				: irb.getInt32Ty();
		op1 = irb.CreateSExtOrTrunc(op1, iTy2);
		op1 = irb.CreateBitCast(op1, getRegisterType(r0));
		irb.CreateStore(op1, getRegister(r0));
	}
	else
	{
		assert(false && "unhandled MIPS_INS_CVT format");
		return;
	}
}

/**
 * MIPS_INS_BEQ, MIPS_INS_BEQL (likely)
 * MIPS_INS_BNE, MIPS_INS_BNEL (likely)
 */
void Capstone2LlvmIrTranslatorMips_impl::translateCondBranchTernary(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(mi, irb);
	op1 = irb.CreateZExtOrTrunc(op1, op0->getType());

	llvm::Value* cond = nullptr;
	switch (i->id)
	{
		case MIPS_INS_BEQ:
		case MIPS_INS_BEQL:
			cond = irb.CreateICmpEQ(op0, op1);
			break;
		case MIPS_INS_BNE:
		case MIPS_INS_BNEL:
			cond = irb.CreateICmpNE(op0, op1);
			break;
		default:
			throw Capstone2LlvmIrError("Unhandled insn ID in translateCondBranchBinary().");
	}

	generateCondBranchFunctionCall(irb, cond, op2);
}

/**
 * MIPS_INS_BLEZ, MIPS_INS_BLEZL (likely)
 * MIPS_INS_BGTZ, MIPS_INS_BGTZL (likely)
 * MIPS_INS_BLTZ, MIPS_INS_BLTZL (likely)
 * MIPS_INS_BGEZ, MIPS_INS_BGEZL (likely)
 * MIPS_INS_BEQZ
 * MIPS_INS_BNEZ
 */
void Capstone2LlvmIrTranslatorMips_impl::translateCondBranchBinary(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(mi, irb);
	auto* zero = llvm::ConstantInt::get(op0->getType(), 0);

	llvm::Value* cond = nullptr;
	switch (i->id)
	{
		case MIPS_INS_BLEZ:
		case MIPS_INS_BLEZL:
			cond = irb.CreateICmpSLE(op0, zero);
			break;
		case MIPS_INS_BGTZ:
		case MIPS_INS_BGTZL:
			cond = irb.CreateICmpSGT(op0, zero);
			break;
		case MIPS_INS_BLTZ:
		case MIPS_INS_BLTZL:
			cond = irb.CreateICmpSLT(op0, zero);
			break;
		case MIPS_INS_BGEZ:
		case MIPS_INS_BGEZL:
			cond = irb.CreateICmpSGE(op0, zero);
			break;
		case MIPS_INS_BEQZ:
			cond = irb.CreateICmpEQ(op0, zero);
			break;
		case MIPS_INS_BNEZ:
			cond = irb.CreateICmpNE(op0, zero);
			break;
		default:
			throw Capstone2LlvmIrError("Unhandled insn ID in translateCondBranchUnary().");
	}

	generateCondBranchFunctionCall(irb, cond, op1);
}

/**
 * MIPS_INS_BITREV
 */
void Capstone2LlvmIrTranslatorMips_impl::translateBitrev(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_bitrev",
			getDefaultType(),
			{getDefaultType()});
	op1 = loadOpBinaryOp1(mi, irb);
	op1 = irb.CreateZExtOrTrunc(op1, getDefaultType());
	auto* c = irb.CreateCall(fnc, {op0});
	storeOp(mi->operands[0], c, irb);
}

/**
 * MIPS_INS_BREAK
 */
void Capstone2LlvmIrTranslatorMips_impl::translateBreak(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// TODO: Modeled as empty instruction in the original semantics.
	// Causes problems in some integration tests
	// (e.g. break 0,7 in gcd.mips.pspgcc-4.3.5.O0.g.elf)
	// because it is sometimes used in the bodies of decompiled functions.
	// Right now, we disable it here, but use a better solution in future --
	// it should be translated, and if decompiler wants it can remove it later.
	// Unit tests were also disabled, re-enable when fixed.
	//
	return;

	if (mi->op_count == 0)
	{
		op0 = llvm::ConstantInt::get(getDefaultType(), 0);
	}
	else if (mi->op_count == 1)
	{
		op0 = loadOpUnary(mi, irb);
	}
	else if (mi->op_count == 2)
	{
		std::tie(op0, op1) = loadOpBinary(mi, irb);
	}
	else
	{
		assert(false && "unhandled break op_count");
		return;
	}

	op0 = irb.CreateZExtOrTrunc(op0, getDefaultType());
	if (op1)
	{
		op1 = irb.CreateZExtOrTrunc(op1, getDefaultType());

		llvm::Function* fnc = getOrCreateAsmFunction(
				i->id,
				"__asm_break_bin",
				llvm::Type::getVoidTy(_module->getContext()),
				{op0->getType(), op1->getType()});
		irb.CreateCall(fnc, {op0, op1});
	}
	else
	{
		llvm::Function* fnc = getOrCreateAsmFunction(
				i->id,
				"__asm_break",
				llvm::Type::getVoidTy(_module->getContext()),
				{op0->getType()});
		irb.CreateCall(fnc, {op0});
	}
}

/**
 * MIPS_INS_C
 */
void Capstone2LlvmIrTranslatorMips_impl::translateC(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::string mnem = i->mnemonic;
	std::tie(op0, op1) = loadOpBinary(mi, irb, eOpConv::THROW);

	llvm::Value* val = nullptr;

	// http://ti.ira.uka.de/TI-2/Mips/Befehlssatz.pdf
	//
	if (mnem == "c.f.s" || mnem == "c.f.d"
			|| mnem == "c.sf.s" || mnem == "c.sf.d")
	{
		val = irb.getFalse(); // This is ok, I checked.
	}
	else if (mnem == "c.un.s" || mnem == "c.un.d")
	{
		val = irb.CreateFCmpUNO(op0, op1);
	}
	else if (mnem == "c.ngle.s" || mnem == "c.ngle.d")
	{
		val = irb.CreateFCmpUNO(op0, op1);
	}
	else if (mnem == "c.eq.s" || mnem == "c.eq.d")
	{
		val = irb.CreateFCmpOEQ(op0, op1);
	}
	else if (mnem == "c.seq.s" || mnem == "c.seq.d")
	{
		val = irb.CreateFCmpOEQ(op0, op1);
	}
	else if (mnem == "c.ngl.s" || mnem == "c.ngl.d")
	{
		val = irb.CreateFCmpOEQ(op0, op1);
	}
	else if (mnem == "c.ueq.s" || mnem == "c.ueq.d")
	{
		val = irb.CreateFCmpUEQ(op0, op1);
	}
	else if (mnem == "c.olt.s" || mnem == "c.olt.d")
	{
		val = irb.CreateFCmpOLT(op0, op1);
	}
	else if (mnem == "c.lt.s" || mnem == "c.lt.d")
	{
		val = irb.CreateFCmpOLT(op0, op1);
	}
	else if (mnem == "c.nge.s" || mnem == "c.nge.d")
	{
		val = irb.CreateFCmpOLT(op0, op1);
	}
	else if (mnem == "c.ult.s" || mnem == "c.ult.d")
	{
		val = irb.CreateFCmpULT(op0, op1);
	}
	else if (mnem == "c.ole.s" || mnem == "c.ole.d")
	{
		val = irb.CreateFCmpOLE(op0, op1);
	}
	else if (mnem == "c.le.s" || mnem == "c.le.d")
	{
		val = irb.CreateFCmpOLE(op0, op1);
	}
	else if (mnem == "c.ngt.s" || mnem == "c.ngt.d")
	{
		val = irb.CreateFCmpOLE(op0, op1);
	}
	else if (mnem == "c.ule.s" || mnem == "c.ule.d")
	{
		val = irb.CreateFCmpULE(op0, op1);
	}
	else
	{
		{
			assert(false && "unhandled MIPS_INS_C format");
			return;
		}
	}

	storeRegister(MIPS_REG_FCC0, val, irb, eOpConv::ZEXT_TRUNC);
}

/**
 * MIPS_INS_CLO
 */
void Capstone2LlvmIrTranslatorMips_impl::translateClo(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	op1 = irb.CreateXor(op1, llvm::ConstantInt::getSigned(op1->getType(), -1));
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			llvm::Intrinsic::ctlz,
			op1->getType());
	auto* ctlz = irb.CreateCall(f, {op1, irb.getTrue()});
	storeOp(mi->operands[0], ctlz, irb);
}

/**
 * MIPS_INS_CLZ
 */
void Capstone2LlvmIrTranslatorMips_impl::translateClz(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			llvm::Intrinsic::ctlz,
			op1->getType());
	auto* ctlz = irb.CreateCall(f, {op1, irb.getTrue()});
	storeOp(mi->operands[0], ctlz, irb);
}

/**
 * MIPS_INS_DIV
 */
void Capstone2LlvmIrTranslatorMips_impl::translateDiv(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (isFpInstructionVariant(i))
	{
		std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::THROW);
		auto* div = irb.CreateFDiv(op1, op2);
		storeOp(mi->operands[0], div, irb);
	}
	else
	{
		std::tie(op0, op1) = loadOpBinary(mi, irb, eOpConv::THROW);
		auto* div = irb.CreateSDiv(op0, op1);
		storeRegister(MIPS_REG_LO, div, irb);
		auto* rem = irb.CreateSRem(op0, op1);
		storeRegister(MIPS_REG_HI, rem, irb);
	}
}

/**
 * MIPS_INS_DIVU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateDivu(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(mi, irb, eOpConv::THROW);
	auto* div = irb.CreateUDiv(op0, op1);
	storeRegister(MIPS_REG_LO, div, irb);
	auto* rem = irb.CreateURem(op0, op1);
	storeRegister(MIPS_REG_HI, rem, irb);
}

/**
 * MIPS_INS_EXT
 */
void Capstone2LlvmIrTranslatorMips_impl::translateExt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 4)
	{
		assert(false && "unexpected number of operands");
		return;
	}

	op1 = loadOp(mi->operands[1], irb);
	op2 = loadOp(mi->operands[2], irb);
	op3 = loadOp(mi->operands[3], irb);

	// This is a special case, when EXT is used to remove sign bit ->  generate
	// absolute value. The problem is, that both ordinary integers and IEEE 754
	// floats have the sign bit at the same place, and that floats can be stored
	// into integer registers. Therefore, this operation may perform floating
	// point abs on an integer register holding floating point value.
	// Since we can not determine, what kind (int vs float) of abs is being
	// performed, we generate floating point variant because it is more general.
	// TODO: In an old semantics, the generate pattern was recognized in an
	// idiom analysis and fabsf function was generated. This function was also
	// marked as idiom fnc in config and placed in "Instruction-Idiom Functions"
	// section in an output C file. This does not happen at the moment ->
	// probably all intrinsic functions generated by any translator could be
	// marked as idiom functions. Discuss with Petr.
	//
	auto* op1Ty = llvm::dyn_cast<llvm::IntegerType>(op1->getType());
	if (op1Ty
			&& llvm::isa<llvm::ConstantInt>(op2)
			&& llvm::cast<llvm::ConstantInt>(op2)->isZero()
			&& llvm::isa<llvm::ConstantInt>(op3)
			&& (llvm::cast<llvm::ConstantInt>(op3)->getZExtValue() + 1)
				== op1Ty->getBitWidth())
	{
		auto* fTy = getFloatTypeFromByteSize(_module, op1Ty->getBitWidth() / 8);
		auto* f = llvm::Intrinsic::getDeclaration(
				_module,
				llvm::Intrinsic::fabs,
				fTy);
		op1 = irb.CreateBitCast(op1, fTy);
		llvm::Value* fabs = irb.CreateCall(f, {op1});
		fabs = irb.CreateBitCast(fabs, op1Ty);
		storeOp(mi->operands[0], fabs, irb);
		return;
	}

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_ext",
			getDefaultType(),
			{op1->getType(), op2->getType(), op3->getType()});
	auto* c = irb.CreateCall(fnc, {op1, op2, op3});
	storeOp(mi->operands[0], c, irb);
}

/**
 * MIPS_INS_INS
 */
void Capstone2LlvmIrTranslatorMips_impl::translateIns(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 4)
	{
		assert(false && "unexpected number of operands");
		return;
	}

	op1 = loadOp(mi->operands[1], irb);
	op2 = loadOp(mi->operands[2], irb);
	op3 = loadOp(mi->operands[3], irb);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_ins",
			getDefaultType(),
			{op1->getType(), op2->getType(), op3->getType()});
	auto* c = irb.CreateCall(fnc, {op1, op2, op3});
	storeOp(mi->operands[0], c, irb);
}

/**
 * MIPS_INS_J, MIPS_INS_JR,
 * MIPS_INS_B,
 */
void Capstone2LlvmIrTranslatorMips_impl::translateJ(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(mi, irb);
	generateBranchFunctionCall(irb, op0);
}

/**
 * MIPS_INS_JAL, MIPS_INS_JALR,
 * MIPS_INS_BAL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateJal(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// Silent ignore -- no throw, assert, etc.
	// TODO: This should be everywhere, but as elegant as possible.
	// E.g. some macro like IS_UNARY(mi) that would silently return if not,
	// or throw that would be catched by translator and ignored if in ignore
	// mode.
	//
	if (mi->op_count != 1)
	{
		return;
	}

	storeRegister(MIPS_REG_RA, getNextNextInsnAddress(i), irb);

	op0 = loadOpUnary(mi, irb);
	generateCallFunctionCall(irb, op0);
}

/**
 * MIPS_INS_LB, MIPS_INS_LBU,
 * MIPS_INS_LH, MIPS_INS_LHU,
 * MIPS_INS_LW, MIPS_INS_LWU,
 * MIPS_INS_LD, MIPS_INS_LDC3,
 * MIPS_INS_LWC1, MIPS_INS_LDC1
 */
void Capstone2LlvmIrTranslatorMips_impl::translateLoadMemory(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	llvm::Type* ty = nullptr;
	eOpConv ct = eOpConv::THROW;

	switch (i->id)
	{
		case MIPS_INS_LB: ty = irb.getInt8Ty(); ct = eOpConv::SEXT_TRUNC; break;
		case MIPS_INS_LBU: ty = irb.getInt8Ty(); ct = eOpConv::ZEXT_TRUNC; break;
		case MIPS_INS_LH: ty = irb.getInt16Ty(); ct = eOpConv::SEXT_TRUNC; break;
		case MIPS_INS_LHU: ty = irb.getInt16Ty(); ct = eOpConv::ZEXT_TRUNC; break;
		case MIPS_INS_LW: ty = irb.getInt32Ty(); ct = eOpConv::SEXT_TRUNC; break;
		case MIPS_INS_LWU: ty = irb.getInt32Ty(); ct = eOpConv::ZEXT_TRUNC; break;
		case MIPS_INS_LD: ty = irb.getInt64Ty(); ct = eOpConv::SEXT_TRUNC; break;
		case MIPS_INS_LDC3: ty = irb.getInt64Ty(); ct = eOpConv::SEXT_TRUNC; break;
		case MIPS_INS_LWC1: ty = irb.getFloatTy(); ct = eOpConv::FP_CAST; break;
		case MIPS_INS_LDC1: ty = irb.getDoubleTy(); ct = eOpConv::FP_CAST; break;
		default:
			throw Capstone2LlvmIrError("Unhandled insn ID in translateLoadMemory().");
	}

	op1 = loadOpBinaryOp1(mi, irb, ty);
	storeOp(mi->operands[0], op1, irb, ct);
}

/**
 * MIPS_INS_SB, MIPS_INS_SH, MIPS_INS_SW, MIPS_INS_SD, MIPS_INS_SDC3,
 * MIPS_INS_SWC1, MIPS_INS_SDC1
 */
void Capstone2LlvmIrTranslatorMips_impl::translateStoreMemory(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	assert(mi->op_count == 2);

	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case MIPS_INS_SB: ty = irb.getInt8Ty(); break;
		case MIPS_INS_SH: ty = irb.getInt16Ty(); break;
		case MIPS_INS_SW: ty = irb.getInt32Ty(); break;
		case MIPS_INS_SD: ty = irb.getInt64Ty(); break;
		case MIPS_INS_SDC3: ty = irb.getInt64Ty(); break;
		case MIPS_INS_SWC1: ty = irb.getFloatTy(); break;
		case MIPS_INS_SDC1: ty = irb.getDoubleTy(); break;
		default:
			throw Capstone2LlvmIrError("Unhandled insn ID in translateStoreMemory().");
	}

	op0 = loadOp(mi->operands[0], irb);
	if (ty->isFloatingPointTy())
	{
		// This is not exact, in 64-bit mode, only lower 32-bits of FPR should
		// be used -> truncate, not cast.
		op0 = irb.CreateFPCast(op0, ty);
	}
	else if (ty->isIntegerTy())
	{
		op0 = irb.CreateZExtOrTrunc(op0, ty);
	}
	else
	{
		assert(false && "unhandled type");
		return;
	}
	storeOp(mi->operands[1], op0, irb);
}

/**
 * MIPS_INS_LUI
 * This behaves like 32-bit MIPS instruction even on 64-bit MIPS.
 */
void Capstone2LlvmIrTranslatorMips_impl::translateLui(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	assert(mi->op_count == 2);
	op1 = loadOp(mi->operands[1], irb);
	op1 = irb.CreateZExt(op1, getDefaultType());
	op1 = irb.CreateShl(op1, llvm::ConstantInt::get(op1->getType(), 16));
	storeOp(mi->operands[0], op1, irb);
}

/**
 * MIPS_INS_LWL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateLwl(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// TODO: Modeled as an empty insn in the old semantics,
	// but it should not have been.
}

/**
 * MIPS_INS_LWR
 */
void Capstone2LlvmIrTranslatorMips_impl::translateLwr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// TODO: Modeled as an empty insn in the old semantics,
	// but it should not have been.
}

/**
 * MIPS_INS_SWL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSwl(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// TODO: Modeled as an empty insn in the old semantics,
	// but it should not have been.
}

/**
 * MIPS_INS_SWR
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSwr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// TODO: Modeled as an empty insn in the old semantics,
	// but it should not have been.
}

/**
 * MIPS_INS_MADD, MIPS_INS_MADDU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMadd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (isFpInstructionVariant(i))
	{
		return translateMaddf(i, mi, irb);
	}

	std::tie(op0, op1) = loadOpBinary(mi, irb, eOpConv::NOTHING);
	auto* hi = loadRegister(MIPS_REG_HI, irb);
	auto* lo = loadRegister(MIPS_REG_LO, irb);

	auto* i32Ty = irb.getInt32Ty();
	auto* i64Ty = irb.getInt64Ty();

	// We operate on 0..31 bits even if on MIPS64.
	//
	if (op0->getType() == i64Ty)
	{
		op0 = irb.CreateTrunc(op0, i32Ty);
	}
	if (op1->getType() == i64Ty)
	{
		op1 = irb.CreateTrunc(op1, i32Ty);
	}
	if (hi->getType() == i64Ty)
	{
		hi = irb.CreateTrunc(hi, i32Ty);
	}
	if (lo->getType() == i64Ty)
	{
		lo = irb.CreateTrunc(lo, i32Ty);
	}

	if (i->id == MIPS_INS_MADD)
	{
		op0 = irb.CreateSExtOrTrunc(op0, i64Ty);
		op1 = irb.CreateSExtOrTrunc(op1, i64Ty);
	}
	else if (i->id == MIPS_INS_MADDU)
	{
		op0 = irb.CreateZExtOrTrunc(op0, i64Ty);
		op1 = irb.CreateZExtOrTrunc(op1, i64Ty);
	}
	else
	{
		assert(false && "translateMadd(): unhandled insn ID");
		return;
	}

	hi = irb.CreateZExt(hi, i64Ty);
	hi = irb.CreateShl(hi, 32);
	lo = irb.CreateZExt(lo, i64Ty);
	auto* hilo = irb.CreateOr(hi, lo);

	auto* mul = irb.CreateMul(op0, op1);
	auto* add = irb.CreateAdd(hilo, mul);

	lo = irb.CreateTrunc(add, i32Ty);
	storeRegister(MIPS_REG_LO, lo, irb);

	hi = irb.CreateLShr(add, 32);
	hi = irb.CreateTrunc(hi, i32Ty);
	storeRegister(MIPS_REG_HI, hi, irb);
}

void Capstone2LlvmIrTranslatorMips_impl::translateMaddf(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 4)
	{
		assert(false && "unhandled number of operands");
		return;
	}
	op1 = loadOp(mi->operands[1], irb);
	op2 = loadOp(mi->operands[2], irb);
	op3 = loadOp(mi->operands[3], irb);

	auto* mul = irb.CreateFMul(op2, op3);
	auto* add = irb.CreateFAdd(mul, op1);
	storeOp(mi->operands[0], add, irb);
}

/**
 * MIPS_INS_NEGU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateNegu(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(op1->getType(), 0), op1);
	storeOp(mi->operands[0], sub, irb);
}

/**
 * MIPS_INS_NMADD -- this could be merged with translateMaddf().
 */
void Capstone2LlvmIrTranslatorMips_impl::translateNmadd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 4)
	{
		assert(false && "unhandled number of operands");
		return;
	}
	op1 = loadOp(mi->operands[1], irb);
	op2 = loadOp(mi->operands[2], irb);
	op3 = loadOp(mi->operands[3], irb);

	auto* mul = irb.CreateFMul(op2, op3);
	auto* add = irb.CreateFAdd(mul, op1);
	// Neg function call could be used here instead.
	auto* neg = irb.CreateFSub(llvm::ConstantFP::get(add->getType(), 0.0), add);
	storeOp(mi->operands[0], neg, irb);
}

/**
 * MIPS_INS_MAX
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMax(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::THROW);
	auto* sge = irb.CreateICmpSGE(op1, op2);
	auto* val = irb.CreateSelect(sge, op1, op2);
	storeOp(mi->operands[0], val, irb);
}

/**
 * MIPS_INS_MFC1
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMfc1(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	auto* ty = op1->getType()->isDoubleTy()
			? irb.getInt64Ty()
			: irb.getInt32Ty();
	op1 = irb.CreateBitCast(op1, ty);
	op1 = irb.CreateZExtOrTrunc(op1, irb.getInt32Ty()); // even on 64-bit it takes only 0..31
	storeOp(mi->operands[0], op1, irb);
}

/**
 * MIPS_INS_MTC1
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMtc1(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpBinaryOp0(mi, irb);
	op0 = irb.CreateZExtOrTrunc(op0, irb.getInt32Ty()); // even on 64-bit it takes only 0..31
	op0 = irb.CreateBitCast(op0, irb.getFloatTy());
	storeOp(mi->operands[1], op0, irb);
}

/**
 * MIPS_INS_MFHI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMfhi(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 1)
	{
		// TODO: This can happen, e.g. big endian "00 20 00 10" -> mfhi $zero, $ac1 (DSP group)
		// however, it is probably decoded data, e.g.
		// mips-elf-e8e3b30ff295c1eac0cc06e1c8b1dc5e @ 0x200000
		return;
	}
	auto* hi = loadRegister(MIPS_REG_HI, irb);
	storeOp(mi->operands[0], hi, irb);
}

/**
 * MIPS_INS_MFLO
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMflo(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 1)
	{
		assert(false && "MIPS_INS_MFLO: unexpected number of ops");
		return;
	}
	auto* lo = loadRegister(MIPS_REG_LO, irb);
	storeOp(mi->operands[0], lo, irb);
}

/**
 * MIPS_INS_MIN
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMin(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::THROW);
	auto* sle = irb.CreateICmpSLE(op1, op2);
	auto* val = irb.CreateSelect(sle, op1, op2);
	storeOp(mi->operands[0], val, irb);
}

/**
 * MIPS_INS_MOV, MIPS_INS_MOVE
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMov(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	storeOp(mi->operands[0], op1, irb);
}

/**
 * MIPS_INS_MSUB, MIPS_INS_MSUBU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMsub(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (isFpInstructionVariant(i))
	{
		return translateMsubf(i, mi, irb);
	}

	std::tie(op0, op1) = loadOpBinary(mi, irb, eOpConv::NOTHING);
	auto* hi = loadRegister(MIPS_REG_HI, irb);
	auto* lo = loadRegister(MIPS_REG_LO, irb);

	auto* i32Ty = irb.getInt32Ty();
	auto* i64Ty = irb.getInt64Ty();

	// We operate on 0..31 bits even if on MIPS64.
	//
	if (op0->getType() == i64Ty)
	{
		op0 = irb.CreateTrunc(op0, i32Ty);
	}
	if (op1->getType() == i64Ty)
	{
		op1 = irb.CreateTrunc(op1, i32Ty);
	}
	if (hi->getType() == i64Ty)
	{
		hi = irb.CreateTrunc(hi, i32Ty);
	}
	if (lo->getType() == i64Ty)
	{
		lo = irb.CreateTrunc(lo, i32Ty);
	}

	if (i->id == MIPS_INS_MSUB)
	{
		op0 = irb.CreateSExtOrTrunc(op0, i64Ty);
		op1 = irb.CreateSExtOrTrunc(op1, i64Ty);
	}
	else if (i->id == MIPS_INS_MSUBU)
	{
		op0 = irb.CreateZExtOrTrunc(op0, i64Ty);
		op1 = irb.CreateZExtOrTrunc(op1, i64Ty);
	}
	else
	{
		assert(false && "translateMsub(): unhandled insn ID");
		return;
	}

	hi = irb.CreateZExt(hi, i64Ty);
	hi = irb.CreateShl(hi, 32);
	lo = irb.CreateZExt(lo, i64Ty);
	auto* hilo = irb.CreateOr(hi, lo);

	auto* mul = irb.CreateMul(op0, op1);
	auto* sub = irb.CreateSub(hilo, mul);

	lo = irb.CreateTrunc(sub, i32Ty);
	storeRegister(MIPS_REG_LO, lo, irb);

	hi = irb.CreateLShr(sub, 32);
	hi = irb.CreateTrunc(hi, i32Ty);
	storeRegister(MIPS_REG_HI, hi, irb);
}

void Capstone2LlvmIrTranslatorMips_impl::translateMsubf(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 4)
	{
		assert(false && "unhandled number of operands");
		return;
	}
	op1 = loadOp(mi->operands[1], irb);
	op2 = loadOp(mi->operands[2], irb);
	op3 = loadOp(mi->operands[3], irb);

	auto* mul = irb.CreateFMul(op2, op3);
	auto* sub = irb.CreateFSub(mul, op1);
	storeOp(mi->operands[0], sub, irb);
}

/**
 * MIPS_INS_NMSUB
 */
void Capstone2LlvmIrTranslatorMips_impl::translateNmsub(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 4)
	{
		assert(false && "unhandled number of operands");
		return;
	}
	op1 = loadOp(mi->operands[1], irb);
	op2 = loadOp(mi->operands[2], irb);
	op3 = loadOp(mi->operands[3], irb);

	auto* mul = irb.CreateFMul(op2, op3);
	auto* sub = irb.CreateFSub(mul, op1);
	// Neg function call could be used here instead.
	auto* neg = irb.CreateFSub(llvm::ConstantFP::get(sub->getType(), 0.0), sub);
	storeOp(mi->operands[0], neg, irb);
}

/**
 * MIPS_INS_MTHI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMthi(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(mi, irb);
	storeRegister(MIPS_REG_HI, op0, irb);
}

/**
 * MIPS_INS_MTLO
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMtlo(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// Silent ignore -- no throw, assert, etc.
	// TODO: This should be everywhere, but as elegant as possible.
	// E.g. some macro like IS_UNARY(mi) that would silently return if not,
	// or throw that would be catched by translator and ignored if in ignore
	// mode.
	//
	if (mi->op_count != 1)
	{
		return;
	}

	op0 = loadOpUnary(mi, irb);
	storeRegister(MIPS_REG_LO, op0, irb);
}

/**
 * MIPS_INS_MOVF
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMovf(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(mi, irb);
	auto* c = irb.CreateICmpEQ(op2, llvm::ConstantInt::get(op2->getType(), 0));
	auto* val = irb.CreateSelect(c, op1, op0);
	storeOp(mi->operands[0], val, irb);
}

/**
 * MIPS_INS_MOVN
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMovn(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(mi, irb);
	auto* e = irb.CreateICmpNE(op2, llvm::ConstantInt::get(op2->getType(), 0));
	auto* val = irb.CreateSelect(e, op1, op0);
	storeOp(mi->operands[0], val, irb);
}

/**
 * MIPS_INS_MOVT
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMovt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(mi, irb);
	auto* c = irb.CreateICmpNE(op2, llvm::ConstantInt::get(op2->getType(), 0));
	auto* val = irb.CreateSelect(c, op1, op0);
	storeOp(mi->operands[0], val, irb);
}

/**
 * MIPS_INS_MOVZ
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMovz(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(mi, irb);
	auto* e = irb.CreateICmpEQ(op2, llvm::ConstantInt::get(op2->getType(), 0));
	auto* val = irb.CreateSelect(e, op1, op0);
	storeOp(mi->operands[0], val, irb);
}

/**
 * MIPS_INS_MUL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMul(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::THROW);
	if (op1->getType()->isFloatingPointTy())
	{
		auto* mul = irb.CreateFMul(op1, op2);
		storeOp(mi->operands[0], mul, irb);
	}
	else
	{
		auto* mul = irb.CreateMul(op1, op2);
		storeOp(mi->operands[0], mul, irb);
		storeRegisterUnpredictable(MIPS_REG_HI, irb);
		storeRegisterUnpredictable(MIPS_REG_LO, irb);
	}
}

/**
 * MIPS_INS_MULT, MIPS_INS_MULTU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateMult(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// TODO: quick fix until better exceptions are thrown and handled.
	// 18 18 62 00:
	// IDA     : mult    $v1, $v0
	// CApstone: mult $ac3, $v1, $v0 (DSP group)
	//
	if (mi->op_count != 2)
	{
		return;
	}

	std::tie(op0, op1) = loadOpBinary(mi, irb, eOpConv::THROW);
	auto* ty = irb.getIntNTy(getArchBitSize() * 2);
	if (i->id == MIPS_INS_MULT)
	{
		op0 = irb.CreateSExt(op0, ty);
		op1 = irb.CreateSExt(op1, ty);
	}
	else if (i->id == MIPS_INS_MULTU)
	{
		op0 = irb.CreateZExt(op0, ty);
		op1 = irb.CreateZExt(op1, ty);
	}
	else
	{
		assert(false && "unhandled insn ID");
	}
	auto* mul = irb.CreateMul(op0, op1);
	auto* low = irb.CreateTrunc(mul, getRegisterType(MIPS_REG_LO));
	storeRegister(MIPS_REG_LO, low, irb);
	auto* shift = irb.CreateLShr(mul, getArchBitSize());
	auto* high = irb.CreateTrunc(shift, getRegisterType(MIPS_REG_HI));
	storeRegister(MIPS_REG_HI, high, irb);
}

/**
 * MIPS_INS_NOP
 */
void Capstone2LlvmIrTranslatorMips_impl::translateNop(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	// Nothing.
}

/**
 * MIPS_INS_NOR, MIPS_INS_NORI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateNor(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* o = irb.CreateOr(op1, op2);
	auto* x = irb.CreateXor(o, llvm::ConstantInt::getSigned(o->getType(), -1));
	storeOp(mi->operands[0], x, irb);
}

/**
 * MIPS_INS_OR, MIPS_INS_ORI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateOr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* o = irb.CreateOr(op1, op2);
	storeOp(mi->operands[0], o, irb);
}

/**
 * MIPS_INS_ROTR, MIPS_INS_ROTRV
 */
void Capstone2LlvmIrTranslatorMips_impl::translateRotr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	op2 = irb.CreateAnd(op2, llvm::ConstantInt::get(op2->getType(), 31)); // low 5 bits
	auto* lshr = irb.CreateLShr(op1, op2);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(op2->getType(), 32), op2);
	auto* shl = irb.CreateShl(op1, sub);
	auto* o = irb.CreateOr(lshr, shl);
	storeOp(mi->operands[0], o, irb);
}

/**
 * MIPS_INS_SEB
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSeb(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	auto* ty = llvm::cast<llvm::IntegerType>(op1->getType());
	std::size_t shiftN = ty->getBitWidth() - 8;
	auto* shiftCi = llvm::ConstantInt::get(op1->getType(), shiftN);
	op1 = irb.CreateShl(op1, shiftCi);
	op1 = irb.CreateAShr(op1, shiftCi);
	storeOp(mi->operands[0], op1, irb);
}

/**
 * MIPS_INS_SEH
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSeh(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(mi, irb);
	auto* ty = llvm::cast<llvm::IntegerType>(op1->getType());
	std::size_t shiftN = ty->getBitWidth() - 16;
	auto* shiftCi = llvm::ConstantInt::get(op1->getType(), shiftN);
	op1 = irb.CreateShl(op1, shiftCi);
	op1 = irb.CreateAShr(op1, shiftCi);
	storeOp(mi->operands[0], op1, irb);
}

/**
 * MIPS_INS_SLL, MIPS_INS_SLLV
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSll(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* shl = irb.CreateShl(op1, op2);
	storeOp(mi->operands[0], shl, irb);
}

/**
 * MIPS_INS_SLT, MIPS_INS_SLTI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSlt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::SEXT_TRUNC);
	auto* slt = irb.CreateICmpSLT(op1, op2);
	slt = irb.CreateZExt(slt, getDefaultType());
	storeOp(mi->operands[0], slt, irb);
}

/**
 * MIPS_INS_SLTU, MIPS_INS_SLTIU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSltu(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::SEXT_TRUNC);
	auto* ult = irb.CreateICmpULT(op1, op2);
	ult = irb.CreateZExt(ult, getDefaultType());
	storeOp(mi->operands[0], ult, irb);
}

/**
 * MIPS_INS_SRA, MIPS_INS_SRAV
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSra(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* sra = irb.CreateAShr(op1, op2);
	storeOp(mi->operands[0], sra, irb);
}

/**
 * MIPS_INS_SRL, MIPS_INS_SRLV
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSrl(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* shr = irb.CreateLShr(op1, op2);
	storeOp(mi->operands[0], shr, irb);
}

/**
 * MIPS_INS_SUB, MIPS_INS_SUBU
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSub(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::SEXT_TRUNC);
	auto* sub = op1->getType()->isFloatingPointTy()
			? irb.CreateFSub(op1, op2)
			: irb.CreateSub(op1, op2);
	storeOp(mi->operands[0], sub, irb);
}

/**
 * MIPS_INS_SYSCALL
 */
void Capstone2LlvmIrTranslatorMips_impl::translateSyscall(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	if (mi->op_count == 0)
	{
		op0 = llvm::ConstantInt::get(getDefaultType(), 0);
	}
	else if (mi->op_count == 1)
	{
		op0 = loadOpUnary(mi, irb);
	}
	else
	{
		assert(false && "unhandled syscall op_count");
		return;
	}

	op0 = irb.CreateZExtOrTrunc(op0, getDefaultType());

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_syscall",
			llvm::Type::getVoidTy(_module->getContext()),
			{op0->getType()});

	irb.CreateCall(fnc, {op0});
}

/**
 * MIPS_INS_WSBH
 */
void Capstone2LlvmIrTranslatorMips_impl::translateWsbh(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_wsbh",
			getDefaultType(),
			{getDefaultType()});
	op1 = loadOpBinaryOp1(mi, irb);
	op1 = irb.CreateZExtOrTrunc(op1, getDefaultType());
	auto* c = irb.CreateCall(fnc, {op1});
	storeOp(mi->operands[0], c, irb);
}

/**
 * MIPS_INS_XOR, MIPS_INS_XORI
 */
void Capstone2LlvmIrTranslatorMips_impl::translateXor(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(mi, irb, eOpConv::ZEXT_TRUNC);
	auto* x = irb.CreateXor(op1, op2);
	storeOp(mi->operands[0], x, irb);
}

//
// TODO:
// - recip.d $f0, $f2:
//   error: instruction requires a CPU feature not currently enabled
//   I could not even find Capstone insn ID for this.
// - rsqrt.s $f0, $f2
//   error: instruction requires a CPU feature not currently enabled
//   I'm not sure if Capstone ID is MIPS_INS_FRSQRT, or not.
//

} // namespace capstone2llvmir
} // namespace retdec
