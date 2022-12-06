/**
 * @file src/capstone2llvmir/arm/arm.cpp
 * @brief ARM implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>

#include "capstone2llvmir/arm/arm_impl.h"

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorArm_impl::Capstone2LlvmIrTranslatorArm_impl(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator_impl(CS_ARCH_ARM, basic, extra, m)
{
	// This needs to be called from concrete's class ctor, not abstract's
	// class ctor, so that virtual table is properly initialized.
	initialize();
}

//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

bool Capstone2LlvmIrTranslatorArm_impl::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_ARM
			|| m == CS_MODE_THUMB;
}

bool Capstone2LlvmIrTranslatorArm_impl::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN
			|| m == CS_MODE_BIG_ENDIAN;
}

uint32_t Capstone2LlvmIrTranslatorArm_impl::getArchByteSize()
{
	return 4;
}

//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorArm_impl::generateEnvironmentArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorArm_impl::generateDataLayout()
{
	_module->setDataLayout("e-p:32:32:32-f80:32:32");
}

void Capstone2LlvmIrTranslatorArm_impl::generateRegisters()
{
	for (auto& p : _reg2type)
	{
		createRegister(p.first, _regLt);
	}
}

uint32_t Capstone2LlvmIrTranslatorArm_impl::getCarryRegister()
{
	return ARM_REG_CPSR_C;
}

void Capstone2LlvmIrTranslatorArm_impl::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	_insn = i;

	cs_detail* d = i->detail;
	cs_arm* ai = &d->arm;

	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;

		bool branchInsn = i->id == ARM_INS_B || i->id == ARM_INS_BX
				|| i->id == ARM_INS_BL || i->id == ARM_INS_BLX
				|| i->id == ARM_INS_CBZ || i->id == ARM_INS_CBNZ;
		if (ai->cc == ARM_CC_AL || ai->cc == ARM_CC_INVALID || branchInsn)
		{
			_inCondition = false;
			(this->*f)(i, ai, irb);
		}
		else
		{
			_inCondition = true;

			auto* cond = generateInsnConditionCode(irb, ai);
			auto bodyIrb = generateIfThen(cond, irb);

			(this->*f)(i, ai, bodyIrb);
		}
	}
	else
	{
		throwUnhandledInstructions(i);

		if (ai->cc == ARM_CC_AL || ai->cc == ARM_CC_INVALID)
		{
			_inCondition = false;
			translatePseudoAsmGeneric(i, ai, irb);
		}
		else
		{
			_inCondition = true;

			auto* cond = generateInsnConditionCode(irb, ai);
			auto bodyIrb = generateIfThen(cond, irb);

			translatePseudoAsmGeneric(i, ai, bodyIrb);
		}
	}
}

//
//==============================================================================
// ARM-specific methods.
//==============================================================================
//

/**
 * During execution, PC does not contain the address of the currently executing
 * instruction. The address of the currently executing instruction is typically
 * PC-8 for ARM, or PC-4 for Thumb.
 *
 * In Thumb state:
 * - For B, BL, CBNZ, and CBZ instructions, the value of the PC is the address
 *   of the current instruction plus 4 bytes.
 * - For all other instructions that use labels, the value of the PC is the
 *   address of the current instruction plus 4 bytes, with bit[1] of the result
 *   cleared to 0 to make it word-aligned.
 *
 * ARM:
 * current = PC - 8
 * =>
 * PC = current + 8 = current + 2*4 = current + 2*insn_size
 *
 * THUMB:
 * current = PC - 4
 * =>
 * PC = current + 4 = current + 2*2 = current + 2*insn_size
 */
llvm::Value* Capstone2LlvmIrTranslatorArm_impl::getCurrentPc(cs_insn* i)
{
	return llvm::ConstantInt::get(
			getDefaultType(),
			((i->address + (2*i->size)) >> 2) << 2);
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::loadRegister(
		uint32_t r,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct)
{
	if (r == ARM_REG_INVALID)
	{
		return nullptr;
	}

	if (r == ARM_REG_PC)
	{
		return getCurrentPc(_insn);
	}

	llvm::Value* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw GenericError("loadRegister() unhandled reg.");
	}

	llvmReg = generateTypeConversion(irb, llvmReg, dstType, ct);

	return irb.CreateLoad(llvmReg);
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateOperandShift(
		llvm::IRBuilder<>& irb,
		cs_arm_op& op,
		llvm::Value* val)
{
	if (op.shift.type == ARM_SFT_INVALID)
	{
		return val;
	}

	llvm::Value* n = nullptr;
	if (op.shift.type == ARM_SFT_ASR
			|| op.shift.type == ARM_SFT_LSL
			|| op.shift.type == ARM_SFT_LSR
			|| op.shift.type == ARM_SFT_ROR
			|| op.shift.type == ARM_SFT_RRX)
	{
		n = llvm::ConstantInt::get(val->getType(), op.shift.value);
	}
	else if (op.shift.type == ARM_SFT_ASR_REG
			|| op.shift.type == ARM_SFT_LSL_REG
			|| op.shift.type == ARM_SFT_LSR_REG
			|| op.shift.type == ARM_SFT_ROR_REG
			|| op.shift.type == ARM_SFT_RRX_REG)
	{
		n = loadRegister(op.shift.value, irb);
	}
	else
	{
		return val;
	}

	n = irb.CreateZExtOrTrunc(n, val->getType());

	switch (op.shift.type)
	{
		case ARM_SFT_ASR:
		case ARM_SFT_ASR_REG:
		{
			return generateShiftAsr(irb, val, n);
		}
		case ARM_SFT_LSL:
		case ARM_SFT_LSL_REG:
		{
			return generateShiftLsl(irb, val, n);
		}
		case ARM_SFT_LSR:
		case ARM_SFT_LSR_REG:
		{
			return generateShiftLsr(irb, val, n);
		}
		case ARM_SFT_ROR:
		case ARM_SFT_ROR_REG:
		{
			return generateShiftRor(irb, val, n);
		}
		case ARM_SFT_RRX:
		case ARM_SFT_RRX_REG:
		{
			return generateShiftRrx(irb, val, n);
		}
		case ARM_SFT_INVALID:
		default:
		{
			return val;
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateShiftAsr(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* cfShl = irb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
	auto* cfAnd = irb.CreateAnd(cfShl, val);
	auto* cfIcmp = irb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
	storeRegister(ARM_REG_CPSR_C, cfIcmp, irb);

	return irb.CreateAShr(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateShiftLsl(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* cfShl = irb.CreateShl(val, cfOp1);
	auto* cfIntT = llvm::cast<llvm::IntegerType>(cfShl->getType());
	auto* cfRightCount = llvm::ConstantInt::get(cfIntT, cfIntT->getBitWidth() - 1);
	auto* cfLow = irb.CreateLShr(cfShl, cfRightCount);
	storeRegister(ARM_REG_CPSR_C, cfLow, irb);

	return irb.CreateShl(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateShiftLsr(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* cfShl = irb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
	auto* cfAnd = irb.CreateAnd(cfShl, val);
	auto* cfIcmp = irb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
	storeRegister(ARM_REG_CPSR_C, cfIcmp, irb);

	return irb.CreateLShr(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateShiftRor(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(n->getType())->getBitWidth();

	auto* srl = irb.CreateLShr(val, n);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW), n);
	auto* shl = irb.CreateShl(val, sub);
	auto* orr = irb.CreateOr(srl, shl);

	auto* cfSrl = irb.CreateLShr(orr, llvm::ConstantInt::get(orr->getType(), op0BitW - 1));
	auto* cfIcmp = irb.CreateICmpNE(cfSrl, llvm::ConstantInt::get(cfSrl->getType(), 0));
	storeRegister(ARM_REG_CPSR_C, cfIcmp, irb);

	return orr;
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateShiftRrx(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(n->getType())->getBitWidth();
	auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);

	auto* cf = loadRegister(ARM_REG_CPSR_C, irb);
	cf = irb.CreateZExtOrTrunc(cf, n->getType());

	auto* srl = irb.CreateLShr(val, n);
	auto* srlZext = irb.CreateZExt(srl, doubleT);
	auto* op0Zext = irb.CreateZExt(val, doubleT);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW + 1), n);
	auto* subZext = irb.CreateZExt(sub, doubleT);
	auto* shl = irb.CreateShl(op0Zext, subZext);
	auto* sub2 = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW), n);
	auto* shl2 = irb.CreateShl(cf, sub2);
	auto* shl2Zext = irb.CreateZExt(shl2, doubleT);
	auto* or1 = irb.CreateOr(shl, srlZext);
	auto* or2 = irb.CreateOr(or1, shl2Zext);
	auto* or2Trunc = irb.CreateTrunc(or2, val->getType());

	auto* sub3 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* shl3 = irb.CreateShl(llvm::ConstantInt::get(sub3->getType(), 1), sub3);
	auto* and1 = irb.CreateAnd(shl3, val);
	auto* cfIcmp = irb.CreateICmpNE(and1, llvm::ConstantInt::get(and1->getType(), 0));
	storeRegister(ARM_REG_CPSR_C, cfIcmp, irb);

	return or2Trunc;
}

/**
 * We cannot use some sysreg ID numbers -> translate them to other ID numbers.
 * See comment for @c arm_sysreg_extension for more details.
 */
uint32_t Capstone2LlvmIrTranslatorArm_impl::sysregNumberTranslation(uint32_t r)
{
	if (ARM_SYSREG_SPSR_C <= r
			&& r <= (ARM_SYSREG_SPSR_C | ARM_SYSREG_SPSR_X | ARM_SYSREG_SPSR_S | ARM_SYSREG_SPSR_F))
	{
		return ARM_SYSREG_SPSR;
	}
	else if (ARM_SYSREG_CPSR_C <= r
			&& r <= (ARM_SYSREG_CPSR_C | ARM_SYSREG_CPSR_X | ARM_SYSREG_CPSR_S | ARM_SYSREG_CPSR_F))
	{
		return ARM_SYSREG_CPSR;
	}
	else
	{
		return r;
	}
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::loadOp(
		cs_arm_op& op,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty,
		bool lea)
{
	switch (op.type)
	{
		case ARM_OP_SYSREG:
		{
			auto* val = loadRegister(sysregNumberTranslation(op.reg), irb);
			return val
				? generateOperandShift(irb, op, val)
				: llvm::UndefValue::get(ty ? ty : getDefaultType());
		}
		case ARM_OP_REG:
		{
			auto* val = loadRegister(op.reg, irb);
			return val
				? generateOperandShift(irb, op, val)
				: llvm::UndefValue::get(ty ? ty : getDefaultType());
		}
		case ARM_OP_IMM:
		case ARM_OP_PIMM:
		case ARM_OP_CIMM:
		{
			auto* val = llvm::ConstantInt::getSigned(getDefaultType(), op.imm);
			return generateOperandShift(irb, op, val);
		}
		case ARM_OP_MEM:
		{
			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = baseR ? baseR->getType() : getDefaultType();
			llvm::Value* disp = op.mem.disp
					? llvm::ConstantInt::get(t, op.mem.disp)
					: nullptr;

			auto* idxR = loadRegister(op.mem.index, irb);
			if (idxR)
			{
				if (op.mem.lshift > 0)
				{
					auto* lshift = llvm::ConstantInt::get(
							idxR->getType(),
							op.mem.lshift);
					idxR = irb.CreateShl(idxR, lshift);
				}

				// arm.h says this is only 1 || -1 -> ignore anything != -1.
				if (op.mem.scale == -1)
				{
					auto* scale = llvm::ConstantInt::get(
							idxR->getType(),
							op.mem.scale);
					idxR = irb.CreateMul(idxR, scale);
				}

				// If there is a shift in memory operand, it is applied to
				// the index register.
				idxR = generateOperandShift(irb, op, idxR);
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
				auto* lty = ty ? ty : getDefaultType();
				auto* pt = llvm::PointerType::get(lty, 0);
				addr = irb.CreateIntToPtr(addr, pt);
				return irb.CreateLoad(addr);
			}
		}
		case ARM_OP_FP:
		{
			auto* val = llvm::ConstantFP::get(irb.getFloatTy(), op.fp);
			return generateOperandShift(irb, op, val);
		}
		case ARM_OP_SETEND:
		{
			return llvm::UndefValue::get(getDefaultType());
		}
		case ARM_OP_INVALID:
		default:
		{
			return llvm::UndefValue::get(ty ? ty : getDefaultType());
		}
	}
}

llvm::Instruction* Capstone2LlvmIrTranslatorArm_impl::storeRegister(
		uint32_t r,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (r == ARM_REG_INVALID)
	{
		return nullptr;
	}

	// ARM allows direct write into Program Counter register -> uncond branch.
	//
	if (r == ARM_REG_PC)
	{
		return generateBranchFunctionCall(irb, val);
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw GenericError("storeRegister() unhandled reg.");
	}
	if (llvmReg->getValueType()->isFloatingPointTy())
	{
		switch (ct)
		{
			case eOpConv::SITOFP_OR_FPCAST:
			case eOpConv::UITOFP_OR_FPCAST:
				val = generateTypeConversion(irb, val, llvmReg->getValueType(), ct);
				break;
			default:
				val = generateTypeConversion(irb, val, llvmReg->getValueType(), eOpConv::FPCAST_OR_BITCAST);
		}
	}
	else
	{
		switch (ct)
		{
			case eOpConv::SEXT_TRUNC_OR_BITCAST:
			case eOpConv::ZEXT_TRUNC_OR_BITCAST:
				val = generateTypeConversion(irb, val, llvmReg->getValueType(), ct);
				break;
			default:
				val = generateTypeConversion(irb, val, llvmReg->getValueType(), eOpConv::SEXT_TRUNC_OR_BITCAST);
		}
	}

	return irb.CreateStore(val, llvmReg);
}

llvm::Instruction* Capstone2LlvmIrTranslatorArm_impl::storeOp(
		cs_arm_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (op.type != ARM_OP_MEM && op.shift.type != ARM_SFT_INVALID)
	{
		throw GenericError("Unhandled situation in storeOp().");
	}

	switch (op.type)
	{
		case ARM_OP_SYSREG:
		{
			return storeRegister(sysregNumberTranslation(op.reg), val, irb, ct);
		}
		case ARM_OP_REG:
		{
			return storeRegister(op.reg, val, irb, ct);
		}
		case ARM_OP_MEM:
		{
			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = baseR ? baseR->getType() : getDefaultType();
			llvm::Value* disp = op.mem.disp
					? llvm::ConstantInt::get(t, op.mem.disp)
					: nullptr;

			auto* idxR = loadRegister(op.mem.index, irb);
			if (idxR)
			{
				if (op.mem.lshift >= 0)
				{
					auto* lshift = llvm::ConstantInt::get(
							idxR->getType(),
							op.mem.lshift);
					idxR = irb.CreateShl(idxR, lshift);
				}

				// arm.h says this is only 1 || -1 -> ignore anything != -1.
				if (op.mem.scale == -1)
				{
					auto* scale = llvm::ConstantInt::get(
							idxR->getType(),
							op.mem.scale);
					idxR = irb.CreateMul(idxR, scale);
				}

				// If there is a shift in memory operand, it is applied to
				// the index register.
				idxR = generateOperandShift(irb, op, idxR);
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
			else
			{
				addr = llvm::ConstantInt::get(getDefaultType(), 0);
			}

			if (idxR && addr != idxR)
			{
				idxR = irb.CreateZExtOrTrunc(idxR, addr->getType());
				addr = irb.CreateAdd(addr, idxR);
			}

			auto* pt = llvm::PointerType::get(val->getType(), 0);
			addr = irb.CreateIntToPtr(addr, pt);
			return irb.CreateStore(val, addr);
		}
		case ARM_OP_PIMM:
		case ARM_OP_CIMM:
		{
			return nullptr;
		}
		case ARM_OP_FP:
		case ARM_OP_IMM:
		case ARM_OP_SETEND:
		case ARM_OP_INVALID:
		default:
		{
			throw GenericError("unhandled value");
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorArm_impl::generateInsnConditionCode(
		llvm::IRBuilder<>& irb,
		cs_arm* ai)
{
	switch (ai->cc)
	{
		// Equal = Zero set
		case ARM_CC_EQ:
		{
			auto* z = loadRegister(ARM_REG_CPSR_Z, irb);
			return z;
		}
		// Not equal = Zero clear
		case ARM_CC_NE:
		{
			auto* z = loadRegister(ARM_REG_CPSR_Z, irb);
			return generateValueNegate(irb, z);
		}
		// Unsigned higher or same = Carry set
		case ARM_CC_HS:
		{
			auto* c = loadRegister(ARM_REG_CPSR_C, irb);
			return c;
		}
		// Unsigned lower = Carry clear
		case ARM_CC_LO:
		{
			auto* c = loadRegister(ARM_REG_CPSR_C, irb);
			return generateValueNegate(irb, c);
		}
		// Negative = N set
		case ARM_CC_MI:
		{
			auto* n = loadRegister(ARM_REG_CPSR_N, irb);
			return n;
		}
		// Positive or zero = N clear
		case ARM_CC_PL:
		{
			auto* n = loadRegister(ARM_REG_CPSR_N, irb);
			return generateValueNegate(irb, n);
		}
		// Overflow = V set
		case ARM_CC_VS:
		{
			auto* v = loadRegister(ARM_REG_CPSR_V, irb);
			return v;
		}
		// No overflow = V clear
		case ARM_CC_VC:
		{
			auto* v = loadRegister(ARM_REG_CPSR_V, irb);
			return generateValueNegate(irb, v);
		}
		// Unsigned higher = Carry set & Zero clear
		case ARM_CC_HI:
		{
			auto* c = loadRegister(ARM_REG_CPSR_C, irb);
			auto* z = loadRegister(ARM_REG_CPSR_Z, irb);
			auto* nz = generateValueNegate(irb, z);
			return irb.CreateAnd(c, nz);
		}
		// Unsigned lower or same = Carry clear or Zero set
		case ARM_CC_LS:
		{
			auto* z = loadRegister(ARM_REG_CPSR_Z, irb);
			auto* c = loadRegister(ARM_REG_CPSR_C, irb);
			auto* nc = generateValueNegate(irb, c);
			return irb.CreateOr(z, nc);
		}
		// Greater than or equal = N set and V set || N clear and V clear
		// (N & V) || (!N & !V) == !(N xor V)
		case ARM_CC_GE:
		{
			auto* n = loadRegister(ARM_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM_REG_CPSR_V, irb);
			auto* x = irb.CreateXor(n, v);
			return generateValueNegate(irb, x);
		}
		// Less than = N set and V clear || N clear and V set
		// (N & !V) || (!N & V) == (N xor V)
		case ARM_CC_LT:
		{
			auto* n = loadRegister(ARM_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM_REG_CPSR_V, irb);
			return irb.CreateXor(n, v);
		}
		// Greater than = Z clear, and either N set and V set, or N clear and V set
		case ARM_CC_GT:
		{
			auto* z = loadRegister(ARM_REG_CPSR_Z, irb);
			auto* n = loadRegister(ARM_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM_REG_CPSR_V, irb);
			auto* xor1 = irb.CreateXor(n, v);
			auto* or1 = irb.CreateOr(z, xor1);
			return generateValueNegate(irb, or1);
		}
		// Less than or equal = Z set, or N set and V clear, or N clear and V set
		case ARM_CC_LE:
		{
			auto* z = loadRegister(ARM_REG_CPSR_Z, irb);
			auto* n = loadRegister(ARM_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM_REG_CPSR_V, irb);
			auto* xor1 = irb.CreateXor(n, v);
			return irb.CreateOr(z, xor1);
		}
		case ARM_CC_AL:
		case ARM_CC_INVALID:
		default:
		{
			throw GenericError("should not be possible");
		}
	}
}

bool Capstone2LlvmIrTranslatorArm_impl::isOperandRegister(cs_arm_op& op)
{
	return op.type == ARM_OP_REG;
}

uint8_t Capstone2LlvmIrTranslatorArm_impl::getOperandAccess(cs_arm_op& op)
{
	return op.access;
}

//
//==============================================================================
// ARM instruction translation methods.
//==============================================================================
//

/**
 * ARM_INS_ADC
 * TODO: Castone sets update_flags==true even when "adc", not "adcs".
 * Check once more and report as bug.
 */
void Capstone2LlvmIrTranslatorArm_impl::translateAdc(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	auto* cf = loadRegister(ARM_REG_CPSR_C, irb);
	auto* add1 = irb.CreateAdd(op1, op2);
	auto* val = irb.CreateAdd(add1, irb.CreateZExtOrTrunc(cf, add1->getType()));
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_C, generateCarryAddC(op1, op2, irb, cf), irb);
		storeRegister(ARM_REG_CPSR_V, generateOverflowAddC(val, op1, op2, irb, cf), irb);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_ADD, ARM_INS_CMN (ADDS but result is discarded)
 */
void Capstone2LlvmIrTranslatorArm_impl::translateAdd(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
//	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);
	EXPECT_IS_EXPR(i, ai, irb, (2 <= ai->op_count && ai->op_count <= 4));

	if (ai->op_count < 4)
	{
		std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	}
	// TODO: "00 C6 8F E2" = "add ip, pc, #0, #12"
	// If we translate this to "@__asm_add(i32 pc, i32 0, i32 12)" then some
	// regression tests fail because values that were computed before can not
	// be computed now.
	// ARM specification does not allow instruction like this, but it looks like
	// it can happend (probably not only in ADD). See:
	// https://stackoverflow.com/questions/16207865/weird-gas-arm-syntax
	// https://reverseengineering.stackexchange.com/questions/16154/arm-add-instruction-with-shift
	//
	// This is just a hack that ignores the fourth operand. We should use it in
	// rotation. But the best solution is to fix Capstone to interpret it as
	// such, not to hack it here in our library.
	//
	else
	{
		std::tie(op1, op2, op3) = loadOpQuaternaryOp1Op2Op3(ai, irb);
	}

	auto* add = irb.CreateAdd(op1, op2);
	if (ai->update_flags || i->id == ARM_INS_CMN)
	{
		llvm::Value* zero = llvm::ConstantInt::get(add->getType(), 0);
		storeRegister(ARM_REG_CPSR_C, generateCarryAdd(add, op1, irb), irb);
		storeRegister(ARM_REG_CPSR_V, generateOverflowAdd(add, op1, op2, irb), irb);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(add, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(add, zero), irb);
	}
	if (i->id != ARM_INS_CMN)
	{
		storeOp(ai->operands[0], add, irb);
	}
}

/**
 * ARM_INS_AND, ARM_INS_BIC, ARM_INS_TST (ANDS but result is discarded)
 */
void Capstone2LlvmIrTranslatorArm_impl::translateAnd(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	if (i->id == ARM_INS_BIC)
	{
		op2 = generateValueNegate(irb, op2);
	}
	auto* val = irb.CreateAnd(op1, op2);
	// If S is specified, the AND instruction:
	// - updates the N and Z flags according to the result
	// - can update the C flag during the calculation of Operand2 (shifts?)
	// - does not affect the V flag.
	if (ai->update_flags || i->id == ARM_INS_TST)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	if (i->id != ARM_INS_TST)
	{
		storeOp(ai->operands[0], val, irb);
	}
}

/**
 * ARM_INS_B, ARM_INS_BX (exchange instruction)
 */
void Capstone2LlvmIrTranslatorArm_impl::translateB(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ai, irb);

	op0 = loadOpUnary(ai, irb);
	bool isReturn = ai->operands[0].type == ARM_OP_REG
			&& ai->operands[0].reg == ARM_REG_LR;

	if (ai->cc == ARM_CC_AL || ai->cc == ARM_CC_INVALID)
	{
		isReturn
			? generateReturnFunctionCall(irb, op0)
			: generateBranchFunctionCall(irb, op0);
	}
	else
	{
		auto* cond = generateInsnConditionCode(irb, ai);
		isReturn
			? generateCondReturnFunctionCall(irb, cond, op0)
			: generateCondBranchFunctionCall(irb, cond, op0);
	}
}

/**
 * ARM_INS_BL, ARM_INS_BLX (exchange instruction)
 */
void Capstone2LlvmIrTranslatorArm_impl::translateBl(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ai, irb);

	storeRegister(ARM_REG_LR, getNextInsnAddress(i), irb);
	op0 = loadOpUnary(ai, irb);
	if (ai->cc == ARM_CC_AL || ai->cc == ARM_CC_INVALID)
	{
		generateCallFunctionCall(irb, op0);
	}
	else
	{
		auto* cond = generateInsnConditionCode(irb, ai);
		generateCondBranchFunctionCall(irb, cond, op0);
	}
}

/**
 * ARM_INS_CBNZ
 */
void Capstone2LlvmIrTranslatorArm_impl::translateCbnz(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	std::tie(op0, op1) = loadOpBinary(ai, irb, eOpConv::NOTHING);
	auto* cond = irb.CreateICmpNE(op0, llvm::ConstantInt::get(op0->getType(), 0));
	if (ai->cc != ARM_CC_AL && ai->cc != ARM_CC_INVALID)
	{
		cond = irb.CreateAnd(cond, generateInsnConditionCode(irb, ai));
	}
	generateCondBranchFunctionCall(irb, cond, op1);
}

/**
 * ARM_INS_CBZ
 */
void Capstone2LlvmIrTranslatorArm_impl::translateCbz(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	std::tie(op0, op1) = loadOpBinary(ai, irb, eOpConv::NOTHING);
	auto* cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
	if (ai->cc != ARM_CC_AL && ai->cc != ARM_CC_INVALID)
	{
		cond = irb.CreateAnd(cond, generateInsnConditionCode(irb, ai));
	}
	generateCondBranchFunctionCall(irb, cond, op1);
}

/**
 * ARM_INS_CLZ
 */
void Capstone2LlvmIrTranslatorArm_impl::translateClz(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			llvm::Intrinsic::ctlz,
			op1->getType());
	auto* ctlz = irb.CreateCall(f, {op1, irb.getTrue()});
	storeOp(ai->operands[0], ctlz, irb);
}

/**
 * ARM_INS_EOR, ARM_INS_TEQ (EORS but result is discarded)
 */
void Capstone2LlvmIrTranslatorArm_impl::translateEor(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	auto* val = irb.CreateXor(op1, op2);
	// If S is specified, the EOR instruction:
	// - updates the N and Z flags according to the result
	// - can update the C flag during the calculation of Operand2 (shifts?)
	// - does not affect the V flag.
	if (ai->update_flags || i->id == ARM_INS_TEQ)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	if (i->id != ARM_INS_TEQ)
	{
		storeOp(ai->operands[0], val, irb);
	}
}

/**
 * ARM_INS_MLA
 */
void Capstone2LlvmIrTranslatorArm_impl::translateMla(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	std::tie(op1, op2, op3) = loadOpQuaternaryOp1Op2Op3(ai, irb);
	auto* val = irb.CreateMul(op1, op2);
	val = irb.CreateAdd(op3, val);

	// Updates the N and Z flags according to the result.
	// Corrupts the C and V flag in ARMv4.
	// Does not affect the C or V flag in ARMv5T and above.
	// TODO: The question is, does it set N/Z according to what is written to
	// dst reg (low 32-bit), or according to the full result (64-bit)?
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_MLS
 */
void Capstone2LlvmIrTranslatorArm_impl::translateMls(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	std::tie(op1, op2, op3) = loadOpQuaternaryOp1Op2Op3(ai, irb);
	auto* val = irb.CreateMul(op1, op2);
	val = irb.CreateSub(op3, val);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_MOV, ARM_INS_MVN,
 */
void Capstone2LlvmIrTranslatorArm_impl::translateMov(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);
	if (i->id == ARM_INS_MVN)
	{
		op1 = generateValueNegate(irb, op1);
	}

	// If S is specified, the MOV instruction:
	// - updates the N and Z flags according to the result
	// - can update the C flag during the calculation of Operand2 (shifts?)
	// - does not affect the V flag.
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(op1->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(op1, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(op1, zero), irb);
	}
	storeOp(ai->operands[0], op1, irb);
}

/**
 * Preferred synonyms for MOV instructions with shifted register operands:
 * ARM_INS_LSL, ARM_INS_LSR, ARM_INS_ROR, ARM_INS_RRX, ARM_INS_ASR
 *
 * TODO: Report Capstone bug:
 * - When shift is imm, it is ok -- imm is part of the operand to be shifted.
 *   e.g. lsl r0, r1, #4 = 2 operands, 4 and LSL part of r1 operand.
 * - When shift is reg, it is NOT ok -- reg is NOT a part of the operand to be
 *   shifted, even though it could be.
 *   e.g. lsl r0, r1, r2 = 3 operands, r1 have ARM_SFT_INVALID, r2 separate op.
 *   It should be 2 operands, r1 with ARM_SFT_LSL_REG, r2 in r1 op as shift val.
 * - On THUMB, not even imm is ok, it creates 3th operand as well.
 */
void Capstone2LlvmIrTranslatorArm_impl::translateShifts(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	// We expect 2nd operand to have shift/rotate set -> loadOp() will take
	// care of shift/rotate computation.
	//
	if (ai->op_count == 2 && ai->operands[1].shift.type != ARM_SFT_INVALID)
	{
		op1 = loadOpBinaryOp1(ai, irb);
	}
	// We expect that 3rd operand is a shift/rotate value, and 2nd operand
	// does not have shift type set - ARM_SFT_INVALID.
	// Shift type is determined by insn ID.
	//
	// TODO: THUMB "99 40" = "lsls r1, r3" -- only 2 ops, no shift in 2nd op.
	// Report Capstone bug - consistency - it should have 2 operands, r1 and r1,
	// r3 should be part of r1 shift.
	//
	else if (ai->op_count == 2 || ai->op_count == 3)
	{
		std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);

		switch (i->id)
		{
			case ARM_INS_ASR: op1 = generateShiftAsr(irb, op1, op2); break;
			case ARM_INS_LSL: op1 = generateShiftLsl(irb, op1, op2); break;
			case ARM_INS_LSR: op1 = generateShiftLsr(irb, op1, op2); break;
			case ARM_INS_ROR: op1 = generateShiftRor(irb, op1, op2); break;
			case ARM_INS_RRX: op1 = generateShiftRrx(irb, op1, op2); break;
			default:
			{
				throw GenericError("unhandled insn ID");
			}
		}
	}

	// If S is specified, the MOV instruction:
	// - updates the N and Z flags according to the result
	// - can update the C flag during the calculation of Operand2 (shifts?)
	// - does not affect the V flag.
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(op1->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(op1, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(op1, zero), irb);
	}
	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM_INS_MOVT
 */
void Capstone2LlvmIrTranslatorArm_impl::translateMovt(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	// TODO: It looks like on THUMB, op0 is not ANDed -- investigate.
	// Add/Fix THUMB unit tests.
	if (_basicMode == CS_MODE_THUMB)
	{
		std::tie(op0, op1) = loadOpBinary(ai, irb, eOpConv::ZEXT_TRUNC_OR_BITCAST);
		op1 = irb.CreateShl(op1, 16);
		op0 = irb.CreateOr(op0, op1);
		storeOp(ai->operands[0], op0, irb);
	}
	else
	{
		std::tie(op0, op1) = loadOpBinary(ai, irb, eOpConv::ZEXT_TRUNC_OR_BITCAST);
		op0 = irb.CreateAnd(op0, 0xffff);
		op1 = irb.CreateShl(op1, 16);
		op0 = irb.CreateOr(op0, op1);
		storeOp(ai->operands[0], op0, irb);
	}
}

/**
 * ARM_INS_MOVW
 */
void Capstone2LlvmIrTranslatorArm_impl::translateMovw(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	// TODO: It looks like on THUMB, result is overwritten -- investigate.
	// Add/Fix THUMB unit tests.
	if (_basicMode == CS_MODE_THUMB)
	{
		op1 = loadOpBinaryOp1(ai, irb);
		op1 = irb.CreateZExtOrTrunc(op1, irb.getInt32Ty());
		storeOp(ai->operands[0], op1, irb);
	}
	else
	{
		std::tie(op0, op1) = loadOpBinary(ai, irb, eOpConv::ZEXT_TRUNC_OR_BITCAST);
		op0 = irb.CreateAnd(op0, 0xffff0000);
		op0 = irb.CreateOr(op0, op1);
		storeOp(ai->operands[0], op0, irb);
	}
}

/**
 * ARM_INS_MUL
 */
void Capstone2LlvmIrTranslatorArm_impl::translateMul(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	auto* val = irb.CreateMul(op1, op2);
	// If S is specified, the MUL instruction:
	// - updates the N and Z flags according to the result
	// - corrupts the C and V flag in ARMv4
	// - does not affect the C or V flag in ARMv5T and above.
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_NOP
 */
void Capstone2LlvmIrTranslatorArm_impl::translateNop(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	// nothing
}

/**
 * ARM_INS_ORR
 */
void Capstone2LlvmIrTranslatorArm_impl::translateOrr(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	auto* val = irb.CreateOr(op1, op2);
	// If S is specified, the ORR instruction:
	// - updates the N and Z flags according to the result
	// - can update the C flag during the calculation of Operand2 (shifts?)
	// - does not affect the V flag.
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_LDM   = IA (increment after) = LDMFD (synonym, IDA)
 * ARM_INS_LDMIB = IB (increment before) (ARM only)
 * ARM_INS_LDMDA = DA (decrement after) (ARM only)
 * ARM_INS_LDMDB = DB (decrement before)
 * ARM_INS_POP   = LDMIA sp! reglist (writeback to SP, increment after)
 *
 * ARM_INS_STM   = IA (increment after)
 * ARM_INS_STMIB = IB (increment before) (ARM only)
 * ARM_INS_STMDA = DA (decrement after) (ARM only)
 * ARM_INS_STMDB = DB (decrement before) = STMFD (synonym, IDA)
 * ARM_INS_PUSH  = STMDB sp!, reglist (writeback to SP, decrement before)
 *
 * ARM_INS_PUSH (ARM_INS_STMDB):
 * Registers are stored on the stack in numerical order, with the lowest
 * numbered register at the lowest address.
 * TODO: Is this also true for ARM_INS_STMDA? Are increment variants ok?
 *
 * TODO: If PC is loaded (store to PC -> branch), then we might generate uncond
 * branch in the middle of the instruction -> before all of it is executed.
 * We should remember such branch and generate it last, because in CPU,
 * all the instruction is executed.
 */
void Capstone2LlvmIrTranslatorArm_impl::translateLdmStm(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (ai->op_count > 0));

	auto sz = getArchByteSize();
	auto* ty = getDefaultType();
	auto* pt = llvm::PointerType::get(ty, 0);

	unsigned opStart = 0;
	if (i->id == ARM_INS_POP || i->id == ARM_INS_PUSH)
	{
		op0 = loadRegister(ARM_REG_SP, irb);
		opStart = 0;
	}
	else
	{
		op0 = loadOp(ai->operands[0], irb);
		opStart = 1;
	}

	bool increment = i->id == ARM_INS_LDM || i->id == ARM_INS_LDMIB || i->id == ARM_INS_POP
			|| i->id == ARM_INS_STM || i->id == ARM_INS_STMIB;
	bool after = i->id == ARM_INS_LDM || i->id == ARM_INS_LDMDA || i->id == ARM_INS_POP
			|| i->id == ARM_INS_STM || i->id == ARM_INS_STMDA;
	bool before = !after;
	bool load = i->id == ARM_INS_LDM || i->id == ARM_INS_LDMIB || i->id == ARM_INS_LDMDA
			|| i->id == ARM_INS_LDMDB || i->id == ARM_INS_POP;

	llvm::Value* incDec = op0;
	llvm::Value* finalIncDec = op0;

	llvm::Value* pcStoreVal = nullptr;
	unsigned pcStoreNum = 0;

	for (unsigned j = opStart; j < ai->op_count; ++j)
	{
		uint64_t c = i->id == ARM_INS_PUSH || i->id == ARM_INS_STMDB
				? sz * (ai->op_count - j)
				: sz * (j-opStart+1);

		auto* ci = llvm::ConstantInt::get(op0->getType(), c);

		if (before)
		{
			if (increment)
			{
				incDec = irb.CreateAdd(op0, ci);
			}
			else
			{
				incDec = irb.CreateSub(op0, ci);
			}
		}

		auto* addr = irb.CreateIntToPtr(incDec, pt);

		if (load)
		{
			auto* l = irb.CreateLoad(addr);
			if (ai->operands[j].type == ARM_OP_REG
					&& ai->operands[j].reg == ARM_REG_PC)
			{
				pcStoreVal = l;
				pcStoreNum = j;
			}
			else
			{
				storeOp(ai->operands[j], l, irb);
			}
		}
		else
		{
			auto* reg = loadOp(ai->operands[j], irb);
			reg = irb.CreateZExtOrTrunc(reg, ty);
			irb.CreateStore(reg, addr);
		}

		if (after)
		{
			if (increment)
			{
				incDec = irb.CreateAdd(op0, ci);
			}
			else
			{
				incDec = irb.CreateSub(op0, ci);
			}
		}

		if (i->id == ARM_INS_PUSH || i->id == ARM_INS_STMDB)
		{
			if (finalIncDec == op0)
			{
				finalIncDec = incDec;
			}
		}
		else
		{
			finalIncDec = incDec;
		}
	}

	if (i->id == ARM_INS_POP || i->id == ARM_INS_PUSH)
	{
		storeRegister(ARM_REG_SP, finalIncDec, irb);
	}
	else if (ai->writeback)
	{
		storeOp(ai->operands[0], finalIncDec, irb);
	}

	if (pcStoreVal)
	{
		storeOp(ai->operands[pcStoreNum], pcStoreVal, irb);
	}
}

/**
 * ARM_INS_REV
 */
void Capstone2LlvmIrTranslatorArm_impl::translateRev(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			llvm::Intrinsic::bswap,
			op1->getType());
	auto* val = irb.CreateCall(f, {op1});
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_SBC, ARM_INS_RSC
 * TODO: The same flag-update problem as with ARM_INS_ADC.
 */
void Capstone2LlvmIrTranslatorArm_impl::translateSbc(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	if (i->id == ARM_INS_SBC)
	{
		std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	}
	else if (i->id == ARM_INS_RSC)
	{
		std::tie(op2, op1) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	}
	auto* cf = loadRegister(ARM_REG_CPSR_C, irb);
	// If the carry flag is clear, the result is reduced by one.
	cf = irb.CreateICmpEQ(cf, irb.getFalse());
	auto* sub1 = irb.CreateSub(op1, op2);
	auto* val = irb.CreateSub(sub1, irb.CreateZExtOrTrunc(cf, sub1->getType()));
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_C, generateValueNegate(irb, generateBorrowSubC(val, op1, op2, irb, cf)), irb);
		storeRegister(ARM_REG_CPSR_V, generateOverflowSubC(val, op1, op2, irb, cf), irb);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM_INS_LDR (word) = ARM_INS_LDRT (unprivileged)
 * ARM_INS_LDRB (unsigned byte) = ARM_INS_LDRBT (unprivileged)
 * ARM_INS_LDRSB (signed byte) = ARM_INS_LDRSBT (unprivileged)
 * ARM_INS_LDRH (unsigned half word) = ARM_INS_LDRHT (unprivileged)
 * ARM_INS_LDRSH (signed half word) = ARM_INS_LDRSHT (unprivileged)
 *
 * ARM_INS_LDREX, ARM_INS_LDREXB, ARM_INS_LDREXH = Exclusive:
 * Conditional load, conditions check physical address atributes (e.g. TLB).
 * We are not able to check those here. Right now, we just ignore it and
 * generate ordinary loads, but we might generate ASM pseudo insn fnc call.
 *
 * LDR R0, [R4, #4]  ; simple offset: R0 = *(int*)(R4+4); R4 unchanged
 * LDR R0, [R4, #4]! ; pre-indexed  : R0 = *(int*)(R4+4); R4 = R4+4
 * LDR R0, [R4], #4  ; post-indexed : R0 = *(int*)(R4+0); R4 = R4+4
 *
 * TODO: "20 f5 bc e5" = "ldr pc, [ip, #0x520]!" -> write to PC -> branch,
 * writeback is generated after the branch call -> problem here, and probably
 * everywhere where writeback is generated. In these cases, branch generated for
 * PC write should be the last instruction.
 */
void Capstone2LlvmIrTranslatorArm_impl::translateLdr(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	llvm::Type* ty = nullptr;
	bool sext = false;
	switch (i->id)
	{
		case ARM_INS_LDR:
		case ARM_INS_LDRT:
		case ARM_INS_LDREX:
		{
			ty = irb.getInt32Ty();
			sext = false;
			break;
		}
		case ARM_INS_LDRB:
		case ARM_INS_LDRBT:
		case ARM_INS_LDREXB:
		{
			ty = irb.getInt8Ty();
			sext = false;
			break;
		}
		case ARM_INS_LDRSB:
		case ARM_INS_LDRSBT:
		{
			ty = irb.getInt8Ty();
			sext = true;
			break;
		}
		case ARM_INS_LDRH:
		case ARM_INS_LDRHT:
		case ARM_INS_LDREXH:
		{
			ty = irb.getInt16Ty();
			sext = false;
			break;
		}
		case ARM_INS_LDRSH:
		case ARM_INS_LDRSHT:
		{
			ty = irb.getInt16Ty();
			sext = true;
			break;
		}
		default:
		{
			throw GenericError("unhandled LDR id");
		}
	}

	uint32_t baseR = ARM_REG_INVALID;
	llvm::Value* idx = nullptr;
	bool subtract = false;
	if (ai->op_count == 2
			&& ai->operands[1].type == ARM_OP_MEM)
	{
		op1 = loadOpBinaryOp1(ai, irb, ty);
		baseR = ai->operands[1].mem.base;
		if (auto disp = ai->operands[1].mem.disp)
		{
			idx = llvm::ConstantInt::getSigned(getDefaultType(), disp);
		}
		else if (ai->operands[1].mem.index != ARM_REG_INVALID)
		{
			idx = loadRegister(ai->operands[1].mem.index, irb);
		}
	}
	else if (ai->op_count == 3
			&& ai->operands[1].type == ARM_OP_MEM)
	{
		op1 = loadOp(ai->operands[1], irb, ty);
		baseR = ai->operands[1].mem.base;
		idx = loadOp(ai->operands[2], irb);
		subtract = ai->operands[2].subtracted;
	}
	else
	{
		throw GenericError("unhandled LDR format");
	}

	op1 = sext
			? irb.CreateSExtOrTrunc(op1, irb.getInt32Ty())
			: irb.CreateZExtOrTrunc(op1, irb.getInt32Ty());

	llvm::Value* v = nullptr;
	if (ai->writeback && idx && baseR != ARM_REG_INVALID)
	{
		auto* b = loadRegister(baseR, irb);
		v = subtract
				? irb.CreateSub(b, idx)
				: irb.CreateAdd(b, idx);
		if (baseR != ARM_REG_PC)
		{
			storeRegister(baseR, v, irb);
		}
	}

	storeOp(ai->operands[0], op1, irb);

	bool op0Pc = ai->operands[0].type == ARM_OP_REG
			&& ai->operands[0].reg == ARM_REG_PC;
	if (!op0Pc && baseR == ARM_REG_PC && v)
	{
		storeRegister(baseR, v, irb);
	}
}

/**
 * ARM_INS_LDRD (double word)
 * ARM_INS_LDREXD (exclusive, see @c translateLdr())
 */
void Capstone2LlvmIrTranslatorArm_impl::translateLdrd(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_SET(i, ai, irb, (std::set<unsigned>{3, 4}));

	uint32_t baseR = ARM_REG_INVALID;
	llvm::Value* idx = nullptr;
	bool subtract = false;
	if (ai->op_count == 3
			&& ai->operands[2].type == ARM_OP_MEM)
	{
		op1 = loadOp(ai->operands[2], irb, irb.getInt64Ty());
		baseR = ai->operands[2].mem.base;
		if (auto disp = ai->operands[2].mem.disp)
		{
			idx = llvm::ConstantInt::getSigned(getDefaultType(), disp);
		}
		else if (ai->operands[2].mem.index != ARM_REG_INVALID)
		{
			idx = loadRegister(ai->operands[2].mem.index, irb);
		}
	}
	else if (ai->op_count == 4
			&& ai->operands[2].type == ARM_OP_MEM)
	{
		op1 = loadOp(ai->operands[2], irb, irb.getInt64Ty());
		baseR = ai->operands[2].mem.base;
		idx = loadOp(ai->operands[3], irb);
		subtract = ai->operands[3].subtracted;
	}
	else
	{
		throw GenericError("unhandled LDRD format");
	}

	auto* lo = irb.CreateTrunc(op1, irb.getInt32Ty());
	auto* hi = irb.CreateTrunc(irb.CreateLShr(op1, 32), irb.getInt32Ty());

	llvm::Value* v = nullptr;
	if (ai->writeback && idx && baseR != ARM_REG_INVALID)
	{
		auto* b = loadRegister(baseR, irb);
		v = subtract
				? irb.CreateSub(b, idx)
				: irb.CreateAdd(b, idx);
		if (baseR != ARM_REG_PC)
		{
			storeRegister(baseR, v, irb);
		}
	}

	bool op0Pc = ai->operands[0].type == ARM_OP_REG
			&& ai->operands[0].reg == ARM_REG_PC;
	bool op1Pc = ai->operands[1].type == ARM_OP_REG
			&& ai->operands[1].reg == ARM_REG_PC;

	if (!op0Pc && !op1Pc)
	{
		storeOp(ai->operands[0], hi, irb);
		storeOp(ai->operands[1], lo, irb);
	}
	else if (op0Pc && !op1Pc)
	{
		storeOp(ai->operands[1], lo, irb);
		storeOp(ai->operands[0], hi, irb);
	}
	else if (!op0Pc && op1Pc)
	{
		storeOp(ai->operands[0], hi, irb);
		storeOp(ai->operands[1], lo, irb);
	}
	else
	{
		// Store only one.
		storeOp(ai->operands[0], hi, irb);
	}

	if (!op0Pc && !op1Pc && baseR == ARM_REG_PC && v)
	{
		storeRegister(baseR, v, irb);
	}
}

/**
 * ARM_INS_STR (word) == ARM_INS_STRT (unprivileged)
 * ARM_INS_STRB (byte) == ARM_INS_STRBT (unprivileged)
 * ARM_INS_STRH (half word) == ARM_INS_STRHT (unprivileged)
 * ARM_INS_STRD (double word)
 *
 * ARM_INS_STREX, ARM_INS_STREXB, ARM_INS_STREXH, ARM_INS_STREXD = Exclusive:
 * Conditional store, conditions check physical address atributes (e.g. TLB).
 * We are not able to check those here. Right now, we just ignore it and
 * generate ordinary stores, but we might generate ASM pseudo insn fnc call.
 * TODO:
 * One more operand - first operand is set to dst reg for returned status
 * -> Translation disabled, this will need more work to work.
 *
 * STR R0, [R4, #4]  ; simple offset: *(int*)(R4+4) = R0; R4 unchanged
 * STR R0, [R4, #4]! ; pre-indexed  : *(int*)(R4+4) = R0; R4 = R4+4
 * STR R0, [R4], #4  ; post-indexed : *(int*)(R4+0) = R0; R4 = R4+4
 */
void Capstone2LlvmIrTranslatorArm_impl::translateStr(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (ai->op_count > 1));

	switch (i->id)
	{
		case ARM_INS_STR:
		case ARM_INS_STRT:
		case ARM_INS_STREX:
		{
			op0 = loadOp(ai->operands[0], irb);
			op0 = irb.CreateZExtOrTrunc(op0, irb.getInt32Ty());
			break;
		}

		case ARM_INS_STRB:
		case ARM_INS_STRBT:
		case ARM_INS_STREXB:
		{
			op0 = loadOp(ai->operands[0], irb);
			op0 = irb.CreateZExtOrTrunc(op0, irb.getInt8Ty());
			break;
		}
		case ARM_INS_STRH:
		case ARM_INS_STRHT:
		case ARM_INS_STREXH:
		{
			op0 = loadOp(ai->operands[0], irb);
			op0 = irb.CreateZExtOrTrunc(op0, irb.getInt16Ty());
			break;
		}
		case ARM_INS_STRD:
		case ARM_INS_STREXD:
		{
			if (!(ai->op_count > 2))
			{
				throw GenericError("Unhandled STRD format.");
			}

			op0 = loadOp(ai->operands[0], irb);
			op1 = loadOp(ai->operands[1], irb);
			break;
		}
		default:
		{
			throw GenericError("Unhandled STR id.");
		}
	}

	uint32_t baseR = ARM_REG_INVALID;
	llvm::Value* idx = nullptr;
	bool subtract = false;
	if (i->id == ARM_INS_STRD || i->id == ARM_INS_STREXD)
	{
		if (ai->op_count == 3
				&& ai->operands[2].type == ARM_OP_MEM)
		{
			storeOp(ai->operands[2], op0, irb);

			auto op3 = ai->operands[2];
			op3.mem.disp += 4;
			storeOp(op3, op1, irb);

			baseR = ai->operands[2].mem.base;
			if (auto disp = ai->operands[2].mem.disp)
			{
				idx = llvm::ConstantInt::getSigned(getDefaultType(), disp);
			}
			else if (ai->operands[2].mem.index != ARM_REG_INVALID)
			{
				idx = loadRegister(ai->operands[2].mem.index, irb);
			}
			// Maybe we should add +4 to idx?
		}
		else if (ai->op_count == 4
				&& ai->operands[2].type == ARM_OP_MEM)
		{
			storeOp(ai->operands[2], op0, irb);

			// We don't use op4 here, post-index offset is applied to source
			// address only after the transfers at writeback.
			auto op3 = ai->operands[2];
			op3.mem.disp += 4;
			storeOp(op3, op1, irb);

			baseR = ai->operands[2].mem.base;
			idx = loadOp(ai->operands[3], irb);
			subtract = ai->operands[3].subtracted;
		}
		else
		{
			throw GenericError("unhandled STRD format");
		}
	}
	else if (ai->op_count == 2
			&& ai->operands[1].type == ARM_OP_MEM)
	{
		storeOp(ai->operands[1], op0, irb);
		baseR = ai->operands[1].mem.base;
		if (auto disp = ai->operands[1].mem.disp)
		{
			idx = llvm::ConstantInt::getSigned(getDefaultType(), disp);
		}
		else if (ai->operands[1].mem.index != ARM_REG_INVALID)
		{
			idx = loadRegister(ai->operands[1].mem.index, irb);
		}
	}
	else if (ai->op_count == 3
			&& ai->operands[1].type == ARM_OP_MEM)
	{
		storeOp(ai->operands[1], op0, irb);
		baseR = ai->operands[1].mem.base;
		idx = loadOp(ai->operands[2], irb);
		subtract = ai->operands[2].subtracted;
	}
	else
	{
		throw GenericError("unhandled STRD format");
	}

	if (ai->writeback && idx && baseR != ARM_REG_INVALID)
	{
		auto* b = loadRegister(baseR, irb);
		auto* v = subtract
				? irb.CreateSub(b, idx)
				: irb.CreateAdd(b, idx);
		storeRegister(baseR, v, irb);
	}
}

/**
 * ARM_INS_SUB, ARM_INS_RSB, ARM_INS_CMP (SUBS but result is discarded)
 */
void Capstone2LlvmIrTranslatorArm_impl::translateSub(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	if (i->id == ARM_INS_RSB)
	{
		std::tie(op2, op1) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	}
	else
	{
		std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	}
	auto* sub = irb.CreateSub(op1, op2);
	if (ai->update_flags || i->id == ARM_INS_CMP)
	{
		llvm::Value* zero = llvm::ConstantInt::get(sub->getType(), 0);

		// ARM - ok, but maybe generates more ugly code.
		storeRegister(ARM_REG_CPSR_C, generateValueNegate(irb, generateBorrowSub(op1, op2, irb)), irb);
		// THUMB - weird, but at least in ackermann.thumb.gnuarmgcc-4.4.1.O0.g.elf
		// it generates prettier code. I'm not even sure they are the same.
//		auto* op2Neg = generateValueNegate(irb, op2);
//		storeRegister(ARM_REG_CPSR_C, genCarryAddC(op1, op2Neg, irb, llvm::ConstantInt::getSigned(op2Neg->getType(), -1)), irb);

		storeRegister(ARM_REG_CPSR_V, generateOverflowSub(sub, op1, op2, irb), irb);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(sub, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(op1, op2), irb);
	}
	if (i->id != ARM_INS_CMP)
	{
		storeOp(ai->operands[0], sub, irb);
	}
}

/**
 * ARM_INS_UMLAL, ARM_INS_SMLAL
 */
void Capstone2LlvmIrTranslatorArm_impl::translateUmlal(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	op0 = loadOp(ai->operands[0], irb);
	op0 = irb.CreateZExtOrTrunc(op0, irb.getInt64Ty());
	op1 = loadOp(ai->operands[1], irb);
	op1 = irb.CreateZExtOrTrunc(op1, irb.getInt64Ty());
	op1 = irb.CreateShl(op1, 32);

	auto* orig = irb.CreateOr(op0, op1);

	op2 = loadOp(ai->operands[2], irb);
	op2 = i->id == ARM_INS_UMLAL
			? irb.CreateZExtOrTrunc(op2, irb.getInt64Ty())
			: irb.CreateSExtOrTrunc(op2, irb.getInt64Ty());
	op3 = loadOp(ai->operands[3], irb);
	op3 = i->id == ARM_INS_UMLAL
			? irb.CreateZExtOrTrunc(op3, irb.getInt64Ty())
			: irb.CreateSExtOrTrunc(op3, irb.getInt64Ty());

	auto* val = irb.CreateMul(op2, op3);
	val = irb.CreateAdd(orig, val);

	auto* hi = irb.CreateTrunc(irb.CreateLShr(val, 32), irb.getInt32Ty());
	auto* lo = irb.CreateTrunc(val, irb.getInt32Ty());

	// - Updates the N and Z flags according to the result.
	// - Does not affect the C or V flags.
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}

	storeOp(ai->operands[0], lo, irb);
	storeOp(ai->operands[1], hi, irb);
}

/**
 * ARM_INS_UMULL, ARM_INS_SMULL
 */
void Capstone2LlvmIrTranslatorArm_impl::translateUmull(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	op2 = loadOp(ai->operands[2], irb);
	op2 = i->id == ARM_INS_UMULL
			? irb.CreateZExtOrTrunc(op2, irb.getInt64Ty())
			: irb.CreateSExtOrTrunc(op2, irb.getInt64Ty());
	op3 = loadOp(ai->operands[3], irb);
	op3 = i->id == ARM_INS_UMULL
			? irb.CreateZExtOrTrunc(op3, irb.getInt64Ty())
			: irb.CreateSExtOrTrunc(op3, irb.getInt64Ty());

	auto* val = irb.CreateMul(op2, op3);

	auto* hi = irb.CreateTrunc(irb.CreateLShr(val, 32), irb.getInt32Ty());
	auto* lo = irb.CreateTrunc(val, irb.getInt32Ty());

	// - Updates the N and Z flags according to the result.
	// - Does not affect the C or V flags.
	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}

	storeOp(ai->operands[0], lo, irb);
	storeOp(ai->operands[1], hi, irb);
}

/**
 * ARM_INS_UXTAH
 */
void Capstone2LlvmIrTranslatorArm_impl::translateUxtah(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::THROW);
	op2 = irb.CreateZExtOrTrunc(op2, irb.getInt16Ty());
	op2 = irb.CreateZExtOrTrunc(op2, irb.getInt32Ty());
	op0 = irb.CreateAdd(op1, op2);
	storeOp(ai->operands[0], op0, irb);
}

/**
 * ARM_INS_UXTB
 */
void Capstone2LlvmIrTranslatorArm_impl::translateUxtb(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);
	op1 = irb.CreateAnd(op1, 0x000000ff);
	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM_INS_UXTB16
 */
void Capstone2LlvmIrTranslatorArm_impl::translateUxtb16(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);
	op1 = irb.CreateAnd(op1, 0x00ff00ff);
	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM_INS_UXTH
 */
void Capstone2LlvmIrTranslatorArm_impl::translateUxth(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);
	op1 = irb.CreateAnd(op1, 0x0000ffff);
	storeOp(ai->operands[0], op1, irb);
}

} // namespace capstone2llvmir
} // namespace retdec
