/**
 * @file src/capstone2llvmir/arm64/arm64.cpp
 * @brief ARM64 implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "capstone2llvmir/arm64/arm64_impl.h"

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorArm64_impl::Capstone2LlvmIrTranslatorArm64_impl(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator_impl(CS_ARCH_ARM64, basic, extra, m)
{
	initialize();
}

Capstone2LlvmIrTranslatorArm64_impl::~Capstone2LlvmIrTranslatorArm64_impl()
{

}

//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

bool Capstone2LlvmIrTranslatorArm64_impl::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_ARM;
	    // || m == CS_MODE_THUMB;
}

bool Capstone2LlvmIrTranslatorArm64_impl::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN
			|| m == CS_MODE_BIG_ENDIAN;
}

uint32_t Capstone2LlvmIrTranslatorArm64_impl::getArchByteSize()
{
	return 8;
}

//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorArm64_impl::generateEnvironmentArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorArm64_impl::generateDataLayout()
{
	_module->setDataLayout("e-p:32:32:32-f80:32:32");
	// TODO: Modify data layout.
}

void Capstone2LlvmIrTranslatorArm64_impl::generateRegisters()
{
			// General purpose registers.
			//

	createRegister(ARM64_REG_X0, _regLt);
	createRegister(ARM64_REG_X1, _regLt);
	createRegister(ARM64_REG_X2, _regLt);
	createRegister(ARM64_REG_X3, _regLt);
	createRegister(ARM64_REG_X4, _regLt);
	createRegister(ARM64_REG_X5, _regLt);
	createRegister(ARM64_REG_X6, _regLt);
	createRegister(ARM64_REG_X7, _regLt);
	createRegister(ARM64_REG_X8, _regLt);
	createRegister(ARM64_REG_X9, _regLt);
	createRegister(ARM64_REG_X10, _regLt);
	createRegister(ARM64_REG_X11, _regLt);
	createRegister(ARM64_REG_X12, _regLt);
	createRegister(ARM64_REG_X13, _regLt);
	createRegister(ARM64_REG_X14, _regLt);
	createRegister(ARM64_REG_X15, _regLt);
	createRegister(ARM64_REG_X16, _regLt);
	createRegister(ARM64_REG_X17, _regLt);
	createRegister(ARM64_REG_X18, _regLt);
	createRegister(ARM64_REG_X19, _regLt);
	createRegister(ARM64_REG_X20, _regLt);
	createRegister(ARM64_REG_X21, _regLt);
	createRegister(ARM64_REG_X22, _regLt);
	createRegister(ARM64_REG_X23, _regLt);
	createRegister(ARM64_REG_X24, _regLt);
	createRegister(ARM64_REG_X25, _regLt);
	createRegister(ARM64_REG_X26, _regLt);
	createRegister(ARM64_REG_X27, _regLt);
	createRegister(ARM64_REG_X28, _regLt);

	// Lower 32 bits of 64 arm{xN} bit regs.
	//
	createRegister(ARM64_REG_W0, _regLt);
	createRegister(ARM64_REG_W1, _regLt);
	createRegister(ARM64_REG_W2, _regLt);
	createRegister(ARM64_REG_W3, _regLt);
	createRegister(ARM64_REG_W4, _regLt);
	createRegister(ARM64_REG_W5, _regLt);
	createRegister(ARM64_REG_W6, _regLt);
	createRegister(ARM64_REG_W7, _regLt);
	createRegister(ARM64_REG_W8, _regLt);
	createRegister(ARM64_REG_W9, _regLt);
	createRegister(ARM64_REG_W10, _regLt);
	createRegister(ARM64_REG_W11, _regLt);
	createRegister(ARM64_REG_W12, _regLt);
	createRegister(ARM64_REG_W13, _regLt);
	createRegister(ARM64_REG_W14, _regLt);
	createRegister(ARM64_REG_W15, _regLt);
	createRegister(ARM64_REG_W16, _regLt);
	createRegister(ARM64_REG_W17, _regLt);
	createRegister(ARM64_REG_W18, _regLt);
	createRegister(ARM64_REG_W19, _regLt);
	createRegister(ARM64_REG_W20, _regLt);
	createRegister(ARM64_REG_W21, _regLt);
	createRegister(ARM64_REG_W22, _regLt);
	createRegister(ARM64_REG_W23, _regLt);
	createRegister(ARM64_REG_W24, _regLt);
	createRegister(ARM64_REG_W25, _regLt);
	createRegister(ARM64_REG_W26, _regLt);
	createRegister(ARM64_REG_W27, _regLt);
	createRegister(ARM64_REG_W28, _regLt);
	createRegister(ARM64_REG_W29, _regLt);
	createRegister(ARM64_REG_W30, _regLt);

	// Special registers.

	// FP Frame pointer.
	createRegister(ARM64_REG_X29, _regLt);

	// LP Link register.
	createRegister(ARM64_REG_X30, _regLt);

	// Stack pointer.
	createRegister(ARM64_REG_SP, _regLt);
	createRegister(ARM64_REG_WSP, _regLt);

	// Zero.
	createRegister(ARM64_REG_XZR, _regLt);
	createRegister(ARM64_REG_WZR, _regLt);

	// Flags.
	createRegister(ARM64_REG_CPSR_N, _regLt);
	createRegister(ARM64_REG_CPSR_Z, _regLt);
	createRegister(ARM64_REG_CPSR_C, _regLt);
	createRegister(ARM64_REG_CPSR_V, _regLt);

	// Program counter.
	createRegister(ARM64_REG_PC, _regLt);
}

uint32_t Capstone2LlvmIrTranslatorArm64_impl::getCarryRegister()
{
	return 0; /* TODO: ARM_REG_CPSR_C; */
}

void Capstone2LlvmIrTranslatorArm64_impl::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	_insn = i;

	cs_detail* d = i->detail;
	cs_arm64* ai = &d->arm64;

	std::cerr << "Translating instruction: " << cs_insn_name(_handle, i->id) << std::endl;
	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;

		//bool branchInsn = i->id == ARM_INS_B || i->id == ARM_INS_BX
		//		|| i->id == ARM_INS_BL || i->id == ARM_INS_BLX
		//		|| i->id == ARM_INS_CBZ || i->id == ARM_INS_CBNZ;
		if (ai->cc == ARM64_CC_AL || ai->cc == ARM64_CC_NV /* || branchInsn */)
		{
			_inCondition = false;
			(this->*f)(i, ai, irb);
		}
		else
		{
			(this->*f)(i, ai, irb);

			//_inCondition = true;
			//auto* cond = generateInsnConditionCode(irb, ai);
			//auto bodyIrb = generateIfThen(cond, irb);

			//(this->*f)(i, ai, bodyIrb);
		}
	}
	else
	{
		assert(false && "Instruction is not implemented");
		// TODO: Automatically generate pseudo asm call.
	}
}

//
//==============================================================================
// ARM64-specific methods.
//==============================================================================
//

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::getCurrentPc(cs_insn* i)
{
	return llvm::ConstantInt::get(
			getDefaultType(),
			((i->address + (2*i->size)) >> 2) << 2);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateOperandShift(
		llvm::IRBuilder<>& irb,
		cs_arm64_op& op,
		llvm::Value* val)
{
	llvm::Value* n = nullptr;
	if (op.shift.type == ARM64_SFT_INVALID)
	{
		return val;
	}
	else
	{
		n = llvm::ConstantInt::get(val->getType(), op.shift.value);
	}

	if (n == nullptr)
	{
		assert(false && "should not be possible");
		return val;
	}
	n = irb.CreateZExtOrTrunc(n, val->getType());

	switch (op.shift.type)
	{
		case ARM64_SFT_ASR:
		{
			return generateShiftAsr(irb, val, n);
		}
		case ARM64_SFT_LSL:
		{
			return generateShiftLsl(irb, val, n);
		}
		case ARM64_SFT_LSR:
		{
			return generateShiftLsr(irb, val, n);
		}
		case ARM64_SFT_ROR:
		{
			return generateShiftRor(irb, val, n);
		}
		case ARM64_SFT_MSL:
		{
			assert(false && "CHECK IMPLEMENTATION");
			return generateShiftMsl(irb, val, n);
		}
		case ARM64_SFT_INVALID:
		default:
		{
			return val;
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftAsr(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	// TODO: In the old semantics, there is:
	// n = (n == 0) ? 32 : n;
	// It looks like capstone does not allow op.shift.value to be zero,
	// in such a case, Capstone throws away the shift.
	// But there still might be zero in register, if register variant
	// is used.

	auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* cfShl = irb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
	auto* cfAnd = irb.CreateAnd(cfShl, val);
	auto* cfIcmp = irb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
	storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);

	return irb.CreateAShr(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftLsl(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* cfShl = irb.CreateShl(val, cfOp1);
	auto* cfIntT = llvm::cast<llvm::IntegerType>(cfShl->getType());
	auto* cfRightCount = llvm::ConstantInt::get(cfIntT, cfIntT->getBitWidth() - 1);
	auto* cfLow = irb.CreateLShr(cfShl, cfRightCount);
	storeRegister(ARM64_REG_CPSR_C, cfLow, irb);

	return irb.CreateShl(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftLsr(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	// TODO: In the old semantics, there is:
	// n = (n == 0) ? 32 : n;

	auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
	auto* cfShl = irb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
	auto* cfAnd = irb.CreateAnd(cfShl, val);
	auto* cfIcmp = irb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
	storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);

	return irb.CreateLShr(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftRor(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value* n)
{
	// TODO: In the old semantics, there is same more complicated code
	// if n == 0.
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(n->getType())->getBitWidth();

	auto* srl = irb.CreateLShr(val, n);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW), n);
	auto* shl = irb.CreateShl(val, sub);
	auto* orr = irb.CreateOr(srl, shl);

	auto* cfSrl = irb.CreateLShr(orr, llvm::ConstantInt::get(orr->getType(), op0BitW - 1));
	auto* cfIcmp = irb.CreateICmpNE(cfSrl, llvm::ConstantInt::get(cfSrl->getType(), 0));
	storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);

	return orr;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftMsl(
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
	storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);

	return or2Trunc;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::loadRegister(
		uint32_t r,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct)
{
	if (r == ARM64_REG_INVALID)
	{
		return nullptr;
	}

	if (r == ARM64_REG_PC)
	{
		return getCurrentPc(_insn);
		// TODO: Check
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("loadRegister() unhandled reg.");
	}

	return irb.CreateLoad(llvmReg);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::loadOp(
		cs_arm64_op& op,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty,
		bool lea)
{
	switch (op.type)
	{
		case ARM64_OP_SYS:
		case ARM64_OP_REG:
		{
			auto* val = loadRegister(op.reg, irb);
			return generateOperandShift(irb, op, val);
		}
		case ARM64_OP_IMM:
		{
			auto* val = llvm::ConstantInt::getSigned(getDefaultType(), op.imm);
			return generateOperandShift(irb, op, val);
		}
		case ARM64_OP_MEM:
		{
			// TODO: MEM OP
		}
		case ARM64_OP_FP:
		case ARM64_OP_INVALID: 
		case ARM64_OP_CIMM: 
		case ARM64_OP_REG_MRS: 
		case ARM64_OP_REG_MSR: 
		case ARM64_OP_PSTATE: 
		case ARM64_OP_PREFETCH: 
		case ARM64_OP_BARRIER: 
		default:
		{
			assert(false && "loadOp(): unhandled operand type.");
			return nullptr;
		}
	}
}

llvm::Instruction* Capstone2LlvmIrTranslatorArm64_impl::storeRegister(
		uint32_t r,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (r == ARM64_REG_INVALID)
	{
		return nullptr;
	}

	if (r == ARM64_REG_PC)
	{
		return nullptr;
		// TODO: Check?
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("storeRegister() unhandled reg.");
	}
	val = generateTypeConversion(irb, val, llvmReg->getValueType(), ct);

	return irb.CreateStore(val, llvmReg);
}

llvm::Instruction* Capstone2LlvmIrTranslatorArm64_impl::storeOp(
		cs_arm64_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	switch (op.type)
	{
		case ARM64_OP_SYS:
		case ARM64_OP_REG:
		{
			return storeRegister(op.reg, val, irb, ct);
		}
		case ARM64_OP_MEM:
		{
			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = baseR ? baseR->getType() : getDefaultType();
			llvm::Value* disp = op.mem.disp
					? llvm::ConstantInt::get(t, op.mem.disp)
					: nullptr;

			auto* idxR = loadRegister(op.mem.index, irb);
			if (idxR)
			{
				//struct {
				//    arm64_shifter type;	// shifter type of this operand
				//    unsigned int value;	// shifter value of this operand
				//} shift;
				//if (op.mem.lshift)
				//{
				//	auto* lshift = llvm::ConstantInt::get(
				//			idxR->getType(),
				//			op.mem.lshift);
				//	idxR = irb.CreateShl(idxR, lshift);
				//}

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
		case ARM64_OP_INVALID: 
		case ARM64_OP_IMM: 
		case ARM64_OP_FP:  
		case ARM64_OP_CIMM: 
		case ARM64_OP_REG_MRS: 
		case ARM64_OP_REG_MSR: 
		case ARM64_OP_PSTATE: 
		case ARM64_OP_PREFETCH: 
		case ARM64_OP_BARRIER: 
		default:
		{
			assert(false && "stroreOp(): unhandled operand type.");
			return nullptr;
		}
	}
}

//
//==============================================================================
// ARM64 instruction translation methods.
//==============================================================================
//

/**
 * ARM64_INS_ADD
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAdd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(ai, irb);
	auto *val = irb.CreateAdd(op1, op2);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_MOV, ARM64_INS_MVN, ARM64_INS_MOVZ
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMov(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	if (ai->op_count != 2)
	{
		return;
	}

	op1 = loadOpBinaryOp1(ai, irb);
	if (i->id == ARM64_INS_MVN)
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
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(op1, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(op1, zero), irb);
	}
	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM64_INS_STR
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateStr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	op0 = loadOp(ai->operands[0], irb);
	op0 = irb.CreateZExtOrTrunc(op0, getDefaultType());

	uint32_t baseR = ARM_REG_INVALID;
	llvm::Value* idx = nullptr;
	bool subtract = false;
	storeOp(ai->operands[1], op0, irb);
	baseR = ai->operands[1].mem.base;
	if (auto disp = ai->operands[1].mem.disp)
	{
		idx = llvm::ConstantInt::getSigned(getDefaultType(), disp);
	}
	else if (ai->operands[1].mem.index != ARM64_REG_INVALID)
	{
		idx = loadRegister(ai->operands[1].mem.index, irb);
	}

	if (ai->writeback && idx && baseR != ARM64_REG_INVALID)
	{
		auto* b = loadRegister(baseR, irb);
		auto* v = subtract
				? irb.CreateSub(b, idx)
				: irb.CreateAdd(b, idx);
		storeRegister(baseR, v, irb);
	}
}

} // namespace capstone2llvmir
} // namespace retdec
