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

			assert(false && "NOT YET IMPLEMENTED");

			_inCondition = true;
			//auto* cond = generateInsnConditionCode(irb, ai);
			//auto bodyIrb = generateIfThen(cond, irb);

			//(this->*f)(i, ai, bodyIrb);
		}
	}
	else
	{
		assert(false && "NOT YET IMPLEMENTED");
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
			// TODO: OP MEM
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

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateOperandShift(
		llvm::IRBuilder<>& irb,
		cs_arm64_op& op,
		llvm::Value* val)
{
	return val;
	// TODO: NOT YET IMPLEMENTED
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

} // namespace capstone2llvmir
} // namespace retdec
