/**
 * @file src/capstone2llvmir/powerpc/powerpc.cpp
 * @brief PowerPC implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "capstone2llvmir/powerpc/powerpc_impl.h"

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorPowerpc_impl::Capstone2LlvmIrTranslatorPowerpc_impl(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator_impl(CS_ARCH_PPC, basic, extra, m)
{
	// This needs to be called from concrete's class ctor, not abstract's
	// class ctor, so that virtual table is properly initialized.
	initialize();
}

Capstone2LlvmIrTranslatorPowerpc_impl::~Capstone2LlvmIrTranslatorPowerpc_impl()
{
	// Nothing specific to PowerPC.
}

//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

bool Capstone2LlvmIrTranslatorPowerpc_impl::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_32 || m == CS_MODE_64 || m == CS_MODE_QPX;
}

bool Capstone2LlvmIrTranslatorPowerpc_impl::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN || m == CS_MODE_BIG_ENDIAN;
}

uint32_t Capstone2LlvmIrTranslatorPowerpc_impl::getArchByteSize()
{
	switch (_origBasicMode)
	{
		case CS_MODE_32:
			return 4;
		case CS_MODE_64:
		case CS_MODE_QPX:
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
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorPowerpc_impl::generateEnvironmentArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorPowerpc_impl::generateDataLayout()
{
	switch (_basicMode)
	{
		case CS_MODE_32:
			_module->setDataLayout("E-p:32:32:32-f80:32:32");
			break;
		case CS_MODE_64:
		case CS_MODE_QPX:
			// TODO: taken from 64-bit MIPS just to put something here.
			_module->setDataLayout("E-m:m-i8:8:32-i16:16:32-i64:64-n32:64-S128");
			break;
		default:
		{
			throw Capstone2LlvmIrError("Unhandled mode in generateDataLayout().");
			break;
		}
	}
}

void Capstone2LlvmIrTranslatorPowerpc_impl::generateRegisters()
{
	// General-purpose registers.
	//
	createRegister(PPC_REG_R0, _regLt);
	createRegister(PPC_REG_R1, _regLt);
	createRegister(PPC_REG_R2, _regLt);
	createRegister(PPC_REG_R3, _regLt);
	createRegister(PPC_REG_R4, _regLt);
	createRegister(PPC_REG_R5, _regLt);
	createRegister(PPC_REG_R6, _regLt);
	createRegister(PPC_REG_R7, _regLt);
	createRegister(PPC_REG_R8, _regLt);
	createRegister(PPC_REG_R9, _regLt);
	createRegister(PPC_REG_R10, _regLt);
	createRegister(PPC_REG_R11, _regLt);
	createRegister(PPC_REG_R12, _regLt);
	createRegister(PPC_REG_R13, _regLt);
	createRegister(PPC_REG_R14, _regLt);
	createRegister(PPC_REG_R15, _regLt);
	createRegister(PPC_REG_R16, _regLt);
	createRegister(PPC_REG_R17, _regLt);
	createRegister(PPC_REG_R18, _regLt);
	createRegister(PPC_REG_R19, _regLt);
	createRegister(PPC_REG_R20, _regLt);
	createRegister(PPC_REG_R21, _regLt);
	createRegister(PPC_REG_R22, _regLt);
	createRegister(PPC_REG_R23, _regLt);
	createRegister(PPC_REG_R24, _regLt);
	createRegister(PPC_REG_R25, _regLt);
	createRegister(PPC_REG_R26, _regLt);
	createRegister(PPC_REG_R27, _regLt);
	createRegister(PPC_REG_R28, _regLt);
	createRegister(PPC_REG_R29, _regLt);
	createRegister(PPC_REG_R30, _regLt);
	createRegister(PPC_REG_R31, _regLt);

	// Floating-point registers.
	//
	createRegister(PPC_REG_F0, _regLt);
	createRegister(PPC_REG_F1, _regLt);
	createRegister(PPC_REG_F2, _regLt);
	createRegister(PPC_REG_F3, _regLt);
	createRegister(PPC_REG_F4, _regLt);
	createRegister(PPC_REG_F5, _regLt);
	createRegister(PPC_REG_F6, _regLt);
	createRegister(PPC_REG_F7, _regLt);
	createRegister(PPC_REG_F8, _regLt);
	createRegister(PPC_REG_F9, _regLt);
	createRegister(PPC_REG_F10, _regLt);
	createRegister(PPC_REG_F11, _regLt);
	createRegister(PPC_REG_F12, _regLt);
	createRegister(PPC_REG_F13, _regLt);
	createRegister(PPC_REG_F14, _regLt);
	createRegister(PPC_REG_F15, _regLt);
	createRegister(PPC_REG_F16, _regLt);
	createRegister(PPC_REG_F17, _regLt);
	createRegister(PPC_REG_F18, _regLt);
	createRegister(PPC_REG_F19, _regLt);
	createRegister(PPC_REG_F20, _regLt);
	createRegister(PPC_REG_F21, _regLt);
	createRegister(PPC_REG_F22, _regLt);
	createRegister(PPC_REG_F23, _regLt);
	createRegister(PPC_REG_F24, _regLt);
	createRegister(PPC_REG_F25, _regLt);
	createRegister(PPC_REG_F26, _regLt);
	createRegister(PPC_REG_F27, _regLt);
	createRegister(PPC_REG_F28, _regLt);
	createRegister(PPC_REG_F29, _regLt);
	createRegister(PPC_REG_F30, _regLt);
	createRegister(PPC_REG_F31, _regLt);

	// Condition registers.
	//
	createRegister(PPC_REG_CR0_LT, _regLt);
	createRegister(PPC_REG_CR0_GT, _regLt);
	createRegister(PPC_REG_CR0_EQ, _regLt);
	createRegister(PPC_REG_CR0_SO, _regLt);

	createRegister(PPC_REG_CR1_LT, _regLt);
	createRegister(PPC_REG_CR1_GT, _regLt);
	createRegister(PPC_REG_CR1_EQ, _regLt);
	createRegister(PPC_REG_CR1_SO, _regLt);

	createRegister(PPC_REG_CR2_LT, _regLt);
	createRegister(PPC_REG_CR2_GT, _regLt);
	createRegister(PPC_REG_CR2_EQ, _regLt);
	createRegister(PPC_REG_CR2_SO, _regLt);

	createRegister(PPC_REG_CR3_LT, _regLt);
	createRegister(PPC_REG_CR3_GT, _regLt);
	createRegister(PPC_REG_CR3_EQ, _regLt);
	createRegister(PPC_REG_CR3_SO, _regLt);

	createRegister(PPC_REG_CR4_LT, _regLt);
	createRegister(PPC_REG_CR4_GT, _regLt);
	createRegister(PPC_REG_CR4_EQ, _regLt);
	createRegister(PPC_REG_CR4_SO, _regLt);

	createRegister(PPC_REG_CR5_LT, _regLt);
	createRegister(PPC_REG_CR5_GT, _regLt);
	createRegister(PPC_REG_CR5_EQ, _regLt);
	createRegister(PPC_REG_CR5_SO, _regLt);

	createRegister(PPC_REG_CR6_LT, _regLt);
	createRegister(PPC_REG_CR6_GT, _regLt);
	createRegister(PPC_REG_CR6_EQ, _regLt);
	createRegister(PPC_REG_CR6_SO, _regLt);

	createRegister(PPC_REG_CR7_LT, _regLt);
	createRegister(PPC_REG_CR7_GT, _regLt);
	createRegister(PPC_REG_CR7_EQ, _regLt);
	createRegister(PPC_REG_CR7_SO, _regLt);

	createRegister(PPC_REG_CR0, _regLt);
	createRegister(PPC_REG_CR1, _regLt);
	createRegister(PPC_REG_CR2, _regLt);
	createRegister(PPC_REG_CR3, _regLt);
	createRegister(PPC_REG_CR4, _regLt);
	createRegister(PPC_REG_CR5, _regLt);
	createRegister(PPC_REG_CR6, _regLt);
	createRegister(PPC_REG_CR7, _regLt);

	createRegister(PPC_REG_CARRY, _regLt);

	// Link register.
	//
	createRegister(PPC_REG_LR, _regLt);

	// Count register.
	//
	createRegister(PPC_REG_CTR, _regLt);
}

uint32_t Capstone2LlvmIrTranslatorPowerpc_impl::getCarryRegister()
{
	return PPC_REG_CARRY;
}

void Capstone2LlvmIrTranslatorPowerpc_impl::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	cs_detail* d = i->detail;
	cs_ppc* pi = &d->ppc;

	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;
		(this->*f)(i, pi, irb);
	}
	else
	{
		// TODO: Automatically generate pseudo asm call.
	}
}

//
//==============================================================================
// PowerPC-specific methods.
//==============================================================================
//

llvm::Value* Capstone2LlvmIrTranslatorPowerpc_impl::loadRegister(
		uint32_t r,
		llvm::IRBuilder<>& irb,
		llvm::Type* dstType,
		eOpConv ct)
{
	if (r == PPC_REG_INVALID)
	{
		return nullptr;
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("loadRegister() unhandled reg.");
	}

	// TODO: do type conversion

	return irb.CreateLoad(llvmReg);
}

llvm::Value* Capstone2LlvmIrTranslatorPowerpc_impl::loadOp(
		cs_ppc_op& op,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty,
		bool lea) // TODO: implement lea
{
	switch (op.type)
	{
		case PPC_OP_REG:
		{
			return loadRegister(op.reg, irb);
		}
		case PPC_OP_IMM:
		{
			return llvm::ConstantInt::getSigned(getDefaultType(), op.imm);
			break;
		}
		case PPC_OP_MEM:
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
		case PPC_OP_CRX:
		{
			assert(false && "unhandled");
			return nullptr;
		}
		case PPC_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

llvm::StoreInst* Capstone2LlvmIrTranslatorPowerpc_impl::storeRegister(
		uint32_t r,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (r == PPC_REG_INVALID)
	{
		return nullptr;
	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("storeRegister() unhandled reg.");
	}
	val = generateTypeConversion(irb, val, llvmReg->getValueType(), ct);

	return irb.CreateStore(val, llvmReg);
}

llvm::Instruction* Capstone2LlvmIrTranslatorPowerpc_impl::storeOp(
		cs_ppc_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	switch (op.type)
	{
		case PPC_OP_REG:
		{
			return storeRegister(op.reg, val, irb, ct);
		}
		case PPC_OP_MEM:
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
		case PPC_OP_IMM:
		case PPC_OP_CRX:
		case PPC_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

void Capstone2LlvmIrTranslatorPowerpc_impl::storeCrX(
		llvm::IRBuilder<>& irb,
		uint32_t crReg,
		llvm::Value* op0,
		llvm::Value* op1, // = nullptr
		bool signedCmp) // = true
{
	llvm::Value* zero = llvm::ConstantInt::get(op0->getType(), 0);
	if (op1 == nullptr)
	{
		op1 = zero;
	}

	if (op0->getType() != op1->getType())
	{
		op1 = irb.CreateSExtOrTrunc(op1, op0->getType());
	}

	auto s = signedCmp;
	auto* lt = s ? irb.CreateICmpSLT(op0, op1) : irb.CreateICmpULT(op0, op1);
	auto* gt = s ? irb.CreateICmpSGT(op0, op1) : irb.CreateICmpUGT(op0, op1);
	auto* eq = irb.CreateICmpEQ(op0, op1);
	// TODO: PPC_REG_CRx_SO is a copy of XER, which we do not have.
	auto* so = zero;

	uint32_t ltR = PPC_REG_CR0_LT;
	uint32_t gtR = PPC_REG_CR0_GT;
	uint32_t eqR = PPC_REG_CR0_EQ;
	uint32_t soR = PPC_REG_CR0_SO;

	switch (crReg)
	{
		case PPC_REG_CR0:
			ltR = PPC_REG_CR0_LT;
			gtR = PPC_REG_CR0_GT;
			eqR = PPC_REG_CR0_EQ;
			soR = PPC_REG_CR0_SO;
			break;
		case PPC_REG_CR1:
			ltR = PPC_REG_CR1_LT;
			gtR = PPC_REG_CR1_GT;
			eqR = PPC_REG_CR1_EQ;
			soR = PPC_REG_CR1_SO;
			break;
		case PPC_REG_CR2:
			ltR = PPC_REG_CR2_LT;
			gtR = PPC_REG_CR2_GT;
			eqR = PPC_REG_CR2_EQ;
			soR = PPC_REG_CR2_SO;
			break;
		case PPC_REG_CR3:
			ltR = PPC_REG_CR3_LT;
			gtR = PPC_REG_CR3_GT;
			eqR = PPC_REG_CR3_EQ;
			soR = PPC_REG_CR3_SO;
			break;
		case PPC_REG_CR4:
			ltR = PPC_REG_CR4_LT;
			gtR = PPC_REG_CR4_GT;
			eqR = PPC_REG_CR4_EQ;
			soR = PPC_REG_CR4_SO;
			break;
		case PPC_REG_CR5:
			ltR = PPC_REG_CR5_LT;
			gtR = PPC_REG_CR5_GT;
			eqR = PPC_REG_CR5_EQ;
			soR = PPC_REG_CR5_SO;
			break;
		case PPC_REG_CR6:
			ltR = PPC_REG_CR6_LT;
			gtR = PPC_REG_CR6_GT;
			eqR = PPC_REG_CR6_EQ;
			soR = PPC_REG_CR6_SO;
			break;
		case PPC_REG_CR7:
			ltR = PPC_REG_CR7_LT;
			gtR = PPC_REG_CR7_GT;
			eqR = PPC_REG_CR7_EQ;
			soR = PPC_REG_CR7_SO;
			break;
		default:
			assert(false && "unhandled CR register");
			break;
	}

	storeRegister(ltR, lt, irb);
	storeRegister(gtR, gt, irb);
	storeRegister(eqR, eq, irb);
	storeRegister(soR, so, irb);
}

std::tuple<llvm::Value*, llvm::Value*, llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorPowerpc_impl::loadCrX(
		llvm::IRBuilder<>& irb,
		uint32_t crReg)
{
	uint32_t ltR = PPC_REG_CR0_LT;
	uint32_t gtR = PPC_REG_CR0_GT;
	uint32_t eqR = PPC_REG_CR0_EQ;
	uint32_t soR = PPC_REG_CR0_SO;

	switch (crReg)
	{
		case PPC_REG_CR0:
			ltR = PPC_REG_CR0_LT;
			gtR = PPC_REG_CR0_GT;
			eqR = PPC_REG_CR0_EQ;
			soR = PPC_REG_CR0_SO;
			break;
		case PPC_REG_CR1:
			ltR = PPC_REG_CR1_LT;
			gtR = PPC_REG_CR1_GT;
			eqR = PPC_REG_CR1_EQ;
			soR = PPC_REG_CR1_SO;
			break;
		case PPC_REG_CR2:
			ltR = PPC_REG_CR2_LT;
			gtR = PPC_REG_CR2_GT;
			eqR = PPC_REG_CR2_EQ;
			soR = PPC_REG_CR2_SO;
			break;
		case PPC_REG_CR3:
			ltR = PPC_REG_CR3_LT;
			gtR = PPC_REG_CR3_GT;
			eqR = PPC_REG_CR3_EQ;
			soR = PPC_REG_CR3_SO;
			break;
		case PPC_REG_CR4:
			ltR = PPC_REG_CR4_LT;
			gtR = PPC_REG_CR4_GT;
			eqR = PPC_REG_CR4_EQ;
			soR = PPC_REG_CR4_SO;
			break;
		case PPC_REG_CR5:
			ltR = PPC_REG_CR5_LT;
			gtR = PPC_REG_CR5_GT;
			eqR = PPC_REG_CR5_EQ;
			soR = PPC_REG_CR5_SO;
			break;
		case PPC_REG_CR6:
			ltR = PPC_REG_CR6_LT;
			gtR = PPC_REG_CR6_GT;
			eqR = PPC_REG_CR6_EQ;
			soR = PPC_REG_CR6_SO;
			break;
		case PPC_REG_CR7:
			ltR = PPC_REG_CR7_LT;
			gtR = PPC_REG_CR7_GT;
			eqR = PPC_REG_CR7_EQ;
			soR = PPC_REG_CR7_SO;
			break;
		default:
			assert(false && "unhandled CR register");
			break;
	}

	llvm::Value* lt = loadRegister(ltR, irb);
	llvm::Value* gt = loadRegister(gtR, irb);
	llvm::Value* eq = loadRegister(eqR, irb);
	llvm::Value* so = loadRegister(soR, irb);

	return std::make_tuple(lt, gt, eq, so);
}

llvm::Value* Capstone2LlvmIrTranslatorPowerpc_impl::loadCrX(
		llvm::IRBuilder<>& irb,
		uint32_t crReg,
		ppc_cr_types type)
{
	uint32_t ltR = PPC_REG_CR0_LT;
	uint32_t gtR = PPC_REG_CR0_GT;
	uint32_t eqR = PPC_REG_CR0_EQ;
	uint32_t soR = PPC_REG_CR0_SO;

	switch (crReg)
	{
		case PPC_REG_CR0:
			ltR = PPC_REG_CR0_LT;
			gtR = PPC_REG_CR0_GT;
			eqR = PPC_REG_CR0_EQ;
			soR = PPC_REG_CR0_SO;
			break;
		case PPC_REG_CR1:
			ltR = PPC_REG_CR1_LT;
			gtR = PPC_REG_CR1_GT;
			eqR = PPC_REG_CR1_EQ;
			soR = PPC_REG_CR1_SO;
			break;
		case PPC_REG_CR2:
			ltR = PPC_REG_CR2_LT;
			gtR = PPC_REG_CR2_GT;
			eqR = PPC_REG_CR2_EQ;
			soR = PPC_REG_CR2_SO;
			break;
		case PPC_REG_CR3:
			ltR = PPC_REG_CR3_LT;
			gtR = PPC_REG_CR3_GT;
			eqR = PPC_REG_CR3_EQ;
			soR = PPC_REG_CR3_SO;
			break;
		case PPC_REG_CR4:
			ltR = PPC_REG_CR4_LT;
			gtR = PPC_REG_CR4_GT;
			eqR = PPC_REG_CR4_EQ;
			soR = PPC_REG_CR4_SO;
			break;
		case PPC_REG_CR5:
			ltR = PPC_REG_CR5_LT;
			gtR = PPC_REG_CR5_GT;
			eqR = PPC_REG_CR5_EQ;
			soR = PPC_REG_CR5_SO;
			break;
		case PPC_REG_CR6:
			ltR = PPC_REG_CR6_LT;
			gtR = PPC_REG_CR6_GT;
			eqR = PPC_REG_CR6_EQ;
			soR = PPC_REG_CR6_SO;
			break;
		case PPC_REG_CR7:
			ltR = PPC_REG_CR7_LT;
			gtR = PPC_REG_CR7_GT;
			eqR = PPC_REG_CR7_EQ;
			soR = PPC_REG_CR7_SO;
			break;
		default:
			assert(false && "unhandled CR register");
			break;
	}

	switch (type)
	{
		case PPC_CR_LT:
			return loadRegister(ltR, irb);;
		case PPC_CR_GT:
			return loadRegister(gtR, irb);
		case PPC_CR_EQ:
			return loadRegister(eqR, irb);
		case PPC_CR_SO:
			return loadRegister(soR, irb);
		default:
			assert(false && "should not happen");
			return nullptr;
	}
}

void Capstone2LlvmIrTranslatorPowerpc_impl::storeCr0(
		llvm::IRBuilder<>& irb,
		cs_ppc* pi,
		llvm::Value* val)
{
	if (!pi->update_cr0)
	{
		return;
	}

	llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);

	auto* ltZero = irb.CreateICmpSLT(val, zero);
	storeRegister(PPC_REG_CR0_LT, ltZero, irb);

	auto* gtZero = irb.CreateICmpSGT(val, zero);
	storeRegister(PPC_REG_CR0_GT, gtZero, irb);

	auto* eqZero = irb.CreateICmpEQ(val, zero);
	storeRegister(PPC_REG_CR0_EQ, eqZero, irb);

	// TODO: PPC_REG_CR0_SO is a copy of XER, which we do not have.
	storeRegister(PPC_REG_CR0_SO, zero, irb);
}

bool Capstone2LlvmIrTranslatorPowerpc_impl::isGeneralPurposeRegister(uint32_t r)
{
	return PPC_REG_R0 <= r && r <= PPC_REG_R31;
}

uint32_t Capstone2LlvmIrTranslatorPowerpc_impl::getGeneralPurposeRegisterIndex(uint32_t r)
{
	return r - PPC_REG_R0;
}

/**
 * 0  -> PPC_REG_CR0_LT
 * 1  -> PPC_REG_CR0_GT
 * 2  -> PPC_REG_CR0_EQ
 * 3  -> PPC_REG_CR0_SO
 * 4  -> PPC_REG_CR1_LT
 * 5  -> PPC_REG_CR2_GT
 * ...
 * 30 -> PPC_REG_CR7_EQ
 * 31 -> PPC_REG_CR7_SO
 */
uint32_t Capstone2LlvmIrTranslatorPowerpc_impl::crBitIndexToCrRegister(uint32_t idx)
{
	return PPC_REG_CR0_LT + idx;
}

bool Capstone2LlvmIrTranslatorPowerpc_impl::isCrRegister(uint32_t r)
{
	return PPC_REG_CR0 <= r && r <= PPC_REG_CR7;
}

bool Capstone2LlvmIrTranslatorPowerpc_impl::isCrRegister(cs_ppc_op& op)
{
	return op.type == PPC_OP_REG && isCrRegister(op.reg);
}

//
//==============================================================================
// PowerPC instruction translation methods.
//==============================================================================
//

/**
 * PPC_INS_ADD, PPC_INS_ADDI
 * PPC_INS_LA - 1. and 2. operands are reversed, but it probbaly does not matter.
 *              la 0, 0x4, 1 (reg, imm, reg) == addi 0, 1, 0x4 (reg, reg, imm)
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAdd(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	auto* add = irb.CreateAdd(op1, op2);
	storeOp(pi->operands[0], add, irb);
	storeCr0(irb, pi, add);
}

/**
 * PPC_INS_ADDC, PPC_INS_ADDIC
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAddc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	auto* add = irb.CreateAdd(op1, op2);
	storeOp(pi->operands[0], add, irb);
	storeCr0(irb, pi, add);
	storeRegister(PPC_REG_CARRY, generateCarryAdd(add, op1, irb), irb);
}

/**
 * PPC_INS_ADDE
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAdde(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	auto* add = irb.CreateAdd(op1, op2);
	auto* carry = loadRegister(PPC_REG_CARRY, irb);
	carry = irb.CreateZExtOrTrunc(carry, add->getType());
	add = irb.CreateAdd(add, carry);
	storeOp(pi->operands[0], add, irb);
	// TODO: In the original semantics, LT is set using final add, GT and EQ
	// using first add. Not sure what is ok.
	storeCr0(irb, pi, add);
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1, op2, irb, carry), irb);
}

/**
 * PPC_INS_ADDIS
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAddis(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = irb.CreateShl(op2, llvm::ConstantInt::get(op2->getType(), 16));
	auto* add = irb.CreateAdd(op1, op2);
	storeOp(pi->operands[0], add, irb);
	storeCr0(irb, pi, add);
}

/**
 * PPC_INS_ADDME
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAddme(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* carry = loadRegister(PPC_REG_CARRY, irb);
	carry = irb.CreateZExtOrTrunc(carry, op1->getType());
	auto* add = irb.CreateAdd(op1, carry);
	auto* one = llvm::ConstantInt::get(add->getType(), 1);
	auto* sub = irb.CreateSub(add, one);
	storeOp(pi->operands[0], sub, irb);

	// TODO: In the original semantics, LT is set using a different value
	// than GT and EQ.
	storeCr0(irb, pi, sub);

	auto* negativeOne = llvm::ConstantInt::getSigned(op1->getType(), -1);
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1, negativeOne, irb, carry), irb);
}

/**
 * PPC_INS_ADDZE
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAddze(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* carry = loadRegister(PPC_REG_CARRY, irb);
	carry = irb.CreateZExtOrTrunc(carry, op1->getType());
	auto* add = irb.CreateAdd(op1, carry);
	storeOp(pi->operands[0], add, irb);

	// TODO: In the original semantics, LT is set using final add, GT and EQ
	// using op1. Not sure what is ok.
	storeCr0(irb, pi, add);

	auto* zero = llvm::ConstantInt::get(op1->getType(), 0);
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1, zero, irb, carry), irb);
}

/**
 * PPC_INS_AND, PPC_INS_ANDI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAnd(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* val = irb.CreateAnd(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_ANDC
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAndc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = generateValueNegate(irb, op2);
	auto* val = irb.CreateAnd(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_ANDIS
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateAndis(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = irb.CreateShl(op2, llvm::ConstantInt::get(op2->getType(), 16));
	auto* val = irb.CreateAnd(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_CLRLWI - clrlwi rA, RS, n (n < 32) = rlwinm rA, rS, 0, n, 31
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateClrlwi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = irb.CreateAnd(op2, llvm::ConstantInt::get(op2->getType(), 31));
	op1 = irb.CreateShl(op1, op2);
	op1 = irb.CreateLShr(op1, op2);
	storeOp(pi->operands[0], op1, irb);
	storeCr0(irb, pi, op1);
}

/**
 * PPC_INS_CMPD  = cmp  0, 1, rA, rB
 * But Capstone also allows things like "cmpd cr5, 0, 1"
 *
 * PPC_INS_CMPDI = cmpi 0, 1, rA, value
 * But Capstone also allows things like "cmpdi cr5, 0, 1"
 *
 * PPC_INS_CMPW, PPC_INS_CMPWI
 * PPC_INS_CMPLD, PPC_INS_CMPLDI
 * PPC_INS_CMPLW, PPC_INS_CMPLWI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateCmp(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	uint32_t crReg = PPC_REG_CR0;
	if (pi->op_count == 2)
	{
		crReg = PPC_REG_CR0;
		std::tie(op0, op1) = loadOpBinary(pi, irb, eOpConv::SEXT_TRUNC);
	}
	else if (pi->op_count == 3
			&& pi->operands[0].type == PPC_OP_REG
			&& pi->operands[0].reg >= PPC_REG_CR0
			&& pi->operands[0].reg <= PPC_REG_CR7)
	{
		crReg = pi->operands[0].reg;
		std::tie(op0, op1) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	}
	else
	{
		assert(false && "unhandled cmp instruction format");
		return;
	}

	if (i->id == PPC_INS_CMPW
			|| i->id == PPC_INS_CMPWI
			|| i->id == PPC_INS_CMPLW
			|| i->id == PPC_INS_CMPLWI)
	{
		op0 = irb.CreateSExtOrTrunc(op0, irb.getInt32Ty());
		op1 = irb.CreateSExtOrTrunc(op1, irb.getInt32Ty());
	}

	bool signedCmp = true;
	if (i->id == PPC_INS_CMPLD
			|| i->id == PPC_INS_CMPLDI
			|| i->id == PPC_INS_CMPLW
			|| i->id == PPC_INS_CMPLWI)
	{
		signedCmp = false;
	}

	storeCrX(irb, crReg, op0, op1, signedCmp);
}

/**
 * PPC_INS_CNTLZW
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateCntlzw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* f = llvm::Intrinsic::getDeclaration(
			_module,
			llvm::Intrinsic::ctlz,
			op1->getType());
	auto* val = irb.CreateCall(f, {op1, irb.getTrue()});
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_DIVW, PPC_INS_DIVWU
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateDivw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
	auto* val = i->id == PPC_INS_DIVW
			? irb.CreateSDiv(op1, op2)
			: irb.CreateUDiv(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_EQV
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateEqv(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* val = irb.CreateXor(op1, op2);
	val = generateValueNegate(irb, val);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_EXTSB, PPC_INS_EXTSH, PPC_INS_EXTSW
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateExtendSign(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* ty = llvm::dyn_cast<llvm::IntegerType>(op1->getType());
	if (ty == nullptr)
	{
		return;
	}
	unsigned shift = 0;
	switch (i->id)
	{
		case PPC_INS_EXTSB: shift = ty->getBitWidth() - 8; break;
		case PPC_INS_EXTSH: shift = ty->getBitWidth() - 16; break;
		case PPC_INS_EXTSW: shift = ty->getBitWidth() - 32; break;
		default: return;
	}

	auto* val = irb.CreateShl(op1, shift);
	val = irb.CreateAShr(val, shift);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val); // TODO: Orig sem is using op1 here.
}

/**
 * PPC_INS_LBZ, PPC_INS_LHZ, PPC_INS_LWZ,
 * PPC_INS_LBZU, PPC_INS_LHZU, PPC_INS_LWZU,
 * PPC_INS_LHA, PPC_INS_LHAU
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateLoad(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case PPC_INS_LBZ:
		case PPC_INS_LBZU:
			ty = irb.getInt8Ty();
			break;
		case PPC_INS_LHZ:
		case PPC_INS_LHZU:
		case PPC_INS_LHA:
		case PPC_INS_LHAU:
			ty = irb.getInt16Ty();
			break;
		case PPC_INS_LWZ:
		case PPC_INS_LWZU:
			ty = irb.getInt32Ty();
			break;
		default:
			return;
	}

	op1 = loadOpBinaryOp1(pi, irb, ty);

	eOpConv conv = eOpConv::ZEXT_TRUNC;
	if (i->id == PPC_INS_LHA || i->id == PPC_INS_LHAU)
	{
		conv = eOpConv::SEXT_TRUNC;
	}
	storeOp(pi->operands[0], op1, irb, conv);

	// With update.
	//
	auto& ppcOp1 = pi->operands[1];
	if (i->id == PPC_INS_LBZU || i->id == PPC_INS_LHZU
			|| i->id == PPC_INS_LWZU ||  i->id == PPC_INS_LHAU)
	if (ppcOp1.type == PPC_OP_MEM && ppcOp1.mem.base != PPC_REG_INVALID)
	if (auto* l = llvm::dyn_cast<llvm::LoadInst>(op1))
	if (auto* cast = llvm::dyn_cast<llvm::CastInst>(l->getPointerOperand()))
	{
		storeRegister(ppcOp1.mem.base, cast->getOperand(0), irb);
	}
}

/**
 * PPC_INS_LBZX, PPC_INS_LHZX, PPC_INS_LWZX,
 * PPC_INS_LBZUX, PPC_INS_LHZUX, PPC_INS_LWZUX,
 * PPC_INS_LHAX, PPC_INS_LHAUX
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateLoadIndexed(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* add = irb.CreateAdd(op1, op2);

	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case PPC_INS_LBZX:
		case PPC_INS_LBZUX:
			ty = irb.getInt8Ty();
			break;
		case PPC_INS_LHZX:
		case PPC_INS_LHZUX:
		case PPC_INS_LHAX:
		case PPC_INS_LHAUX:
			ty = irb.getInt16Ty();
			break;
		case PPC_INS_LWZX:
		case PPC_INS_LWZUX:
			ty = irb.getInt32Ty();
			break;
		default:
			return;
	}

	auto* pty = llvm::PointerType::get(ty, 0);
	auto* addr = irb.CreateIntToPtr(add, pty);
	auto* l = irb.CreateLoad(addr);

	eOpConv conv = eOpConv::ZEXT_TRUNC;
	if (i->id == PPC_INS_LHAX || i->id == PPC_INS_LHAUX)
	{
		conv = eOpConv::SEXT_TRUNC;
	}
	storeOp(pi->operands[0], l, irb, conv);

	// With update.
	//
	auto& ppcOp1 = pi->operands[1];
	if (i->id == PPC_INS_LBZUX || i->id == PPC_INS_LHZUX
			|| i->id == PPC_INS_LWZUX || i->id == PPC_INS_LHAUX)
	if (ppcOp1.type == PPC_OP_REG && ppcOp1.reg != PPC_REG_INVALID)
	{
		storeRegister(ppcOp1.reg, add, irb);
	}
}

/**
 * PPC_INS_STB, PPC_INS_STH, PPC_INS_STW,
 * PPC_INS_STBU, PPC_INS_STHU, PPC_INS_STWU,
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateStore(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	assert(pi->op_count == 2);

	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case PPC_INS_STB:
		case PPC_INS_STBU:
			ty = irb.getInt8Ty();
			break;
		case PPC_INS_STH:
		case PPC_INS_STHU:
			ty = irb.getInt16Ty();
			break;
		case PPC_INS_STW:
		case PPC_INS_STWU:
			ty = irb.getInt32Ty();
			break;
		default:
			return;
	}

	op0 = loadOpBinaryOp0(pi, irb);
	if (ty->isIntegerTy())
	{
		op0 = irb.CreateZExtOrTrunc(op0, ty);
	}
	else
	{
		assert(false && "unhandled type");
		return;
	}

	auto* si = storeOp(pi->operands[1], op0, irb);

	// With update.
	//
	auto& ppcOp1 = pi->operands[1];
	if (i->id == PPC_INS_STBU || i->id == PPC_INS_STHU
			|| i->id == PPC_INS_STWU)
	if (ppcOp1.type == PPC_OP_MEM && ppcOp1.mem.base != PPC_REG_INVALID)
	if (auto* s = llvm::dyn_cast<llvm::StoreInst>(si))
	if (auto* cast = llvm::dyn_cast<llvm::CastInst>(s->getPointerOperand()))
	{
		storeRegister(ppcOp1.mem.base, cast->getOperand(0), irb);
	}
}

/**
 * PPC_INS_STBX, PPC_INS_STHX, PPC_INS_STWX,
 * PPC_INS_STBUX, PPC_INS_STHUX, PPC_INS_STWUX,
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateStoreIndexed(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(pi, irb);

	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case PPC_INS_STBX:
		case PPC_INS_STBUX:
			ty = irb.getInt8Ty();
			break;
		case PPC_INS_STHX:
		case PPC_INS_STHUX:
			ty = irb.getInt16Ty();
			break;
		case PPC_INS_STWX:
		case PPC_INS_STWUX:
			ty = irb.getInt32Ty();
			break;
		default:
			return;
	}

	if (ty->isIntegerTy())
	{
		op0 = irb.CreateZExtOrTrunc(op0, ty);
	}
	else
	{
		assert(false && "unhandled type");
		return;
	}

	auto* add = irb.CreateAdd(op1, op2);
	auto* pty = llvm::PointerType::get(ty, 0);
	auto* addr = irb.CreateIntToPtr(add, pty);
	irb.CreateStore(op0, addr);

	// With update.
	//
	auto& ppcOp1 = pi->operands[1];
	if (i->id == PPC_INS_STBUX || i->id == PPC_INS_STHUX
			|| i->id == PPC_INS_STWUX)
	if (ppcOp1.type == PPC_OP_REG && ppcOp1.reg != PPC_REG_INVALID)
	{
		storeRegister(ppcOp1.reg, add, irb);
	}
}

/**
 * PPC_INS_STHBRX, PPC_INS_STWBRX
 * TODO: The same case as in PPC_INS_LWBRX.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateStoreReverseIndexed(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(pi, irb);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			irb.getVoidTy(),
			{op0->getType(), op1->getType(), op2->getType()});

	irb.CreateCall(fnc, {op0, op1, op2});
}

/**
 * PPC_INS_LHBRX
 * TODO: Maybe model this as ASM pseudo call as PPC_INS_LWBRX.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateLhbrx(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);

	auto* pty = llvm::PointerType::get(irb.getInt8Ty(), 0);

	auto* addHi = irb.CreateAdd(op1, op2);
	auto* addrHi = irb.CreateIntToPtr(addHi, pty);
	llvm::Value* lHi = irb.CreateLoad(addrHi);
	lHi = irb.CreateZExtOrTrunc(lHi, irb.getInt16Ty());

	auto* addLo = irb.CreateAdd(addHi, llvm::ConstantInt::get(addHi->getType(), 1));
	auto* addrLo = irb.CreateIntToPtr(addLo, pty);
	llvm::Value* lLo = irb.CreateLoad(addrLo);
	lLo = irb.CreateZExtOrTrunc(lLo, irb.getInt16Ty());
	lLo = irb.CreateShl(lLo, 8);

	auto* val = irb.CreateOr(lLo, lHi);

	storeOp(pi->operands[0], val, irb, eOpConv::ZEXT_TRUNC);
}

/**
 * PPC_INS_LI = addi rD, 0, value
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateLi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	storeOp(pi->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
	storeCr0(irb, pi, op1); // ?
}

/**
 * PPC_INS_LIS = addis rD, 0, value
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateLis(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	op1 = irb.CreateShl(op1, llvm::ConstantInt::get(op1->getType(), 16));
	storeOp(pi->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
	storeCr0(irb, pi, op1); // ?
}

/**
 * PPC_INS_LWBRX
 * TODO: This loads data (decompilation could create global variable load),
 * but because there is no load, it will not know about it.
 * Maybe compute address, load, and only then call some pseudo function that
 * reverses bytes?
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateLwbrx(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			op1->getType(),
			{op1->getType(), op2->getType()});

	auto* val = irb.CreateCall(fnc, {op1, op2});
	storeOp(pi->operands[0], val, irb, eOpConv::ZEXT_TRUNC);
}

/**
 * PPC_INS_MR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	storeOp(pi->operands[0], op1, irb);
	storeCr0(irb, pi, op1);
}

/**
 * PPC_INS_MTCRF
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMtcrf(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(pi, irb);

	auto* i1 = irb.getInt1Ty();
	auto* i4 = irb.getIntNTy(4);
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			llvm::StructType::create({i1, i1, i1, i1, i4, i4, i4, i4, i4, i4, i4}),
			{op0->getType(), op1->getType()});

	auto* c = irb.CreateCall(fnc, {op0, op1});

	storeRegister(PPC_REG_CR0_LT, irb.CreateExtractValue(c, {0}), irb);
	storeRegister(PPC_REG_CR0_GT, irb.CreateExtractValue(c, {1}), irb);
	storeRegister(PPC_REG_CR0_EQ, irb.CreateExtractValue(c, {2}), irb);
	storeRegister(PPC_REG_CR0_SO, irb.CreateExtractValue(c, {3}), irb);

	storeRegister(PPC_REG_CR1, irb.CreateExtractValue(c, {4}), irb);
	storeRegister(PPC_REG_CR2, irb.CreateExtractValue(c, {5}), irb);
	storeRegister(PPC_REG_CR3, irb.CreateExtractValue(c, {6}), irb);
	storeRegister(PPC_REG_CR4, irb.CreateExtractValue(c, {7}), irb);
	storeRegister(PPC_REG_CR5, irb.CreateExtractValue(c, {8}), irb);
	storeRegister(PPC_REG_CR6, irb.CreateExtractValue(c, {9}), irb);
	storeRegister(PPC_REG_CR7, irb.CreateExtractValue(c, {10}), irb);
}

/**
 * PPC_INS_MTCR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMtcr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(pi, irb);
	op0 = irb.CreateZExtOrTrunc(op0, irb.getInt32Ty());

	storeRegister(PPC_REG_CR0_LT, irb.CreateAnd(op0, irb.getInt32(1 << 0)), irb);
	storeRegister(PPC_REG_CR0_GT, irb.CreateAnd(op0, irb.getInt32(1 << 1)), irb);
	storeRegister(PPC_REG_CR0_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 2)), irb);
	storeRegister(PPC_REG_CR0_SO, irb.CreateAnd(op0, irb.getInt32(1 << 3)), irb);

	storeRegister(PPC_REG_CR1_LT, irb.CreateAnd(op0, irb.getInt32(1 << 4)), irb);
	storeRegister(PPC_REG_CR1_GT, irb.CreateAnd(op0, irb.getInt32(1 << 5)), irb);
	storeRegister(PPC_REG_CR1_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 6)), irb);
	storeRegister(PPC_REG_CR1_SO, irb.CreateAnd(op0, irb.getInt32(1 << 7)), irb);

	storeRegister(PPC_REG_CR2_LT, irb.CreateAnd(op0, irb.getInt32(1 << 8)), irb);
	storeRegister(PPC_REG_CR2_GT, irb.CreateAnd(op0, irb.getInt32(1 << 9)), irb);
	storeRegister(PPC_REG_CR2_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 10)), irb);
	storeRegister(PPC_REG_CR2_SO, irb.CreateAnd(op0, irb.getInt32(1 << 11)), irb);

	storeRegister(PPC_REG_CR3_LT, irb.CreateAnd(op0, irb.getInt32(1 << 12)), irb);
	storeRegister(PPC_REG_CR3_GT, irb.CreateAnd(op0, irb.getInt32(1 << 13)), irb);
	storeRegister(PPC_REG_CR3_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 14)), irb);
	storeRegister(PPC_REG_CR3_SO, irb.CreateAnd(op0, irb.getInt32(1 << 15)), irb);

	storeRegister(PPC_REG_CR4_LT, irb.CreateAnd(op0, irb.getInt32(1 << 16)), irb);
	storeRegister(PPC_REG_CR4_GT, irb.CreateAnd(op0, irb.getInt32(1 << 17)), irb);
	storeRegister(PPC_REG_CR4_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 18)), irb);
	storeRegister(PPC_REG_CR4_SO, irb.CreateAnd(op0, irb.getInt32(1 << 19)), irb);

	storeRegister(PPC_REG_CR5_LT, irb.CreateAnd(op0, irb.getInt32(1 << 20)), irb);
	storeRegister(PPC_REG_CR5_GT, irb.CreateAnd(op0, irb.getInt32(1 << 21)), irb);
	storeRegister(PPC_REG_CR5_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 22)), irb);
	storeRegister(PPC_REG_CR5_SO, irb.CreateAnd(op0, irb.getInt32(1 << 23)), irb);

	storeRegister(PPC_REG_CR6_LT, irb.CreateAnd(op0, irb.getInt32(1 << 24)), irb);
	storeRegister(PPC_REG_CR6_GT, irb.CreateAnd(op0, irb.getInt32(1 << 25)), irb);
	storeRegister(PPC_REG_CR6_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 26)), irb);
	storeRegister(PPC_REG_CR6_SO, irb.CreateAnd(op0, irb.getInt32(1 << 27)), irb);

	storeRegister(PPC_REG_CR7_LT, irb.CreateAnd(op0, irb.getInt32(1 << 28)), irb);
	storeRegister(PPC_REG_CR7_GT, irb.CreateAnd(op0, irb.getInt32(1 << 29)), irb);
	storeRegister(PPC_REG_CR7_EQ, irb.CreateAnd(op0, irb.getInt32(1 << 30)), irb);
	storeRegister(PPC_REG_CR7_SO, irb.CreateAnd(op0, irb.getInt32(1 << 31)), irb);
}

/**
 * PPC_INS_MTCTR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMtctr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(pi, irb);
	storeRegister(PPC_REG_CTR, op0, irb);
}

/**
 * PPC_INS_MTLR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMtlr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op0 = loadOpUnary(pi, irb);
	storeRegister(PPC_REG_LR, op0, irb);
}

/**
 * PPC_INS_CRAND, PPC_INS_CRANDC, PPC_INS_CREQV, PPC_INS_CRNAND, PPC_INS_CRNOR,
 * PPC_INS_CROR, PPC_INS_CRORC, PPC_INS_CRXOR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateCrModifTernary(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1, op2) = loadOpTernary(pi, irb);

	auto* i1 = irb.getInt1Ty();
	auto* i4 = irb.getIntNTy(4);
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			llvm::StructType::create({i1, i1, i1, i1, i4, i4, i4, i4, i4, i4, i4}),
			{op0->getType(), op1->getType(), op2->getType()});

	auto* c = irb.CreateCall(fnc, {op0, op1, op2});

	storeRegister(PPC_REG_CR0_LT, irb.CreateExtractValue(c, {0}), irb);
	storeRegister(PPC_REG_CR0_GT, irb.CreateExtractValue(c, {1}), irb);
	storeRegister(PPC_REG_CR0_EQ, irb.CreateExtractValue(c, {2}), irb);
	storeRegister(PPC_REG_CR0_SO, irb.CreateExtractValue(c, {3}), irb);

	storeRegister(PPC_REG_CR1, irb.CreateExtractValue(c, {4}), irb);
	storeRegister(PPC_REG_CR2, irb.CreateExtractValue(c, {5}), irb);
	storeRegister(PPC_REG_CR3, irb.CreateExtractValue(c, {6}), irb);
	storeRegister(PPC_REG_CR4, irb.CreateExtractValue(c, {7}), irb);
	storeRegister(PPC_REG_CR5, irb.CreateExtractValue(c, {8}), irb);
	storeRegister(PPC_REG_CR6, irb.CreateExtractValue(c, {9}), irb);
	storeRegister(PPC_REG_CR7, irb.CreateExtractValue(c, {10}), irb);
}

/**
 * PPC_INS_CRNOT  - crnot bx, by = crnor bx, by, by
 * PPC_INS_CRMOVE - crmove bx, by = cror bx, by, by
 *
 * TODO: CRNOT and others? modeled as asm pseudo calls???
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateCrNotMove(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	uint32_t crReg0 = 0;
	uint32_t crReg1 = 0;
	if (pi->op_count == 2
			&& pi->operands[0].type == PPC_OP_REG
			&& isGeneralPurposeRegister(pi->operands[0].reg)
			&& pi->operands[1].type == PPC_OP_REG
			&& isGeneralPurposeRegister(pi->operands[1].reg))
	{
		auto r0 = pi->operands[0].reg;
		crReg0 = crBitIndexToCrRegister(getGeneralPurposeRegisterIndex(r0));
		auto r1 = pi->operands[1].reg;
		crReg1 = crBitIndexToCrRegister(getGeneralPurposeRegisterIndex(r1));
	}
	else
	{
		assert(false);
		return;
	}

	op1 = loadRegister(crReg1, irb);

	if (i->id == PPC_INS_CRMOVE)
	{
		storeRegister(crReg0, op1, irb);
	}
	else if (i->id == PPC_INS_CRNOT)
	{
		op1 = generateValueNegate(irb, op1);
		storeRegister(crReg0, op1, irb);
	}
}

/**
 * PPC_INS_CRSET - set CR bit
 * PPC_INS_CRCLR - clear CR bit
 * Unary, operand is general purpose register r0-r31 == bit 0-31 of CR.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateCrSetClr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	uint32_t crReg = 0;
	if (pi->op_count == 1
			&& pi->operands[0].type == PPC_OP_REG
			&& isGeneralPurposeRegister(pi->operands[0].reg))
	{
		auto r = pi->operands[0].reg;
		crReg = crBitIndexToCrRegister(getGeneralPurposeRegisterIndex(r));
	}
	else
	{
		assert(false);
		return;
	}

	if (i->id == PPC_INS_CRSET)
	{
		storeRegister(crReg, irb.getTrue(), irb);
	}
	else if (i->id == PPC_INS_CRCLR)
	{
		storeRegister(crReg, irb.getFalse(), irb);
	}
}

/**
 * PPC_INS_MTSPR
 * First operand is imm, if it is some known value, we could actually write
 * appropriate registers. However, it looks like Capstone creates different
 * instructions when this happens, so we need to translate them, but do not
 * need to handle it here.
 * E.g. "mtspr 8, 1" -> "mtlr r1" -> writes LR.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMtspr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op0, op1) = loadOpBinary(pi, irb);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			irb.getVoidTy(),
			{op0->getType(), op1->getType()});

	irb.CreateCall(fnc, {op0, op1});
}

/**
 * PPC_INS_MCRF
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMcrf(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	if (pi->op_count != 2)
	{
		return;
	}

	if (pi->operands[0].type == PPC_OP_REG
			&& pi->operands[1].type == PPC_OP_REG
			&& pi->operands[0].reg == pi->operands[1].reg)
	{
		return;
	}

	if (pi->operands[1].type == PPC_OP_REG
			&& pi->operands[1].reg == PPC_REG_CR0)
	{
		auto* lt = loadRegister(PPC_REG_CR0_LT, irb);
		auto* gt = loadRegister(PPC_REG_CR0_GT, irb);
		auto* eq = loadRegister(PPC_REG_CR0_EQ, irb);
		auto* so = loadRegister(PPC_REG_CR0_SO, irb);

		llvm::Function* fnc = getOrCreateAsmFunction(
				i->id,
				"__asm_" + std::string(i->mnemonic) + "_cr0_read",
				irb.getIntNTy(4),
				{lt->getType(), gt->getType(), eq->getType(), so->getType()});

		auto* c = irb.CreateCall(fnc, {lt, gt, eq, so});
		storeOp(pi->operands[0], c, irb);
	}
	else if (pi->operands[0].type == PPC_OP_REG
			&& pi->operands[0].reg == PPC_REG_CR0)
	{
		op1 = loadOpBinaryOp1(pi, irb);

		auto* i1 = irb.getInt1Ty();
		llvm::Function* fnc = getOrCreateAsmFunction(
				i->id,
				"__asm_" + std::string(i->mnemonic) + "_cr0_write",
				llvm::StructType::create({i1, i1, i1, i1}),
				{op1->getType()});

		auto* c = irb.CreateCall(fnc, {op1});

		storeRegister(PPC_REG_CR0_LT, irb.CreateExtractValue(c, {0}), irb);
		storeRegister(PPC_REG_CR0_GT, irb.CreateExtractValue(c, {1}), irb);
		storeRegister(PPC_REG_CR0_EQ, irb.CreateExtractValue(c, {2}), irb);
		storeRegister(PPC_REG_CR0_SO, irb.CreateExtractValue(c, {3}), irb);
	}
	else
	{
		op1 = loadOpBinaryOp1(pi, irb);

		llvm::Function* fnc = getOrCreateAsmFunction(
				i->id,
				"__asm_" + std::string(i->mnemonic),
				op1->getType(),
				{op1->getType()});

		auto* c = irb.CreateCall(fnc, {op1});
		storeOp(pi->operands[0], c, irb);
	}
}

/**
 * PPC_INS_MFCR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMfcr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			getDefaultType(),
			{});

	auto* val = irb.CreateCall(fnc);
	storeOp(pi->operands[0], val, irb);
}

/**
 * PPC_INS_MFCTR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMfctr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	assert(pi->op_count == 1); // TODO: isUnary() check -> exception.

	auto* ctr = loadRegister(PPC_REG_CTR, irb);
	storeOp(pi->operands[0], ctr, irb);
}

/**
 * PPC_INS_MFLR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMflr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	assert(pi->op_count == 1); // TODO: isUnary() check -> exception.

	auto* ctr = loadRegister(PPC_REG_LR, irb);
	storeOp(pi->operands[0], ctr, irb);
}

/**
 * PPC_INS_MFSPR
 * The same case as PPC_INS_MTSPR.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMfspr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			getDefaultType(),
			{op1->getType()});

	auto* val = irb.CreateCall(fnc, {op1});
	storeOp(pi->operands[0], val, irb);
}

/**
 * PPC_INS_MULHW, PPC_INS_MULHWU
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMulhw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
	if (i->id == PPC_INS_MULHW)
	{
		op1 = irb.CreateSExtOrTrunc(op1, irb.getInt64Ty());
		op2 = irb.CreateSExtOrTrunc(op2, irb.getInt64Ty());
	}
	else if (i->id == PPC_INS_MULHWU)
	{
		op1 = irb.CreateZExtOrTrunc(op1, irb.getInt64Ty());
		op2 = irb.CreateZExtOrTrunc(op2, irb.getInt64Ty());
	}
	auto* val = irb.CreateMul(op1, op2);
	val = irb.CreateLShr(val, 32);
	val = irb.CreateTrunc(val, irb.getInt32Ty());
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_MULLW, PPC_INS_MULLI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateMullw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	auto* val = irb.CreateMul(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_NAND
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateNand(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* val = irb.CreateAnd(op1, op2);
	val = generateValueNegate(irb, val);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_NEG
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateNeg(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* val = irb.CreateSub(llvm::ConstantInt::get(op1->getType(), 0), op1);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_NOP
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateNop(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	// nothing
}

/**
 * PPC_INS_NOR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateNor(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* val = irb.CreateOr(op1, op2);
	val = generateValueNegate(irb, val);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_NOT
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateNot(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	op2 = op1;
	auto* val = irb.CreateOr(op1, op2);
	val = generateValueNegate(irb, val);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_OR, PPC_INS_ORI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateOr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* val = irb.CreateOr(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_ORC
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateOrc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = generateValueNegate(irb, op2);
	auto* val = irb.CreateOr(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_ORIS
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateOris(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = irb.CreateShl(op2, llvm::ConstantInt::get(op2->getType(), 16));
	auto* val = irb.CreateOr(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_RLWINM, PPC_INS_RLWIMI, PPC_INS_RLWNM
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateRotateComplex5op(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	if (pi->op_count != 5)
	{
		return;
	}

	auto* op1 = loadOp(pi->operands[1], irb);
	auto* op2 = loadOp(pi->operands[2], irb);
	auto* op3 = loadOp(pi->operands[3], irb);
	auto* op4 = loadOp(pi->operands[4], irb);

	llvm::Function* fnc = getOrCreateAsmFunction(
			i->id,
			"__asm_" + std::string(i->mnemonic),
			op1->getType(),
			{op1->getType(), op2->getType(), op3->getType(), op4->getType()});

	// TODO: Make sure parameters have expected types.
	// Probably create a call generation helper method that does it everywhere.
	//
	auto* val = irb.CreateCall(fnc, {op1, op2, op3, op4});

	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_ROTLW, PPC_INS_ROTLWI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateRotlw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(op1->getType())->getBitWidth();
	unsigned maskC = op0BitW == 64 ? 0x3f : 0x1f;
	auto* mask = llvm::ConstantInt::get(op2->getType(), maskC);
	op2 = irb.CreateAnd(op2, mask);

	auto* shl = irb.CreateShl(op1, op2);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(op2->getType(), op0BitW), op2);
	auto* srl = irb.CreateLShr(op1, sub);
	auto* orr = irb.CreateOr(srl, shl);

	storeOp(pi->operands[0], orr, irb);
	storeCr0(irb, pi, orr);
}

/**
 * PPC_INS_SLW
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateShiftLeft(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
	op1 = irb.CreateZExtOrTrunc(op1, irb.getInt32Ty());
	op2 = irb.CreateAnd(op2, llvm::ConstantInt::get(op2->getType(), 0x3f)); // low 6 bits
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	auto* val = irb.CreateShl(op1, op2);
	storeOp(pi->operands[0], val, irb, eOpConv::ZEXT_TRUNC); // TODO: check it all others are using correct conversion
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_SRW
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateShiftRight(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
	op1 = irb.CreateZExtOrTrunc(op1, irb.getInt32Ty());
	op2 = irb.CreateAnd(op2, llvm::ConstantInt::get(op2->getType(), 0x3f)); // low 6 bits
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	auto* val = irb.CreateLShr(op1, op2);
	storeOp(pi->operands[0], val, irb, eOpConv::ZEXT_TRUNC);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_SLWI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSlwi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
	auto* shl = irb.CreateShl(op1, op2);
	storeOp(pi->operands[0], shl, irb);
	storeCr0(irb, pi, shl);
}

/**
 * PPC_INS_SRWI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSrwi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
	auto* shr = irb.CreateLShr(op1, op2);
	storeOp(pi->operands[0], shr, irb);
	storeCr0(irb, pi, shr);
}

/**
 * PPC_INS_SRAW, PPC_INS_SRAWI - Shift Right Algebraic
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSraw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
//	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);
//
//	llvm::Function* fnc = getOrCreateAsmFunction(
//			i->id,
//			"__asm_" + std::string(i->mnemonic),
//			llvm::StructType::create({op1->getType(), irb.getInt1Ty()}),
//			{op1->getType(), op2->getType()});
//
//	auto* c = irb.CreateCall(fnc, {op1, op2});
//	op0 = irb.CreateExtractValue(c, {0});
//
//	storeOp(pi->operands[0], op0, irb, eOpConv::ZEXT_TRUNC);
//	storeRegister(PPC_REG_CARRY, irb.CreateExtractValue(c, {1}), irb);
//	storeCr0(irb, pi, op0);

	// TODO: this is one-to-one from old semantics, it is super ugly, can it be better?

	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb);

	auto* andV = irb.CreateAnd(op2, llvm::ConstantInt::get(op2->getType(), 31));
	auto* u2 = irb.CreateSub(llvm::ConstantInt::get(op2->getType(), 0), op2);
	auto* and4 = irb.CreateAnd(u2, llvm::ConstantInt::get(u2->getType(), 31));
	auto* shl = irb.CreateShl(op1, and4);
	auto* u3 = irb.CreateXor(and4, llvm::ConstantInt::get(and4->getType(), 31));
	auto* shr = irb.CreateLShr(op1, u3);
	auto* shr8 = irb.CreateLShr(shr, llvm::ConstantInt::get(shr->getType(), 1));
	auto* orv = irb.CreateOr(shr8, shl);
	auto* and10 = irb.CreateAnd(op2, llvm::ConstantInt::get(op2->getType(), 32));
	auto* toBool = irb.CreateICmpNE(and10, llvm::ConstantInt::get(and10->getType(), 0));
	auto* shr11 = irb.CreateLShr(llvm::ConstantInt::getSigned(andV->getType(), -1), andV);
	auto* storemerge = irb.CreateSelect(toBool, llvm::ConstantInt::get(shr11->getType(), 0), shr11);
	auto* and19 = irb.CreateAnd(orv, storemerge);
	auto* lobit = irb.CreateAShr(op1, llvm::ConstantInt::get(op1->getType(), 31));
	auto* neg = irb.CreateXor(storemerge, llvm::ConstantInt::getSigned(storemerge->getType(), -1));
	auto* and21 = irb.CreateAnd(lobit, neg);
	auto* or22 = irb.CreateOr(and19, and21);

	storeOp(pi->operands[0], or22, irb);
	storeCr0(irb, pi, or22);

	auto* and26 = irb.CreateAnd(orv, neg);
	auto* cmp27 = irb.CreateICmpNE(and26, llvm::ConstantInt::get(and26->getType(), 0));
	auto* conv28 = irb.CreateZExt(cmp27, op1->getType());
	auto* lobit1 = irb.CreateLShr(op1, llvm::ConstantInt::get(op1->getType(), 31));
	auto* and29 = irb.CreateAnd(conv28, lobit1);
	auto* shl31 = irb.CreateShl(and29, llvm::ConstantInt::get(and29->getType(), 29));

	storeRegister(PPC_REG_CARRY, shl31, irb);
}

/**
 * PPC_INS_SUBF,
 * PPC_INS_SUB  - sub rD, rA, rB = subf rD, rB, rA
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSubf(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	if (i->id == PPC_INS_SUB)
	{
		std::swap(op1, op2);
	}
	auto* val = irb.CreateSub(op2, op1);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_SUBFC, PPC_INS_SUBFIC
 * PPC_INS_SUBC - subfc rD, rA, rB = subfc rD, rB, rA
 * TODO: This is different than the original semantics, it is according to
 * PowerPC specification.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSubfc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	if (i->id == PPC_INS_SUBC)
	{
		std::swap(op1, op2);
	}

	// PowerPC specification.
//	op1 = generateValueNegate(irb, op1);
//	auto* val = irb.CreateAdd(op1, op2);
//	val = irb.CreateAdd(val, llvm::ConstantInt::get(val->getType(), 1));

	// The same but simpler?
	auto* val = irb.CreateSub(op2, op1);
	op1 = generateValueNegate(irb, op1);

	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);

	// TODO: This is according to old semantics, but I'm not sure if it is ok.
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1, op2, irb, irb.getTrue()), irb);
	// TODO: PPC_INS_SUBFIC was using overflow_add_c() instead in an old
	// sematics, but these operations looks the same, so I have no idea why.
	// It may be the same thing.
//	storeRegister(PPC_REG_CARRY, genOverflowAddC(val, op1, op2, irb, irb.getTrue()), irb);
}

/**
 * PPC_INS_SUBFE
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSubfe(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::SEXT_TRUNC);
	auto* op1Neg = generateValueNegate(irb, op1);
	auto* val = irb.CreateAdd(op1Neg, op2);
	auto* carry = loadRegister(PPC_REG_CARRY, irb);
	carry = irb.CreateZExtOrTrunc(carry, val->getType());
	val = irb.CreateAdd(val, carry);

	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1, op2, irb, carry), irb);
}

/**
 * PPC_INS_SUBFME
 * TODO: This is modeled as it was in an old semantics, It looks a bit different
 * than in specification, but it may be doing the same thing, or may not,
 * I'm not really sure.
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSubfme(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* op1Neg = generateValueNegate(irb, op1);
	auto* carry = loadRegister(PPC_REG_CARRY, irb);
	carry = irb.CreateZExtOrTrunc(carry, op1->getType());
	auto* negativeTwo = llvm::ConstantInt::getSigned(op1->getType(), -2);
	auto* negativeOne = llvm::ConstantInt::getSigned(op1->getType(), -1);

	auto* sub = irb.CreateSub(negativeTwo, op1);
	auto* val = irb.CreateAdd(sub, carry);

	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1Neg, negativeOne, irb, carry), irb);
}

/**
 * PPC_INS_SUBFZE
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateSubfze(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	op1 = loadOpBinaryOp1(pi, irb);
	auto* op1Neg = generateValueNegate(irb, op1);
	auto* carry = loadRegister(PPC_REG_CARRY, irb);
	carry = irb.CreateZExtOrTrunc(carry, op1->getType());
	auto* val = irb.CreateAdd(op1Neg, carry);

	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
	auto* zero = llvm::ConstantInt::get(op1Neg->getType(), 0);
	storeRegister(PPC_REG_CARRY, generateCarryAddC(op1Neg, zero, irb, carry), irb);
}

/**
 * PPC_INS_XOR, PPC_INS_XORI
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateXor(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	auto* val = irb.CreateXor(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

/**
 * PPC_INS_XORIS
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateXoris(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	std::tie(op1, op2) = loadOpTernaryOp1Op2(pi, irb, eOpConv::ZEXT_TRUNC);
	op2 = irb.CreateShl(op2, llvm::ConstantInt::get(op2->getType(), 16));
	auto* val = irb.CreateXor(op1, op2);
	storeOp(pi->operands[0], val, irb);
	storeCr0(irb, pi, val);
}

//
//==============================================================================
//

/**
 * link   = Store next insn address to LR.
 * toLR   = Branch to LR.
 * toCTR  = branch to CTR.
 * primal = Complex variants all other simplified mnemonics are derived from.
 *          Right now, we probably will not be able handle it -- to many ops.
 *          E.g. bc BO, BI, target_addr
 *          No idea if Capstone actually generates this with three ops.
 *
 * Basic unconditional branches (not really, it can be conditional):
 * PPC_INS_B       - uncond/cond (blt, beq, bne, ...)
 * PPC_INS_BA      - absolute, cond/uncond
 * PPC_INS_BL      - link, cond/uncond
 * PPC_INS_BLA     - link, absolute, cond/uncond
 *
 * Basic conditional branches (not really sure it they are ever used):
 * PPC_INS_BC      - cond, primal
 * PPC_INS_BCA     - cond, absolute, primal
 * PPC_INS_BCLR    - cond, toLR, primal
 * PPC_INS_BCCTR   - cond, toCTR, primal
 * PPC_INS_BCL     - cond, link, primal
 * PPC_INS_BCLA    - cond, absolute, link, primal
 * PPC_INS_BCLRL   - cond, toLR, link, primal
 * PPC_INS_BCCTRL  - cond, toCTR, link, primal
 *
 * Branch unconditionally (not really, it can be conditional):
 * PPC_INS_BLR      - uncond/cond (beqlr, ...), toLR
 * PPC_INS_BCTR     - uncond/cond, toCTR
 * PPC_INS_BLRL     - uncond/cond, toLR, link
 * PPC_INS_BCTRL    - uncond/cond, toCTR, link
 *
 * Branch if condition true:
 * Not sure if these are ever used, looks like they are equal to:
 * (equal to b, ba, blr, bctr, bl, bla, blrl, bctrl).
 * PPC_INS_BT       - cond                  =>  (b)
 * PPC_INS_BTA      - cond, absolute        =>  (ba)
 * PPC_INS_BTLR     - cond, toLR            =>  (blr)
 * PPC_INS_BTCTR    - cond, toCTR           =>  (bctr)
 * PPC_INS_BTL      - cond, link            =>  (bl)
 * PPC_INS_BTLA     - cond, link, absolute  =>  (bla)
 * PPC_INS_BTLRL    - cond, link, toLR      =>  (blrl)
 * PPC_INS_BTCTRL   - cond, link, toCTR     =>  (bctrl)
 *
 * Branch if condition false:
 * Not sure if these are ever used, looks like they are translated to:
 * (b, ba, blr, bctr, bl, bla, blrl, bctrl) reversed conditions.
 * PPC_INS_BF       - cond                  =>  (b)
 * PPC_INS_BFA      - cond, absolute        =>  (ba)
 * PPC_INS_BFLR     - cond, toLR            =>  (blr)
 * PPC_INS_BFCTR    - cond, toCTR           =>  (bctr)
 * PPC_INS_BFL      - cond, link            =>  (bl)
 * PPC_INS_BFLA     - cond, link, absolute  =>  (bla)
 * PPC_INS_BFLRL    - cond, link, toLR      =>  (blrl)
 * PPC_INS_BFCTRL   - cond, link, toCTR     =>  (bctrl)
 *
 * Decrement CTR, branch if CTR != 0:
 * PPC_INS_BDNZ     - cond
 * PPC_INS_BDNZA    - cond, absolute
 * PPC_INS_BDNZLR   - cond, toLR
 * PPC_INS_BDNZL    - cond, link
 * PPC_INS_BDNZLA   - cond, absolute, link
 * PPC_INS_BDNZLRL  - cond, link, toLR
 *
 * Decrement CTR, branch if CTR != 0 & cond true:
 * PPC_INS_BDNZT    - cond
 * PPC_INS_BDNZTA   - cond, absolute
 * PPC_INS_BDNZTLR  - cond, toLR
 * PPC_INS_BDNZTL   - cond, link
 * PPC_INS_BDNZTLA  - cond, absolute, link
 * PPC_INS_BDNZTLRL - cond, link, toLR
 *
 * Decrement CTR, branch if CTR != 0 & cond false:
 * PPC_INS_BDNZF    - cond
 * PPC_INS_BDNZFA   - cond, absolute
 * PPC_INS_BDNZFLR  - cond, toLR, (missing)
 * PPC_INS_BDNZFL   - cond, link
 * PPC_INS_BDNZFLA  - cond, ansolute, link
 * PPC_INS_BDNZFLRL - cond, link, toLR
 *
 * Decrement CTR, branch if CTR == 0:
 * PPC_INS_BDZ      - cond
 * PPC_INS_BDZA     - cond, absolute
 * PPC_INS_BDZLR    - cond, toLR
 * PPC_INS_BDZL     - cond, link
 * PPC_INS_BDZLA    - cond, absolute, link
 * PPC_INS_BDZLRL   - cond, link, toLR
 *
 * Decrement CTR, branch if CTR == 0 & cond true:
 * PPC_INS_BDZT     - cond
 * PPC_INS_BDZTA    - cond, absolute
 * PPC_INS_BDZTLR   - cond, toLR
 * PPC_INS_BDZTL    - cond, link
 * PPC_INS_BDZTLA   - cond, absolute, link
 * PPC_INS_BDZTLRL  - cond, link, toLR
 *
 * Decrement CTR, branch if CTR == 0 & cond false:
 * PPC_INS_BDZF     - cond
 * PPC_INS_BDZFA    - cond, absolute
 * PPC_INS_BDZFLR   - cond, toLR
 * PPC_INS_BDZFL    - cond, link
 * PPC_INS_BDZFLA   - cond, absolute, link
 * PPC_INS_BDZFLRL  - cond, link, toLR
 */
void Capstone2LlvmIrTranslatorPowerpc_impl::translateB(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
{
	// Link.
	//
	static std::set<unsigned int> linkIds =
	{
			PPC_INS_BL, PPC_INS_BLA,
			PPC_INS_BCL, PPC_INS_BCLA, PPC_INS_BCLRL, PPC_INS_BCCTRL,
			PPC_INS_BLRL, PPC_INS_BCTRL,
			PPC_INS_BTL, PPC_INS_BTLA, PPC_INS_BTLRL, PPC_INS_BTCTRL,
			PPC_INS_BFL, PPC_INS_BFLA, PPC_INS_BFLRL, PPC_INS_BFCTRL,

			PPC_INS_BDNZL, PPC_INS_BDNZLA, PPC_INS_BDNZLRL,
			PPC_INS_BDNZTL, PPC_INS_BDNZTLA, PPC_INS_BDNZTLRL,
			PPC_INS_BDNZFL, PPC_INS_BDNZFLA, PPC_INS_BDNZFLRL,

			PPC_INS_BDZL, PPC_INS_BDZLA, PPC_INS_BDZLRL,
			PPC_INS_BDZTL, PPC_INS_BDZTLA, PPC_INS_BDZTLRL,
			PPC_INS_BDZFL, PPC_INS_BDZFLA, PPC_INS_BDZFLRL,
	};
	bool link = linkIds.count(i->id);

	// toLR.
	//
	static std::set<unsigned int> toLRIds =
	{
			PPC_INS_BCLR, PPC_INS_BCLRL,
			PPC_INS_BLR, PPC_INS_BLRL,
			PPC_INS_BTLR, PPC_INS_BTLRL,
			PPC_INS_BFLR, PPC_INS_BFLRL,

			PPC_INS_BDNZLR, PPC_INS_BDNZLRL,
			PPC_INS_BDNZTLR, PPC_INS_BDNZTLRL,
			PPC_INS_BDNZFLRL,

			PPC_INS_BDZLR, PPC_INS_BDZLRL,
			PPC_INS_BDZTLR, PPC_INS_BDZTLRL,
			PPC_INS_BDZFLR, PPC_INS_BDZFLRL,
	};
	bool toLR = toLRIds.count(i->id);

	// toCTR.
	//
	static std::set<unsigned int> toCTRIds =
	{
			PPC_INS_BCCTR, PPC_INS_BCCTRL,
			PPC_INS_BCTR, PPC_INS_BCTRL,
			PPC_INS_BTCTR, PPC_INS_BTCTRL,
			PPC_INS_BFCTR, PPC_INS_BFCTRL
	};
	bool toCTR = toCTRIds.count(i->id);

	// Reverse condition.
	//
	static std::set<unsigned int> reverseCondIds =
	{
			PPC_INS_BF, PPC_INS_BFA, PPC_INS_BFLR, PPC_INS_BFCTR,
			PPC_INS_BFL, PPC_INS_BFLA, PPC_INS_BFLRL, PPC_INS_BFCTRL,

			PPC_INS_BDNZF, PPC_INS_BDNZFA,
			PPC_INS_BDNZFL, PPC_INS_BDNZFLA, PPC_INS_BDNZFLRL,

			PPC_INS_BDZF, PPC_INS_BDZFA, PPC_INS_BDZFLR,
			PPC_INS_BDZFL, PPC_INS_BDZFLA, PPC_INS_BDZFLRL,
	};
	bool reverseCond = reverseCondIds.count(i->id);

	// Decrement CTR, branch if CTR != 0.
	//
	static std::set<unsigned int> ctrNonzeroCondIds =
	{
			PPC_INS_BDNZ, PPC_INS_BDNZA, PPC_INS_BDNZLR,
			PPC_INS_BDNZL, PPC_INS_BDNZLA, PPC_INS_BDNZLRL,

			PPC_INS_BDNZT, PPC_INS_BDNZTA, PPC_INS_BDNZTLR,
			PPC_INS_BDNZTL, PPC_INS_BDNZTLA, PPC_INS_BDNZTLRL,

			PPC_INS_BDNZF, PPC_INS_BDNZFA,
			PPC_INS_BDNZFL, PPC_INS_BDNZFLA, PPC_INS_BDNZFLRL,
	};
	bool ctrNonzero = ctrNonzeroCondIds.count(i->id);

	// Decrement CTR, branch if CTR == 0.
	//
	static std::set<unsigned int> ctrZeroCondIds =
	{
			PPC_INS_BDZ, PPC_INS_BDZA, PPC_INS_BDZLR,
			PPC_INS_BDZL, PPC_INS_BDZLA, PPC_INS_BDZLRL,

			PPC_INS_BDZT, PPC_INS_BDZTA, PPC_INS_BDZTLR,
			PPC_INS_BDZTL, PPC_INS_BDZTLA, PPC_INS_BDZTLRL,

			PPC_INS_BDZF, PPC_INS_BDZFA, PPC_INS_BDZFLR,
			PPC_INS_BDZFL, PPC_INS_BDZFLA, PPC_INS_BDZFLRL,
	};
	bool ctrZero = ctrZeroCondIds.count(i->id);

	// Decrement CTR, and condition.
	//
	static std::set<unsigned int> ctrAndCondIds =
	{
			PPC_INS_BDNZT, PPC_INS_BDNZTA, PPC_INS_BDNZTLR,
			PPC_INS_BDNZTL, PPC_INS_BDNZTLA, PPC_INS_BDNZTLRL,

			PPC_INS_BDNZF, PPC_INS_BDNZFA,
			PPC_INS_BDNZFL, PPC_INS_BDNZFLA, PPC_INS_BDNZFLRL,

			PPC_INS_BDZT, PPC_INS_BDZTA, PPC_INS_BDZTLR,
			PPC_INS_BDZTL, PPC_INS_BDZTLA, PPC_INS_BDZTLRL,

			PPC_INS_BDZF, PPC_INS_BDZFA, PPC_INS_BDZFLR,
			PPC_INS_BDZFL, PPC_INS_BDZFLA, PPC_INS_BDZFLRL,
	};
	bool ctrAndCond = ctrAndCondIds.count(i->id);

	// Get target and CR register.
	//
	llvm::Value* target = nullptr;
	uint32_t crReg = PPC_REG_CR0;
	ppc_bc crBc = pi->bc;

	// TODO: Special handling because of Capstone bug:
	// https://github.com/aquynh/capstone/issues/968
	if (i->id == PPC_INS_BDZLA)
	{
		assert(pi->op_count == 1);
		assert(pi->operands[0].type == PPC_OP_IMM);

		target = llvm::ConstantInt::get(getDefaultType(), pi->operands[0].imm - i->address);
	}
	else if (toLR)
	{
		target = loadRegister(PPC_REG_LR, irb);

		if (pi->op_count == 0)
		{
			crReg = PPC_REG_CR0;
		}
		else if (pi->op_count == 1
				&& pi->operands[0].type == PPC_OP_CRX)
		{
			crReg = pi->operands[0].crx.reg;
			crBc = pi->operands[0].crx.cond;
		}
		else if (pi->op_count == 1
				&& isCrRegister(pi->operands[0]))
		{
			crReg = pi->operands[0].reg;
		}
		else
		{
			assert(false && "unhandled branch instruction format");
			return;
		}
	}
	else if (toCTR)
	{
		target = loadRegister(PPC_REG_CTR, irb);

		if (pi->op_count == 0)
		{
			crReg = PPC_REG_CR0;
		}
		else if (pi->op_count == 1
				&& pi->operands[0].type == PPC_OP_CRX)
		{
			crReg = pi->operands[0].crx.reg;
			crBc = pi->operands[0].crx.cond;
		}
		else if (pi->op_count == 1
				&& isCrRegister(pi->operands[0]))
		{
			crReg = pi->operands[0].reg;
		}
		else
		{
			assert(false && "unhandled branch instruction format");
			return;
		}
	}
	else
	{
		if (pi->op_count == 1
				&& pi->operands[0].type == PPC_OP_IMM)
		{
			crReg = PPC_REG_CR0;
			target = loadOpUnary(pi, irb);
		}
		else if (pi->op_count == 2
				&& pi->operands[0].type == PPC_OP_CRX
				&& pi->operands[1].type == PPC_OP_IMM)
		{
			crReg = pi->operands[0].crx.reg;
			crBc = pi->operands[0].crx.cond;
			target = loadOpBinaryOp1(pi, irb);
		}
		else if (pi->op_count == 2
				&& isCrRegister(pi->operands[0])
				&& pi->operands[1].type == PPC_OP_IMM)
		{
			crReg = pi->operands[0].reg;
			target = loadOpBinaryOp1(pi, irb);
		}
		// capstone-dumper -a ppc -m 32 -e big -c "40 b1 00 00"
		// Has only one operand = cr4.
		// IDA: 10003F80: 40 B1 00 00        ble+ cr4, loc_10003F80
		// Branches to itself.
		// TODO: Maybe report to Capstone as a bug, there should be a parameter,
		// even when relative branch to zero == itself.
		//
		else if (pi->op_count == 1
				&& isCrRegister(pi->operands[0]))
		{
			crReg = pi->operands[0].reg;
			target = getThisInsnAddress(i);
		}
		// The same with PPC_OP_CRX - one operand of this type.
		// capstone-dumper -a ppc -m 32 -e big -c "40 02 00 00"
		// IDA: 00017E24: 40 02 00 00        bdnzf eq, loc_17E24
		//
		else if (pi->op_count == 1
				&& pi->operands[0].type == PPC_OP_CRX)
		{
			crReg = pi->operands[0].crx.reg;
			crBc = pi->operands[0].crx.cond;
			target = getThisInsnAddress(i);
		}
		// The same without parameters.
		// IDA: 000383B8: 43 53 00 00        bc 26, 4*cr4+so, loc_383B8
		//
		else if (pi->op_count == 0)
		{
			crReg = PPC_REG_CR0;
			target = getThisInsnAddress(i);
		}
		else
		{
			assert(false && "unhandled branch instruction format");
			return;
		}
	}

	if (target == nullptr)
	{
		return; // TODO: assert? exception?
	}

	// Store to LR, right before branch generation.
	//
	if (link)
	{
		storeRegister(PPC_REG_LR, getNextInsnAddress(i), irb);
	}

	// Unconditional branch.
	//
	if (crBc == PPC_BC_INVALID
			&& !ctrNonzero
			&& !ctrZero)
	{
		if (toLR)
		{
			if (link)
			{
				generateBranchFunctionCall(irb, target);
			}
			else
			{
				generateReturnFunctionCall(irb, target);
			}
		}
		else if (toCTR)
		{
			if (link)
			{
				// TODO: It is probably not guaranteed that this is function call,
				// but if we use generateBranchFunctionCall(), decoder will not follow
				// to the next address after branch.
				// This should be done for all LR updating branches?
				// The best would be if decoder could try next block even if branch
				// was simple unconditional.
				generateCallFunctionCall(irb, target);
			}
			else
			{
				generateBranchFunctionCall(irb, target);
			}
		}
		else if (link)
		{
			generateCallFunctionCall(irb, target);
		}
		else
		{
			generateBranchFunctionCall(irb, target);
		}
		return;
	}

	// Conditional branch.
	//
	llvm::Value* condCtr = nullptr;
	llvm::Value* condCr = nullptr;
	if (ctrNonzero || ctrZero)
	{
		auto* ctr = loadRegister(PPC_REG_CTR, irb);
		ctr = irb.CreateSub(ctr, llvm::ConstantInt::get(ctr->getType(), 1));
		storeRegister(PPC_REG_CTR, ctr, irb);

		if (ctrNonzero)
		{
			condCtr = irb.CreateICmpNE(ctr, llvm::ConstantInt::get(ctr->getType(), 0));
		}
		else if (ctrZero)
		{
			condCtr = irb.CreateICmpEQ(ctr, llvm::ConstantInt::get(ctr->getType(), 0));
		}
	}

	if (ctrAndCond || !(ctrNonzero || ctrZero))
	{
		switch (crBc)
		{
			case PPC_BC_LT:
				condCr = loadCrX(irb, crReg, PPC_CR_LT);
				break;
			case PPC_BC_LE:
				condCr = irb.CreateOr(
						loadCrX(irb, crReg, PPC_CR_LT),
						loadCrX(irb, crReg, PPC_CR_EQ));
				break;
			case PPC_BC_EQ:
				condCr = loadCrX(irb, crReg, PPC_CR_EQ);
				break;
			case PPC_BC_GE:
				condCr = irb.CreateOr(
						loadCrX(irb, crReg, PPC_CR_GT),
						loadCrX(irb, crReg, PPC_CR_EQ));
				break;
			case PPC_BC_GT:
				condCr = loadCrX(irb, crReg, PPC_CR_GT);
				break;
			case PPC_BC_NE:
				condCr = irb.CreateNot(loadCrX(irb, crReg, PPC_CR_EQ));
				break;
			case PPC_BC_UN:
				// FP cmp use SO as FU = floating-point unordered.
				condCr = loadCrX(irb, crReg, PPC_CR_SO);
				break;
			case PPC_BC_NU:
				condCr = irb.CreateNot(loadCrX(irb, crReg, PPC_CR_SO));
				break;
			case PPC_BC_SO:
				condCr = loadCrX(irb, crReg, PPC_CR_SO);
				break;
			case PPC_BC_NS:
				condCr = irb.CreateNot(loadCrX(irb, crReg, PPC_CR_SO));
				break;
			case PPC_BC_INVALID: // Already handled, should not get here.
			default:
				assert(false && "unhandled branch condidition");
				break;
		}

		if (reverseCond)
		{
			condCr = irb.CreateICmpEQ(condCr, irb.getFalse());
		}
	}

	llvm::Value* cond = nullptr;
	if (condCtr && condCr == nullptr)
	{
		cond = condCtr;
	}
	else if (condCr && condCtr == nullptr)
	{
		cond = condCr;
	}
	else if (condCtr && condCr)
	{
		cond = irb.CreateAnd(condCtr, condCr);
	}
	else
	{
		return; // TODO: assert? exception?
	}

	if (toLR)
	{
		generateCondReturnFunctionCall(irb, cond, target);
	}
	else if (toCTR)
	{
		// TODO: Some combos (e.g. with link) could be cond function calls.
		generateCondBranchFunctionCall(irb, cond, target);
	}
	else if (link)
	{
		// TODO: Conditional function call?
		generateCondBranchFunctionCall(irb, cond, target);
	}
	else
	{
		generateCondBranchFunctionCall(irb, cond, target);
	}
}

 void Capstone2LlvmIrTranslatorPowerpc_impl::translateASSERT(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb)
 {
 //	std::cout << std::hex << i->address << " @ " << i->mnemonic << " " << i->op_str << std::endl;
 	assert(false);
 }

} // namespace capstone2llvmir
} // namespace retdec
