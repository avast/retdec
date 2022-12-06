/**
 * @file src/capstone2llvmir/arm64/arm64.cpp
 * @brief ARM64 implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <iomanip>

#include "retdec/utils/io/log.h"

#include "capstone2llvmir/arm64/arm64_impl.h"

using namespace retdec::utils::io;

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

//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//

bool Capstone2LlvmIrTranslatorArm64_impl::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_ARM;
}

bool Capstone2LlvmIrTranslatorArm64_impl::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN || m == CS_MODE_BIG_ENDIAN;
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
	initializeRegistersParentMap();
}

void Capstone2LlvmIrTranslatorArm64_impl::generateDataLayout()
{
	// clang -x c /dev/null -emit-llvm -S -o -
	_module->setDataLayout("e-m:e-i64:64-i128:128-n32:64-S128");
}

void Capstone2LlvmIrTranslatorArm64_impl::generateRegisters()
{
	// FP&SIMD registers
	createRegister(ARM64_REG_V0, _regLt);
	createRegister(ARM64_REG_V1, _regLt);
	createRegister(ARM64_REG_V2, _regLt);
	createRegister(ARM64_REG_V3, _regLt);
	createRegister(ARM64_REG_V4, _regLt);
	createRegister(ARM64_REG_V5, _regLt);
	createRegister(ARM64_REG_V6, _regLt);
	createRegister(ARM64_REG_V7, _regLt);
	createRegister(ARM64_REG_V8, _regLt);
	createRegister(ARM64_REG_V9, _regLt);
	createRegister(ARM64_REG_V10, _regLt);
	createRegister(ARM64_REG_V11, _regLt);
	createRegister(ARM64_REG_V12, _regLt);
	createRegister(ARM64_REG_V13, _regLt);
	createRegister(ARM64_REG_V14, _regLt);
	createRegister(ARM64_REG_V15, _regLt);
	createRegister(ARM64_REG_V16, _regLt);
	createRegister(ARM64_REG_V17, _regLt);
	createRegister(ARM64_REG_V18, _regLt);
	createRegister(ARM64_REG_V19, _regLt);
	createRegister(ARM64_REG_V20, _regLt);
	createRegister(ARM64_REG_V21, _regLt);
	createRegister(ARM64_REG_V22, _regLt);
	createRegister(ARM64_REG_V23, _regLt);
	createRegister(ARM64_REG_V24, _regLt);
	createRegister(ARM64_REG_V25, _regLt);
	createRegister(ARM64_REG_V26, _regLt);
	createRegister(ARM64_REG_V27, _regLt);
	createRegister(ARM64_REG_V28, _regLt);
	createRegister(ARM64_REG_V29, _regLt);
	createRegister(ARM64_REG_V30, _regLt);
	createRegister(ARM64_REG_V31, _regLt);

	createRegister(ARM64_REG_Q0, _regLt);
	createRegister(ARM64_REG_Q1, _regLt);
	createRegister(ARM64_REG_Q2, _regLt);
	createRegister(ARM64_REG_Q3, _regLt);
	createRegister(ARM64_REG_Q4, _regLt);
	createRegister(ARM64_REG_Q5, _regLt);
	createRegister(ARM64_REG_Q6, _regLt);
	createRegister(ARM64_REG_Q7, _regLt);
	createRegister(ARM64_REG_Q8, _regLt);
	createRegister(ARM64_REG_Q9, _regLt);
	createRegister(ARM64_REG_Q10, _regLt);
	createRegister(ARM64_REG_Q11, _regLt);
	createRegister(ARM64_REG_Q12, _regLt);
	createRegister(ARM64_REG_Q13, _regLt);
	createRegister(ARM64_REG_Q14, _regLt);
	createRegister(ARM64_REG_Q15, _regLt);
	createRegister(ARM64_REG_Q16, _regLt);
	createRegister(ARM64_REG_Q17, _regLt);
	createRegister(ARM64_REG_Q18, _regLt);
	createRegister(ARM64_REG_Q19, _regLt);
	createRegister(ARM64_REG_Q20, _regLt);
	createRegister(ARM64_REG_Q21, _regLt);
	createRegister(ARM64_REG_Q22, _regLt);
	createRegister(ARM64_REG_Q23, _regLt);
	createRegister(ARM64_REG_Q24, _regLt);
	createRegister(ARM64_REG_Q25, _regLt);
	createRegister(ARM64_REG_Q26, _regLt);
	createRegister(ARM64_REG_Q27, _regLt);
	createRegister(ARM64_REG_Q28, _regLt);
	createRegister(ARM64_REG_Q29, _regLt);
	createRegister(ARM64_REG_Q30, _regLt);
	createRegister(ARM64_REG_Q31, _regLt);

	createRegister(ARM64_REG_D0, _regLt);
	createRegister(ARM64_REG_D1, _regLt);
	createRegister(ARM64_REG_D2, _regLt);
	createRegister(ARM64_REG_D3, _regLt);
	createRegister(ARM64_REG_D4, _regLt);
	createRegister(ARM64_REG_D5, _regLt);
	createRegister(ARM64_REG_D6, _regLt);
	createRegister(ARM64_REG_D7, _regLt);
	createRegister(ARM64_REG_D8, _regLt);
	createRegister(ARM64_REG_D9, _regLt);
	createRegister(ARM64_REG_D10, _regLt);
	createRegister(ARM64_REG_D11, _regLt);
	createRegister(ARM64_REG_D12, _regLt);
	createRegister(ARM64_REG_D13, _regLt);
	createRegister(ARM64_REG_D14, _regLt);
	createRegister(ARM64_REG_D15, _regLt);
	createRegister(ARM64_REG_D16, _regLt);
	createRegister(ARM64_REG_D17, _regLt);
	createRegister(ARM64_REG_D18, _regLt);
	createRegister(ARM64_REG_D19, _regLt);
	createRegister(ARM64_REG_D20, _regLt);
	createRegister(ARM64_REG_D21, _regLt);
	createRegister(ARM64_REG_D22, _regLt);
	createRegister(ARM64_REG_D23, _regLt);
	createRegister(ARM64_REG_D24, _regLt);
	createRegister(ARM64_REG_D25, _regLt);
	createRegister(ARM64_REG_D26, _regLt);
	createRegister(ARM64_REG_D27, _regLt);
	createRegister(ARM64_REG_D28, _regLt);
	createRegister(ARM64_REG_D29, _regLt);
	createRegister(ARM64_REG_D30, _regLt);
	createRegister(ARM64_REG_D31, _regLt);

	createRegister(ARM64_REG_S0, _regLt);
	createRegister(ARM64_REG_S1, _regLt);
	createRegister(ARM64_REG_S2, _regLt);
	createRegister(ARM64_REG_S3, _regLt);
	createRegister(ARM64_REG_S4, _regLt);
	createRegister(ARM64_REG_S5, _regLt);
	createRegister(ARM64_REG_S6, _regLt);
	createRegister(ARM64_REG_S7, _regLt);
	createRegister(ARM64_REG_S8, _regLt);
	createRegister(ARM64_REG_S9, _regLt);
	createRegister(ARM64_REG_S10, _regLt);
	createRegister(ARM64_REG_S11, _regLt);
	createRegister(ARM64_REG_S12, _regLt);
	createRegister(ARM64_REG_S13, _regLt);
	createRegister(ARM64_REG_S14, _regLt);
	createRegister(ARM64_REG_S15, _regLt);
	createRegister(ARM64_REG_S16, _regLt);
	createRegister(ARM64_REG_S17, _regLt);
	createRegister(ARM64_REG_S18, _regLt);
	createRegister(ARM64_REG_S19, _regLt);
	createRegister(ARM64_REG_S20, _regLt);
	createRegister(ARM64_REG_S21, _regLt);
	createRegister(ARM64_REG_S22, _regLt);
	createRegister(ARM64_REG_S23, _regLt);
	createRegister(ARM64_REG_S24, _regLt);
	createRegister(ARM64_REG_S25, _regLt);
	createRegister(ARM64_REG_S26, _regLt);
	createRegister(ARM64_REG_S27, _regLt);
	createRegister(ARM64_REG_S28, _regLt);
	createRegister(ARM64_REG_S29, _regLt);
	createRegister(ARM64_REG_S30, _regLt);
	createRegister(ARM64_REG_S31, _regLt);

	createRegister(ARM64_REG_H0, _regLt);
	createRegister(ARM64_REG_H1, _regLt);
	createRegister(ARM64_REG_H2, _regLt);
	createRegister(ARM64_REG_H3, _regLt);
	createRegister(ARM64_REG_H4, _regLt);
	createRegister(ARM64_REG_H5, _regLt);
	createRegister(ARM64_REG_H6, _regLt);
	createRegister(ARM64_REG_H7, _regLt);
	createRegister(ARM64_REG_H8, _regLt);
	createRegister(ARM64_REG_H9, _regLt);
	createRegister(ARM64_REG_H10, _regLt);
	createRegister(ARM64_REG_H11, _regLt);
	createRegister(ARM64_REG_H12, _regLt);
	createRegister(ARM64_REG_H13, _regLt);
	createRegister(ARM64_REG_H14, _regLt);
	createRegister(ARM64_REG_H15, _regLt);
	createRegister(ARM64_REG_H16, _regLt);
	createRegister(ARM64_REG_H17, _regLt);
	createRegister(ARM64_REG_H18, _regLt);
	createRegister(ARM64_REG_H19, _regLt);
	createRegister(ARM64_REG_H20, _regLt);
	createRegister(ARM64_REG_H21, _regLt);
	createRegister(ARM64_REG_H22, _regLt);
	createRegister(ARM64_REG_H23, _regLt);
	createRegister(ARM64_REG_H24, _regLt);
	createRegister(ARM64_REG_H25, _regLt);
	createRegister(ARM64_REG_H26, _regLt);
	createRegister(ARM64_REG_H27, _regLt);
	createRegister(ARM64_REG_H28, _regLt);
	createRegister(ARM64_REG_H29, _regLt);
	createRegister(ARM64_REG_H30, _regLt);
	createRegister(ARM64_REG_H31, _regLt);

	createRegister(ARM64_REG_B0, _regLt);
	createRegister(ARM64_REG_B1, _regLt);
	createRegister(ARM64_REG_B2, _regLt);
	createRegister(ARM64_REG_B3, _regLt);
	createRegister(ARM64_REG_B4, _regLt);
	createRegister(ARM64_REG_B5, _regLt);
	createRegister(ARM64_REG_B6, _regLt);
	createRegister(ARM64_REG_B7, _regLt);
	createRegister(ARM64_REG_B8, _regLt);
	createRegister(ARM64_REG_B9, _regLt);
	createRegister(ARM64_REG_B10, _regLt);
	createRegister(ARM64_REG_B11, _regLt);
	createRegister(ARM64_REG_B12, _regLt);
	createRegister(ARM64_REG_B13, _regLt);
	createRegister(ARM64_REG_B14, _regLt);
	createRegister(ARM64_REG_B15, _regLt);
	createRegister(ARM64_REG_B16, _regLt);
	createRegister(ARM64_REG_B17, _regLt);
	createRegister(ARM64_REG_B18, _regLt);
	createRegister(ARM64_REG_B19, _regLt);
	createRegister(ARM64_REG_B20, _regLt);
	createRegister(ARM64_REG_B21, _regLt);
	createRegister(ARM64_REG_B22, _regLt);
	createRegister(ARM64_REG_B23, _regLt);
	createRegister(ARM64_REG_B24, _regLt);
	createRegister(ARM64_REG_B25, _regLt);
	createRegister(ARM64_REG_B26, _regLt);
	createRegister(ARM64_REG_B27, _regLt);
	createRegister(ARM64_REG_B28, _regLt);
	createRegister(ARM64_REG_B29, _regLt);
	createRegister(ARM64_REG_B30, _regLt);
	createRegister(ARM64_REG_B31, _regLt);

	// General purpose registers
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

	// Special registers.

	// FP Frame pointer.
	createRegister(ARM64_REG_X29, _regLt);

	// LP Link register.
	createRegister(ARM64_REG_X30, _regLt);

	// Stack pointer.
	createRegister(ARM64_REG_SP, _regLt);

	// Create system & flag registers in this loop
	for (const auto& r : _reg2name)
	{
		createRegister(r.first, _regLt);
	}

}

uint32_t Capstone2LlvmIrTranslatorArm64_impl::getCarryRegister()
{
	return ARM64_REG_CPSR_C;
}

void Capstone2LlvmIrTranslatorArm64_impl::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	_insn = i;

	cs_detail* d = i->detail;
	cs_arm64* ai = &d->arm64;

	//std::cout << i->mnemonic << " " << i->op_str << std::endl;

	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;

		(this->*f)(i, ai, irb);
	}
	else
	{
		generatePseudoInstruction(i, ai, irb);
	}
}

uint32_t Capstone2LlvmIrTranslatorArm64_impl::getParentRegister(uint32_t r) const
{
	try {
		return _reg2parentMap.at(r);
	}
	catch (std::out_of_range &e)
	{
		return r;
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
			i->address + i->size);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::extractVectorValue(
		llvm::IRBuilder<>& irb,
		cs_arm64_op& op,
		llvm::Value* val)
{
	if (val->getType() != llvm::IntegerType::getInt128Ty(_module->getContext()))
	{
		return val;
	}

	// Vector element size specifier
	switch(op.vas)
	{
		case ARM64_VAS_16B:
		case ARM64_VAS_8B :
		case ARM64_VAS_4B :
		case ARM64_VAS_1B :
			val = irb.CreateLShr(val, llvm::ConstantInt::get(val->getType(), 8 * op.vector_index));
			return irb.CreateZExtOrTrunc(val, llvm::IntegerType::getInt8Ty(_module->getContext()));
		case ARM64_VAS_8H:
		case ARM64_VAS_4H:
		case ARM64_VAS_2H:
		case ARM64_VAS_1H:
			val = irb.CreateLShr(val, llvm::ConstantInt::get(val->getType(), 16 * op.vector_index));
			return irb.CreateZExtOrTrunc(val, llvm::IntegerType::getInt16Ty(_module->getContext()));
		case ARM64_VAS_4S:
		case ARM64_VAS_2S:
		case ARM64_VAS_1S:
			val = irb.CreateLShr(val, llvm::ConstantInt::get(val->getType(), 32 * op.vector_index));
			val = irb.CreateZExtOrTrunc(val, llvm::IntegerType::getInt32Ty(_module->getContext()));
			return irb.CreateBitCast(val, llvm::Type::getFloatTy(_module->getContext()));
		case ARM64_VAS_1D:
			val = irb.CreateLShr(val, llvm::ConstantInt::get(val->getType(), 64 * op.vector_index));
			val = irb.CreateZExtOrTrunc(val, llvm::IntegerType::getInt64Ty(_module->getContext()));
			return irb.CreateBitCast(val, llvm::Type::getDoubleTy(_module->getContext()));
		case ARM64_VAS_1Q:
			val = irb.CreateLShr(val, llvm::ConstantInt::get(val->getType(), 128 * op.vector_index));
			val = irb.CreateZExtOrTrunc(val, llvm::IntegerType::getInt128Ty(_module->getContext()));
			return irb.CreateBitCast(val, llvm::Type::getFP128Ty(_module->getContext()));
		case ARM64_VAS_INVALID:
			return val;
		default:
			throw GenericError("Arm64: extractVectorValue(): Unknown VESS type");
	}

	return val;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateOperandExtension(
		llvm::IRBuilder<>& irb,
		arm64_extender ext,
		llvm::Value* val,
		llvm::Type* destType)
{
	auto* i8  = llvm::IntegerType::getInt8Ty(_module->getContext());
	auto* i16 = llvm::IntegerType::getInt16Ty(_module->getContext());
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());

	auto* ty  = destType ? destType : getDefaultType();

	llvm::Value* trunc = nullptr;
	switch(ext)
	{
		case ARM64_EXT_INVALID:
		{
			return val;
		}
		case ARM64_EXT_UXTB:
		{
			trunc = irb.CreateTrunc(val, i8);
			return irb.CreateZExt(trunc, ty);
		}
		case ARM64_EXT_UXTH:
		{
			trunc = irb.CreateTrunc(val, i16);
			return irb.CreateZExt(trunc, ty);
		}
		case ARM64_EXT_UXTW:
		{
			trunc = irb.CreateTrunc(val, i32);
			return irb.CreateZExt(trunc, ty);
		}
		case ARM64_EXT_UXTX:
		{
			trunc = irb.CreateTrunc(val, i32);
			return irb.CreateZExt(trunc, ty);
		}
		case ARM64_EXT_SXTB:
		{
			trunc = irb.CreateTrunc(val, i8);
			return irb.CreateSExt(trunc, ty);
		}
		case ARM64_EXT_SXTH:
		{
			trunc = irb.CreateTrunc(val, i16);
			return irb.CreateSExt(trunc, ty);
		}
		case ARM64_EXT_SXTW:
		{
			trunc = irb.CreateTrunc(val, i32);
			return irb.CreateSExt(trunc, ty);
		}
		case ARM64_EXT_SXTX:
		{
			trunc = irb.CreateTrunc(val, i32);
			return irb.CreateSExt(trunc, ty);
		}
		default:
			throw GenericError("Arm64: generateOperandExtension(): Unsupported extension type");
	}
	return val;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateOperandShift(
		llvm::IRBuilder<>& irb,
		cs_arm64_op& op,
		llvm::Value* val,
		bool updateFlags)
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
		throw GenericError("generateOperandShift(): nullptr shift value");
	}

	n = irb.CreateZExtOrTrunc(n, val->getType());

	switch (op.shift.type)
	{
		case ARM64_SFT_ASR:
		{
			return generateShiftAsr(irb, val, n, updateFlags);
		}
		case ARM64_SFT_LSL:
		{
			return generateShiftLsl(irb, val, n, updateFlags);
		}
		case ARM64_SFT_LSR:
		{
			return generateShiftLsr(irb, val, n, updateFlags);
		}
		case ARM64_SFT_ROR:
		{
			return generateShiftRor(irb, val, n, updateFlags);
		}
		case ARM64_SFT_MSL:
		{
			return generateShiftMsl(irb, val, n, updateFlags);
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
		llvm::Value *n,
		bool updateFlags)
{
	if (updateFlags)
	{
		auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
		auto* cfShl = irb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
		auto* cfAnd = irb.CreateAnd(cfShl, val);
		auto* cfIcmp = irb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
		storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);
	}
	return irb.CreateAShr(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftLsl(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value *n,
		bool updateFlags)
{
	if (updateFlags)
	{
		auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
		auto* cfShl = irb.CreateShl(val, cfOp1);
		auto* cfIntT = llvm::cast<llvm::IntegerType>(cfShl->getType());
		auto* cfRightCount = llvm::ConstantInt::get(cfIntT, cfIntT->getBitWidth() - 1);
		auto* cfLow = irb.CreateLShr(cfShl, cfRightCount);
		storeRegister(ARM64_REG_CPSR_C, cfLow, irb);
	}
	return irb.CreateShl(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftLsr(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value *n,
		bool updateFlags)
{
	if (updateFlags)
	{
		auto* cfOp1 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
		auto* cfShl = irb.CreateShl(llvm::ConstantInt::get(cfOp1->getType(), 1), cfOp1);
		auto* cfAnd = irb.CreateAnd(cfShl, val);
		auto* cfIcmp = irb.CreateICmpNE(cfAnd, llvm::ConstantInt::get(cfAnd->getType(), 0));
		storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);
	}

	return irb.CreateLShr(val, n);
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftRor(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value *n,
		bool updateFlags)
{
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(n->getType())->getBitWidth();

	auto* srl = irb.CreateLShr(val, n);
	auto* sub = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW), n);
	auto* shl = irb.CreateShl(val, sub);
	auto* orr = irb.CreateOr(srl, shl);
	if (updateFlags)
	{

		auto* cfSrl = irb.CreateLShr(orr, llvm::ConstantInt::get(orr->getType(), op0BitW - 1));
		auto* cfIcmp = irb.CreateICmpNE(cfSrl, llvm::ConstantInt::get(cfSrl->getType(), 0));
		storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);
	}

	return orr;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateShiftMsl(
		llvm::IRBuilder<>& irb,
		llvm::Value* val,
		llvm::Value *n,
		bool updateFlags)
{
	return val;
// 	unsigned op0BitW = llvm::cast<llvm::IntegerType>(n->getType())->getBitWidth();
// 	auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);

// 	auto* cf = loadRegister(ARM64_REG_CPSR_C, irb);
// 	cf = irb.CreateZExtOrTrunc(cf, n->getType());

// 	auto* srl = irb.CreateLShr(val, n);
// 	auto* srlZext = irb.CreateZExt(srl, doubleT);
// 	auto* op0Zext = irb.CreateZExt(val, doubleT);
// 	auto* sub = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW + 1), n);
// 	auto* subZext = irb.CreateZExt(sub, doubleT);
// 	auto* shl = irb.CreateShl(op0Zext, subZext);
// 	auto* sub2 = irb.CreateSub(llvm::ConstantInt::get(n->getType(), op0BitW), n);
// 	auto* shl2 = irb.CreateShl(cf, sub2);
// 	auto* shl2Zext = irb.CreateZExt(shl2, doubleT);
// 	auto* or1 = irb.CreateOr(shl, srlZext);
// 	auto* or2 = irb.CreateOr(or1, shl2Zext);
// 	auto* or2Trunc = irb.CreateTrunc(or2, val->getType());

// 	auto* sub3 = irb.CreateSub(n, llvm::ConstantInt::get(n->getType(), 1));
// 	auto* shl3 = irb.CreateShl(llvm::ConstantInt::get(sub3->getType(), 1), sub3);
// 	auto* and1 = irb.CreateAnd(shl3, val);
// 	auto* cfIcmp = irb.CreateICmpNE(and1, llvm::ConstantInt::get(and1->getType(), 0));
// 	storeRegister(ARM64_REG_CPSR_C, cfIcmp, irb);

// 	return or2Trunc;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateGetOperandMemAddr(
		cs_arm64_op& op,
		llvm::IRBuilder<>& irb)
{
	auto* baseR = loadRegister(op.mem.base, irb);
	auto* t = baseR ? baseR->getType() : getDefaultType();
	llvm::Value* disp = op.mem.disp
			? llvm::ConstantInt::get(t, op.mem.disp)
			: nullptr;

	auto* idxR = loadRegister(op.mem.index, irb);
	if (idxR)
	{
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
	return addr;
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

	// There is no such instruction that can access PC, but in case
	// it happens somewhere in LLVM, we should be able to handle it.
	if (r == ARM64_REG_PC)
	{
		return getCurrentPc(_insn);
	}

	llvm::Type* rt = nullptr;
	try
	{
		rt = getRegisterType(r);
	}
	catch (GenericError &e)
	{
		// If we dont find the register type, try to recover from this returning at
		// least the number of register
		// Maybe solve this better
		Log::error() << e.what() << std::endl;
		return llvm::ConstantInt::get(dstType ? dstType : getDefaultType(), r);
	}

	if (r == ARM64_REG_XZR || r == ARM64_REG_WZR)
	{
		// Loads from XZR registers generate zero
		return llvm::ConstantInt::get(rt, 0);
	}

	auto pr = getParentRegister(r);
	auto* llvmReg = getRegister(pr);
	if (llvmReg == nullptr)
	{
		throw GenericError("loadRegister() unhandled reg.");
	}

	llvm::Value* ret = irb.CreateLoad(llvmReg);
	if (r != pr)
	{
		ret = irb.CreateTrunc(ret, rt);
	}

	ret = generateTypeConversion(irb, ret, dstType, ct);
	return ret;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::loadOp(
		cs_arm64_op& op,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty,
		bool lea)
{
	switch (op.type)
	{
		case ARM64_OP_PSTATE:
		case ARM64_OP_SYS:
		case ARM64_OP_REG_MRS:
		case ARM64_OP_REG_MSR:
		case ARM64_OP_REG:
		{
			auto* val = loadRegister(op.reg, irb);
			if (val == nullptr)
			{
				return llvm::UndefValue::get(ty ? ty : getDefaultType());
			}
			auto* vec = extractVectorValue(irb, op, val);
			auto* ext = generateOperandExtension(irb, op.ext, vec, ty);
			return generateOperandShift(irb, op, ext);
		}
		case ARM64_OP_IMM:
		{
			auto* val = llvm::ConstantInt::getSigned(getDefaultType(), op.imm);
			return generateOperandShift(irb, op, val);
		}
		case ARM64_OP_MEM:
		{
			auto* addr = generateGetOperandMemAddr(op, irb);

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
		case ARM64_OP_FP:
		{
			auto* val = llvm::ConstantFP::get(irb.getDoubleTy(), op.fp);
			return val;
		}
		case ARM64_OP_INVALID:
		case ARM64_OP_CIMM:
		case ARM64_OP_PREFETCH:
		case ARM64_OP_BARRIER:
		default:
		{
			return llvm::UndefValue::get(ty ? ty : getDefaultType());
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

	// Direct writes to PC are not supported, the intended way to alter control flow is to
	// use a branching instruction or exception, those will call pseudo llvm pseudo functions
	if (r == ARM64_REG_PC)
	{
		return nullptr;
	}

	if (r == ARM64_REG_XZR || r == ARM64_REG_WZR)
	{
		// When written the register discards the result
		return nullptr;
	}

	//auto* rt = getRegisterType(r);
	auto pr = getParentRegister(r);
	auto* llvmReg = getRegister(pr);
	if (llvmReg == nullptr)
	{
		// Maybe return xchg eax, eax?
		Log::error() << "storeRegister() unhandled reg." << std::endl;
		return nullptr;
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

llvm::Instruction* Capstone2LlvmIrTranslatorArm64_impl::storeOp(
		cs_arm64_op& op,
		llvm::Value* val,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	switch (op.type)
	{
		case ARM64_OP_PSTATE:
		case ARM64_OP_SYS:
		case ARM64_OP_REG:
		case ARM64_OP_REG_MRS:
		case ARM64_OP_REG_MSR:
		{
			return storeRegister(op.reg, val, irb, ct);
		}
		case ARM64_OP_MEM:
		{
			auto* addr = generateGetOperandMemAddr(op, irb);

			auto* pt = llvm::PointerType::get(val->getType(), 0);
			addr = irb.CreateIntToPtr(addr, pt);
			return irb.CreateStore(val, addr);
		}
		case ARM64_OP_INVALID:
		case ARM64_OP_IMM:
		{
			// This is here because some operands that are for example in post-index addressing mode
			// will have the write flag set and generic functions try to write to IMM, which is not correct
			// Maybe solve this better?
			return nullptr;
		}
		case ARM64_OP_FP:
		case ARM64_OP_CIMM:
		case ARM64_OP_PREFETCH:
		case ARM64_OP_BARRIER:
		default:
		{
			throw GenericError("storeOp(): unhandled operand type");
			return nullptr;
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateInsnConditionCode(
		llvm::IRBuilder<>& irb,
		cs_arm64* ai)
{
	switch (ai->cc)
	{
		// Equal = Zero set
		case ARM64_CC_EQ:
		{
			auto* z = loadRegister(ARM64_REG_CPSR_Z, irb);
			return z;
		}
		// Not equal = Zero clear
		case ARM64_CC_NE:
		{
			auto* z = loadRegister(ARM64_REG_CPSR_Z, irb);
			return generateValueNegate(irb, z);
		}
		// Unsigned higher or same = Carry set
		case ARM64_CC_HS:
		{
			auto* c = loadRegister(ARM64_REG_CPSR_C, irb);
			return c;
		}
		// Unsigned lower = Carry clear
		case ARM64_CC_LO:
		{
			auto* c = loadRegister(ARM64_REG_CPSR_C, irb);
			return generateValueNegate(irb, c);
		}
		// Negative = N set
		case ARM64_CC_MI:
		{
			auto* n = loadRegister(ARM64_REG_CPSR_N, irb);
			return n;
		}
		// Positive or zero = N clear
		case ARM64_CC_PL:
		{
			auto* n = loadRegister(ARM64_REG_CPSR_N, irb);
			return generateValueNegate(irb, n);
		}
		// Overflow = V set
		case ARM64_CC_VS:
		{
			auto* v = loadRegister(ARM64_REG_CPSR_V, irb);
			return v;
		}
		// No overflow = V clear
		case ARM64_CC_VC:
		{
			auto* v = loadRegister(ARM64_REG_CPSR_V, irb);
			return generateValueNegate(irb, v);
		}
		// Unsigned higher = Carry set & Zero clear
		case ARM64_CC_HI:
		{
			auto* c = loadRegister(ARM64_REG_CPSR_C, irb);
			auto* z = loadRegister(ARM64_REG_CPSR_Z, irb);
			auto* nz = generateValueNegate(irb, z);
			return irb.CreateAnd(c, nz);
		}
		// Unsigned lower or same = Carry clear or Zero set
		case ARM64_CC_LS:
		{
			auto* z = loadRegister(ARM64_REG_CPSR_Z, irb);
			auto* c = loadRegister(ARM64_REG_CPSR_C, irb);
			auto* nc = generateValueNegate(irb, c);
			return irb.CreateOr(z, nc);
		}
		// Greater than or equal = N set and V set || N clear and V clear
		// (N & V) || (!N & !V) == !(N xor V)
		case ARM64_CC_GE:
		{
			auto* n = loadRegister(ARM64_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM64_REG_CPSR_V, irb);
			auto* x = irb.CreateXor(n, v);
			return generateValueNegate(irb, x);
		}
		// Less than = N set and V clear || N clear and V set
		// (N & !V) || (!N & V) == (N xor V)
		case ARM64_CC_LT:
		{
			auto* n = loadRegister(ARM64_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM64_REG_CPSR_V, irb);
			return irb.CreateXor(n, v);
		}
		// Greater than = Z clear, and either N set and V set, or N clear and V set
		case ARM64_CC_GT:
		{
			auto* z = loadRegister(ARM64_REG_CPSR_Z, irb);
			auto* n = loadRegister(ARM64_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM64_REG_CPSR_V, irb);
			auto* xor1 = irb.CreateXor(n, v);
			auto* or1 = irb.CreateOr(z, xor1);
			return generateValueNegate(irb, or1);
		}
		// Less than or equal = Z set, or N set and V clear, or N clear and V set
		case ARM64_CC_LE:
		{
			auto* z = loadRegister(ARM64_REG_CPSR_Z, irb);
			auto* n = loadRegister(ARM64_REG_CPSR_N, irb);
			auto* v = loadRegister(ARM64_REG_CPSR_V, irb);
			auto* xor1 = irb.CreateXor(n, v);
			return irb.CreateOr(z, xor1);
		}
		case ARM64_CC_AL:
			// Allways
		case ARM64_CC_NV:
			// The Condition code NV exists only to provide a valid disassembly of the 0b1111 encoding, otherwise its behavior is identical to AL.
			return llvm::ConstantInt::get(llvm::IntegerType::getInt1Ty(_module->getContext()), 1);
		case ARM64_CC_INVALID:
		default:
		{
			throw GenericError("Probably wrong condition code.");
		}
	}
}

bool Capstone2LlvmIrTranslatorArm64_impl::isOperandRegister(cs_arm64_op& op)
{
	return op.type == ARM64_OP_REG;
}

bool Capstone2LlvmIrTranslatorArm64_impl::isFPRegister(cs_arm64_op& op, bool onlySupported) const
{
	if (op.type != ARM64_OP_REG)
	{
	    return false;
	}
	bool is_q_reg = (op.reg >= ARM64_REG_Q0 && op.reg <= ARM64_REG_Q31);
	bool is_d_reg = (op.reg >= ARM64_REG_D0 && op.reg <= ARM64_REG_D31);
	bool is_h_reg = (op.reg >= ARM64_REG_H0 && op.reg <= ARM64_REG_H31);
	bool is_s_reg = (op.reg >= ARM64_REG_S0 && op.reg <= ARM64_REG_S31);
	if (onlySupported)
	{
	    return is_d_reg || is_h_reg;
	}
	else
	{
	    // This is the overall correct behavior but since the support for 16bit floats
	    // or 128 bit floats is not implemented, we want to check only D and H registers
	    return is_q_reg || is_d_reg || is_h_reg || is_s_reg;
	}
}

bool Capstone2LlvmIrTranslatorArm64_impl::isVectorRegister(cs_arm64_op& op) const
{
	return op.type == ARM64_OP_REG && op.reg >= ARM64_REG_V0 && op.reg <= ARM64_REG_V31;
}

uint8_t Capstone2LlvmIrTranslatorArm64_impl::getOperandAccess(cs_arm64_op& op)
{
	return op.access;
}

bool Capstone2LlvmIrTranslatorArm64_impl::isCondIns(cs_arm64 * i) const
{
	return (i->cc == ARM64_CC_INVALID) ? false : true;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateIntBitCastToFP(llvm::IRBuilder<>& irb, llvm::Value* val) const
{
	if (auto* it = llvm::dyn_cast<llvm::IntegerType>(val->getType()))
	{
		switch(it->getBitWidth())
		{
		case 32:
			return irb.CreateBitCast(val, irb.getFloatTy());
		case 64:
			return irb.CreateBitCast(val, irb.getDoubleTy());
		default:
			throw GenericError("Arm64::generateIntBitCastToFP: unhandled Integer type");
		}
	}
	// Return unchanged value if its not FP type
	return val;
}

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateFPBitCastToIntegerType(llvm::IRBuilder<>& irb, llvm::Value* val) const
{
	auto* ty = val->getType();
	if (ty->isFloatingPointTy())
	{
		if (ty->isDoubleTy())
		{
			return irb.CreateBitCast(val, irb.getInt64Ty());
		}
		else if (ty->isFloatTy())
		{
			return irb.CreateBitCast(val, irb.getInt32Ty());
		}
		else
		{
			throw GenericError("Arm64::generateFPBitCastToIntegerType: unhandled FP type");
		}
	}
	// Return unchanged value if its not FP type
	return val;
}

void Capstone2LlvmIrTranslatorArm64_impl::generatePseudoInstruction(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	throwUnhandledInstructions(i);

	if (!isCondIns(ai))
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

bool Capstone2LlvmIrTranslatorArm64_impl::ifVectorGeneratePseudo(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb, _translator_fnc trans)
{
    bool pseudo = false;
    for (std::uint8_t i = 0; i < ai->op_count; ++i)
    {
	    if (isVectorRegister(ai->operands[i]))
	    {
		    pseudo = true;
		    break;
	    }
    }

    if (pseudo)
    {
	    throwUnhandledInstructions(i);
	    if (trans == nullptr)
	    {
		    generatePseudoInstruction(i, ai, irb);
	    }
	    else
	    {
		    (this->*trans)(i, ai, irb);
	    }
    }

    return pseudo;
}

//
//==============================================================================
// ARM64 instruction translation methods.
//==============================================================================
//

/**
 * ARM64_INS_ADC
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAdc(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::ZEXT_TRUNC_OR_BITCAST);
	auto* carry = loadRegister(ARM64_REG_CPSR_C, irb);

	auto* val = irb.CreateAdd(op1, op2);
	val       = irb.CreateAdd(val, irb.CreateZExtOrTrunc(carry, val->getType()));

	storeOp(ai->operands[0], val, irb);

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateCarryAddC(op1, op2, irb, carry), irb);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowAddC(val, op1, op2, irb, carry), irb);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
}

/**
 * ARM64_INS_ADD, ARM64_INS_CMN
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAdd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = generateTypeConversion(irb, op2, op1->getType(), eOpConv::ZEXT_TRUNC_OR_BITCAST);

	// For some reason it is possible to add two FP registers with integer add?
	// This looks to be also true for sub
	if (isFPRegister(ai->operands[0]) && i->id != ARM64_INS_CMN)
	{
		op1 = generateFPBitCastToIntegerType(irb, op1);
		op2 = generateFPBitCastToIntegerType(irb, op2);
	}

	auto *val = irb.CreateAdd(op1, op2);
	if (i->id != ARM64_INS_CMN)
	{
		storeOp(ai->operands[0], val, irb);
	}

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateCarryAdd(val, op1, irb), irb);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowAdd(val, op1, op2, irb), irb);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
}

/**
 * ARM64_INS_SUB, ARM64_INS_CMP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateSub(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = generateTypeConversion(irb, op2, op1->getType(), eOpConv::ZEXT_TRUNC_OR_BITCAST);

	// For some reason it is possible to sub two FP registers with integer sub?
	// This looks to be also true for add
	if (isFPRegister(ai->operands[0]) && i->id != ARM64_INS_CMP)
	{
		op1 = generateFPBitCastToIntegerType(irb, op1);
		op2 = generateFPBitCastToIntegerType(irb, op2);
	}

	auto* val = irb.CreateSub(op1, op2);
	if (i->id != ARM64_INS_CMP)
	{
		storeOp(ai->operands[0], val, irb);
	}

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateValueNegate(irb, generateBorrowSub(op1, op2, irb)), irb);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowSub(val, op1, op2, irb), irb);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
}

/**
 * ARM64_INS_NEG
 * ARM64_INS_NEGS for some reason capstone includes this instruction as alias.
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateNeg(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	auto* op2 = loadOpBinaryOp1(ai, irb);

	llvm::Value* val = nullptr;
	if (isFPRegister(ai->operands[1]))
	{
		val = irb.CreateFNeg(op2);
	}
	else
	{
		llvm::Value* zero = llvm::ConstantInt::get(op2->getType(), 0);
		val = irb.CreateSub(zero, op2);
	}

	storeOp(ai->operands[0], val, irb);

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateValueNegate(irb, generateBorrowSub(zero, op2, irb)), irb);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowSub(val, zero, op2, irb), irb);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
}

/**
 * ARM64_INS_SBC
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateSbc(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);

	auto* carry = loadRegister(ARM64_REG_CPSR_C, irb);

	// NOT(OP2)
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());
	op2 = generateValueNegate(irb, op2);

	// OP1 + NOT(OP2) + CARRY
	auto* val = irb.CreateAdd(op1, op2);
	val       = irb.CreateAdd(val, irb.CreateZExtOrTrunc(carry, val->getType()));

	storeOp(ai->operands[0], val, irb);

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateCarryAddC(op1, op2, irb, carry), irb);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowAddC(val, op1, op2, irb, carry), irb);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
}

/**
 * ARM64_INS_NGC, ARM64_INS_NGCS
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateNgc(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	auto* op2 = loadOpBinaryOp1(ai, irb);
	llvm::Value* op1 = llvm::ConstantInt::get(op2->getType(), 0);
	auto* carry = loadRegister(ARM64_REG_CPSR_C, irb);

	// NOT(OP2)
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());
	op2 = generateValueNegate(irb, op2);

	// OP1 + NOT(OP2) + CARRY
	auto* val = irb.CreateAdd(op1, op2);
	val       = irb.CreateAdd(val, irb.CreateZExtOrTrunc(carry, val->getType()));

	storeOp(ai->operands[0], val, irb);

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateCarryAddC(op1, op2, irb, carry), irb);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowAddC(val, op1, op2, irb, carry), irb);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
	}
}

/**
 * ARM64_INS_NOP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateNop(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	// Don't translate anything.
}

/**
 * ARM64_INS_MOV, ARM64_INS_MVN, ARM64_INS_MOVZ, ARM64_INS_MOVN
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMov(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	if (!op1->getType()->isFloatingPointTy())
	{
		op1 = irb.CreateZExtOrTrunc(op1, getRegisterType(ai->operands[0].reg));
	}

	if (i->id == ARM64_INS_MVN || i->id == ARM64_INS_MOVN)
	{
		op1 = generateValueNegate(irb, op1);
	}

	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM64_INS_MOVK
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMovk(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	// Load the destination register
	op0 = loadOp(ai->operands[0], irb);

	// Create simple imm16 bit inverted mask
	llvm::Value* and_mask = llvm::ConstantInt::get(op0->getType(), 0xffff);

	// Get the operand shift value
	auto shift_val = (ai->operands[1].shift.type == ARM64_SFT_INVALID) ? 0 : ai->operands[1].shift.value;

	// Shift the mask to proper place in case of LSL imm shift (example: movk x0, #123, LSL #32)
	and_mask = irb.CreateShl(and_mask, llvm::ConstantInt::get(op0->getType(), shift_val));

	// Invert the mask
	and_mask = generateValueNegate(irb, and_mask);

	op0 = irb.CreateAnd(op0, and_mask);

	op1 = loadOp(ai->operands[1], irb);
	op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
	// Move the value keeping the original data in register changing only the 16bit imm
	auto *val = irb.CreateOr(op0, op1);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_STR, ARM64_INS_STRB, ARM64_INS_STRH
 * ARM64_INS_STUR, ARM64_INS_STURB, ARM64_INS_STURH
 * ARM64_INS_STTR, ARM64_INS_STTRB, ARM64_INS_STTRH
 * ARM64_INS_STXR, ARM64_INS_STXRB, ARM64_INS_STXRH -- Maybe those should be pseudo
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateStr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case ARM64_INS_STR:
		case ARM64_INS_STUR:
		case ARM64_INS_STTR:
		//case ARM64_INS_STXR:
		{
			ty = getRegisterType(ai->operands[0].reg);
			if (ty->isFloatTy())
			{
				ty = irb.getInt32Ty();
			}
			else if (ty->isDoubleTy())
			{
				ty = irb.getInt64Ty();
			}
			break;
		}
		case ARM64_INS_STRB:
		case ARM64_INS_STURB:
		case ARM64_INS_STTRB:
		//case ARM64_INS_STXRB:
		{
			ty = irb.getInt8Ty();
			break;
		}
		case ARM64_INS_STRH:
		case ARM64_INS_STURH:
		case ARM64_INS_STTRH:
		//case ARM64_INS_STXRH:
		{
			ty = irb.getInt16Ty();
			break;
		}
		default:
		{
			throw GenericError("Arm64: unhandled STR id");
		}
	}

	op0 = loadOp(ai->operands[0], irb);

	// If its floating point operand bit cast it to integer type
	// since the ZExt or Trunc doesn't work fp numbers
	//op0 = generateFPBitCastToIntegerType(irb, op0);
	//op0 = irb.CreateBitCast(op0, irb.getInt32Ty());
	if (!op0->getType()->isFloatingPointTy())
	{
		op0 = irb.CreateZExtOrTrunc(op0, ty);
	}
	auto* dest = generateGetOperandMemAddr(ai->operands[1], irb);

	auto* pt = llvm::PointerType::get(op0->getType(), 0);
	auto* addr = irb.CreateIntToPtr(dest, pt);
	irb.CreateStore(op0, addr);

	uint32_t baseR = ARM64_REG_INVALID;
	if (ai->op_count == 2)
	{
		baseR = ai->operands[1].reg;
	}
	else if (ai->op_count == 3)
	{
		baseR = ai->operands[1].reg;

		auto* disp = llvm::ConstantInt::get(getDefaultType(), ai->operands[2].imm);
		dest = irb.CreateAdd(dest, disp);
		// post-index -> always writeback
	}
	else
	{
		throw GenericError("STR: unsupported STR format");
	}

	if (ai->writeback && baseR != ARM64_REG_INVALID)
	{
		storeRegister(baseR, dest, irb);
	}
}

/**
 * ARM64_INS_STP, ARM64_INS_STNP
 * ARM64_INS_STXP -- Maybe should be pseudo
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateStp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (2 <= ai->op_count && ai->op_count <= 4));

	op0 = loadOp(ai->operands[0], irb);
	op1 = loadOp(ai->operands[1], irb);

	uint32_t baseR = ARM64_REG_INVALID;
	llvm::Value* newDest = nullptr;
	auto* dest = generateGetOperandMemAddr(ai->operands[2], irb);
	auto* registerSize = llvm::ConstantInt::get(getDefaultType(), getRegisterByteSize(ai->operands[0].reg));
	storeOp(ai->operands[2], op0, irb);
	if (ai->op_count == 3)
	{
		newDest = irb.CreateAdd(dest, registerSize);

		auto* pt = llvm::PointerType::get(op1->getType(), 0);
		auto* addr = irb.CreateIntToPtr(newDest, pt);
		irb.CreateStore(op1, addr);

		baseR = ai->operands[2].mem.base;
	}
	else if (ai->op_count == 4)
	{
		auto* disp = llvm::ConstantInt::get(getDefaultType(), ai->operands[3].imm);
		newDest    = irb.CreateAdd(dest, registerSize);

		auto* pt = llvm::PointerType::get(op1->getType(), 0);
		auto* addr = irb.CreateIntToPtr(newDest, pt);
		irb.CreateStore(op1, addr);

		baseR = ai->operands[2].mem.base;

		newDest = irb.CreateAdd(dest, disp);
	}
	else
	{
		throw GenericError("STR: unsupported STP format");
	}

	if (ai->writeback && baseR != ARM64_REG_INVALID)
	{
		storeRegister(baseR, newDest, irb);
	}
}

/**
 * ARM64_INS_LDR
 * ARM64_INS_LDURB, ARM64_INS_LDUR, ARM64_INS_LDURH, ARM64_INS_LDURSB, ARM64_INS_LDURSH, ARM64_INS_LDURSW
 * ARM64_INS_LDRB, ARM64_INS_LDRH, ARM64_INS_LDRSB, ARM64_INS_LDRSH, ARM64_INS_LDRSW
 * ARM64_INS_LDTR, ARM64_INS_LDTRB, ARM64_INS_LDTRSB, ARM64_INS_LDTRH, ARM64_INS_LDTRSH, ARM64_INS_LDTRSW
 * ARM64_INS_LDXR, ARM64_INS_LDXRB, ARM64_INS_LDXRH
 * ARM64_INS_LDAXR, ARM64_INS_LDAXRB, ARM64_INS_LDAXRH
 * ARM64_INS_LDAR, ARM64_INS_LDARB, ARM64_INS_LDARH
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateLdr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	llvm::Type* ty = nullptr;
	bool sext = false;
	switch (i->id)
	{
		case ARM64_INS_LDR:
		case ARM64_INS_LDUR:
		case ARM64_INS_LDTR:
		case ARM64_INS_LDXR:
		case ARM64_INS_LDAXR:
		case ARM64_INS_LDAR:
		{
			ty = getRegisterType(ai->operands[0].reg);
			sext = false;
			break;
		}
		case ARM64_INS_LDRB:
		case ARM64_INS_LDURB:
		case ARM64_INS_LDTRB:
		case ARM64_INS_LDXRB:
		case ARM64_INS_LDAXRB:
		case ARM64_INS_LDARB:
		{
			ty = irb.getInt8Ty();
			sext = false;
			break;
		}
		case ARM64_INS_LDRH:
		case ARM64_INS_LDURH:
		case ARM64_INS_LDTRH:
		case ARM64_INS_LDXRH:
		case ARM64_INS_LDAXRH:
		case ARM64_INS_LDARH:
		{
			ty = irb.getInt16Ty();
			sext = false;
			break;
		}
		// Signed loads
		case ARM64_INS_LDRSB:
		case ARM64_INS_LDURSB:
		case ARM64_INS_LDTRSB:
		{
			ty = irb.getInt8Ty();
			sext = true;
			break;
		}
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDURSH:
		case ARM64_INS_LDTRSH:
		{
			ty = irb.getInt16Ty();
			sext = true;
			break;
		}
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
		case ARM64_INS_LDTRSW:
		{
			ty = irb.getInt32Ty();
			sext = true;
			break;
		}
		default:
		{
			throw GenericError("Arm64: unhandled LDR id");
		}
	}

	auto* regType = getRegisterType(ai->operands[0].reg);
	auto* dest = loadOp(ai->operands[1], irb, nullptr, true);
	auto* pt = llvm::PointerType::get(ty, 0);
	auto* addr = irb.CreateIntToPtr(dest, pt);

	llvm::Value* loaded_value = irb.CreateLoad(addr);
	// If the result should be floating point, bit cast it
	if (!regType->isFloatingPointTy())
	{
		loaded_value = sext
			? irb.CreateSExtOrTrunc(loaded_value, regType)
			: irb.CreateZExtOrTrunc(loaded_value, regType);
	}

	storeRegister(ai->operands[0].reg, loaded_value, irb);

	uint32_t baseR = ARM64_REG_INVALID;
	if (ai->op_count == 2)
	{
		baseR = ai->operands[1].reg;
	}
	else if (ai->op_count == 3) // POST-index
	{
		baseR = ai->operands[1].reg;

		auto* disp = llvm::ConstantInt::get(getDefaultType(), ai->operands[2].imm);
		dest = irb.CreateAdd(dest, disp);
	}
	else
	{
		throw GenericError("Arm64: unsupported ldr format");
	}

	if (ai->writeback && baseR != ARM64_REG_INVALID)
	{
		storeRegister(baseR, dest, irb);
	}
}

/**
 * ARM64_INS_LDP, ARM64_INS_LDPSW
 * ARM64_INS_LDNP (Non-temporal)
 * ARM64_INS_LDXP (Exclusive)
 * ARM64_INS_LDAXP (Exclusive Aquire)
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateLdp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (2 <= ai->op_count && ai->op_count <= 4));

	llvm::Value* data_size = nullptr;
	llvm::Type* ty = nullptr;
	eOpConv ct = eOpConv::THROW;
	switch(i->id)
	{
	case ARM64_INS_LDNP:
		// Hints PE that the memory is not going to be used in near future
	case ARM64_INS_LDP:
	case ARM64_INS_LDXP:
	case ARM64_INS_LDAXP:
		data_size = llvm::ConstantInt::get(getDefaultType(), getRegisterByteSize(ai->operands[0].reg));
		ty = getRegisterType(ai->operands[0].reg);
		ct = eOpConv::ZEXT_TRUNC_OR_BITCAST;
		break;
	case ARM64_INS_LDPSW:
		data_size = llvm::ConstantInt::get(getDefaultType(), 4);
		ty = irb.getInt32Ty();
		ct = eOpConv::SEXT_TRUNC_OR_BITCAST;
		break;
	default:
		throw GenericError("Arm64 Ldp: Instruction id error");
	}

	auto* dest = loadOp(ai->operands[2], irb, nullptr, true);
	auto* pt = llvm::PointerType::get(ty, 0);
	auto* addr = irb.CreateIntToPtr(dest, pt);

	auto* newReg1Value = irb.CreateLoad(addr);

	llvm::Value* newDest = nullptr;
	llvm::Value* newReg2Value = nullptr;
	uint32_t baseR = ARM64_REG_INVALID;
	if (ai->op_count == 3)
	{
		storeRegister(ai->operands[0].reg, newReg1Value, irb, ct);
		newDest = irb.CreateAdd(dest, data_size);
		addr = irb.CreateIntToPtr(newDest, pt);
		newReg2Value = irb.CreateLoad(addr);
		storeRegister(ai->operands[1].reg, newReg2Value, irb, ct);

		baseR = ai->operands[2].mem.base;
	}
	else if (ai->op_count == 4)
	{

		storeRegister(ai->operands[0].reg, newReg1Value, irb, ct);
		newDest = irb.CreateAdd(dest, data_size);
		addr = irb.CreateIntToPtr(newDest, pt);
		newReg2Value = irb.CreateLoad(addr);
		storeRegister(ai->operands[1].reg, newReg2Value, irb, ct);

		auto* disp = llvm::ConstantInt::get(getDefaultType(), ai->operands[3].imm);
		dest = irb.CreateAdd(dest, disp);
		baseR = ai->operands[2].mem.base;
	}
	else
	{
		throw GenericError("ldp, ldpsw: Unsupported instruction format");
	}

	if (ai->writeback && baseR != ARM64_REG_INVALID)
	{
		storeRegister(baseR, dest, irb);
	}
}

/**
 * ARM64_INS_ADR, ARM64_INS_ADRP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAdr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	auto* imm  = loadOpBinaryOp1(ai, irb);

	// Even though the semantics for this instruction is
	// base = PC[]
	// X[t] = base + imm
	// It looks like capstone is already doing this work for us and
	// second operand has calculated value already
	/*
	auto* base = loadRegister(ARM64_REG_PC, irb);
	// ADRP loads address to 4KB page
	if (i->id == ARM64_INS_ADRP)
	{
		base = llvm::ConstantInt::get(getDefaultType(), (((i->address + i->size) >> 12) << 12));
	}
	auto* res  = irb.CreateAdd(base, imm);
	*/

	storeRegister(ai->operands[0].reg, imm, irb);
}

/**
 * ARM64_INS_AND, ARM64_INS_BIC, ARM64_INS_TST
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAnd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	if (i->id == ARM64_INS_BIC || i->id == ARM64_INS_BICS)
	{
		op2 = generateValueNegate(irb, op2);
	}
	auto* val = irb.CreateAnd(op1, op2);

	if (i->id != ARM64_INS_TST)
	{
		storeOp(ai->operands[0], val, irb);
	}

	if (ai->update_flags)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_N, irb.CreateICmpSLT(val, zero), irb);
		storeRegister(ARM64_REG_CPSR_Z, irb.CreateICmpEQ(val, zero), irb);
		// According to documentation carry and overflow should be
		// set to zero.
		storeRegister(ARM64_REG_CPSR_C, zero, irb);
		storeRegister(ARM64_REG_CPSR_V, zero, irb);
	}
}

/**
 * ARM64_INS_ASR, ARM64_INS_LSL, ARM64_INS_LSR, ARM64_INS_ROR
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateShifts(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	llvm::Value* val = nullptr;
	switch(i->id)
	{
		case ARM64_INS_ASR:
		{
			val = irb.CreateAShr(op1, op2);
			break;
		}
		case ARM64_INS_LSL:
		{
			val = irb.CreateShl(op1, op2);
			break;
		}
		case ARM64_INS_LSR:
		{
			val = irb.CreateLShr(op1, op2);
			break;
		}
		case ARM64_INS_ROR:
		{
			val = generateShiftRor(irb, op1, op2);
			break;
		}
		default:
		{
			throw GenericError("Shifts: unhandled insn ID");
		}
	}

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_BR, ARM64_INS_BRL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateBr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ai, irb);

	// Branch with link to register
	if (i->id == ARM64_INS_BLR)
	{
		storeRegister(ARM64_REG_LR, getNextInsnAddress(i), irb);
	}

	op0 = loadOpUnary(ai, irb);
	generateBranchFunctionCall(irb, op0);
}

/**
 * ARM64_INS_B
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateB(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ai, irb);

	op0 = loadOpUnary(ai, irb);

	if (isCondIns(ai)) {
		auto* cond = generateInsnConditionCode(irb, ai);
		generateCondBranchFunctionCall(irb, cond, op0);
	}
	else
	{
		generateBranchFunctionCall(irb, op0);
	}
}

/**
 * ARM64_INS_BL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateBl(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ai, irb);

	storeRegister(ARM64_REG_LR, getNextInsnAddress(i), irb);
	op0 = loadOpUnary(ai, irb);
	generateCallFunctionCall(irb, op0);
}

/**
 * ARM64_INS_CLZ
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateClz(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);

	auto* f = llvm::Intrinsic::getDeclaration(
	    _module,
	    llvm::Intrinsic::ctlz,
	    op1->getType());

	auto* val = irb.CreateCall(f, {op1, irb.getTrue()});
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_CBNZ, ARM64_INS_CBZ
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateCbnz(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	std::tie(op0, op1) = loadOpBinary(ai, irb);
	llvm::Value* cond = nullptr;
	if (i->id == ARM64_INS_CBNZ)
	{
		cond = irb.CreateICmpNE(op0, llvm::ConstantInt::get(op0->getType(), 0));
	}
	else if (i->id == ARM64_INS_CBZ)
	{
		cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
	}
	else
	{
		throw GenericError("cbnz, cbz: Instruction id error");
	}
	generateCondBranchFunctionCall(irb, cond, op1);
}

/**
 * ARM64_INS_CCMN, ARM64_INS_CCMP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateCondCompare(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	op1 = loadOp(ai->operands[0], irb);
	op2 = loadOp(ai->operands[1], irb);
	auto* nzvc = loadOp(ai->operands[2], irb);

	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	auto* cond = generateInsnConditionCode(irb, ai);
	auto irbP = generateIfThenElse(cond, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	//IF - condition holds
	llvm::Value* val = nullptr;
	if (i->id == ARM64_INS_CCMP)
	{
		val = bodyIf.CreateSub(op1, op2);
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateValueNegate(bodyIf, generateBorrowSub(op1, op2, bodyIf)), bodyIf);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowSub(val, op1, op2, bodyIf), bodyIf);
		storeRegister(ARM64_REG_CPSR_N, bodyIf.CreateICmpSLT(val, zero), bodyIf);
		storeRegister(ARM64_REG_CPSR_Z, bodyIf.CreateICmpEQ(val, zero), bodyIf);
	}
	else if (i->id == ARM64_INS_CCMN)
	{
		val = bodyIf.CreateAdd(op1, op2);
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		storeRegister(ARM64_REG_CPSR_C, generateCarryAdd(val, op1, bodyIf), bodyIf);
		storeRegister(ARM64_REG_CPSR_V, generateOverflowAdd(val, op1, op2, bodyIf), bodyIf);
		storeRegister(ARM64_REG_CPSR_N, bodyIf.CreateICmpSLT(val, zero), bodyIf);
		storeRegister(ARM64_REG_CPSR_Z, bodyIf.CreateICmpEQ(val, zero), bodyIf);
	}
	else
	{
		throw GenericError("Arm64 ccmp, ccmn: Instruction id error");
	}

	//ELSE - Set the flags from IMM
	// We only use shifts because the final value to be stored is truncated to i1.
	storeRegister(ARM64_REG_CPSR_N, bodyElse.CreateLShr(nzvc, llvm::ConstantInt::get(nzvc->getType(), 3)), bodyElse);
	storeRegister(ARM64_REG_CPSR_Z, bodyElse.CreateLShr(nzvc, llvm::ConstantInt::get(nzvc->getType(), 2)), bodyElse);
	storeRegister(ARM64_REG_CPSR_C, bodyElse.CreateLShr(nzvc, llvm::ConstantInt::get(nzvc->getType(), 1)), bodyElse);
	storeRegister(ARM64_REG_CPSR_V, nzvc, bodyElse);

}

/**
 * ARM64_INS_CSEL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateCsel(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);

	auto* cond = generateInsnConditionCode(irb, ai);
	auto* val  = irb.CreateSelect(cond, op1, op2);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_CINC, ARM64_INS_CINV, ARM64_INS_CNEG
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateCondOp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);

	auto* cond = generateInsnConditionCode(irb, ai);
	// Invert the condition
	cond = generateValueNegate(irb, cond);
	auto irbP = generateIfThenElse(cond, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	//IF - store first operand
	storeOp(ai->operands[0], op1, bodyIf);

	//ELSE
	llvm::Value *val = nullptr;
	switch(i->id)
	{
	case ARM64_INS_CINC:
		val = bodyElse.CreateAdd(op1, llvm::ConstantInt::get(op1->getType(), 1));
		break;
	case ARM64_INS_CINV:
		val = generateValueNegate(bodyElse, op1);
		break;
	case ARM64_INS_CNEG:
		val = generateValueNegate(bodyElse, op1);
		val = bodyElse.CreateAdd(val, llvm::ConstantInt::get(val->getType(), 1));
		break;
	default:
		throw GenericError("translateCondOp: Instruction id error");
		break;
	}
	storeOp(ai->operands[0], val, bodyElse);
	//ENDIF
}

/**
 * ARM64_INS_CSINC, ARM64_INS_CSINV, ARM64_INS_CSNEG
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateCondSelOp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	auto* cond = generateInsnConditionCode(irb, ai);
	auto irbP = generateIfThenElse(cond, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	//IF
	storeOp(ai->operands[0], op1, bodyIf);

	//ELSE
	llvm::Value *val = nullptr;
	switch(i->id)
	{
	case ARM64_INS_CSINC:
		val = bodyElse.CreateAdd(op2, llvm::ConstantInt::get(op2->getType(), 1));
		break;
	case ARM64_INS_CSINV:
		val = generateValueNegate(bodyElse, op2);
		break;
	case ARM64_INS_CSNEG:
		val = generateValueNegate(bodyElse, op2);
		val = bodyElse.CreateAdd(val, llvm::ConstantInt::get(val->getType(), 1));
		break;
	default:
		throw GenericError("translateCondSelOp: Instruction id error");
		break;
	}
	storeOp(ai->operands[0], val, bodyElse);
	//ENDIF
}

/**
 * ARM64_INS_CSET, ARM64_INS_CSETM
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateCset(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_UNARY(i, ai, irb);

	auto* rt = getRegisterType(ai->operands[0].reg);
	auto* zero = llvm::ConstantInt::get(rt, 0);
	llvm::Value* one = nullptr;
	if (i->id == ARM64_INS_CSET)
	{
		one = llvm::ConstantInt::get(rt, 1);
	}
	else if (i->id == ARM64_INS_CSETM)
	{
		one = llvm::ConstantInt::get(rt, ~0);
		// 0xffffffffffffffff - one in all bits
	}
	else
	{
		throw GenericError("cset, csetm: Instruction id error");
	}

	auto* cond = generateInsnConditionCode(irb, ai);
	auto* val  = irb.CreateSelect(cond, one, zero);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_EOR, ARM64_INS_EON
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateEor(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::ZEXT_TRUNC_OR_BITCAST);

	if (i->id == ARM64_INS_EON)
	{
	    op2 = generateValueNegate(irb, op2);
	}

	auto* val = irb.CreateXor(op1, op2);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_SXTB, ARM64_INS_SXTH, ARM64_INS_SXTW
 * ARM64_INS_UXTB, ARM64_INS_UXTH
*/
void Capstone2LlvmIrTranslatorArm64_impl::translateExtensions(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	auto* val = loadOp(ai->operands[1], irb);

	auto* i8  = llvm::IntegerType::getInt8Ty(_module->getContext());
	auto* i16 = llvm::IntegerType::getInt16Ty(_module->getContext());
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());

	auto* ty  = getRegisterType(ai->operands[0].reg);

	llvm::Value* trunc = nullptr;
	switch(i->id)
	{
		case ARM64_INS_UXTB:
		{
			trunc = irb.CreateTrunc(val, i8);
			val   = irb.CreateZExt(trunc, ty);
			break;
		}
		case ARM64_INS_UXTH:
		{
			trunc = irb.CreateTrunc(val, i16);
			val   = irb.CreateZExt(trunc, ty);
			break;
		}
		/*
		case ARM64_INS_UXTW:
		{
			trunc = irb.CreateTrunc(val, i32);
			val   = irb.CreateZExt(trunc, ty);
			break;
		}
		*/
		case ARM64_INS_SXTB:
		{
			trunc = irb.CreateTrunc(val, i8);
			val   = irb.CreateSExt(trunc, ty);
			break;
		}
		case ARM64_INS_SXTH:
		{
			trunc = irb.CreateTrunc(val, i16);
			val   = irb.CreateSExt(trunc, ty);
			break;
		}
		case ARM64_INS_SXTW:
		{
			trunc = irb.CreateTrunc(val, i32);
			val   = irb.CreateSExt(trunc, ty);
			break;
		}
		default:
			throw GenericError("Arm64 translateExtension(): Unsupported extension type");
	}

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_EXTR
*/
void Capstone2LlvmIrTranslatorArm64_impl::translateExtr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);
	auto* lsb1 = loadOp(ai->operands[3], irb);
	lsb1 = irb.CreateZExtOrTrunc(lsb1, op1->getType());
	llvm::Value* lsb2 = llvm::ConstantInt::get(op1->getType(), llvm::cast<llvm::IntegerType>(op2->getType())->getBitWidth());
	lsb2 = irb.CreateSub(lsb2, lsb1);

	auto* left_val  = irb.CreateLShr(op2, lsb1);
	auto* right_val = irb.CreateShl(op1, lsb2);

	auto* val = irb.CreateOr(left_val, right_val);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_ORR, ARM64_INS_ORN
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateOrr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::ZEXT_TRUNC_OR_BITCAST);

	if (i->id == ARM64_INS_ORN)
	{
	    op2 = generateValueNegate(irb, op2);
	}

	auto* val = irb.CreateOr(op1, op2);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_UDIV, ARM64_INS_SDIV
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateDiv(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb, eOpConv::SEXT_TRUNC_OR_BITCAST);
	llvm::Value *val = nullptr;
	if (i->id == ARM64_INS_UDIV)
	{
		val = irb.CreateUDiv(op1, op2);
	}
	else if (i->id == ARM64_INS_SDIV)
	{
		val = irb.CreateSDiv(op1, op2);
	}

	storeOp(ai->operands[0], val, irb);

	/*
	// Zero division yelds zero as result in this case we
	// don't want undefined behaviour so we
	// check for zero division and manualy set the result, for now.
	llvm::Value* zero = llvm::ConstantInt::get(op1->getType(), 0);
	auto* cond = irb.CreateICmpEQ(op2, zero);
	auto irbP = generateIfThenElse(cond, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	//IF - store zero
	storeOp(ai->operands[0], zero, bodyIf);

	//ELSE - store result of division
	llvm::Value *val = nullptr;
	if (i->id == ARM64_INS_UDIV)
	{
		val = bodyElse.CreateUDiv(op1, op2);
	}
	else if (i->id == ARM64_INS_SDIV)
	{
		val = bodyElse.CreateSDiv(op1, op2);
	}

	storeOp(ai->operands[0], val, bodyElse);
	//ENDIF
	*/
}

/**
 * ARM64_INS_UMULH, ARM64_INS_SMULH
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMulh(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	bool sext = true;
	if (i->id == ARM64_INS_UMULH)
	{
		sext = false;
	}
	else if (i->id == ARM64_INS_SMULH)
	{
		sext = true;
	}
	else
	{
		throw GenericError("Mulh: Unhandled instruction ID");
	}

	auto* res_type = llvm::IntegerType::getInt128Ty(_module->getContext());
	auto* op1 = loadOp(ai->operands[1], irb);
	auto* op2 = loadOp(ai->operands[2], irb);
	if (sext)
	{
		op1 = irb.CreateSExtOrTrunc(op1, res_type);
		op2 = irb.CreateSExtOrTrunc(op2, res_type);
	}
	else
	{
		op1 = irb.CreateZExtOrTrunc(op1, res_type);
		op2 = irb.CreateZExtOrTrunc(op2, res_type);
	}

	auto *val = irb.CreateMul(op1, op2);

	// Get the high bits of the result
	val = irb.CreateAShr(val, llvm::ConstantInt::get(val->getType(), 64));

	val = irb.CreateSExtOrTrunc(val, getDefaultType());

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_UMULL, ARM64_INS_SMULL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMull(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	bool sext = true;
	if (i->id == ARM64_INS_UMULL)
	{
		sext = false;
	}
	else if (i->id == ARM64_INS_SMULL)
	{
		sext = true;
	}
	else
	{
		throw GenericError("Mull: Unhandled instruction ID");
	}

	auto* res_type = getDefaultType();
	auto* op1 = loadOp(ai->operands[1], irb);
	auto* op2 = loadOp(ai->operands[2], irb);
	if (sext)
	{
		op1 = irb.CreateSExtOrTrunc(op1, res_type);
		op2 = irb.CreateSExtOrTrunc(op2, res_type);
	}
	else
	{
		op1 = irb.CreateZExtOrTrunc(op1, res_type);
		op2 = irb.CreateZExtOrTrunc(op2, res_type);
	}

	auto *val = irb.CreateMul(op1, op2);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_UMADDL, ARM64_INS_SMADDL
 * ARM64_INS_UMSUBL, ARM64_INS_SMSUBL
 * ARM64_INS_UMNEGL, ARM64_INS_SMNEGL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMulOpl(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (3 <= ai->op_count && ai->op_count <= 4));

	bool sext = true;
	bool add_operation = true;
	bool op3_zero = false;
	switch(i->id) {
	case ARM64_INS_UMADDL:
		sext = false;
		add_operation = true;
		break;
	case ARM64_INS_SMADDL:
		sext = true;
		add_operation = true;
		break;
	case ARM64_INS_UMSUBL:
		sext = false;
		add_operation = false;
		break;
	case ARM64_INS_SMSUBL:
		sext = true;
		add_operation = false;
		break;
	case ARM64_INS_UMNEGL:
		sext = false;
		add_operation = false;
		op3_zero = true;
		break;
	case ARM64_INS_SMNEGL:
		sext = true;
		add_operation = false;
		op3_zero = true;
		break;
	default:
		throw GenericError("Maddl: Unhandled instruction ID");
	}

	auto* res_type = getDefaultType();

	auto* op1 = loadOp(ai->operands[1], irb);
	auto* op2 = loadOp(ai->operands[2], irb);
	if (sext)
	{
		op1 = irb.CreateSExtOrTrunc(op1, res_type);
		op2 = irb.CreateSExtOrTrunc(op2, res_type);
	}
	else
	{
		op1 = irb.CreateZExtOrTrunc(op1, res_type);
		op2 = irb.CreateZExtOrTrunc(op2, res_type);
	}

	auto *val = irb.CreateMul(op1, op2);

	llvm::Value* op3;
	if (op3_zero)
	{
		op3 = llvm::ConstantInt::get(res_type, 0);
	}
	else
	{
		op3 = loadOp(ai->operands[3], irb);
	}

	if (add_operation)
	{
		val = irb.CreateAdd(op3, val);
	}
	else
	{
		val = irb.CreateSub(op3, val);
	}

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_MUL, ARM64_INS_MADD, ARM64_INS_MSUB, ARM64_INS_MNEG
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMul(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (3 <= ai->op_count && ai->op_count <= 4));

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	auto* op1 = loadOp(ai->operands[1], irb);
	auto* op2 = loadOp(ai->operands[2], irb);

	auto *val = irb.CreateMul(op1, op2);
	if (i->id == ARM64_INS_MADD)
	{
		auto* op3 = loadOp(ai->operands[3], irb);
		val = irb.CreateAdd(val, op3);
	}
	else if (i->id == ARM64_INS_MSUB)
	{
		auto* op3 = loadOp(ai->operands[3], irb);
		val = irb.CreateSub(op3, val);
	}

	if (i->id == ARM64_INS_MNEG)
	{
		llvm::Value* zero = llvm::ConstantInt::get(val->getType(), 0);
		val = irb.CreateSub(zero, val);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_TBNZ, ARM64_INS_TBZ
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateTbnz(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op0, op1, op2) = loadOpTernary(ai, irb);

	// Get the needed bit
	auto* ext_imm = irb.CreateZExtOrTrunc(op1, op0->getType());
	auto* shifted_one = irb.CreateShl(llvm::ConstantInt::get(op0->getType(), 1), ext_imm);
	auto* test_bit = irb.CreateAnd(shifted_one, op0);

	llvm::Value* cond = nullptr;
	if (i->id == ARM64_INS_TBNZ)
	{
		cond = irb.CreateICmpNE(test_bit, llvm::ConstantInt::get(op0->getType(), 0));
	}
	else if (i->id == ARM64_INS_TBZ)
	{
		cond = irb.CreateICmpEQ(test_bit, llvm::ConstantInt::get(op0->getType(), 0));
	}
	else
	{
		throw GenericError("cbnz, cbz: Instruction id error");
	}
	generateCondBranchFunctionCall(irb, cond, op2);
}

/**
 * ARM64_INS_RET
*/
void Capstone2LlvmIrTranslatorArm64_impl::translateRet(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_NULLARY_OR_UNARY(i, ai, irb);

	// If the register operand is present
	if (ai->op_count == 1)
	{
		op0 = loadOp(ai->operands[0], irb);
	}
	else
	{
		// Default use x30
		op0 = loadRegister(ARM64_REG_LR, irb);
	}
	generateReturnFunctionCall(irb, op0);
}

/**
 * ARM64_INS_REV, ARM64_INS_RBIT
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateRev(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);

	llvm::Function* f = nullptr;
	if (i->id == ARM64_INS_REV)
	{
		f = llvm::Intrinsic::getDeclaration(
				_module,
				llvm::Intrinsic::bswap,
				op1->getType());
	}
	else if (i->id == ARM64_INS_RBIT)
	{
		f = llvm::Intrinsic::getDeclaration(
				_module,
				llvm::Intrinsic::bitreverse,
				op1->getType());
	}
	else
	{
		throw GenericError("Arm64 REV, RBIT: Unhandled instruction id");
	}

	auto* val = irb.CreateCall(f, {op1});
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FADD
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFAdd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	auto *val = irb.CreateFAdd(op1, op2);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FCCMP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFCCmp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	op0 = loadOp(ai->operands[0], irb);
	op1 = loadOp(ai->operands[1], irb);
	auto* nzvc = loadOp(ai->operands[2], irb);

	auto* cond = generateInsnConditionCode(irb, ai);
	auto irbCond = generateIfThenElse(cond, irb);
	llvm::IRBuilder<>& condIf(irbCond.first), condElse(irbCond.second);

	// IF condition holds

	// IF op1 == op2
	auto* fcmpOeq = condIf.CreateFCmpOEQ(op0, op1);
	auto irbP = generateIfThenElse(fcmpOeq, condIf);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(ARM64_REG_CPSR_N, bodyIf.getFalse(), bodyIf);
	storeRegister(ARM64_REG_CPSR_Z, bodyIf.getTrue(), bodyIf);
	storeRegister(ARM64_REG_CPSR_C, bodyIf.getTrue(), bodyIf);
	storeRegister(ARM64_REG_CPSR_V, bodyIf.getFalse(), bodyIf);

	// ELSE IF op1 < op2
	auto* fcmpOgt = bodyElse.CreateFCmpOGT(op0, op1);
	auto irbP1 = generateIfThenElse(fcmpOgt, bodyElse);
	llvm::IRBuilder<>& bodyIf1(irbP1.first), bodyElse1(irbP1.second);

	storeRegister(ARM64_REG_CPSR_N, bodyIf1.getTrue(), bodyIf1);
	storeRegister(ARM64_REG_CPSR_Z, bodyIf1.getFalse(), bodyIf1);
	storeRegister(ARM64_REG_CPSR_C, bodyIf1.getFalse(), bodyIf1);
	storeRegister(ARM64_REG_CPSR_V, bodyIf1.getFalse(), bodyIf1);

	// ELSE IF op1 > op2
	auto* fcmpOlt = bodyElse1.CreateFCmpOLT(op0, op1);
	auto irbP2 = generateIfThenElse(fcmpOlt, bodyElse1);
	llvm::IRBuilder<>& bodyIf2(irbP2.first), bodyElse2(irbP2.second);

	storeRegister(ARM64_REG_CPSR_N, bodyIf2.getFalse(), bodyIf2);
	storeRegister(ARM64_REG_CPSR_Z, bodyIf2.getFalse(), bodyIf2);
	storeRegister(ARM64_REG_CPSR_C, bodyIf2.getTrue(), bodyIf2);
	storeRegister(ARM64_REG_CPSR_V, bodyIf2.getFalse(), bodyIf2);

	// ELSE - NAN
	storeRegister(ARM64_REG_CPSR_N, bodyElse2.getFalse(), bodyElse2);
	storeRegister(ARM64_REG_CPSR_Z, bodyElse2.getFalse(), bodyElse2);
	storeRegister(ARM64_REG_CPSR_C, bodyElse2.getTrue(), bodyElse2);
	storeRegister(ARM64_REG_CPSR_V, bodyElse2.getTrue(), bodyElse2);

	//ELSE - Set the flags from IMM
	// We only use shifts because the final value to be stored is truncated to i1.
	storeRegister(ARM64_REG_CPSR_N, bodyElse.CreateLShr(nzvc, llvm::ConstantInt::get(nzvc->getType(), 3)), condElse);
	storeRegister(ARM64_REG_CPSR_Z, bodyElse.CreateLShr(nzvc, llvm::ConstantInt::get(nzvc->getType(), 2)), condElse);
	storeRegister(ARM64_REG_CPSR_C, bodyElse.CreateLShr(nzvc, llvm::ConstantInt::get(nzvc->getType(), 1)), condElse);
	storeRegister(ARM64_REG_CPSR_V, nzvc, condElse);

}

/**
 * ARM64_INS_FCMP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFCmp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op0 = loadOp(ai->operands[0], irb);
	op1 = loadOp(ai->operands[1], irb);

	op1 = generateTypeConversion(irb, op1, op0->getType(), eOpConv::FPCAST_OR_BITCAST);

	// IF op1 == op2
	auto* fcmpOeq = irb.CreateFCmpOEQ(op0, op1);
	auto irbP = generateIfThenElse(fcmpOeq, irb);
	llvm::IRBuilder<>& bodyIf(irbP.first), bodyElse(irbP.second);

	storeRegister(ARM64_REG_CPSR_N, bodyIf.getFalse(), bodyIf);
	storeRegister(ARM64_REG_CPSR_Z, bodyIf.getTrue(), bodyIf);
	storeRegister(ARM64_REG_CPSR_C, bodyIf.getTrue(), bodyIf);
	storeRegister(ARM64_REG_CPSR_V, bodyIf.getFalse(), bodyIf);

	// ELSE IF op1 < op2
	auto* fcmpOgt = bodyElse.CreateFCmpOGT(op0, op1);
	auto irbP1 = generateIfThenElse(fcmpOgt, bodyElse);
	llvm::IRBuilder<>& bodyIf1(irbP1.first), bodyElse1(irbP1.second);

	storeRegister(ARM64_REG_CPSR_N, bodyIf1.getTrue(), bodyIf1);
	storeRegister(ARM64_REG_CPSR_Z, bodyIf1.getFalse(), bodyIf1);
	storeRegister(ARM64_REG_CPSR_C, bodyIf1.getFalse(), bodyIf1);
	storeRegister(ARM64_REG_CPSR_V, bodyIf1.getFalse(), bodyIf1);

	// ELSE IF op1 > op2
	auto* fcmpOlt = bodyElse1.CreateFCmpOLT(op0, op1);
	auto irbP2 = generateIfThenElse(fcmpOlt, bodyElse1);
	llvm::IRBuilder<>& bodyIf2(irbP2.first), bodyElse2(irbP2.second);

	storeRegister(ARM64_REG_CPSR_N, bodyIf2.getFalse(), bodyIf2);
	storeRegister(ARM64_REG_CPSR_Z, bodyIf2.getFalse(), bodyIf2);
	storeRegister(ARM64_REG_CPSR_C, bodyIf2.getTrue(), bodyIf2);
	storeRegister(ARM64_REG_CPSR_V, bodyIf2.getFalse(), bodyIf2);

	// ELSE
	storeRegister(ARM64_REG_CPSR_N, bodyElse2.getFalse(), bodyElse2);
	storeRegister(ARM64_REG_CPSR_Z, bodyElse2.getFalse(), bodyElse2);
	storeRegister(ARM64_REG_CPSR_C, bodyElse2.getTrue(), bodyElse2);
	storeRegister(ARM64_REG_CPSR_V, bodyElse2.getTrue(), bodyElse2);
}

/**
 * ARM64_INS_FCSEL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFCsel(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	auto* cond = generateInsnConditionCode(irb, ai);
	auto* val  = irb.CreateSelect(cond, op1, op2);

	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FCVT
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFCvt(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	storeOp(ai->operands[0], op1, irb, eOpConv::FPCAST_OR_BITCAST);
}

/**
 * ARM64_INS_UCVTF, ARM64_INS_SCVTF
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFCvtf(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOpBinaryOp1(ai, irb);

	switch(i->id)
	{
	case ARM64_INS_UCVTF:
		storeOp(ai->operands[0], op1, irb, eOpConv::UITOFP_OR_FPCAST);
		break;
	case ARM64_INS_SCVTF:
		storeOp(ai->operands[0], op1, irb, eOpConv::SITOFP_OR_FPCAST);
		break;
	default:
		throw GenericError("Arm64: translateFCvtf(): Unsupported instruction id");
	}
}

/**
 * ARM64_INS_FCVTZS, ARM64_INS_FCVTZU
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFCvtz(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);

	switch(i->id)
	{
	case ARM64_INS_FCVTZU:
		op1 = irb.CreateFPToSI(op1, getRegisterType(ai->operands[0].reg));
		break;
	case ARM64_INS_FCVTZS:
		op1 = irb.CreateFPToUI(op1, getRegisterType(ai->operands[0].reg));
		break;
	default:
		throw GenericError("Arm64: translateFCvtz(): Unsupported instruction id");
	}
	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM64_INS_FDIV
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFDiv(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	auto *val = irb.CreateFDiv(op1, op2);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FMADD, ARM64_INS_FNMADD
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFMadd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);
	op3 = loadOp(ai->operands[3], irb);

	auto *val = irb.CreateFMul(op1, op2);
	val = irb.CreateFAdd(op3, val);
	if (i->id == ARM64_INS_FNMADD)
	{
		val = irb.CreateFNeg(val);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FMAX, ARM64_INS_FMIN
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFMinMax(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	llvm::Value* cond;
	switch(i->id)
	{
	case ARM64_INS_FMIN:
		cond = irb.CreateFCmpULE(op1, op2);
		break;
	case ARM64_INS_FMAX:
		cond = irb.CreateFCmpUGE(op1, op2);
		break;
	default:
		throw GenericError("Arm64: translateFMinMax(): Unsupported instruction id");
	}

	auto* val = irb.CreateSelect(cond, op1, op2);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FMAXNM, ARM64_INS_FMINNM
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFMinMaxNum(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	llvm::Value* val = nullptr;
	llvm::Function* intrinsic = nullptr;
	switch(i->id)
	{
	case ARM64_INS_FMINNM:
		intrinsic = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::minnum, op1->getType());
		break;
	case ARM64_INS_FMAXNM:
		intrinsic = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::maxnum, op1->getType());
		break;
	default:
		throw GenericError("Arm64: translateFMinMaxNum(): Unsupported instruction id");
	}

	val = irb.CreateCall(intrinsic, {op1, op2});
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FMOV
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFMov(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	if (isVectorRegister(ai->operands[0]) || isVectorRegister(ai->operands[1]))
	{
		// We want this behavior in cases when move destination is vector register
		generatePseudoInstruction(i, ai, irb);
		return;
	}

	op1 = loadOp(ai->operands[1], irb);
	if (ai->operands[1].type == ARM64_OP_FP)
	{
		op1 = generateTypeConversion(irb, op1, getRegisterType(ai->operands[0].reg), eOpConv::FPCAST_OR_BITCAST);
	}
	else
	{
		op1 = irb.CreateBitCast(op1, getRegisterType(ai->operands[0].reg));
	}

	storeOp(ai->operands[0], op1, irb);
}

/**
 * ARM64_INS_MOVI
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMovi(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	if (!isFPRegister(ai->operands[0]))
	{
		// We want this behavior in cases when move destination is vector register
		generatePseudoInstruction(i, ai, irb);
		return;
	}

	op1 = loadOp(ai->operands[1], irb);
	storeOp(ai->operands[0], op1, irb, eOpConv::FPCAST_OR_BITCAST);
}

/**
 * ARM64_INS_FMUL, ARM64_INS_FNMUL
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFMul(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	auto *val = irb.CreateFMul(op1, op2);
	if (i->id == ARM64_INS_FNMUL)
	{
		val = irb.CreateFNeg(val);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FMSUB, ARM64_INS_FNMSUB
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFMsub(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_QUATERNARY(i, ai, irb);

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);
	op3 = loadOp(ai->operands[3], irb);

	auto *val = irb.CreateFMul(op1, op2);
	val = irb.CreateFSub(op3, val);
	if (i->id == ARM64_INS_FNMSUB)
	{
		val = irb.CreateFNeg(val);
	}
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FSUB
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFSub(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);
	op2 = loadOp(ai->operands[2], irb);

	auto *val = irb.CreateFSub(op1, op2);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_FNEG, ARM64_INS_FABS, ARM64_INS_FSQRT
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateFUnaryOp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	if (ifVectorGeneratePseudo(i, ai, irb))
	{
	    return;
	}

	op1 = loadOp(ai->operands[1], irb);

	llvm::Value* val = nullptr;
	llvm::Function* intrinsic = nullptr;
	switch(i->id)
	{
	case ARM64_INS_FNEG:
		val = irb.CreateFNeg(op1);
		break;
	case ARM64_INS_FABS:
		intrinsic = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::fabs, op1->getType());
		val = irb.CreateCall(intrinsic, {op1});
		break;
	case ARM64_INS_FSQRT:
		intrinsic = llvm::Intrinsic::getDeclaration(_module, llvm::Intrinsic::sqrt, op1->getType());
		val = irb.CreateCall(intrinsic, {op1});
		break;
	default:
		throw GenericError("Arm64: translateFUnary(): Unsupported instruction id");
	}

	storeOp(ai->operands[0], val, irb);
}

} // namespace capstone2llvmir
} // namespace retdec
