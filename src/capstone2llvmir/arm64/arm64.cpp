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
		Capstone2LlvmIrTranslator_impl(CS_ARCH_ARM64, basic, extra, m),
		_reg2parentMap(ARM64_REG_ENDING, ARM64_REG_INVALID)
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
	for (auto& p : _reg2type)
	{
		createRegister(p.first, _regLt);
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
		throwUnhandledInstructions(i);

		if (ai->cc == ARM64_CC_AL
		    || ai->cc == ARM64_CC_INVALID)
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

uint32_t Capstone2LlvmIrTranslatorArm64_impl::getParentRegister(uint32_t r) const
{
	return r < _reg2parentMap.size() ? _reg2parentMap[r] : r;
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

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateOperandExtension(
		llvm::IRBuilder<>& irb,
		arm64_extender ext,
		llvm::Value* val,
		llvm::Type* destType)
{
	auto* i8  = llvm::IntegerType::getInt8Ty(_module->getContext());
	auto* i16 = llvm::IntegerType::getInt16Ty(_module->getContext());
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());
	auto* i64 = llvm::IntegerType::getInt64Ty(_module->getContext());

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
			trunc = irb.CreateTrunc(val, i64);
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
			trunc = irb.CreateTrunc(val, i64);
			return irb.CreateSExt(trunc, ty);
		}
		default:
		    assert(false && "generateOperandExtension(): Unsupported extension type");
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
		assert(false && "should not be possible");
		return val;
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
	assert(false && "Check implementation");
	unsigned op0BitW = llvm::cast<llvm::IntegerType>(n->getType())->getBitWidth();
	auto* doubleT = llvm::Type::getIntNTy(_module->getContext(), op0BitW*2);

	auto* cf = loadRegister(ARM64_REG_CPSR_C, irb);
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

llvm::Value* Capstone2LlvmIrTranslatorArm64_impl::generateGetOperandMemAddr(
		cs_arm64_op& op,
		llvm::IRBuilder<>& irb)
{
	// TODO: Check the operand types
	// TODO: If the type is IMM return load of that value, or variable
	// TODO: name, maybe generateGetOperandValue?
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

	if (r == ARM64_REG_PC)
	{
		return getCurrentPc(_insn);
		// TODO: Check
	}

	auto* rt = getRegisterType(r);
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
		case ARM64_OP_SYS:
		case ARM64_OP_REG:
		{
			auto* val = loadRegister(op.reg, irb);
			auto* ext = generateOperandExtension(irb, op.ext, val, ty);
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

	auto* rt = getRegisterType(r);
	auto pr = getParentRegister(r);
	auto* llvmReg = getRegister(pr);
	if (llvmReg == nullptr)
	{
		throw GenericError("storeRegister() unhandled reg.");
	}

	val = generateTypeConversion(irb, val, llvmReg->getValueType(), ct);

	llvm::StoreInst* ret = nullptr;
	if (r == pr
			// Zext for 64-bit target llvmRegs & 32-bit source regs.
			|| (getRegisterBitSize(pr) == 64 && getRegisterBitSize(r) == 32))
	{
		ret = irb.CreateStore(val, llvmReg);
	}
	else
	{
		llvm::Value* l = irb.CreateLoad(llvmReg);
		if (!(l->getType()->isIntegerTy(16)
				|| l->getType()->isIntegerTy(32)
				|| l->getType()->isIntegerTy(64)))
		{
			throw GenericError("Unexpected parent type.");
		}

		llvm::Value* andC = nullptr;
		if (rt->isIntegerTy(32))
		{
			if (l->getType()->isIntegerTy(64))
			{
				andC = irb.getInt64(0xffffffff00000000);
			}
		}
		assert(andC);
		l = irb.CreateAnd(l, andC);

		auto* o = irb.CreateOr(l, val);
		ret = irb.CreateStore(o, llvmReg);
	}

	return ret;
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
			auto* addr = generateGetOperandMemAddr(op, irb);

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
		case ARM64_CC_NV:
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

uint8_t Capstone2LlvmIrTranslatorArm64_impl::getOperandAccess(cs_arm64_op& op)
{
	return op.access;
}

bool Capstone2LlvmIrTranslatorArm64_impl::isCondIns(cs_arm64 * i) {
    return (i->cc == ARM64_CC_AL || i->cc == ARM64_CC_INVALID) ? false : true;
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

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());
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
 * ARM64_INS_ADD
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAdd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	auto *val = irb.CreateAdd(op1, op2);
	storeOp(ai->operands[0], val, irb);

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
 * ARM64_INS_SUB
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateSub(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_TERNARY(i, ai, irb);

	std::tie(op1, op2) = loadOpBinaryOrTernaryOp1Op2(ai, irb);
	op2 = irb.CreateZExtOrTrunc(op2, op1->getType());

	auto *val = irb.CreateSub(op1, op2);
	storeOp(ai->operands[0], val, irb);
}

/**
 * ARM64_INS_MOV, ARM64_INS_MVN, ARM64_INS_MOVZ
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateMov(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

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
 * ARM64_INS_STR, ARM64_INS_STRB, ARM64_INS_STRH
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateStr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY_OR_TERNARY(i, ai, irb);

	llvm::Type* ty = nullptr;
	switch (i->id)
	{
		case ARM64_INS_STR:
		{
			ty = getDefaultType();
			break;
		}
		case ARM64_INS_STRB:
		{
			ty = irb.getInt8Ty();
			break;
		}
		case ARM64_INS_STRH:
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
	op0 = irb.CreateZExtOrTrunc(op0, ty);
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
		assert(false && "unsupported STR format");
	}

	if (ai->writeback && baseR != ARM64_REG_INVALID)
	{
		storeRegister(baseR, dest, irb);
	}
}

/**
 * ARM64_INS_STP
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
		assert(false && "unsupported STP format");
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
		{
			ty = irb.getInt32Ty();
			sext = false;
			break;
		}
		case ARM64_INS_LDRB:
		case ARM64_INS_LDURB:
		{
			ty = irb.getInt8Ty();
			sext = false;
			break;
		}
		case ARM64_INS_LDRH:
		case ARM64_INS_LDURH:
		{
			ty = irb.getInt16Ty();
			sext = false;
			break;
		}
		// Signed loads
		case ARM64_INS_LDRSB:
		case ARM64_INS_LDURSB:
		{
			ty = irb.getInt8Ty();
			sext = true;
			break;
		}
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDURSH:
		{
			ty = irb.getInt16Ty();
			sext = true;
			break;
		}
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
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

	auto* loaded_value = irb.CreateLoad(addr);
	auto* ext_value    = sext
			? irb.CreateSExtOrTrunc(loaded_value, regType)
			: irb.CreateZExtOrTrunc(loaded_value, regType);

	storeRegister(ai->operands[0].reg, ext_value, irb);

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
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateLdp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_EXPR(i, ai, irb, (2 <= ai->op_count && ai->op_count <= 4));

	llvm::Value* data_size = nullptr;
	llvm::Type* ty = nullptr;
	eOpConv ct = eOpConv::THROW;
	if(i->id == ARM64_INS_LDP)
	{
		data_size = llvm::ConstantInt::get(getDefaultType(), getRegisterByteSize(ai->operands[0].reg));
		ty = getRegisterType(ai->operands[0].reg);
		ct = eOpConv::ZEXT_TRUNC;
	}
	else if(i->id == ARM64_INS_LDPSW)
	{
		data_size = llvm::ConstantInt::get(getDefaultType(), 4);
		ty = irb.getInt32Ty();
		ct = eOpConv::SEXT_TRUNC;
	}
	else
	{
		throw GenericError("ldp, ldpsw: Instruction id error");
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
 * ARM64_INS_ADRP
 */
void Capstone2LlvmIrTranslatorArm64_impl::translateAdrp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb)
{
	EXPECT_IS_BINARY(i, ai, irb);

	auto* imm  = loadOpBinaryOp1(ai, irb);
	auto* base = llvm::ConstantInt::get(getDefaultType(), (((i->address + i->size) >> 12) << 12));

	auto* res  = irb.CreateAdd(base, imm);

	storeRegister(ai->operands[0].reg, res, irb);
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

} // namespace capstone2llvmir
} // namespace retdec
