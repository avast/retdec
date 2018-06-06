/**
* @file src/bin2llvmir/optimizations/idioms_libgcc/idioms_libgcc.cpp
* @brief Idioms produced by libgcc.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <functional>

#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/idioms_libgcc/idioms_libgcc.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// IdiomsLibgccImpl
//==============================================================================
//

class IdiomsLibgccImpl
{
	private:
		llvm::GlobalVariable* op0Single = nullptr;
		llvm::GlobalVariable* op0Double = nullptr;
		llvm::GlobalVariable* op1Single = nullptr;
		llvm::GlobalVariable* op1Double = nullptr;
		llvm::GlobalVariable* res0Single = nullptr;
		llvm::GlobalVariable* res0Double = nullptr;
		llvm::GlobalVariable* res1Single = nullptr;
		llvm::GlobalVariable* res1Double = nullptr;

	public:
		bool testArchAndInitialize(config::Architecture& arch, Abi* abi);

		void localize(llvm::Value* v);

		void log(
				llvm::Instruction* orig,
				std::initializer_list<llvm::Value*> news);

		void replaceResultUses(llvm::CallInst* c, llvm::Instruction* r);

		template<typename N>
		llvm::Value* getOp0(llvm::CallInst* call)
		{
			assert(false && "unhandled type");
			return getOp0<std::int32_t>(call);
		}

		template<typename N>
		llvm::Value* getOp1(llvm::CallInst* call)
		{
			assert(false && "unhandled type");
			return getOp1<std::int32_t>(call);
		}

		template<typename N>
		llvm::Value* getRes0(llvm::CallInst* call, llvm::Value* res)
		{
			assert(false && "unhandled type");
			return getRes0<std::int32_t>(call, res);
		}

		template<typename N>
		llvm::Value* getRes1(llvm::CallInst* call, llvm::Value* res)
		{
			assert(false && "unhandled type");
			return getRes1<std::int32_t>(call, res);
		}

		template<typename N>
		void aeabi_idivmod(llvm::CallInst* inst);

		template<typename N>
		void ldivmoddi(llvm::CallInst* inst);

		template<typename N>
		void modi(llvm::CallInst* inst);

		template<typename N>
		void divi(llvm::CallInst* inst);

		template<typename N>
		void udivi(llvm::CallInst* inst);

		template<typename N>
		void addi(llvm::CallInst* inst);

		template<typename N>
		void ashldi3(llvm::CallInst* inst);

		template<typename N>
		void ashrdi3(llvm::CallInst* inst);

		template<typename N>
		void lshrdi3(llvm::CallInst* inst);

		template<typename N>
		void muli(llvm::CallInst* inst);

		template<typename N>
		void negi(llvm::CallInst* inst);

		template<typename N>
		void subi(llvm::CallInst* inst);

		template<typename N>
		void umodi(llvm::CallInst* inst);

		template<typename N>
		void addf(llvm::CallInst* inst);

		template<typename N>
		void divf(llvm::CallInst* inst);

		template<typename N>
		void mulf(llvm::CallInst* inst);

		template<typename N>
		void subf(llvm::CallInst* inst);

		template<typename N>
		void subrf(llvm::CallInst* inst);

		template<typename N>
		void negf(llvm::CallInst* inst);

		template<typename N>
		void fp2si32(llvm::CallInst* inst);

		template<typename N>
		void fp2si64(llvm::CallInst* inst);

		template<typename N>
		void fp2ui32(llvm::CallInst* inst);

		template<typename N>
		void fp2ui64(llvm::CallInst* inst);

		template<typename N>
		void si2float(llvm::CallInst* inst);

		template<typename N>
		void si2double(llvm::CallInst* inst);

		template<typename N>
		void ui2float(llvm::CallInst* inst);

		template<typename N>
		void ui2double(llvm::CallInst* inst);

		void float2double(llvm::CallInst* inst);

		void double2float(llvm::CallInst* inst);

		template<typename N>
		void cmpf(llvm::CallInst* inst, bool revert = false);

		template<typename N>
		void gef(llvm::CallInst* inst);

		template<typename N>
		void lef(llvm::CallInst* inst);

		template<typename N>
		void cmpdi2(llvm::CallInst* inst);

		template<typename N>
		void ucmpdi2(llvm::CallInst* inst);

		template<typename N>
		void eqf(llvm::CallInst* inst);

		template<typename N>
		void gtf(llvm::CallInst* inst, bool reverse = false);

		template<typename N>
		void ltf(llvm::CallInst* inst);

		template<typename N>
		void nef(llvm::CallInst* inst);

		template<typename N>
		void cmpge(llvm::CallInst* inst, bool reverse = false);

		template<typename N>
		void rcmpge(llvm::CallInst* inst);

}; // IdiomsLibgccImpl

/**
 * @return @c True if analysis should continue, @c false if there is nothing
 *         to do for the current architecture.
 */
bool IdiomsLibgccImpl::testArchAndInitialize(
		config::Architecture& arch,
		Abi* abi)
{
	if (arch.isArmOrThumb())
	{
		op0Single = abi->getRegister(ARM_REG_R0);
		op0Double = abi->getRegister(ARM_REG_R0); // + r1
		op1Single = abi->getRegister(ARM_REG_R1);
		op1Double = abi->getRegister(ARM_REG_R2); // + r3
		res0Single = abi->getRegister(ARM_REG_R0);
		res0Double = abi->getRegister(ARM_REG_R0); // + r1
		res1Single = abi->getRegister(ARM_REG_R1);
		res1Double = abi->getRegister(ARM_REG_R2); // + r3
	}
	else if (arch.isPic32())
	{
		op0Single = abi->getRegister(MIPS_REG_A0);
		op0Double = abi->getRegister(MIPS_REG_A0); // + a1
		op1Single = abi->getRegister(MIPS_REG_A1);
		op1Double = abi->getRegister(MIPS_REG_A2); // + a3

//		res0Single = abi->getRegister(MIPS_REG_A0);
//		res0Double = abi->getRegister(MIPS_REG_A0); // + a1
//		res1Single = abi->getRegister(MIPS_REG_A1);
//		res1Double = abi->getRegister(MIPS_REG_A2); // + a3

		res0Single = abi->getRegister(MIPS_REG_V0);
		res0Double = abi->getRegister(MIPS_REG_V0); // + a1
		res1Single = abi->getRegister(MIPS_REG_V1);
		res1Double = abi->getRegister(MIPS_REG_V1); // + a3
	}
	else
	{
		return false;
	}
	return true;
}

void IdiomsLibgccImpl::localize(llvm::Value* v)
{
	Instruction* i = dyn_cast<Instruction>(llvm_utils::skipCasts(v));
	if (i == nullptr)
	{
		return;
	}

	auto defs = ReachingDefinitionsAnalysis::defsFromUse_onDemand(i);
	if (defs.size() != 1)
	{
		return;
	}
	auto* def = dyn_cast<StoreInst>(*defs.begin());

	auto uses = ReachingDefinitionsAnalysis::usesFromDef_onDemand(def);
	IrModifier::localize(def, uses);
}

void IdiomsLibgccImpl::log(
		llvm::Instruction* orig,
		std::initializer_list<llvm::Value*> news)
{
	LOG << llvmObjToString(orig) << std::endl;
	for (auto* n : news)
	{
		LOG << "\t" << llvmObjToString(n) << std::endl;
	}
}

template<>
llvm::Value* IdiomsLibgccImpl::getOp0<std::int32_t>(llvm::CallInst* call)
{
	return new llvm::LoadInst(op0Single, "", call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getOp0<std::int64_t>(llvm::CallInst* call)
{
	return new llvm::LoadInst(op0Double, "", call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getOp0<float>(llvm::CallInst* call)
{
	auto* t = Type::getFloatTy(call->getContext());
	auto* l = new llvm::LoadInst(op0Single, "", call);
	return IrModifier::convertValueToType(l, t, call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getOp0<double>(llvm::CallInst* call)
{
	auto* t = Type::getDoubleTy(call->getContext());
	auto* l = new llvm::LoadInst(op0Double, "", call);
	return IrModifier::convertValueToType(l, t, call);
}

template<>
llvm::Value* IdiomsLibgccImpl::getOp1<std::int32_t>(llvm::CallInst* call)
{
	return new llvm::LoadInst(op1Single, "", call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getOp1<std::int64_t>(llvm::CallInst* call)
{
	return new llvm::LoadInst(op1Double, "", call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getOp1<float>(llvm::CallInst* call)
{
	auto* t = Type::getFloatTy(call->getContext());
	auto* l = new llvm::LoadInst(op1Single, "", call);
	return IrModifier::convertValueToType(l, t, call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getOp1<double>(llvm::CallInst* call)
{
	auto* t = Type::getDoubleTy(call->getContext());
	auto* l = new llvm::LoadInst(op1Double, "", call);
	return IrModifier::convertValueToType(l, t, call);
}

template<>
llvm::Value* IdiomsLibgccImpl::getRes0<std::int32_t>(
		llvm::CallInst* call,
		llvm::Value* res)
{
	auto* c = IrModifier::convertValueToType(
			res,
			res0Single->getType()->getElementType(),
			call);
	return new llvm::StoreInst(c, res0Single, call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getRes0<std::int64_t>(
		llvm::CallInst* call,
		llvm::Value* res)
{
	auto* c = IrModifier::convertValueToType(
			res,
			res0Double->getType()->getElementType(),
			call);
	return new llvm::StoreInst(c, res0Double, call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getRes0<float>(
		llvm::CallInst* call,
		llvm::Value* res)
{
	auto* c = IrModifier::convertValueToType(
			res,
			res0Single->getType()->getElementType(),
			call);
	return new llvm::StoreInst(c, res0Single, call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getRes0<double>(
		llvm::CallInst* call,
		llvm::Value* res)
{
	auto* resType = res0Double->getType()->getElementType();
	auto* c = IrModifier::convertValueToType(res, resType, call);
	return new llvm::StoreInst(c, res0Double, call);
}

template<>
llvm::Value* IdiomsLibgccImpl::getRes1<std::int32_t>(
		llvm::CallInst* call,
		llvm::Value* res)
{
	auto* c = IrModifier::convertValueToType(
			res,
			res1Single->getType()->getElementType(),
			call);
	return new llvm::StoreInst(c, res1Single, call);
}
template<>
llvm::Value* IdiomsLibgccImpl::getRes1<std::int64_t>(
		llvm::CallInst* call,
		llvm::Value* res)
{
	auto* c = IrModifier::convertValueToType(
			res,
			res1Double->getType()->getElementType(),
			call);
	return new llvm::StoreInst(c, res1Double, call);
}

void IdiomsLibgccImpl::replaceResultUses(llvm::CallInst* c, llvm::Instruction* r)
{
	for (auto it = c->user_begin(), end = c->user_end(); it != end;)
	{
		auto* s = dyn_cast<StoreInst>(*it);
		assert(s);
		++it;
		if (s)
		{
			s->eraseFromParent();
		}
	}
	if (c->user_empty())
	{
		c->eraseFromParent();
	}
}

/**
 * i32 (unsigned):
 *   reg0 = reg0 / reg1
 *   reg1 = reg0 % reg1
 * i64 (unsigned):
 *   reg0:reg1 = reg0:reg1 / reg2:reg3
 *   reg2:reg3 = reg0:reg1 % reg2:reg3  // result reg4:reg5 ???
 */
template<typename N>
void IdiomsLibgccImpl::aeabi_idivmod(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateUDiv(l0, l1, "", inst);
	auto* r1 = BinaryOperator::CreateURem(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);
	auto* s1 = getRes1<N>(inst, r1);

	log(inst, {l0, l1, r0, r1, s0, s1});

	replaceResultUses(inst, r0);
}

/**
 * i32 (signed):
 *   reg0 = reg0 / reg1
 *   reg1 = reg0 % reg1
 * i64 (signed):
 *   reg0:reg1 = reg0:reg1 / reg2:reg3
 *   reg2:reg3 = reg0:reg1 % reg2:reg3  // result reg4:reg5 ???
 */
template<typename N>
void IdiomsLibgccImpl::ldivmoddi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateSDiv(l0, l1, "", inst);
	auto* r1 = BinaryOperator::CreateSRem(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);
	auto* s1 = getRes1<N>(inst, r1);

	log(inst, {l0, l1, r0, r1, s0, s1});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = reg0 % reg1
 * i64:
 *   reg0:reg1 = reg0:reg1 % reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::modi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateSRem(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = reg0 / reg1
 * i64:
 *   reg0:reg1 = reg0:reg1 / reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::divi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateSDiv(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = reg0 / reg1
 * i64:
 *   reg0:reg1 = reg0:reg1 / reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::udivi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateUDiv(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = reg0 + reg1
 * i64:
 *   reg0:reg1 = reg0:reg1 + reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::addi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateAdd(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i64:
 *   reg0:reg1 = reg0:reg1 << reg2
 */
template<typename N>
void IdiomsLibgccImpl::ashldi3(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateShl(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i64:
 *   reg0:reg1 = reg0:reg1 (arithmetic) >> reg2
 */
template<typename N>
void IdiomsLibgccImpl::ashrdi3(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateAShr(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i64:
 *   reg0:reg1 = reg0:reg1 (logical) >> reg2
 */
template<typename N>
void IdiomsLibgccImpl::lshrdi3(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateLShr(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i64:
 *   reg0:reg1 = reg0:reg1 * reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::muli(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateMul(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = - reg0
 * i64:
 *   reg0:reg1 = - reg0:reg1
 */
template<typename N>
void IdiomsLibgccImpl::negi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* zero = ConstantInt::get(l0->getType(), 0);
	auto* r0 = BinaryOperator::CreateMul(zero, l0, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = reg0 - reg1
 * i64:
 *   reg0:reg1 = reg0:reg1 - reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::subi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateSub(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32:
 *   reg0 = reg0 % reg1
 * i64:
 *   reg0:reg01 = reg0:reg01 % reg2:reg03
 */
template<typename N>
void IdiomsLibgccImpl::umodi(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateURem(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float:
 *   reg0 = reg0 + reg1
 * double:
 *   reg0:reg1 = reg0:reg1 + reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::addf(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateFAdd(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);

	localize(l0);
	localize(l1);
}

/**
 * float:
 *   reg0 = reg0 / reg0
 * double:
 *   reg0:reg1 = reg0:reg1 / reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::divf(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateFDiv(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);

	localize(l0);
	localize(l1);
}

/**
 * float:
 *   reg0 = reg0 * reg0
 * double:
 *   reg0:reg1 = reg0:reg1 * reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::mulf(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateFMul(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);

	localize(l0);
	localize(l1);
}

/**
 * float:
 *   reg0 = reg0 - reg1
 * double:
 *   reg0:reg1 = reg0:reg1 - reg2:reg3
 */
template<typename N>
void IdiomsLibgccImpl::subf(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* r0 = BinaryOperator::CreateFSub(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);

	localize(l0);
	localize(l1);
}

/**
 * float:
 *   reg0 = reg1 - reg0
 * double:
 *   reg0:reg1 = reg2:reg3 - reg0:reg1
 */
template<typename N>
void IdiomsLibgccImpl::subrf(llvm::CallInst* inst)
{
	auto* l0 = getOp1<N>(inst);
	auto* l1 = getOp0<N>(inst);
	auto* r0 = BinaryOperator::CreateFSub(l0, l1, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, l1, r0, s0});
	replaceResultUses(inst, r0);

	localize(l0);
	localize(l1);
}

/**
 * float:
 *   reg0 = - reg0
 * double:
 *   reg0:regs1 = - reg0:regs1
 */
template<typename N>
void IdiomsLibgccImpl::negf(llvm::CallInst* inst)
{
	auto* l0 = getOp0<N>(inst);
	auto* zero = ConstantFP::getZeroValueForNegation(l0->getType());
	auto* r0 = BinaryOperator::CreateFSub(zero, l0, "", inst);
	auto* s0 = getRes0<N>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float:
 *   float -> i32 (signed)
 * double:
 *   double -> i32 (signed)
 */
template<typename N>
void IdiomsLibgccImpl::fp2si32(llvm::CallInst* inst)
{
	auto* t = Type::getInt32Ty(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new FPToSIInst(l0, t, "", inst);
	auto* s0 = getRes0<std::int32_t>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float:
 *   float -> i64 (signed)
 * double:
 *   double -> i64 (signed)
 */
template<typename N>
void IdiomsLibgccImpl::fp2si64(llvm::CallInst* inst)
{
	auto* t = Type::getInt64Ty(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new FPToSIInst(l0, t, "", inst);
	auto* s0 = getRes0<std::int64_t>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float:
 *   float -> i32 (unsigned)
 * double:
 *   double -> i32 (unsigned)
 */
template<typename N>
void IdiomsLibgccImpl::fp2ui32(llvm::CallInst* inst)
{
	auto* t = Type::getInt32Ty(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new FPToUIInst(l0, t, "", inst);
	auto* s0 = getRes0<std::int32_t>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float:
 *   float -> i64 (unsigned)
 * double:
 *   double -> i64 (unsigned)
 */
template<typename N>
void IdiomsLibgccImpl::fp2ui64(llvm::CallInst* inst)
{
	auto* t = Type::getInt64Ty(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new FPToUIInst(l0, t, "", inst);
	auto* s0 = getRes0<std::int64_t>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32 (signed):
 *   i32 -> float
 * i64 (signed):
 *   i64 -> float
 */
template<typename N>
void IdiomsLibgccImpl::si2float(llvm::CallInst* inst)
{
	auto* t = Type::getFloatTy(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new SIToFPInst(l0, t, "", inst);
	auto* s0 = getRes0<float>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32 (signed):
 *   i32 -> double
 * i64 (signed):
 *   i64 -> double
 */
template<typename N>
void IdiomsLibgccImpl::si2double(llvm::CallInst* inst)
{
	auto* t = Type::getDoubleTy(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new SIToFPInst(l0, t, "", inst);
	auto* s0 = getRes0<double>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32 (unsigned):
 *   i32 -> float
 * i64 (unsigned):
 *   i64 -> float
 */
template<typename N>
void IdiomsLibgccImpl::ui2float(llvm::CallInst* inst)
{
	auto* t = Type::getFloatTy(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new UIToFPInst(l0, t, "", inst);
	auto* s0 = getRes0<float>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * i32 (unsigned):
 *   i32 -> double
 * i64 (unsigned):
 *   i64 -> double
 */
template<typename N>
void IdiomsLibgccImpl::ui2double(llvm::CallInst* inst)
{
	auto* t = Type::getDoubleTy(inst->getContext());
	auto* l0 = getOp0<N>(inst);
	auto* r0 = new UIToFPInst(l0, t, "", inst);
	auto* s0 = getRes0<double>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float -> double
 */
void IdiomsLibgccImpl::float2double(llvm::CallInst* inst)
{
	auto* t = Type::getDoubleTy(inst->getContext());
	auto* l0 = getOp0<float>(inst);
	auto* r0 = new FPExtInst(l0, t, "", inst);
	auto* s0 = getRes0<double>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * double -> float
 */
void IdiomsLibgccImpl::double2float(llvm::CallInst* inst)
{
	auto* t = Type::getFloatTy(inst->getContext());
	auto* l0 = getOp0<double>(inst);
	auto* r0 = new FPTruncInst(l0, t, "", inst);
	auto* s0 = getRes0<float>(inst, r0);

	log(inst, {l0, r0, s0});
	replaceResultUses(inst, r0);
}

/**
 * float:
 *   if (reg0 > reg1)
 *     reg0 = 1
 *   else if (reg0 < reg1)
 *     reg0 = -1
 *   else // equal
 *     reg0 = 0
 *
 * double:
 *   if (reg0:reg1 > reg2:reg3)
 *     reg0 = 1
 *   else if (reg0:reg1 < reg2:reg3)
 *     reg0 = -1
 *   else // equal
 *     reg0 = 0
 *
 * ==>
 *
 * a = (reg0 > reg1)
 * b = (reg0 == reg1)
 * c = select a, 1, -1
 * d = select b, 0, c
 * store d, reg0
 */
template<typename N>
void IdiomsLibgccImpl::cmpf(llvm::CallInst* inst, bool revert)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	if (revert)
	{
		auto* tmp = l0;
		l0 = l1;
		l1 = tmp;
	}
	auto* a = new FCmpInst(inst, CmpInst::FCMP_OGT, l0, l1);
	auto* b = new FCmpInst(inst, CmpInst::FCMP_OEQ, l0, l1);
	auto* c = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, -1),
			"",
			inst);
	auto* d = SelectInst::Create(
			b,
			ConstantInt::getSigned(t, 0),
			c,
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, d);

	log(inst, {l0, l1, a, b, c, d, s});
	replaceResultUses(inst, d);
}

/**
 * gedf2()/gesf2()
 * df:
 *   if (reg0:reg1 == reg2:reg3)
 *     reg0 = 0
 *   else if (reg0:reg1 > reg2:reg3)
 *     reg0 = 1
 *   else if (reg0:reg1 < reg2:reg3)
 *     reg0 = -1
 * sf:
 *   if (reg0 == reg1)
 *     reg0 = 0
 *   else if (reg0 > reg1)
 *     reg0 = 1
 *   else if (reg0 < reg1)
 *     reg0 = -1
 *
 * same as cmpf() but reverted operands.
 */
template<typename N>
void IdiomsLibgccImpl::gef(llvm::CallInst* inst)
{
	cmpf<N>(inst, false);
}

/**
 * ledf2()/lesf2()
 */
template<typename N>
void IdiomsLibgccImpl::lef(llvm::CallInst* inst)
{
	cmpf<N>(inst, true);
}

/**
 * cmpdi2()
 * if (reg0:reg1 > reg2:reg3)
 *   reg0 = 1
 * else if (reg0:reg1 < reg2:reg3)
 *   reg0 = -1
 * else // equal
 *   reg0 = 0
 *
 * same as cmpf() but with (long?) integers.
 *
 * TODO: google these functions, it looks like:
 * __aeabi_lcmp() = __cmpdi2() - 1
 */
template<typename N>
void IdiomsLibgccImpl::cmpdi2(llvm::CallInst* inst)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* a = new ICmpInst(inst, CmpInst::ICMP_SGT, l0, l1);
	auto* b = new ICmpInst(inst, CmpInst::ICMP_EQ, l0, l1);
	auto* c = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, -1),
			"",
			inst);
	auto* d = SelectInst::Create(
			b,
			ConstantInt::getSigned(t, 0),
			c,
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, d);

	log(inst, {l0, l1, a, b, c, d, s});
	replaceResultUses(inst, d);
}

/**
 * ucmpdi2()
 * if (reg0:reg1 < reg2:reg3)
 *   reg0 = 0
 * else if (reg0:reg1 == reg2:reg3)
 *   reg0 = 1
 * else if (reg0:reg1 > reg2:reg3)
 *   reg0 = 2
 */
template<typename N>
void IdiomsLibgccImpl::ucmpdi2(llvm::CallInst* inst)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* a = new ICmpInst(inst, CmpInst::ICMP_UGT, l0, l1);
	auto* b = new ICmpInst(inst, CmpInst::ICMP_EQ, l0, l1);
	auto* c = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, -1),
			"",
			inst);
	auto* d = SelectInst::Create(
			b,
			ConstantInt::getSigned(t, 0),
			c,
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, d);

	log(inst, {l0, l1, a, b, c, d, s});
	replaceResultUses(inst, d);
}

/**
 * eqdf2()/eqsf2()
 * df:
 *   if (reg0:reg1 == reg2:reg3)
 *     reg0 = 1
 *   else
 *     reg0 = 0
 * sf:
 *   if (reg0 == reg1)
 *     reg0 = 1
 *   else
 *     reg0 = 0
 */
template<typename N>
void IdiomsLibgccImpl::eqf(llvm::CallInst* inst)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* a = new FCmpInst(inst, CmpInst::FCMP_OEQ, l0, l1);
	auto* b = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, 0),
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, b);

	log(inst, {l0, l1, a, b, s});
	replaceResultUses(inst, b);
}

/**
 * gtdf2()/gtsf2()
 * df:
 *   if (reg0:reg1 > reg2:reg3)
 *     reg0 = 1
 *   else
 *     reg0 = 0
 * sf:
 *   if (reg0 > reg1)
 *     reg0 = 1
 *   else
 *     reg0 = 0
 */
template<typename N>
void IdiomsLibgccImpl::gtf(llvm::CallInst* inst, bool reverse)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* a = new FCmpInst(inst, CmpInst::FCMP_OGT, l0, l1);
	auto* b = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, 0),
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, b);

	log(inst, {l0, l1, a, b, s});
	replaceResultUses(inst, b);
}

/**
 * ltdf2()/ltsf2()
 */
template<typename N>
void IdiomsLibgccImpl::ltf(llvm::CallInst* inst)
{
	gtf<N>(inst, true);
}

/**
 * nedf2()/nesf2()
 */
template<typename N>
void IdiomsLibgccImpl::nef(llvm::CallInst* inst)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* a = new FCmpInst(inst, CmpInst::FCMP_ONE, l0, l1);
	auto* b = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, 0),
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, b);

	log(inst, {l0, l1, a, b, s});
	replaceResultUses(inst, b);
}

/**
 * aeabi_fcmpge()/aeabi_dcmpge()/aeabi_fcmple()/aeabi_dcmple()
 *
 *   if (a ?? b)
 *     a = 1
 *   else
 *     b = 0
 *
 * where a, b is reg or reg pair depending on df
 * and ?? is >= or <= for reverse == true
 */
template<typename N>
void IdiomsLibgccImpl::cmpge(llvm::CallInst* inst, bool reverse)
{
	auto* t = Abi::getDefaultType(inst->getModule());
	auto* l0 = getOp0<N>(inst);
	auto* l1 = getOp1<N>(inst);
	auto* a = reverse ?
			new FCmpInst(inst, CmpInst::FCMP_OLE, l0, l1):
			new FCmpInst(inst, CmpInst::FCMP_OGE, l0, l1);
	auto* b = SelectInst::Create(
			a,
			ConstantInt::getSigned(t, 1),
			ConstantInt::getSigned(t, 0),
			"",
			inst);
	auto* s = getRes0<std::int32_t>(inst, b);

	log(inst, {l0, l1, a, b, s});
	replaceResultUses(inst, b);
}

template<typename N>
void IdiomsLibgccImpl::rcmpge(llvm::CallInst* inst)
{
	return cmpge<N>(inst, true);
}

//
//==============================================================================
// IdiomsLibgcc
//==============================================================================
//

#define ID_FNC_PAIR(ID, FNC) \
		{ID, [this] (llvm::CallInst* c) { return this->_impl->FNC(c); }}

char IdiomsLibgcc::ID = 0;

static RegisterPass<IdiomsLibgcc> X(
		"idioms-libgcc",
		"Libgcc idioms optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

/**
 * Check the given container for element ordering problems.
 * Entries in the container are tried to be applied from first to last.
 * Function ID of any element can not be contained in any later element,
 * otherwise later would never be applied.
 * @param fnc2action This method could access @c _fnc2action directly, but
 *                   we want to unit test it with custom container.
 * @return @c True if problem in map found, @c false otherwise.
 * @note Method is static so it can be easily used in unit tests.
 */
bool IdiomsLibgcc::checkFunctionToActionMap(const Fnc2Action& fnc2action)
{
	for (auto it = fnc2action.begin(); it != fnc2action.end(); ++it)
	{
		auto next = it;
		++next;
		while (next != fnc2action.end())
		{
			if (contains(next->first, it->first))
			{
				LOG << it->first << " in " << next->first << std::endl;
				return true;
			}
			++next;
		}
	}
	return false;
}

IdiomsLibgcc::IdiomsLibgcc() :
		ModulePass(ID),
		_impl(std::make_unique<IdiomsLibgccImpl>())
{
	_fnc2action =
	{
			// integers
			//
			ID_FNC_PAIR("aeabi_uidiv_from_thumb", udivi<std::int32_t>),
			ID_FNC_PAIR("aeabi_idiv_from_thumb", udivi<std::int32_t>),
			ID_FNC_PAIR("aeabi_idivmod", aeabi_idivmod<std::int32_t>),
			ID_FNC_PAIR("aeabi_uidivmod", aeabi_idivmod<std::int32_t>),
			ID_FNC_PAIR("aeabi_uidiv", udivi<std::int32_t>),
			ID_FNC_PAIR("aeabi_idiv", divi<std::int32_t>),
			ID_FNC_PAIR("udivmoddi4", aeabi_idivmod<std::int64_t>),
			ID_FNC_PAIR("aeabiuldivmod", aeabi_idivmod<std::int64_t>),
			ID_FNC_PAIR("umodsi3", umodi<std::int32_t>),
			ID_FNC_PAIR("umoddi3", umodi<std::int64_t>),
			ID_FNC_PAIR("modsi3", modi<std::int32_t>),
			ID_FNC_PAIR("moddi3", modi<std::int64_t>),
			ID_FNC_PAIR("udivsi3", udivi<std::int32_t>),
			ID_FNC_PAIR("divsi3", divi<std::int32_t>),
			ID_FNC_PAIR("udiv_w_sdiv", divi<std::int32_t>),
			ID_FNC_PAIR("udivdi3", udivi<std::int64_t>),
			ID_FNC_PAIR("divdi3", divi<std::int64_t>),
			ID_FNC_PAIR("addvsi3", addi<std::int32_t>),
			ID_FNC_PAIR("addvdi3", addi<std::int64_t>),
			ID_FNC_PAIR("ashldi3", ashldi3<std::int64_t>),
			ID_FNC_PAIR("aeabillsl", ashldi3<std::int64_t>),
			ID_FNC_PAIR("ashrdi3", ashrdi3<std::int64_t>),
			ID_FNC_PAIR("aeabilasr", ashrdi3<std::int64_t>),
			ID_FNC_PAIR("lshrdi3", lshrdi3<std::int64_t>),
			ID_FNC_PAIR("aeabillsr", lshrdi3<std::int64_t>),
			ID_FNC_PAIR("muldi3", muli<std::int64_t>),
			ID_FNC_PAIR("aeabilmul", muli<std::int64_t>),
			ID_FNC_PAIR("negdi2", negi<std::int64_t>),
			ID_FNC_PAIR("negvdi2", negi<std::int64_t>),
			ID_FNC_PAIR("negvsi2", negi<std::int32_t>),
			ID_FNC_PAIR("subvsi3", subi<std::int32_t>),
			ID_FNC_PAIR("subvdi3", subi<std::int64_t>),
			ID_FNC_PAIR("aeabildivmod", ldivmoddi<std::int64_t>),

			// floats
			//
			ID_FNC_PAIR("mulsf3", mulf<float>),
			ID_FNC_PAIR("fpmul", mulf<float>),
			ID_FNC_PAIR("aeabifmul", mulf<float>),
			ID_FNC_PAIR("muldf3", mulf<double>),
			ID_FNC_PAIR("aeabidmul", mulf<double>),
			ID_FNC_PAIR("aeabi_dmul", mulf<double>),
			ID_FNC_PAIR("addsf3", addf<float>),
			ID_FNC_PAIR("fpadd", addf<float>),
			ID_FNC_PAIR("aeabifadd", addf<float>),
			ID_FNC_PAIR("adddf3", addf<double>),
			ID_FNC_PAIR("aeabidadd", addf<double>),
			ID_FNC_PAIR("aeabi_dadd", addf<double>),
			ID_FNC_PAIR("divsf3", divf<float>),
			ID_FNC_PAIR("fpdiv", divf<float>),
			ID_FNC_PAIR("aeabifdiv", divf<float>),
			ID_FNC_PAIR("divdf3", divf<double>),
			ID_FNC_PAIR("aeabiddiv", divf<double>),
			ID_FNC_PAIR("aeabi_ddiv", divf<double>),
			ID_FNC_PAIR("subdf3", subf<double>),
			ID_FNC_PAIR("aeabidsub", subf<double>),
			ID_FNC_PAIR("subsf3", subf<float>),
			ID_FNC_PAIR("aeabifsub", subf<float>),
			ID_FNC_PAIR("aeabifrsub", subrf<float>),
			ID_FNC_PAIR("aeabidrsub", subrf<double>),
			ID_FNC_PAIR("negdf2", negf<double>),
			ID_FNC_PAIR("negsf2", negf<float>),

			// casts
			//
			ID_FNC_PAIR("fixsfsi", fp2si32<float>),
			ID_FNC_PAIR("fptosi", fp2si32<float>),
			ID_FNC_PAIR("aeabif2iz", fp2si32<float>),
			ID_FNC_PAIR("fixdfsi", fp2si32<double>),
			ID_FNC_PAIR("aeabid2iz", fp2si32<double>),
			ID_FNC_PAIR("aeabi_d2iz", fp2si32<double>),
			ID_FNC_PAIR("fixdfdi", fp2si64<double>),
			ID_FNC_PAIR("aeabid2lz", fp2si64<double>),
			ID_FNC_PAIR("fixsfdi", fp2si64<float>),
			ID_FNC_PAIR("fptoli", fp2si64<float>),
			ID_FNC_PAIR("aeabif2lz", fp2si64<float>),
			ID_FNC_PAIR("extendsfdf2", float2double),
			ID_FNC_PAIR("aeabid2f", float2double),
			ID_FNC_PAIR("aeabi_f2d", float2double),
			ID_FNC_PAIR("truncdfsf2", double2float),
			ID_FNC_PAIR("aeabif2d", double2float),
			ID_FNC_PAIR("aeabi_d2f", double2float),
			ID_FNC_PAIR("floatsisf", si2float<std::int32_t>),
			ID_FNC_PAIR("sitofp", si2float<std::int32_t>),
			ID_FNC_PAIR("aeabii2f", si2float<std::int32_t>),
			ID_FNC_PAIR("aeabi_i2f", si2float<std::int32_t>),
			ID_FNC_PAIR("floatdisf", si2float<std::int64_t>),
			ID_FNC_PAIR("aeabil2f", si2float<std::int64_t>),
			ID_FNC_PAIR("floatsidf", si2double<std::int32_t>),
			ID_FNC_PAIR("aeabii2d", si2double<std::int32_t>),
			ID_FNC_PAIR("aeabi_i2d", si2double<std::int32_t>),
			ID_FNC_PAIR("floatdidf", si2double<std::int64_t>),
			ID_FNC_PAIR("aeabil2d", si2double<std::int64_t>),
			ID_FNC_PAIR("fixunsdfdi", fp2ui64<double>),
			ID_FNC_PAIR("aeabid2ulz", fp2ui64<double>),
			ID_FNC_PAIR("fixunssfdi", fp2ui64<float>),
			ID_FNC_PAIR("aeabif2ulz", fp2ui64<float>),
			ID_FNC_PAIR("fixunsdfsi", fp2ui32<double>),
			ID_FNC_PAIR("aeabid2uiz", fp2ui32<double>),
			ID_FNC_PAIR("fixunssfsi", fp2ui32<float>),
			ID_FNC_PAIR("aeabif2uiz", fp2ui32<float>),
			ID_FNC_PAIR("floatunsidf", ui2double<std::int32_t>),
			ID_FNC_PAIR("ui2d", ui2double<std::int32_t>),
			ID_FNC_PAIR("floatundidf", ui2double<std::int64_t>),
			ID_FNC_PAIR("aeabiul2d", ui2double<std::int64_t>),
			ID_FNC_PAIR("floatunsisf", ui2float<std::int32_t>),
			ID_FNC_PAIR("aeabiui2f", ui2float<std::int32_t>),
			ID_FNC_PAIR("floatundisf", ui2float<std::int64_t>),
			ID_FNC_PAIR("aeabiul2f", ui2float<std::int64_t>),

			// comparisons
			//
			ID_FNC_PAIR("cmpdf2", cmpf<double>),
			ID_FNC_PAIR("cmpsf2", cmpf<float>),
			ID_FNC_PAIR("gedf2", gef<double>),
			ID_FNC_PAIR("gesf2", gef<float>),
			ID_FNC_PAIR("ucmpdi2", ucmpdi2<std::int64_t>),
			ID_FNC_PAIR("cmpdi2", cmpdi2<std::int64_t>),
			ID_FNC_PAIR("aeabilcmp", cmpdi2<std::int64_t>),
			ID_FNC_PAIR("aeabiulcmp", ucmpdi2<std::int64_t>),
			ID_FNC_PAIR("eqdf2", eqf<double>),
			ID_FNC_PAIR("aeabidcmpeq", eqf<double>),
			ID_FNC_PAIR("eqsf2", eqf<float>),
			ID_FNC_PAIR("aeabifcmpeq", eqf<float>),
			ID_FNC_PAIR("gtdf2", gtf<double>),
			ID_FNC_PAIR("aeabidcmpgt", gtf<double>),
			ID_FNC_PAIR("gtsf2", gtf<float>),
			ID_FNC_PAIR("aeabifcmpgt", gtf<float>),
			ID_FNC_PAIR("ledf2", lef<double>),
			ID_FNC_PAIR("lesf2", lef<float>),
			ID_FNC_PAIR("ltdf2", ltf<double>),
			ID_FNC_PAIR("aeabidcmplt", ltf<double>),
			ID_FNC_PAIR("ltsf2", ltf<float>),
			ID_FNC_PAIR("aeabifcmplt", ltf<float>),
			ID_FNC_PAIR("nedf2", nef<double>),
			ID_FNC_PAIR("nesf2", nef<float>),
			ID_FNC_PAIR("aeabidcmpge", rcmpge<double>),
			ID_FNC_PAIR("aeabifcmpge", rcmpge<float>),
			ID_FNC_PAIR("aeabidcmple", cmpge<double>),
			ID_FNC_PAIR("aeabifcmple", cmpge<float>)
	};

	assert(!checkFunctionToActionMap(_fnc2action));
}

bool IdiomsLibgcc::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool IdiomsLibgcc::runOnModuleCustom(llvm::Module& M, Config* c, Abi* abi)
{
	_module = &M;
	_config = c;
	_abi = abi;
	return run();
}

bool IdiomsLibgcc::run()
{
	if (_config == nullptr || _abi == nullptr)
	{
		return false;
	}

	if (!_impl->testArchAndInitialize(_config->getConfig().architecture, _abi))
	{
		return false;
	}

	bool changed = false;

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction* insn = &*it;
		++it;
		// Move to the next call. Other instructions might get removed by
		// analuzing this call.
		while (it != eIt && !isa<CallInst>(*it))
		{
			++it;
		}

		changed |= runInstruction(insn);
	}

	return changed;
}

bool IdiomsLibgcc::runInstruction(llvm::Instruction* inst)
{
	CallInst* call = dyn_cast<CallInst>(inst);
	if (call == nullptr || call->getCalledFunction() == nullptr)
	{
		return false;
	}

	std::string calledFnc = call->getCalledFunction()->getName();

	for (auto& p : _fnc2action)
	{
		if (contains(calledFnc, p.first))
		{
			p.second(call);
			return true;
		}
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
