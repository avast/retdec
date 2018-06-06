/**
 * @file src/capstone2llvmir/arm/arm_impl.h
 * @brief ARM implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_ARM_ARM_IMPL_H
#define CAPSTONE2LLVMIR_ARM_ARM_IMPL_H

#include "retdec/capstone2llvmir/arm/arm.h"
#include "capstone2llvmir/capstone2llvmir_impl.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorArm_impl :
		public Capstone2LlvmIrTranslator_impl<cs_arm, cs_arm_op>,
		public Capstone2LlvmIrTranslatorArm
{
	public:
		Capstone2LlvmIrTranslatorArm_impl(
				llvm::Module* m,
				cs_mode basic = CS_MODE_ARM,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorArm_impl();
//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//
	public:
		virtual bool isAllowedBasicMode(cs_mode m) override;
		virtual bool isAllowedExtraMode(cs_mode m) override;
		virtual uint32_t getArchByteSize() override;
//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//
	protected:
		virtual void initializeArchSpecific() override;
		virtual void initializeRegNameMap() override;
		virtual void initializeRegTypeMap() override;
		virtual void initializePseudoCallInstructionIDs() override;
		virtual void generateEnvironmentArchSpecific() override;
		virtual void generateDataLayout() override;
		virtual void generateRegisters() override;
		virtual uint32_t getCarryRegister() override;

		virtual void translateInstruction(
				cs_insn* i,
				llvm::IRBuilder<>& irb) override;
//
//==============================================================================
// ARM-specific methods.
//==============================================================================
//
	protected:
		llvm::Value* getCurrentPc(cs_insn* i);

		virtual llvm::Value* loadRegister(
				uint32_t r,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW) override;
		virtual llvm::Value* loadOp(
				cs_arm_op& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr,
				bool lea = false) override;

		virtual llvm::Instruction* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC) override;
		virtual llvm::Instruction* storeOp(
				cs_arm_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC) override;

		llvm::Value* generateInsnConditionCode(
				llvm::IRBuilder<>& irb,
				cs_arm* ai);

		llvm::Value* generateOperandShift(
				llvm::IRBuilder<>& irb,
				cs_arm_op& op,
				llvm::Value* val);
		llvm::Value* generateShiftAsr(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n);
		llvm::Value* generateShiftLsl(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n);
		llvm::Value* generateShiftLsr(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n);
		llvm::Value* generateShiftRor(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n);
		llvm::Value* generateShiftRrx(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n);
//
//==============================================================================
// ARM implementation data.
//==============================================================================
//
	protected:
		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorArm_impl::*)(
					cs_insn* i,
					cs_arm*,
					llvm::IRBuilder<>&)> _i2fm;
//
//==============================================================================
// ARM instruction translation methods.
//==============================================================================
//
	protected:
		void translateAdc(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateAdd(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateAnd(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateB(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateBl(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateCbnz(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateCbz(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateClz(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateEor(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateLdmStm(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateLdr(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateLdrd(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateMla(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateMls(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateMov(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateMovt(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateMovw(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateMul(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateNop(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateOrr(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateRev(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateSbc(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateShifts(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateStr(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateSub(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateUmlal(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateUmull(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);

		void translateUxtah(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateUxtb(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateUxtb16(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateUxth(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);

		void translateBinaryPseudoAsm(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateTernaryPseudoAsm(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateTernaryPseudoAsm3Args(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateQuaternaryPseudoAsm(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateQuaternaryPseudoAsm4Args(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);
		void translateQuaternaryPseudoAsm4Args2Dsts(cs_insn* i, cs_arm* ai, llvm::IRBuilder<>& irb);

};

} // namespace capstone2llvmir
} // namespace retdec

#endif
