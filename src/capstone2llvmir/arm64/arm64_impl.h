/**
 * @file src/capstone2llvmir/arm64/arm64_impl.h
 * @brief ARM implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_ARM64_ARM64_IMPL_H
#define CAPSTONE2LLVMIR_ARM64_ARM64_IMPL_H

#include "retdec/capstone2llvmir/arm64/arm64.h"
#include "capstone2llvmir/capstone2llvmir_impl.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorArm64_impl :
		public Capstone2LlvmIrTranslator_impl<cs_arm64, cs_arm64_op>,
		public Capstone2LlvmIrTranslatorArm64
{
	public:
		Capstone2LlvmIrTranslatorArm64_impl(
				llvm::Module* m,
				cs_mode basic = CS_MODE_ARM,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorArm64_impl();
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
// Arm64 specialization methods - from Capstone2LlvmIrTranslatorX86
//==============================================================================
//
	public:

		virtual uint32_t getParentRegister(uint32_t r) const override;
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
// ARM64-specific methods.
//==============================================================================
//
	protected:
		llvm::Value* getCurrentPc(cs_insn* i);

		void initializeRegistersParentMapToOther(
				const std::vector<arm64_reg>& rs,
				arm64_reg other);

		void initializeRegistersParentMap();

		llvm::Value* generateOperandExtension(
				llvm::IRBuilder<>& irb,
				arm64_extender ext,
				llvm::Value* val,
				llvm::Type* destType = nullptr);

		llvm::Value* generateOperandShift(
				llvm::IRBuilder<>& irb,
				cs_arm64_op& op,
				llvm::Value* val,
				bool updateFlags = false);
		llvm::Value* generateShiftAsr(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n,
				bool updateFlags = false);
		llvm::Value* generateShiftLsl(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n,
				bool updateFlags = false);
		llvm::Value* generateShiftLsr(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n,
				bool updateFlags = false);
		llvm::Value* generateShiftRor(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n,
				bool updateFlags = false);
		llvm::Value* generateShiftMsl(
				llvm::IRBuilder<>& irb,
				llvm::Value* val,
				llvm::Value* n,
				bool updateFlags = false);

		llvm::Value* generateInsnConditionCode(
				llvm::IRBuilder<>& irb,
				cs_arm64* ai);

		llvm::Value* generateGetOperandMemAddr(
				cs_arm64_op& op,
				llvm::IRBuilder<>& irb);

		virtual llvm::Value* loadRegister(
				uint32_t r,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW) override;
		virtual llvm::Value* loadOp(
				cs_arm64_op& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr,
				bool lea = false) override;

		virtual llvm::Instruction* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::ZEXT_TRUNC) override;
		virtual llvm::Instruction* storeOp(
				cs_arm64_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::ZEXT_TRUNC) override;
		bool isCondIns(cs_arm64 * i);
//
//==============================================================================
// Helper methods.
//==============================================================================
//
	protected:
		virtual bool isOperandRegister(cs_arm64_op& op) override;
		virtual uint8_t getOperandAccess(cs_arm64_op& op) override;
//
//==============================================================================
// ARM64 implementation data.
//==============================================================================
//
	protected:

		std::vector<uint32_t> _reg2parentMap;

		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorArm64_impl::*)(
					cs_insn* i,
					cs_arm64*,
					llvm::IRBuilder<>&)> _i2fm;
//
//==============================================================================
// ARM64 instruction translation methods.
//==============================================================================
//
	protected:
		void translateAdc(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateAdd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateAnd(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateShifts(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateSub(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateNeg(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateNgc(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateSbc(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateMov(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateStr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateStp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateLdr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateLdp(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateAdr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateB(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateBl(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateBr(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateCbnz(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateCsel(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateCset(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateDiv(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateMul(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateTbnz(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);
		void translateRet(cs_insn* i, cs_arm64* ai, llvm::IRBuilder<>& irb);

};

} // namespace capstone2llvmir
} // namespace retdec

#endif /* CAPSTONE2LLVMIR_ARM64_ARM64_IMPL_H */
