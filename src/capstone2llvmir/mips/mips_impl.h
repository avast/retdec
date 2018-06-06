/**
 * @file src/capstone2llvmir/mips/mips_impl.h
 * @brief MIPS implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_MIPS_MIPS_IMPL_H
#define CAPSTONE2LLVMIR_MIPS_MIPS_IMPL_H

#include "retdec/capstone2llvmir/mips/mips.h"
#include "capstone2llvmir/capstone2llvmir_impl.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorMips_impl :
		public Capstone2LlvmIrTranslator_impl<cs_mips, cs_mips_op>,
		public Capstone2LlvmIrTranslatorMips
{
	public:
		Capstone2LlvmIrTranslatorMips_impl(
				llvm::Module* m,
				cs_mode basic = CS_MODE_MIPS32,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorMips_impl();
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
// Capstone related getters - from Capstone2LlvmIrTranslator.
//==============================================================================
//
	public:
		virtual bool hasDelaySlot(uint32_t id) const override;
		virtual bool hasDelaySlotTypical(uint32_t id) const override;
		virtual bool hasDelaySlotLikely(uint32_t id) const override;
		virtual std::size_t getDelaySlot(uint32_t id) const override;
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
// MIPS-specific methods.
//==============================================================================
//
	protected:
		llvm::Value* getCurrentPc(cs_insn* i);
		llvm::Value* getNextNextInsnAddress(cs_insn* i);
		llvm::Value* getUnpredictableValue();

		uint32_t singlePrecisionToDoublePrecisionFpRegister(uint32_t r) const;

		virtual llvm::Value* loadRegister(
				uint32_t r,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW) override;
		virtual llvm::Value* loadOp(
				cs_mips_op& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr,
				bool lea = false) override;

		virtual llvm::StoreInst* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC) override;
		virtual llvm::Instruction* storeOp(
				cs_mips_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC) override;

		llvm::StoreInst* storeRegisterUnpredictable(
				uint32_t r,
				llvm::IRBuilder<>& irb);
		bool isFpInstructionVariant(cs_insn* i);
//
//==============================================================================
// MIPS implementation data.
//==============================================================================
//
	protected:
		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorMips_impl::*)(
					cs_insn* i,
					cs_mips*,
					llvm::IRBuilder<>&)> _i2fm;
//
//==============================================================================
// MIPS instruction translation methods.
//==============================================================================
//
	protected:
		void translateAdd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateAnd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateBc1f(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateBc1t(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateBcondal(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateBinaryPseudoAsm(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateBitrev(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateBreak(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateC(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateClo(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateClz(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateCondBranchTernary(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateCondBranchBinary(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateCtc1(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateCvt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateDiv(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateDivu(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateExt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateIns(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateJ(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateJal(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateLoadMemory(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateLui(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateLwl(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateLwr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMadd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMaddf(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMax(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMfc1(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMfhi(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMflo(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMin(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMov(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMsub(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMsubf(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMtc1(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMthi(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMtlo(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMovf(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMovn(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMovt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMovz(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMul(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateMult(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateNegu(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateNmadd(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateNmsub(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateNop(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateNor(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateOr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateRotr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSeb(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSeh(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSll(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSlt(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSltu(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSra(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSrl(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateStoreMemory(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSub(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSwl(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSwr(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateSyscall(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateWsbh(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
		void translateXor(cs_insn* i, cs_mips* mi, llvm::IRBuilder<>& irb);
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
