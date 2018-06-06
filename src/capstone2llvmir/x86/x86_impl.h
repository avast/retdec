/**
 * @file src/capstone2llvmir/x86/x86_impl.h
 * @brief X86 implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_X86_X86_IMPL_H
#define CAPSTONE2LLVMIR_X86_X86_IMPL_H

#include "retdec/capstone2llvmir/x86/x86.h"
#include "capstone2llvmir/capstone2llvmir_impl.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorX86_impl :
		public Capstone2LlvmIrTranslator_impl<cs_x86, cs_x86_op>,
		public Capstone2LlvmIrTranslatorX86
{
	public:
		Capstone2LlvmIrTranslatorX86_impl(
				llvm::Module* m,
				cs_mode basic = CS_MODE_32,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorX86_impl();
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
// LLVM related getters and query methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//
	public:
		virtual bool isAnyPseudoFunction(llvm::Function* f) const override;
		virtual bool isAnyPseudoFunctionCall(llvm::CallInst* c) const override;
//
//==============================================================================
// x86 specialization methods - from Capstone2LlvmIrTranslatorX86
//==============================================================================
//
	public:
		virtual bool isX87DataStoreFunction(llvm::Function* f) const override;
		virtual bool isX87DataStoreFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getX87DataStoreFunction() const override;
		virtual bool isX87TagStoreFunction(llvm::Function* f) const override;
		virtual bool isX87TagStoreFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getX87TagStoreFunction() const override;
		virtual bool isX87DataLoadFunction(llvm::Function* f) const override;
		virtual bool isX87DataLoadFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getX87DataLoadFunction() const override;
		virtual bool isX87TagLoadFunction(llvm::Function* f) const override;
		virtual bool isX87TagLoadFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getX87TagLoadFunction() const override;

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
// x86-specific methods.
//==============================================================================
//
	protected:
		void generateRegistersCommon();
		void generateRegisters16();
		void generateRegisters32();
		void generateRegisters64();

		void generateX87RegLoadStoreFunctions();

		void initializeRegistersParentMap();
		void initializeRegistersParentMapCommon();
		void initializeRegistersParentMap16();
		void initializeRegistersParentMap32();
		void initializeRegistersParentMap64();
		void initializeRegistersParentMapToSelf(const std::vector<x86_reg>& rs);
		void initializeRegistersParentMapToOther(
				const std::vector<x86_reg>& rs,
				x86_reg other);
		uint32_t getAccumulatorRegister(std::size_t size);
		uint32_t getStackPointerRegister();
		uint32_t getBasePointerRegister();

		virtual llvm::Value* getCurrentPc(cs_insn* i);

	protected:
		virtual llvm::Value* loadRegister(
				uint32_t r,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW) override;
		virtual llvm::Value* loadOp(
				cs_x86_op& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr,
				bool lea = false) override;

		virtual llvm::StoreInst* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::ZEXT_TRUNC) override;
		virtual llvm::Instruction* storeOp(
				cs_x86_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::ZEXT_TRUNC) override;

		void storeRegisters(
				llvm::IRBuilder<>& irb,
				const std::vector<std::pair<uint32_t, llvm::Value*>>& regs);
		void storeRegistersPlusSflags(
				llvm::IRBuilder<>& irb,
				llvm::Value* sflagsVal,
				const std::vector<std::pair<uint32_t, llvm::Value*>>& regs);

		llvm::Value* loadX87Top(llvm::IRBuilder<>& irb);
		llvm::Value* loadX87TopDec(llvm::IRBuilder<>& irb);
		llvm::Value* loadX87TopInc(llvm::IRBuilder<>& irb);
		llvm::Value* loadX87TopDecStore(llvm::IRBuilder<>& irb);
		llvm::Value* loadX87TopIncStore(llvm::IRBuilder<>& irb);
		llvm::Value* x87IncTop(llvm::IRBuilder<>& irb, llvm::Value* top = nullptr);
		llvm::Value* x87DecTop(llvm::IRBuilder<>& irb, llvm::Value* top = nullptr);

		llvm::CallInst* storeX87DataReg(
				llvm::IRBuilder<>& irb,
				llvm::Value* rNum,
				llvm::Value* val);
		llvm::CallInst* storeX87TagReg(
				llvm::IRBuilder<>& irb,
				llvm::Value* rNum,
				llvm::Value* val);
		llvm::CallInst* clearX87TagReg(
				llvm::IRBuilder<>& irb,
				llvm::Value* rNum);
		llvm::CallInst* loadX87DataReg(
				llvm::IRBuilder<>& irb,
				llvm::Value* rNum);
		llvm::CallInst* loadX87TagReg(
				llvm::IRBuilder<>& irb,
				llvm::Value* rNum);

		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*, llvm::Value*> loadOpFloatingUnaryTop(
				cs_insn* i,
				cs_x86* xi,
				llvm::IRBuilder<>& irb);

		llvm::Value* generateZeroFlag(llvm::Value* val, llvm::IRBuilder<>& irb);
		llvm::Value* generateSignFlag(llvm::Value* val, llvm::IRBuilder<>& irb);
		llvm::Value* generateParityFlag(llvm::Value* val, llvm::IRBuilder<>& irb);
		void generateSetSflags(
				llvm::Value* val,
				llvm::IRBuilder<>& irb);

		llvm::Value* generateCcAE(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcA(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcBE(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcB(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcE(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcGE(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcG(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcLE(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcL(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcNE(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcNO(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcNP(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcNS(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcO(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcP(llvm::IRBuilder<>& irb);
		llvm::Value* generateCcS(llvm::IRBuilder<>& irb);
//
//==============================================================================
// x86 implementation data.
//==============================================================================
//
	protected:
		/// Maps register numbers to numbers of their parents depending on the
		/// original basic mode (e.g. X86_REG_AH to X86_REG_EAX in 32-bit mode,
		/// or to X86_REG_RAX in 64-bit mode).
		/// Unhandled mappings are set to X86_REG_INVALID (e.g. mapping of
		/// X86_REG_EAX in 16-bit mode).
		/// Once generated, it does not change.
		/// Register's number is a key into the array of parent number values.
		/// Only values of the Capstone's original @c x86_reg enum are handled,
		/// our added enums (e.g. @c x86_reg_rflags) are not.
		/// Always use @c getParentRegister() method to get values from this
		/// map -- it will deal with added enums.
		std::vector<uint32_t> _reg2parentMap;

		/// Mapping of Capstone instruction IDs to their translation functions.
		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorX86_impl::*)(
					cs_insn* i,
					cs_x86*,
					llvm::IRBuilder<>&)> _i2fm;

		llvm::Value* top = nullptr;
		llvm::Value* idx = nullptr;

		llvm::Function* _x87DataStoreFunction = nullptr; // void (i3, fp80)
		llvm::Function* _x87TagStoreFunction = nullptr; // void (i3, i2)
		llvm::Function* _x87DataLoadFunction = nullptr; // fp80 (i3)
		llvm::Function* _x87TagLoadFunction = nullptr; // i2 (i3)
//
//==============================================================================
// x86 instruction translation methods.
//==============================================================================
//
	protected:
		void translateAaa(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateAad(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateAam(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateAdc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateAdd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateAnd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBound(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBsf(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBswap(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBtc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBtr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateBts(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCall(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCbw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCdq(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCdqe(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateClc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCld(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCli(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCmc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCMovCc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCmpxchg(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCmpxchg8b(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCmpxchg16b(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCompareString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCpuid(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCqo(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCwd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateCwde(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateDaaDas(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateDec(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateDiv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateEnter(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFabs(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFadd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFchs(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFcos(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFdecstp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFdiv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFdivr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFincstp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFist(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFld(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFloadConstant(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFmul(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFninit(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFnstcw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFnstsw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFnstenv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFldcw(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFldenv(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFrndint(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFsin(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFsincos(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFsqrt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFst(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFsub(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFsubr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFucomPop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFxam(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateFxch(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateHlt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateImul(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateInc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateIns(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateInt(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateInt1(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateInt3(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateInto(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateJCc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateJecxz(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateJmp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLahf(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLea(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLeave(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLcall(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLjmp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLoadFarPtr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLoadString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateLoop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateMov(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateMoveString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateMul(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateNeg(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateNop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateNot(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateOr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateOuts(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translatePop(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translatePopa(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translatePopEflags(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translatePush(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translatePusha(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translatePushEflags(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRcr(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRcl(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRdtsc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRdtscp(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRol(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRor(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateRet(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateSahf(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateSalc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateSbb(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateScanString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateSetCc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateShiftLeft(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateShiftRight(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateShld(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateShrd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateStc(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateStd(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateStoreString(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateSub(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateWait(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateXchg(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateXlatb(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
		void translateXor(cs_insn* i, cs_x86* xi, llvm::IRBuilder<>& irb);
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
