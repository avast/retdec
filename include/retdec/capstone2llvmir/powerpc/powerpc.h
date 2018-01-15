/**
 * @file include/retdec/capstone2llvmir/powerpc/powerpc.h
 * @brief PowerPC implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_POWERPC_POWERPC_H
#define RETDEC_CAPSTONE2LLVMIR_POWERPC_POWERPC_H

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/capstone2llvmir/powerpc/powerpc_defs.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorPowerpc : public Capstone2LlvmIrTranslator
{
	// Constructor, destructor.
	//
	public:
		Capstone2LlvmIrTranslatorPowerpc(
				llvm::Module* m,
				cs_mode basic = CS_MODE_32,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorPowerpc();

	// Public pure virtual methods that must be implemented in concrete classes.
	//
	public:
		virtual bool isAllowedBasicMode(cs_mode m) override;
		virtual bool isAllowedExtraMode(cs_mode m) override;
		virtual void modifyBasicMode(cs_mode m) override;
		virtual void modifyExtraMode(cs_mode m) override;
		virtual uint32_t getArchByteSize() override;
		virtual uint32_t getArchBitSize() override;

	// Protected pure virtual methods that must be implemented in concrete
	// classes.
	//
	protected:
		virtual void initializeArchSpecific() override;
		virtual void initializeRegNameMap() override;
		virtual void initializeRegTypeMap() override;
		virtual void generateEnvironmentArchSpecific() override;
		virtual void generateDataLayout() override;
		virtual void generateRegisters() override;

		virtual void translateInstruction(
				cs_insn* i,
				llvm::IRBuilder<>& irb) override;

	protected:
		llvm::IntegerType* getDefaultType();

		llvm::Value* getThisInsnAddress(cs_insn* i);
		llvm::Value* getNextInsnAddress(cs_insn* i);

		llvm::Value* loadRegister(uint32_t r, llvm::IRBuilder<>& irb);
		llvm::Value* loadOp(
				cs_ppc_op& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		llvm::Value* loadOpUnary(
				cs_ppc* pi,
				llvm::IRBuilder<>& irb);
		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				cs_ppc* pi,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);
		llvm::Value* loadOpBinaryOp0(
				cs_ppc* pi,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		llvm::Value* loadOpBinaryOp1(
				cs_ppc* pi,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpTernary(
				cs_ppc* pi,
				llvm::IRBuilder<>& irb);
		std::pair<llvm::Value*, llvm::Value*> loadTernaryOp1Op2(
				cs_ppc* pi,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);

		llvm::StoreInst* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC);
		llvm::Instruction* storeOp(
				cs_ppc_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC);

		void storeCrX(
				llvm::IRBuilder<>& irb,
				uint32_t crReg,
				llvm::Value* op0,
				llvm::Value* op1 = nullptr,
				bool signedCmp = true);
		void storeCr0(llvm::IRBuilder<>& irb, cs_ppc* pi, llvm::Value* val);

		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*, llvm::Value*> loadCrX(
				llvm::IRBuilder<>& irb,
				uint32_t crReg);
		llvm::Value* loadCrX(
				llvm::IRBuilder<>& irb,
				uint32_t crReg,
				ppc_cr_types type);

		llvm::Value* genCarryAdd(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::IRBuilder<>& irb);
		llvm::Value* genCarryAddC(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* genOverflowAddC(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);

		bool isGeneralPurposeRegister(uint32_t r);
		uint32_t getGeneralPurposeRegisterIndex(uint32_t r);
		uint32_t crBitIndexToCrRegister(uint32_t idx);
		bool isCrRegister(uint32_t r);
		bool isCrRegister(cs_ppc_op& op);

	protected:
		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorPowerpc::*)(cs_insn* i, cs_ppc*, llvm::IRBuilder<>&)> _i2fm;

		// These are used to save lines needed to declare locale operands in
		// each translation function.
		// In C++17, we could use Structured Bindings:
		// auto [ op0, op1 ] = loadOpBinary();
		llvm::Value* op0 = nullptr;
		llvm::Value* op1 = nullptr;
		llvm::Value* op2 = nullptr;

	// Instruction translation methods.
	//
	protected:
		void translateAdd(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAddc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAdde(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAddis(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAddme(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAddze(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAnd(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAndc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateAndis(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateB(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateClrlwi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateCmp(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateCntlzw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateCrModifTernary(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateCrNotMove(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateCrSetClr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateDivw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateEqv(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateExtendSign(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateLhbrx(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateLi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateLis(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateLwbrx(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateLoad(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateLoadIndexed(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMcrf(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMfcr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMfctr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMflr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMfspr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMtcrf(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMtcr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMtctr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMtlr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMtspr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMulhw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateMullw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateNand(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateNeg(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateNop(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateNor(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateNot(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateOr(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateOrc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateOris(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateRotateComplex5op(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateRotlw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateShiftLeft(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateShiftRight(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSlwi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSrwi(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSraw(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateStore(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateStoreIndexed(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateStoreReverseIndexed(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSubf(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSubfc(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSubfe(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSubfme(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateSubfze(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateXor(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
		void translateXoris(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);

		void translateASSERT(cs_insn* i, cs_ppc* pi, llvm::IRBuilder<>& irb);
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
