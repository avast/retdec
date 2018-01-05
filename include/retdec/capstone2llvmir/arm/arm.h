/**
 * @file include/retdec/capstone2llvmir/arm/arm.h
 * @brief ARM implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_ARM_ARM_H
#define RETDEC_CAPSTONE2LLVMIR_ARM_ARM_H

#include "retdec/capstone2llvmir/arm/arm_defs.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorArm : public Capstone2LlvmIrTranslator
{
	// Constructor, destructor.
	//
	public:
		Capstone2LlvmIrTranslatorArm(
				llvm::Module* m,
				cs_mode basic = CS_MODE_ARM,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorArm();

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
		llvm::Value* getCurrentPc(cs_insn* i);
		llvm::Value* getNextInsnAddress(cs_insn* i);

		llvm::Value* loadRegister(uint32_t r, llvm::IRBuilder<>& irb);
		llvm::Value* loadOp(
				cs_arm_op& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		llvm::Value* loadOpUnary(
				cs_arm* ai,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				cs_arm* ai,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);
		llvm::Value* loadOpBinaryOp0(
				cs_arm* ai,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		llvm::Value* loadOpBinaryOp1(
				cs_arm* ai,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpTernary(
				cs_arm* ai,
				llvm::IRBuilder<>& irb);
		std::pair<llvm::Value*, llvm::Value*> loadOpTernaryOp1Op2(
				cs_arm* ai,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);
		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpQuaternaryOp1Op2Op3(
				cs_arm* ai,
				llvm::IRBuilder<>& irb);

		llvm::Instruction* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC);
		llvm::Instruction* storeOp(
				cs_arm_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC);

		llvm::Value* generateInsnConditionCode(
				llvm::IRBuilder<>& irb,
				cs_arm* ai);
		llvm::Value* genCarryAdd(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::IRBuilder<>& irb);
		llvm::Value* genCarryAddC(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* genOverflowAdd(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* genOverflowAddC(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* genBorrowSub(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* genBorrowSubC(
				llvm::Value* sub,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* genOverflowSub(
				llvm::Value* sub,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* genOverflowSubC(
				llvm::Value* sub,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);

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

	protected:
		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorArm::*)(cs_insn* i, cs_arm*, llvm::IRBuilder<>&)> _i2fm;

		// These are used to save lines needed to declare locale operands in
		// each translation function.
		// In C++17, we could use Structured Bindings:
		// auto [ op0, op1 ] = loadOpBinary();
		llvm::Value* op0 = nullptr;
		llvm::Value* op1 = nullptr;
		llvm::Value* op2 = nullptr;
		llvm::Value* op3 = nullptr;

		// TODO: This is a hack, sometimes we need cs_insn deep in helper
		// methods like @c loadRegister() where it is hard to propagate it.
		cs_insn* _insn = nullptr;

	// Instruction translation methods.
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
