/**
 * @file include/retdec/capstone2llvmir/x86/x86.h
 * @brief X86 implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_X86_X86_H
#define RETDEC_CAPSTONE2LLVMIR_X86_X86_H

#include <array>
#include <tuple>
#include <utility>

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/capstone2llvmir/x86/x86_defs.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorX86 : public Capstone2LlvmIrTranslator
{
	// Constructor, destructor.
	//
	public:
		Capstone2LlvmIrTranslatorX86(
				llvm::Module* m,
				cs_mode basic = CS_MODE_32,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorX86();

	// Public pure virtual methods that must be implemented in concrete classes.
	//
	public:
		virtual bool isAllowedBasicMode(cs_mode m) override;
		virtual bool isAllowedExtraMode(cs_mode m) override;
		virtual void modifyBasicMode(cs_mode m) override;
		virtual void modifyExtraMode(cs_mode m) override;
		virtual uint32_t getArchByteSize() override;
		virtual uint32_t getArchBitSize() override;

	public:
		llvm::Function* getX87DataStoreFunction();
		llvm::Function* getX87TagStoreFunction();
		llvm::Function* getX87DataLoadFunction();
		llvm::Function* getX87TagLoadFunction();
		uint32_t getParentRegister(uint32_t r);

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
		cs_mode _origBasicMode = CS_MODE_LITTLE_ENDIAN;

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
			void (Capstone2LlvmIrTranslatorX86::*)(cs_insn* i, cs_x86*, llvm::IRBuilder<>&)> _i2fm;


	// Translation helper methods.
	//
	protected:
		llvm::Type* getDefaultType();

		llvm::Value* loadRegister(
				uint32_t r,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW);
		llvm::StoreInst* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::ZEXT_TRUNC);
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

		llvm::Value* loadOp(
				cs_x86_op& op,
				llvm::IRBuilder<>& irb,
				bool lea = false,
				bool fp = false);
		llvm::Value* loadOpUnary(
				cs_x86* xi,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW,
				bool fp = false);
		llvm::Value* loadOpUnaryFloat(
				cs_x86* xi,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW);

		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*, llvm::Value*> loadOpFloatingUnaryTop(
				cs_insn* i,
				cs_x86* xi,
				llvm::IRBuilder<>& irb);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				cs_x86* xi,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::THROW);
		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpTernary(
				cs_x86* xi,
				llvm::IRBuilder<>& irb);
		llvm::Instruction* setOp(
				cs_x86_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::ZEXT_TRUNC,
				bool fp = false);
		llvm::Instruction* setOpFloat(
				cs_x86_op& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::FP_CAST);

		llvm::Value* genCarryAddInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* genCarryAddCInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
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
		llvm::Value* genBorrowSubInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* genBorrowSubCInt4(
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
		llvm::Value* genZeroFlag(llvm::Value* val, llvm::IRBuilder<>& irb);
		llvm::Value* genSignFlag(llvm::Value* val, llvm::IRBuilder<>& irb);
		llvm::Value* genParityFlag(llvm::Value* val, llvm::IRBuilder<>& irb);
		void genSetSflags(
				llvm::Value* val,
				llvm::IRBuilder<>& irb);

		llvm::Value* genCcAE(llvm::IRBuilder<>& irb);
		llvm::Value* genCcA(llvm::IRBuilder<>& irb);
		llvm::Value* genCcBE(llvm::IRBuilder<>& irb);
		llvm::Value* genCcB(llvm::IRBuilder<>& irb);
		llvm::Value* genCcE(llvm::IRBuilder<>& irb);
		llvm::Value* genCcGE(llvm::IRBuilder<>& irb);
		llvm::Value* genCcG(llvm::IRBuilder<>& irb);
		llvm::Value* genCcLE(llvm::IRBuilder<>& irb);
		llvm::Value* genCcL(llvm::IRBuilder<>& irb);
		llvm::Value* genCcNE(llvm::IRBuilder<>& irb);
		llvm::Value* genCcNO(llvm::IRBuilder<>& irb);
		llvm::Value* genCcNP(llvm::IRBuilder<>& irb);
		llvm::Value* genCcNS(llvm::IRBuilder<>& irb);
		llvm::Value* genCcO(llvm::IRBuilder<>& irb);
		llvm::Value* genCcP(llvm::IRBuilder<>& irb);
		llvm::Value* genCcS(llvm::IRBuilder<>& irb);

	// Helper members.
	//
	protected:
		// These are used to save lines needed to declare locale operands in
		// each translation function.
		// In C++17, we could use Structured Bindings:
		// auto [ op0, op1 ] = loadOpBinary();
		llvm::Value* op0 = nullptr;
		llvm::Value* op1 = nullptr;
		llvm::Value* op2 = nullptr;

		llvm::Value* top = nullptr;
		llvm::Value* idx = nullptr;

		// TODO: This is a hack, sometimes we need cs_insn deep in helper
		// methods like @c loadRegister() where it is hard to propagate it.
		cs_insn* _insn = nullptr;

		///
		llvm::Function* _x87DataStoreFunction = nullptr; // void (i3, fp80)
		llvm::Function* _x87TagStoreFunction = nullptr; // void (i3, i2)
		llvm::Function* _x87DataLoadFunction = nullptr; // fp80 (i3)
		llvm::Function* _x87TagLoadFunction = nullptr; // i2 (i3)

	// Instruction translation methods.
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
