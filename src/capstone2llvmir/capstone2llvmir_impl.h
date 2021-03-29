/**
 * @file src/capstone2llvmir/capstone2llvmir_impl.h
 * @brief Common private implementation for translators converting bytes to
 * LLVM IR.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CAPSTONE2LLVMIR_CAPSTONE2LLVMIR_IMPL_H
#define CAPSTONE2LLVMIR_CAPSTONE2LLVMIR_IMPL_H

#include "capstone2llvmir/llvmir_utils.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"

namespace retdec {
namespace capstone2llvmir {

/**
 * Private implementation class.
 *
 * Implements a lot of stuff from @c Capstone2LlvmIrTranslator public interface
 * that is common for all translators. However:
 * - Not all the pure virtual methods are implemented, some of them are
 *   inherently architecture specific and must be implemented in the concrete
 *   translator classes.
 * - Even those virtual methods that are implemented here may be overriden and
 *   re-implemented in the concrete translator classes.
 * - Adds more implementation-related pure virtual methods that must be
 *   implemented in the concrete translator classes.
 */
template <typename CInsn, typename CInsnOp>
class Capstone2LlvmIrTranslator_impl : virtual public Capstone2LlvmIrTranslator
{
	public:
		Capstone2LlvmIrTranslator_impl(
				cs_arch a,
				cs_mode basic,
				cs_mode extra,
				llvm::Module* m);
		virtual ~Capstone2LlvmIrTranslator_impl();
//
//==============================================================================
// Translator configuration methods.
//==============================================================================
//
		virtual void setIgnoreUnexpectedOperands(bool f) override;
		virtual void setIgnoreUnhandledInstructions(bool f) override;
		virtual void setGeneratePseudoAsmFunctions(bool f) override;

		virtual bool isIgnoreUnexpectedOperands() const override;
		virtual bool isIgnoreUnhandledInstructions() const override;
		virtual bool isGeneratePseudoAsmFunctions() const override;
//
//==============================================================================
// Mode query & modification methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//
		virtual void modifyBasicMode(cs_mode m) override;
		virtual void modifyExtraMode(cs_mode m) override;
		virtual uint32_t getArchBitSize() override;
		// Some of these are inherently architecture specific -> implemented
		// in the concrete translator classes.
//
//==============================================================================
// Translation methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//
	public:
		virtual TranslationResult translate(
				const uint8_t* bytes,
				std::size_t size,
				retdec::common::Address a,
				llvm::IRBuilder<>& irb,
				std::size_t count = 0,
				bool stopOnBranch = false) override;
		virtual TranslationResultOne translateOne(
				const uint8_t*& bytes,
				std::size_t& size,
				retdec::common::Address& a,
				llvm::IRBuilder<>& irb) override;
//
//==============================================================================
// Capstone related getters - from Capstone2LlvmIrTranslator.
//==============================================================================
//
	public:
		virtual const csh& getCapstoneEngine() const override;
		virtual cs_arch getArchitecture() const override;
		virtual cs_mode getBasicMode() const override;
		virtual cs_mode getExtraMode() const override;

		virtual bool hasDelaySlot(uint32_t id) const override;
		virtual bool hasDelaySlotTypical(uint32_t id) const override;
		virtual bool hasDelaySlotLikely(uint32_t id) const override;
		virtual std::size_t getDelaySlot(uint32_t id) const override;

		virtual llvm::GlobalVariable* getRegister(uint32_t r) override;
		virtual std::string getRegisterName(uint32_t r) const override;
		virtual uint32_t getRegisterBitSize(uint32_t r) const override;
		virtual uint32_t getRegisterByteSize(uint32_t r) const override;
		virtual llvm::Type* getRegisterType(uint32_t r) const override;

		virtual bool isControlFlowInstruction(cs_insn& i) const override;
		virtual bool isCallInstruction(cs_insn& i) const override;
		virtual bool isReturnInstruction(cs_insn& i) const override;
		virtual bool isBranchInstruction(cs_insn& i) const override;
		virtual bool isCondBranchInstruction(cs_insn& i) const override;
//
//==============================================================================
// LLVM related getters and query methods - from Capstone2LlvmIrTranslator.
//==============================================================================
//
	public:
		virtual llvm::Module* getModule() const override;

		virtual bool isSpecialAsm2LlvmMapGlobal(llvm::Value* v) const override;
		virtual llvm::StoreInst* isSpecialAsm2LlvmInstr(llvm::Value* v) const override;
		virtual llvm::GlobalVariable* getAsm2LlvmMapGlobalVariable() const override;

		virtual bool isCallFunction(llvm::Function* f) const override;
		virtual bool isCallFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::BranchInst* isInConditionCallFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getCallFunction() const override;

		virtual bool isReturnFunction(llvm::Function* f) const override;
		virtual bool isReturnFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::BranchInst* isInConditionReturnFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getReturnFunction() const override;

		virtual bool isBranchFunction(llvm::Function* f) const override;
		virtual bool isBranchFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::BranchInst* isInConditionBranchFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getBranchFunction() const override;

		virtual bool isCondBranchFunction(llvm::Function* f) const override;
		virtual bool isCondBranchFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::BranchInst* isInConditionCondBranchFunctionCall(llvm::CallInst* c) const override;
		virtual llvm::Function* getCondBranchFunction() const override;

		virtual bool isAnyPseudoFunction(llvm::Function* f) const override;
		virtual bool isAnyPseudoFunctionCall(llvm::CallInst* c) const override;

		virtual llvm::GlobalVariable* isRegister(llvm::Value* v) const override;
		virtual uint32_t getCapstoneRegister(llvm::GlobalVariable* gv) const override;

		virtual bool isPseudoAsmFunction(llvm::Function* f) const override;
		virtual bool isPseudoAsmFunctionCall(llvm::CallInst* c) const override;
		virtual const std::set<llvm::Function*>& getPseudoAsmFunctions() const override;
//
//==============================================================================
// Common implementation enums, structures, classes, etc.
//==============================================================================
//
	protected:
		/**
		 * What should instruction operand loading method do if types of
		 * loaded operands are not the same.
		 */
		enum class eOpConv
		{
			/// Throw exception.
			THROW,
			/// Operand types does not have to be equal.
			NOTHING,
			/// Convert to destination integer type using ZEXT or TRUNC.
			/// If source is FP type converts it using bitcast.
			ZEXT_TRUNC_OR_BITCAST,
			/// Convert to destination integer type using SEXT or TRUNC.
			/// If source is FP type converts it using bitcast.
			SEXT_TRUNC_OR_BITCAST,
			/// Convert to destination FP type using FPCast (FPExt, BitCast,
			/// or FPTrunc).
			/// If source is integer type converts it using bitcast.
			FPCAST_OR_BITCAST,
			/// Convert to destination FP type using SIToFP.
			/// Source must be integer, destination fp, or LLVM asserts.
			SITOFP_OR_FPCAST,
			/// Convert to destination FP type using UIToFP.
			/// Source must be integer, destination fp, or LLVM asserts.
			UITOFP_OR_FPCAST
		};

		llvm::Value* generateTypeConversion(
				llvm::IRBuilder<>& irb,
				llvm::Value* from,
				llvm::Type* to,
				eOpConv ct);

		/**
		 * Internal method used to correct type used for operands
		 * convertion based on specified "convertion type method" - ct.
		 *
		 * @param irb   LLVM IR Builder required for IR modifications.
		 * @param to    result type that will be used to convert operands.
		 * @param ct    convertion method by which will be opeands converted to the resut type.
		 * @return      If result type for convertion can be used with specified conversion method
		 *              returns param to. Otherwise will this method try to create suitable type
		 *              for convertion method ct with size of llvm type of param to.
		 */
		llvm::Type* _checkTypeConversion(
				llvm::IRBuilder<>& irb,
				llvm::Type* to,
				eOpConv ct);
//
//==============================================================================
// New implementation-related pure virtual methods.
//==============================================================================
//
	protected:
		/**
		 * Do architecture and mode specific initialization on top of common
		 * initialization done by @c initialize();
		 */
		virtual void initializeArchSpecific() = 0;

		/**
		 * Initialize @c _reg2name. See comment for @c _reg2name to know what
		 * must be initialized, and what may or may not be initialized.
		 */
		virtual void initializeRegNameMap() = 0;

		/**
		 * Initialize @c _reg2type. See comment for @c _reg2type to know what
		 * must be initialized, and what may or may not be initialized.
		 */
		virtual void initializeRegTypeMap() = 0;

		/**
		 * If possible, initialize @c _callInsnIds, @c _returnInsnIds,
		 * @c _branchInsnIds, @c _condBranchInsnIds, @c _condBranchInsnIds sets.
		 *
		 * For some architectures, it is not possible to initialize all the
		 * instructions that may generate control flow change. E.g. Any kind
		 * of ARM instruction that writes to PC is changing control flow.
		 *
		 * This is not ideal, because each time some instruction that generates
		 * one of these is added, or removed, its ID must also be manualy added,
		 * or removed, here. This could be easily forgotten. Right now, I do not
		 * know how to solve this better (i.e. automatic update).
		 */
		virtual void initializePseudoCallInstructionIDs() = 0;

		/**
		 * Generate architecture specific environment on top of common
		 * environment generated by @c generateEnvironment().
		 */
		virtual void generateEnvironmentArchSpecific() = 0;

		/**
		 * Generate LLVM global variables for registers. This is architecture
		 * and mode specific and must be implemented in concrete classes.
		 */
		virtual void generateRegisters() = 0;

		/**
		 * Generate LLVM data layout into the module. This is architecture
		 * and mode specific and must be implemented in concrete classes.
		 */
		virtual void generateDataLayout() = 0;

		/**
		 * @return Capstone carry register.
		 */
		virtual uint32_t getCarryRegister() = 0;

		/**
		 * Translate single Capstone instruction.
		 */
		virtual void translateInstruction(
				cs_insn* i,
				llvm::IRBuilder<>& irb) = 0;
//
//==============================================================================
// Virtual translation initialization and environment generation methods.
//==============================================================================
//
	protected:
		virtual void initialize();
		virtual void openHandle();
		virtual void configureHandle();
		virtual void closeHandle();
		virtual void generateEnvironment();

		virtual void generateSpecialAsm2LlvmMapGlobal();
		virtual llvm::StoreInst* generateSpecialAsm2LlvmInstr(
				llvm::IRBuilder<>& irb,
				cs_insn* i);
		virtual void generateCallFunction();
		virtual llvm::CallInst* generateCallFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* t);
		virtual llvm::CallInst* generateCondCallFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* cond,
				llvm::Value* t);
		virtual void generateReturnFunction();
		virtual llvm::CallInst* generateReturnFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* t);
		virtual llvm::CallInst* generateCondReturnFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* cond,
				llvm::Value* t);
		virtual void generateBranchFunction();
		virtual llvm::CallInst* generateBranchFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* t);
		virtual void generateCondBranchFunction();
		virtual llvm::CallInst* generateCondBranchFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* cond,
				llvm::Value* t);

		virtual llvm::GlobalVariable* createRegister(
				uint32_t r,
				llvm::GlobalValue::LinkageTypes lt =
						llvm::GlobalValue::LinkageTypes::InternalLinkage,
				llvm::Constant* initializer = nullptr);
//
//==============================================================================
// Load/store methods.
//==============================================================================
//
		/**
		 * Load LLVM register corresponding to Capstone register @p r, using
		 * instruction builder @p irb. Optionally convert the loaded value to
		 * type @p dstType using cast type @p ct.
		 * @return Loaded value.
		 */
		virtual llvm::Value* loadRegister(
				uint32_t r,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW) = 0;
		virtual llvm::Value* loadOp(
				CInsnOp& op,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr,
				bool lea = false) = 0;

		virtual llvm::Instruction* storeRegister(
				uint32_t r,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC_OR_BITCAST) = 0;
		virtual llvm::Instruction* storeOp(
				CInsnOp& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC_OR_BITCAST) = 0;

		/**
		 * Creates LLVM load from LLVM value representing
		 * operand of instruction ci on index idx. User
		 * of this method may specify type to which will be
		 * loaded value converted and method of the conversion.
		 *
		 * @param ci       Instruction of which operand will be loaded.
		 * @param irb      LLVM IR Builder required for IR modifications.
		 * @param idx      Operand index.
		 * @param loadType Type of loaded value. (not relevant if nullptr)
		 * @param dstType  Desired type of loaded value (not changed if nullptr).
		 * @param ct       Used conversion. Defaultly NOTHING as "do not convert".
		 */
		llvm::Value* loadOp(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				std::size_t idx,
				llvm::Type* loadType = nullptr,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::NOTHING);

		/**
		 * Create LLVM loads for LLVM values representing last N operands
		 * (opCnt) of specified instruction. If strict check is set, this
		 * method will check wheater number of operands of the instructions
		 * is equal to the "opCnt". If conversion type is set to NOTHING
		 * no conversion will happen and each operand may have different
		 * size and type.
		 *
		 * This method was created to be used in internal load
		 * methods. Usage of adequate loadOp(Binary|Ternary|...)
		 * is preffered.
		 *
		 * @param ci	Instruction of which operands will be loaded.
		 * @param irb	LLVM IR Builder required for IR modifications.
		 * @param opCnt	Number of operands that will be loaded.
		 * @param strictCheck	If set to true opCnt will be equal as number of operands. Otherwise will load N last operands.
		 * @param loadType	Type of loaded value. (not relevant if nullptr)
		 * @param dstType	Desired type of loaded value (not changed if nullptr).
		 * @param ct		Used conversion. Defaultly NOTHING as "do not convert".
		 */
		std::vector<llvm::Value*> _loadOps(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				std::size_t opCnt,
				bool strictCheck = true,
				llvm::Type* loadType = nullptr,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::NOTHING);

		/**
		 * Similiar functionality as `_loadOps` but used conversion is determined
		 * by type of first loaded operand. This means that if first operand
		 * is of integer type then `ict` convertion will be used on all other opernads.
		 * If first perand is floting point type then used convertion will be `fct`.
		 *
		 * @param ci
		 * @param irb
		 * @param opCnt
		 * @param strictCheck
		 * @param ict	Integer convertion type.
		 * @param fct	Floting point convertion type.
		 */
		std::vector<llvm::Value*> _loadOpsUniversal(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				std::size_t opCnt,
				bool strictCheck = true,
				eOpConv ict = eOpConv::SEXT_TRUNC_OR_BITCAST,
				eOpConv fct = eOpConv::FPCAST_OR_BITCAST);

		llvm::Value* loadOpUnary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				llvm::Type* loadType = nullptr,
				eOpConv ct = eOpConv::THROW);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				eOpConv ict,
				eOpConv fct);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				llvm::Type* loadType,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::NOTHING);

		llvm::Value* loadOpBinaryOp0(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);
		llvm::Value* loadOpBinaryOp1(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				llvm::Type* ty = nullptr);

		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpTernary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);
		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpTernary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				eOpConv ict,
				eOpConv fct);
		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpTernary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				llvm::Type* loadType,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::NOTHING);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinaryOrTernaryOp1Op2(
				CInsn* ai,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinaryOrTernaryOp1Op2(
				CInsn* ai,
				llvm::IRBuilder<>& irb,
				eOpConv ict,
				eOpConv fct);

		std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> loadOpQuaternaryOp1Op2Op3(
				CInsn* ai,
				llvm::IRBuilder<>& irb);
//
//==============================================================================
// Carry/overflow/borrow add/sub generation routines.
//==============================================================================
//
	protected:
		llvm::Value* generateCarryAdd(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::IRBuilder<>& irb);
		llvm::Value* generateCarryAddC(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* generateCarryAddInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* generateCarryAddCInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* generateOverflowAdd(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* generateOverflowAddC(
				llvm::Value* add,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* generateOverflowSub(
				llvm::Value* sub,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* generateOverflowSubC(
				llvm::Value* sub,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* generateBorrowSub(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* generateBorrowSubC(
				llvm::Value* sub,
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
		llvm::Value* generateBorrowSubInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb);
		llvm::Value* generateBorrowSubCInt4(
				llvm::Value* op0,
				llvm::Value* op1,
				llvm::IRBuilder<>& irb,
				llvm::Value* cf = nullptr);
//
//==============================================================================
// Helper methods.
//==============================================================================
//
	protected:
		llvm::IntegerType* getDefaultType();
		llvm::Value* getThisInsnAddress(cs_insn* i);
		llvm::Value* getNextInsnAddress(cs_insn* i);

	protected:
		llvm::BranchInst* getCondBranchForInsnInIfThen(
				llvm::Instruction* i) const;

	protected:
		std::string getPseudoAsmFunctionName(cs_insn* insn);
		llvm::Function* getPseudoAsmFunction(
				cs_insn* insn,
				llvm::FunctionType* type,
				const std::string& name = "");
		llvm::Function* getPseudoAsmFunction(
				cs_insn* insn,
				llvm::Type* retType,
				llvm::ArrayRef<llvm::Type*> params,
				const std::string& name = "");

		// Unary.
		void translatePseudoAsmOp0Fnc(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmFncOp0(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp0(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		// Binary.
		void translatePseudoAsmFncOp0Op1(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp1(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp0Op1(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		// Ternary.
		void translatePseudoAsmFncOp0Op1Op2(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp1Op2(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp0Op1Op2(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		// Quaternary.
		void translatePseudoAsmFncOp0Op1Op2Op3(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp1Op2Op3(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0FncOp0Op1Op2Op3(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		void translatePseudoAsmOp0Op1FncOp0Op1Op2Op3(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);
		// Generic.
		virtual bool isOperandRegister(CInsnOp& op) = 0;
		virtual uint8_t getOperandAccess(CInsnOp& op);
		virtual void translatePseudoAsmGeneric(cs_insn* i, CInsn* ci, llvm::IRBuilder<>& irb);

		void throwUnexpectedOperands(cs_insn* i, const std::string comment = "");
		void throwUnhandledInstructions(cs_insn* i, const std::string comment = "");

//
//==============================================================================
// Common implementation data.
//==============================================================================
//
	protected:
		csh _handle = 0;
		cs_arch _arch = CS_ARCH_ALL;
		cs_mode _basicMode = CS_MODE_LITTLE_ENDIAN;
		cs_mode _extraMode = CS_MODE_LITTLE_ENDIAN;
		cs_mode _origBasicMode = CS_MODE_LITTLE_ENDIAN;

		llvm::Module* _module = nullptr;
		llvm::GlobalVariable* _asm2llvmGv = nullptr;
		llvm::Function* _callFunction = nullptr; // void (i<arch_sz>)
		llvm::Function* _returnFunction = nullptr; // void (i<arch_sz>)
		llvm::Function* _branchFunction = nullptr; // void (i<arch_sz>)
		llvm::Function* _condBranchFunction = nullptr; // void (i1, i<arch_sz>)
		llvm::GlobalValue::LinkageTypes _regLt =
				llvm::GlobalValue::LinkageTypes::InternalLinkage;

		/// (fnc_name, fnc_type) -> fnc
		std::map<std::pair<std::string, llvm::FunctionType*>, llvm::Function*>
				_insn2asmFunctions;
		// The same functions as in the map above, but meant for fast search.
		std::set<llvm::Function*> _asmFunctions;

		/// Register number to register name map. If register number is not
		/// mapped here, Capstone's @c cs_reg_name() function is used to get
		/// the name.
		/// All registers added by translator (i.e. registers that are not in
		/// the original Capstone register enums) must have entries here.
		/// Also, it can be used to change default Capstone names.
		std::map<uint32_t, std::string> _reg2name;
		/// Register number to register LLVM type. It does not look like
		/// Capstone provides type information for registers, so all registers
		/// need to be manually mapped here.
		std::map<uint32_t, llvm::Type*> _reg2type;

		/// Maps with all LLVM registers created by the translator.
		/// Used for bidirectional queries.
		std::map<llvm::GlobalVariable*, uint32_t> _llvm2CapstoneRegs;
		std::map<uint32_t, llvm::GlobalVariable*> _capstone2LlvmRegs;

		/// If the last translated instruction generated branch call, it is
		/// stored to this member.
		llvm::CallInst* _branchGenerated = nullptr;

		/// @c True if generated branch is in conditional code, e.g. uncond
		/// branch in if-then.
		bool _inCondition = false;

		// These are used to save lines needed to declare locale operands in
		// each translation function.
		// In C++17, we could use Structured Bindings:
		// auto [ op0, op1 ] = loadOpBinary();
		llvm::Value* op0 = nullptr;
		llvm::Value* op1 = nullptr;
		llvm::Value* op2 = nullptr;
		llvm::Value* op3 = nullptr;

		/// Capstone instruction being currently translated.
		cs_insn* _insn = nullptr;

		/// Set of Capstone instruction IDs translation of which would produce
		/// call pseudo call.
		std::set<unsigned int> _callInsnIds;
		/// Set of Capstone instruction IDs translation of which would produce
		/// return pseudo call.
		std::set<unsigned int> _returnInsnIds;
		/// Set of Capstone instruction IDs translation of which would produce
		/// branch pseudo call.
		std::set<unsigned int> _branchInsnIds;
		/// Set of Capstone instruction IDs translation of which would produce
		/// conditional branch pseudo call.
		std::set<unsigned int> _condBranchInsnIds;
		/// Sometimes it is not possible to categorize an instruction ID to one
		/// of the sets above without its full analysis. Such instructions
		/// can be inserted here.
		/// Set of Capstone instruction IDs translation of which may produce
		/// any kind of control flow changing pseudo call.
		std::set<unsigned int> _controlFlowInsnIds;

		bool _ignoreUnexpectedOperands = true;
		bool _ignoreUnhandledInstructions = true;
		bool _generatePseudoAsmFunctions = true;
};

//
// Arity checking utility macros.
//
// Yeah, macros are ugly, but we want them to potentially cause return in
// function that uses them so that there does not need to be if condition or
// other such construction.
//

#define EXPECT_IS_NULLARY(i, ci, irb)          \
{                                              \
	if (ci->op_count != 0)                     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_UNARY(i, ci, irb)            \
{                                              \
	if (ci->op_count != 1)                     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_NULLARY_OR_UNARY(i, ci, irb) \
{                                              \
	if (ci->op_count != 0 &&ci->op_count != 1) \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_BINARY(i, ci, irb)           \
{                                              \
	if (ci->op_count != 2)                     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_UNARY_OR_BINARY(i, ci, irb)  \
{                                              \
	if (ci->op_count != 1 &&ci->op_count != 2) \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_TERNARY(i, ci, irb)          \
{                                              \
	if (ci->op_count != 3)                     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_BINARY_OR_TERNARY(i, ci, irb)\
{                                              \
	if (ci->op_count != 2 &&ci->op_count != 3) \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_QUATERNARY(i, ci, irb)       \
{                                              \
	if (ci->op_count != 4)                     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_NARY(i, ci, irb, n)          \
{                                              \
	if (ci->op_count != n)                     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_SET(i, ci, irb, ns)          \
{                                              \
	if (ns.find(ci->op_count) == ns.end())     \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

#define EXPECT_IS_EXPR(i, ci, irb, expr)       \
{                                              \
	if (!(expr))                               \
	{                                          \
		throwUnexpectedOperands(i);            \
		translatePseudoAsmGeneric(i, ci, irb); \
		return;                                \
	}                                          \
}

} // namespace capstone2llvmir
} // namespace retdec

#endif
