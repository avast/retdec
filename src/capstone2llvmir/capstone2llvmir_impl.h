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
				retdec::utils::Address a,
				llvm::IRBuilder<>& irb,
				std::size_t count = 0,
				bool stopOnBranch = false) override;
		virtual TranslationResultOne translateOne(
				const uint8_t*& bytes,
				std::size_t& size,
				retdec::utils::Address& a,
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
			/// Convert to destination type using ZEXT or TRUNC.
			/// Types must be integer, or LLVM asserts.
			ZEXT_TRUNC,
			/// Convert to destination type using SEXT or TRUNC.
			/// Types must be integer, or LLVM asserts.
			SEXT_TRUNC,
			/// Convert to destination type using FPCast (FPExt, BitCast,
			/// or FPTrunc).
			/// Types must be floating point, or LLVM asserts.
			FP_CAST,
			/// Convert to destination type using SIToFP.
			/// Source must be integer, destination fp, or LLVM asserts.
			SITOFP,
			/// Convert to destination type using UIToFP.
			/// Source must be integer, destination fp, or LLVM asserts.
			UITOFP
		};

		llvm::Value* generateTypeConversion(
				llvm::IRBuilder<>& irb,
				llvm::Value* from,
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
				eOpConv ct = eOpConv::SEXT_TRUNC) = 0;
		virtual llvm::Instruction* storeOp(
				CInsnOp& op,
				llvm::Value* val,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::SEXT_TRUNC) = 0;

		llvm::Value* loadOpUnary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
				llvm::Type* dstType = nullptr,
				eOpConv ct = eOpConv::THROW,
				llvm::Type* loadType = nullptr);

		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
				CInsn* ci,
				llvm::IRBuilder<>& irb,
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
				llvm::IRBuilder<>& irb);
		std::pair<llvm::Value*, llvm::Value*> loadOpTernaryOp1Op2(
				CInsn* ai,
				llvm::IRBuilder<>& irb,
				eOpConv ct = eOpConv::NOTHING);

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
// Non-virtual helper methods.
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
		llvm::Function* getAsmFunction(const std::string& name) const;
		llvm::Function* getOrCreateAsmFunction(
				std::size_t insnId,
				const std::string& name,
				llvm::FunctionType* type);
		llvm::Function* getOrCreateAsmFunction(
				std::size_t insnId,
				const std::string& name,
				llvm::Type* retType);
		llvm::Function* getOrCreateAsmFunction(
				std::size_t insnId,
				const std::string& name,
				llvm::ArrayRef<llvm::Type*> params);
		llvm::Function* getOrCreateAsmFunction(
				std::size_t insnId,
				const std::string& name,
				llvm::Type* retType,
				llvm::ArrayRef<llvm::Type*> params);
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

		std::map<std::string, llvm::Function*> _asmFunctions;

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

		/// This is a helper map with all LLVM registers created by the
		/// translator. It is used to check, if given LLVM value is a register.
		/// Maybe, it would be possible to do this task without this.
		std::map<llvm::GlobalVariable*, uint32_t> _allLlvmRegs;

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
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
