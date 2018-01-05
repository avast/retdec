/**
 * @file include/retdec/capstone2llvmir/capstone2llvmir.h
 * @brief Converts bytes to Capstone representation, and Capstone representation
 *        to LLVM IR.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_RETDEC_CAPSTONE2LLVMIR_H
#define RETDEC_CAPSTONE2LLVMIR_RETDEC_CAPSTONE2LLVMIR_H

#include <cassert>
#include <memory>

#include <capstone/capstone.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/utils/address.h"
#include "retdec/capstone2llvmir/exceptions.h"

namespace retdec {
namespace capstone2llvmir {

/**
 * This is an abstract Capstone 2 LLVM IR translator class.
 * It can be used to create instances of concrete classes.
 * It should also be possible to create concreate classes on their own (they
 * should have public constructors), so that it is not  neccessary to modify
 * this class when adding new translators.
 */
class Capstone2LlvmIrTranslator
{
	// Named constructors.
	//
	public:
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArch(
				cs_arch a,
				llvm::Module* m,
				cs_mode basic = CS_MODE_LITTLE_ENDIAN,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArm(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createThumb(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArm64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips3(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips32R6(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_16(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpc32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpc64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpcQpx(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createSparc(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createSysz(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		static std::unique_ptr<Capstone2LlvmIrTranslator> createXcore(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);

		virtual ~Capstone2LlvmIrTranslator();

	// Capstone related getters.
	//
	public:
		const csh& getCapstoneEngine() const;
		cs_arch getArchitecture() const;
		cs_mode getBasicMode() const;
		cs_mode getExtraMode() const;

		virtual bool hasDelaySlot(uint32_t id) const;
		virtual bool hasDelaySlotTypical(uint32_t id) const;
		virtual bool hasDelaySlotLikely(uint32_t id) const;
		virtual std::size_t getDelaySlot(uint32_t id) const;

	// LLVM related getters and query methods.
	//
	public:
		llvm::Module* getModule() const;

		bool isSpecialAsm2LlvmMapGlobal(llvm::Value* v) const;
		llvm::StoreInst* isSpecialAsm2LlvmInstr(llvm::Value* v) const;
		llvm::GlobalVariable* getAsm2LlvmMapGlobalVariable() const;

		virtual bool isCallFunction(llvm::Function* f) const;
		virtual bool isCallFunctionCall(llvm::CallInst* c) const;
		llvm::Function* getCallFunction() const;

		virtual bool isReturnFunction(llvm::Function* f) const;
		virtual bool isReturnFunctionCall(llvm::CallInst* c) const;
		llvm::Function* getReturnFunction() const;

		virtual bool isBranchFunction(llvm::Function* f) const;
		virtual bool isBranchFunctionCall(llvm::CallInst* c) const;
		llvm::Function* getBranchFunction() const;

		virtual bool isCondBranchFunction(llvm::Function* f) const;
		virtual bool isCondBranchFunctionCall(llvm::CallInst* c) const;
		llvm::Function* getCondBranchFunction() const;

		llvm::Function* getAsmFunction(const std::string& name) const;

		llvm::GlobalVariable* isRegister(llvm::Value* v) const;
		virtual uint32_t getCapstoneRegister(llvm::GlobalVariable* gv) const;
		virtual llvm::GlobalVariable* getRegister(uint32_t r);
		virtual std::string getRegisterName(uint32_t r) const;
		virtual uint32_t getRegisterBitSize(uint32_t r) const;
		virtual uint32_t getRegisterByteSize(uint32_t r) const;
		virtual llvm::Type* getRegisterType(uint32_t r) const;

	// Translation methods.
	//
	public:
		struct TranslationResult
		{
			llvm::StoreInst* first = nullptr;
			llvm::StoreInst* last = nullptr;
			std::size_t size = 0;
			/// This is any branch type. i.e. call, return, branch, cond branch.
			llvm::CallInst* branchCall = nullptr;
			bool inCondition = false;
			bool failed() const { return size == 0; }
		};

		virtual TranslationResult translate(
				const std::vector<uint8_t>& bytes,
				retdec::utils::Address a,
				llvm::IRBuilder<>& irb,
				bool stopOnBranch = false);

	// Public pure virtual methods that must be implemented in concrete classes.
	//
	public:
		/**
		 * Check if mode @c m is an allowed basic mode for the translator.
		 * This must be implemented in concrete classes, since it is
		 * architecture and translator specific.
		 * @return @c True if mode is allowed, @c false otherwise.
		 */
		virtual bool isAllowedBasicMode(cs_mode m) = 0;
		/**
		 * Check if mode @c m is an allowed extra mode for the translator.
		 * This must be implemented in concrete classes, since it is
		 * architecture and translator specific.
		 * @return @c True if mode is allowed, @c false otherwise.
		 */
		virtual bool isAllowedExtraMode(cs_mode m) = 0;
		/**
		 * Modify basic mode (e.g. CS_MODE_ARM to CS_MODE_THUMB). This must be
		 * implemented in concrete classes, so they can check if the requested
		 * mode is applicable. Not every basic mode can be used with every
		 * architecture. Translators for some architectures (e.g. CS_ARCH_X86)
		 * may not even allow switching between modes that is otherwise allowed
		 * by Capstone due to internal problems (e.g. different register
		 * environments between 16/32/64 x86 architectures).
		 */
		virtual void modifyBasicMode(cs_mode m) = 0;
		/**
		 * Modify extra mode (e.g. CS_MODE_LITTLE_ENDIAN to CS_MODE_BIG_ENDIAN).
		 * This must be implemented in concrete classes, so they can check if
		 * the requested mode is applicable. Not every special mode can be used
		 * with every architecture.
		 */
		virtual void modifyExtraMode(cs_mode m) = 0;

		virtual uint32_t getArchByteSize() = 0;
		virtual uint32_t getArchBitSize() = 0;

	// Protected pure virtual methods that must be implemented in concrete
	// classes.
	//
	protected:
		/**
		 * Do architecture and mode specific initialization on top of common
		 * initialization done by @c initialize();
		 */
		virtual void initializeArchSpecific() = 0;

		/**
		 * Initialize @c _reg2name. See comment for @c _reg2name to know what must
		 * be initialized, and what may or may not be initialized.
		 */
		virtual void initializeRegNameMap() = 0;

		/**
		 * Initialize @c _reg2type. See comment for @c _reg2type to know what
		 * must be initialized, and what may or may not be initialized.
		 */
		virtual void initializeRegTypeMap() = 0;

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
		 * Translate single Capstone instruction.
		 */
		virtual void translateInstruction(
				cs_insn* i,
				llvm::IRBuilder<>& irb) = 0;

	protected:
		/**
		 * What should instruction operand loading method do, if types of
		 * loaded operands are not the same.
		 */
		enum class eOpConv
		{
			/// Throw exception.
			THROW,
			/// Operand types does not have to be equal.
			NOTHING,
			/// Convert second using SEXT.
			/// Types must be integer, or LLVM asserts.
			SECOND_SEXT,
			/// Convert second using ZEXT.
			/// Types must be integer, or LLVM asserts.
			SECOND_ZEXT,
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

	protected:
		Capstone2LlvmIrTranslator(
				cs_arch a,
				cs_mode basic,
				cs_mode extra,
				llvm::Module* m);

	protected:
		virtual void openHandle();
		virtual void configureHandle();
		virtual void closeHandle();
		virtual void initialize();
		virtual void generateEnvironment();

	protected:
		virtual void generateSpecialAsm2LlvmMapGlobal();
		virtual llvm::StoreInst* generateSpecialAsm2LlvmInstr(
				llvm::IRBuilder<>& irb,
				cs_insn* i);
		virtual void generateCallFunction();
		virtual llvm::CallInst* generateCallFunctionCall(
				llvm::IRBuilder<>& irb,
				llvm::Value* t);
		virtual void generateReturnFunction();
		virtual llvm::CallInst* generateReturnFunctionCall(
				llvm::IRBuilder<>& irb,
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

	protected:
		llvm::IRBuilder<> generateIfThen(
				llvm::Value* cond,
				llvm::IRBuilder<>& irb);
		llvm::IRBuilder<> generateIfNotThen(
				llvm::Value* cond,
				llvm::IRBuilder<>& irb);
		std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateIfThenElse(
				llvm::Value* cond,
				llvm::IRBuilder<>& irb);
		std::pair<llvm::IRBuilder<>, llvm::IRBuilder<>> generateWhile(
				llvm::BranchInst*& branch,
				llvm::IRBuilder<>& irb);

		llvm::Value* genValueNegate(llvm::IRBuilder<>& irb, llvm::Value* val);

	// Translation helper methods.
	//
	protected:
		llvm::Type* getIntegerTypeFromByteSize(unsigned sz);
		llvm::Type* getFloatTypeFromByteSize(unsigned sz);

	private:
		llvm::IRBuilder<> _generateIfThen(
				llvm::Value* cond,
				llvm::IRBuilder<>& irb,
				bool reverse = false);

	protected:
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

	protected:
		csh _handle = 0;
		cs_arch _arch = CS_ARCH_ALL;
		cs_mode _basicMode = CS_MODE_LITTLE_ENDIAN;
		cs_mode _extraMode = CS_MODE_LITTLE_ENDIAN;

		llvm::Module* _module = nullptr;
		llvm::GlobalVariable* _asm2llvmGv = nullptr;
		llvm::Function* _callFunction = nullptr; // void (i<arch_sz>)
		llvm::Function* _returnFunction = nullptr; // void (i<arch_sz>)
		llvm::Function* _branchFunction = nullptr; // void (i<arch_sz>)
		llvm::Function* _condBranchFunction = nullptr; // void (i1, i<arch_sz>)
		llvm::GlobalValue::LinkageTypes _regLt =
				llvm::GlobalValue::LinkageTypes::InternalLinkage;

		// TODO
//		std::map<std::size_t, llvm::Function*> _asmFunctions;
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

		/// TODO:
		/// @c True if generated branch is in conditional code, e.g. uncond
		/// branch in if-then.
		bool _inCondition = false;
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
