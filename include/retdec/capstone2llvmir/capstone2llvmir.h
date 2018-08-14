/**
 * @file include/retdec/capstone2llvmir/capstone2llvmir.h
 * @brief Common public interface for translators converting bytes to LLVM IR.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_RETDEC_CAPSTONE2LLVMIR_H
#define RETDEC_CAPSTONE2LLVMIR_RETDEC_CAPSTONE2LLVMIR_H

#include <list>
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

// These are additions to capstone - include them all here.
#include "retdec/capstone2llvmir/arm/arm_defs.h"
#include "retdec/capstone2llvmir/mips/mips_defs.h"
#include "retdec/capstone2llvmir/powerpc/powerpc_defs.h"
#include "retdec/capstone2llvmir/x86/x86_defs.h"

namespace retdec {
namespace capstone2llvmir {

/**
 * Abstract public interface class for all translators.
 *
 * Translator accepts binary data and position in LLVM module, disassembles
 * the data into Capstone instruction(s), and translates these instruction(s)
 * to LLVM IR instructions located at the given position.
 */
class Capstone2LlvmIrTranslator
{
//
//==============================================================================
// Named constructors.
//==============================================================================
//
	public:
		/**
		 * Create translator for the specified architecture @p a, module @p m,
		 * architecture basic HW mode @p basicMode corresponding to HW
		 * architectures (e.g. CS_MODE_ARM or CS_MODE_THUMB for CS_ARCH_ARM),
		 * and extra mode @p extraMode that can be combined with basic HW mode
		 * (e.g. CS_MODE_BIG_ENDIAN).
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified modes) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArch(
				cs_arch a,
				llvm::Module* m,
				cs_mode basic = CS_MODE_LITTLE_ENDIAN,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create 32-bit ARM translator with basic mode @c CS_MODE_ARM,
		 * and extra mode @c extra.
		 * This is meant to be used when ARM needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create THUMB translator
		 * use @c createThumb().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArm(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create 32-bit ARM translator with basic mode @c CS_MODE_THUMB,
		 * and extra mode @c extra.
		 * This is meant to be used when THUMB needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create ARM translator use
		 * @c createArm().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createThumb(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create 64-bit ARM translator with basic mode @c CS_MODE_ARM,
		 * and extra mode @c extra.
		 * This is meant to be used when 64-bit ARM needs to be used with
		 * extra mode like @c CS_MODE_BIG_ENDIAN.
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createArm64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create MIPS translator with basic mode @c CS_MODE_MIPS32, and extra
		 * mode @c extra.
		 * This is meant to be used when MIPS needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of MIPS translator use @c createMips64(), @c createMips3(), or
		 * @c createMips32R6().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create MIPS translator with basic mode @c CS_MODE_MIPS64, and extra
		 * mode @c extra.
		 * This is meant to be used when MIPS needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of MIPS translator use @c createMips32(), @c createMips3(), or
		 * @c createMips32R6().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create MIPS translator with basic mode @c CS_MODE_MIPS3, and extra
		 * mode @c extra.
		 * This is meant to be used when MIPS needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of MIPS translator use @c createMips32(), @c createMips64(), or
		 * @c createMips32R6().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips3(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create MIPS translator with basic mode @c CS_MODE_MIPS32R6, and extra
		 * mode @c extra.
		 * This is meant to be used when MIPS needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of MIPS translator use @c createMips32(), @c createMips64(),
		 * or @c createMips3().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createMips32R6(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create x86 translator with basic mode @c CS_MODE_16, and extra mode
		 * @c extra.
		 * This is meant to be used when x86 needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of x86 translator use @c createX86_32() or @c createX86_64().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_16(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create x86 translator with basic mode @c CS_MODE_32, and extra mode
		 * @c extra.
		 * This is meant to be used when x86 needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of x86 translator use @c createX86_16() or @c createX86_64().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create x86 translator with basic mode @c CS_MODE_64, and extra mode
		 * @c extra.
		 * This is meant to be used when x86 needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN. If you want to create a different flavour
		 * of x86 translator use @c createX86_16() or @c createX86_32().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createX86_64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create 32-bit PowerPC translator with basic mode @c CS_MODE_32,
		 * and extra mode @c extra.
		 * This is meant to be used when PowerPC needs to be used with extra
		 * mode like @c CS_MODE_BIG_ENDIAN. If you want to create 64-bit PowerPC
		 * translator use @c createPpc64().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpc32(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create 64-bit PowerPC translator with basic mode @c CS_MODE_64,
		 * and extra mode @c extra.
		 * This is meant to be used when PowerPC needs to be used with extra
		 * mode like @c CS_MODE_BIG_ENDIAN. If you want to create 32-bit PowerPC
		 * translator use @c createPpc32().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpc64(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create QPX PowerPC translator with basic mode @c CS_MODE_QPX, and
		 * extra mode @c extra.
		 * This is meant to be used when PowerPC needs to be used with extra
		 * mode like @c CS_MODE_BIG_ENDIAN. If you want to create 32-bit PowerPC
		 * translator use @c createPpc32().
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createPpcQpx(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create SPARC translator with extra mode @c extra.
		 * This is meant to be used when SPARC needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN.
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createSparc(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create SystemZ translator with extra mode @c extra.
		 * This is meant to be used when SystemZ needs to be used with extra
		 * mode like @c CS_MODE_BIG_ENDIAN.
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createSysz(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		/**
		 * Create XCore translator with extra mode @c extra.
		 * This is meant to be used when XCore needs to be used with extra mode
		 * like @c CS_MODE_BIG_ENDIAN.
		 * @return Unique pointer to created translator, or @c nullptr if
		 * translator (with the specified mode) could not be created.
		 */
		static std::unique_ptr<Capstone2LlvmIrTranslator> createXcore(
				llvm::Module* m,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);

		virtual ~Capstone2LlvmIrTranslator();
//
//==============================================================================
// Mode query & modification methods.
//==============================================================================
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

		/**
		 * @return Architecture byte size according to the currently set basic
		 * mode.
		 */
		virtual uint32_t getArchByteSize() = 0;
		/**
		 * @return Architecture bit size according to the currently set basic
		 * mode.
		 */
		virtual uint32_t getArchBitSize() = 0;
//
//==============================================================================
// Translation methods.
//==============================================================================
//
	public:
		struct TranslationResult
		{
			bool failed() const { return size == 0; }

			/// List of translated instruction pairs:
			/// first = LLVM IR instruction used for LLVM IR <-> Capstone
			/// instruction mapping.
			/// second = capstone instruction.
			/// All created LLVM IR instructions are added to the working LLVM
			/// module and should be automatically destroyed when module is
			/// destroyed.
			/// All capstone instructions are dynamically allocated by this
			/// method, and must be freed by caller to avoid memory leaks.
			std::list<std::pair<llvm::StoreInst*, cs_insn*>> insns;
			/// Byte size of the translated binary chunk.
			std::size_t size = 0;
			/// Number of translated assembly instructions.
			std::size_t count = 0;
			/// If @c stopOnBranch was set, this is set to the terminating
			/// branch instruction (any type, i.e. call, return, branch, cond
			/// branch), or @c nullptr if there was no such instruction.
			llvm::CallInst* branchCall = nullptr;
			/// @c True if @c branchCall is in conditional code,
			/// e.g. unconditional branch in if-then.
			bool inCondition = false;
		};
		/**
		 * Translate the given bytes.
		 * @param bytes Bytes to translate.
		 * @param size  Size of the @p bytes buffer.
		 * @param a     Memory address where @p bytes are located.
		 * @param irb   LLVM IR builder used to create LLVM IR translation.
		 *              Translated LLVM IR instructions are created at its
		 *              current position.
		 * @param count Number of assembly instructions to translate, or 0 to
		 *              translate them all.
		 * @param stopOnBranch If set, the translation aborts after any kind of
		 *              branch is encountered (call, return, branch, conditional
		 *              branch).
		 * @return See @c TranslationResult structure.
		 */
		virtual TranslationResult translate(
				const uint8_t* bytes,
				std::size_t size,
				retdec::utils::Address a,
				llvm::IRBuilder<>& irb,
				std::size_t count = 0,
				bool stopOnBranch = false) = 0;

		struct TranslationResultOne
		{
			bool failed() const { return size == 0; }

			/// Translated special LLVM IR instruction used for
			/// LLVM IR <-> Capstone instruction mapping.
			/// All created LLVM IR instructions are added to the working LLVM
			/// module and should be automatically destroyed when module is
			/// destroyed.
			llvm::StoreInst* llvmInsn = nullptr;
			/// Translated capstone instruction.
			/// Capstone instruction is dynamically allocated by this
			/// method, and must be freed by caller to avoid memory leaks.
			cs_insn* capstoneInsn = nullptr;
			/// Byte size of the translated binary chunk.
			std::size_t size = 0;
			/// If @c stopOnBranch was set, this is set to the terminating
			/// branch instruction (any type, i.e. call, return, branch, cond
			/// branch), or @c nullptr if there was no such instruction.
			llvm::CallInst* branchCall = nullptr;
			/// @c True if @c branchCall is in conditional code,
			/// e.g. unconditional branch in if-then.
			bool inCondition = false;
		};
		/**
		 * Translate one assembly instruction from the given bytes.
		 * @param bytes Bytes to translate.
		 *              This will be updated to point to the next instruction.
		 * @param size  Size of the @p bytes buffer.
		 *              This will be updated to reflect @p bytes update.
		 * @param a     Memory address where @p bytes are located.
		 *              This will be updated to point to the next instruction.
		 * @param irb   LLVM IR builder used to create LLVM IR translation.
		 *              Translated LLVM IR instructions are created at its
		 *              current position.
		 * @return See @c TranslationResult structure.
		 */
		virtual TranslationResultOne translateOne(
				const uint8_t*& bytes,
				std::size_t& size,
				retdec::utils::Address& a,
				llvm::IRBuilder<>& irb) = 0;
//
//==============================================================================
// Capstone related getters and query methods.
//==============================================================================
//
	public:
		/**
		 * @return Handle to the underlying Capstone engine.
		 */
		virtual const csh& getCapstoneEngine() const = 0;
		/**
		 * @return Capstone architecture this translator was initialized with.
		 */
		virtual cs_arch getArchitecture() const = 0;
		/**
		 * @return Capstone basic mode this translator is currently in.
		 */
		virtual cs_mode getBasicMode() const = 0;
		/**
		 * @return Capstone extra mode this translator is currently in.
		 */
		virtual cs_mode getExtraMode() const = 0;

		/**
		 * Has the specified Capstone instruction @p id any kind of delay slot?
		 */
		virtual bool hasDelaySlot(uint32_t id) const = 0;
		/**
		 * Has the specified Capstone instruction @p id typical delay slot?
		 */
		virtual bool hasDelaySlotTypical(uint32_t id) const = 0;
		/**
		 * Has the specified Capstone instruction @p id likely delay slot?
		 */
		virtual bool hasDelaySlotLikely(uint32_t id) const = 0;
		/**
		 * @return Size (number of instructions) of delay slot for the specified
		 * Capstone instruction @p id.
		 */
		virtual std::size_t getDelaySlot(uint32_t id) const = 0;

		/**
		 * @return LLVM global variable corresponding to the specified Capstone
		 * register @p r, or @c nullptr if such global does not exist.
		 */
		virtual llvm::GlobalVariable* getRegister(uint32_t r) = 0;
		/**
		 * @return Register name corresponding to the specified Capstone
		 * register @p r. The name may differ from names used by the Capstone
		 * library. This function works even for the additional registers
		 * defined in translators and missing in Capstone (e.g. individual flag
		 * registers).
		 * Throws @c Capstone2LlvmIrError exception if register name not found.
		 */
		virtual std::string getRegisterName(uint32_t r) const = 0;
		/**
		 * @return Register bit size corresponding to the specified Capstone
		 * register @p r. This function works even for the additional registers
		 * defined in translators and missing in Capstone (e.g. individual flag
		 * registers).
		 * Throws @c Capstone2LlvmIrError exception if register bit size not
		 * found.
		 */
		virtual uint32_t getRegisterBitSize(uint32_t r) const = 0;
		/**
		 * @return Register byte size corresponding to the specified Capstone
		 * register @p r. This function works even for the additional registers
		 * defined in translators and missing in Capstone (e.g. individual flag
		 * registers).
		 * Throws @c Capstone2LlvmIrError exception if register byte size not
		 * found.
		 */
		virtual uint32_t getRegisterByteSize(uint32_t r) const = 0;
		/**
		 * @return Register data type corresponding to the specified Capstone
		 * register @p r. This function works even for the additional registers
		 * defined in translators and missing in Capstone (e.g. individual flag
		 * registers).
		 * Throws @c Capstone2LlvmIrError exception if register data type not
		 * found.
		 */
		virtual llvm::Type* getRegisterType(uint32_t r) const = 0;

		/**
		 * Check if the translation of this instruction will/may produce any
		 * kind of control flow changing pseudo call (i.e. call/return/br/condbr
		 * pseudo function call).
		 *
		 * For ARM, parameter @p i must include @c detail member - instruction
		 * cannot be disassembled with CS_OP_DETAIL = CS_OPT_OFF, or with
		 * CS_OP_SKIPDATA = CS_OPT_OFF.
		 *
		 * For x86, MIPS, PowerPC, parameter @p i may not include @c detail
		 * member - instruction can be disassembled with
		 * CS_OP_DETAIL = CS_OPT_ON, or with CS_OP_SKIPDATA = CS_OPT_ON.
		 *
		 * It is sometimes tricky to find this information without actually
		 * translating the instruction. On the other hand, for some
		 * architectures, it would be possible to give more detailed information
		 * (e.g. the kind of pseudo function call), sometimes even from
		 * instruction ID alone (i.e. @c cs_insn::id):
		 * - x86: All kinds of pseudo function calls can be recognized from
		 *        the instruction ID alone.
		 * - mips: All kinds of pseudo function calls can be recognized from
		 *         the instruction ID alone.
		 * - powerpc: Can determine if the instruction is control flow changing
		 *            from the instruction ID alone. Hard/impossible to
		 *            determine the type without @c detail and replicating
		 *            the full analysis used in translation.
		 * - arm: Impossible to determine if the instruction is control flow
		 *        changing from the instruction ID alone. Instructions may
		 *        directly write the program counter - instruction details are
		 *        needed. Instructions may be conditional.
		 */
		virtual bool isControlFlowInstruction(cs_insn& i) const = 0;
		/**
		 * @return @c True if the Capstone instruction @p i is any kind of call
		 * instruction, translation of which would produce call pseudo call.
		 * @c False otherwise.
		 * @note This may not be always known for all architectures. Right now,
		 * it only works for x86 and MIPS. See @c isControlFlowInstruction()
		 * for more details.
		 */
		virtual bool isCallInstruction(cs_insn& i) const = 0;
		/**
		 * @return @c True if the Capstone instruction @p i is any kind of
		 * return instruction, translation of which would produce return
		 * pseudo call. @c False otherwise.
		 * @note This may not be always known for all architectures. Right now,
		 * it only works for x86 and MIPS. See @c isControlFlowInstruction()
		 * for more details.
		 */
		virtual bool isReturnInstruction(cs_insn& i) const = 0;
		/**
		 * @return @c True if the Capstone instruction @p i is any kind of
		 * branch instruction, translation of which would produce branch
		 * pseudo call. @c False otherwise.
		 * @note This may not be always known for all architectures. Right now,
		 * it only works for x86 and MIPS. See @c isControlFlowInstruction()
		 * for more details.
		 */
		virtual bool isBranchInstruction(cs_insn& i) const = 0;
		/**
		 * @return @c True if the Capstone instruction @p i is any kind of
		 * conditional branch instruction, translation of which would produce
		 * conditional branch pseudo call. @c False otherwise.
		 * @note This may not be always known for all architectures. Right now,
		 * it only works for x86 and MIPS. See @c isControlFlowInstruction()
		 * for more details.
		 */
		virtual bool isCondBranchInstruction(cs_insn& i) const = 0;
//
//==============================================================================
// LLVM related getters and query methods.
//==============================================================================
//
	public:
		/**
		 * @return LLVM module this translator works with.
		 */
		virtual llvm::Module* getModule() const = 0;

		/**
		 * Is the passed LLVM value @p v the special global variable used for
		 * LLVM IR <-> Capstone instruction mapping?
		 */
		virtual bool isSpecialAsm2LlvmMapGlobal(llvm::Value* v) const = 0;
		/**
		 * Is the passed LLVM value @p v a special instruction used for
		 * LLVM IR <-> Capstone instruction mapping?
		 * @return Value @p v casted to @c llvm::StoreInst if it is a special
		 * mapping instruction, @c nullptr otherwise.
		 */
		virtual llvm::StoreInst* isSpecialAsm2LlvmInstr(llvm::Value* v) const = 0;
		/**
		 * @return LLVM global variable used for LLVM IR <-> Capstone
		 * instruction mapping?
		 */
		virtual llvm::GlobalVariable* getAsm2LlvmMapGlobalVariable() const = 0;

		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents call operation in the translated LLVM IR?
		 */
		virtual bool isCallFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a call operation in the translated LLVM IR?
		 */
		virtual bool isCallFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is @c isCallFunctionCall() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionCallFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a call operation in the translated LLVM IR.
		 * Function signature: @code{.cpp} void (i<arch_sz>) @endcode
		 */
		virtual llvm::Function* getCallFunction() const = 0;
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents return operation in the translated LLVM IR?
		 */
		virtual bool isReturnFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a return operation in the translated
		 * LLVM IR?
		 */
		virtual bool isReturnFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is @c isReturnFunctionCall() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionReturnFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a return operation in the translated LLVM IR.
		 * Function signature: @code{.cpp} void (i<arch_sz>) @endcode
		 */
		virtual llvm::Function* getReturnFunction() const = 0;
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents branch operation in the translated LLVM IR?
		 */
		virtual bool isBranchFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a branch operation in the translated
		 * LLVM IR?
		 */
		virtual bool isBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is @c isBranchFunctionCall() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a branch operation in the translated LLVM IR.
		 * Function signature: @code{.cpp} void (i<arch_sz>) @endcode
		 */
		virtual llvm::Function* getBranchFunction() const = 0;
		/**
		 * Is the passed LLVM function @p f the special pseudo function
		 * whose call represents conditional branch operation in the translated
		 * LLVM IR?
		 * Function signature: @code{.cpp} void (i1, i<arch_sz>) @endcode
		 */
		virtual bool isCondBranchFunction(llvm::Function* f) const = 0;
		/**
		 * Is @c isCondBranchFunction() @c true for the passed LLVM call
		 * instruction @p c, and execution of the call instruction @p c is
		 * conditional.
		 * @return Branch instruction which true branch jumps to the @p c if
		 *         @p c is conditional, @c nullptr otherwise.
		 */
		virtual llvm::BranchInst* isInConditionCondBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * Is the passed LLVM call instruction @p c a special pseudo call
		 * instruction representing a conditional branch operation in the
		 * translated LLVM IR?
		 */
		virtual bool isCondBranchFunctionCall(llvm::CallInst* c) const = 0;
		/**
		 * @return LLVM function used as special pseudo function whose call
		 * represents a conditional branch operation in the translated LLVM IR.
		 */
		virtual llvm::Function* getCondBranchFunction() const = 0;

		/**
		 * Is the passed LLVM function @p f any kind of pseudo function
		 * generated by capstone2llvmir (e.g. call/return/br/... function).
		 */
		virtual bool isAnyPseudoFunction(llvm::Function* f) const = 0;
		/**
		 * Is the passed LLVM call @p c any kind of pseudo call generated by
		 * capstone2llvmir (e.g. call/return/br/... function call).
		 */
		virtual bool isAnyPseudoFunctionCall(llvm::CallInst* c) const = 0;

		/**
		 * Is the passed LLVM value @p v a global variable representing some
		 * HW register?
		 * @return Value @p v casted to @c llvm::GlobalVariable if it is
		 * representing some HW register, @c nullptr otherwise.
		 */
		virtual llvm::GlobalVariable* isRegister(llvm::Value* v) const = 0;
		/**
		 * @return Capstone register corresponding to the provided LLVM global
		 * variable @p gv if such register exists, zero otherwise (zero equals
		 * to @c [arch]_REG_INVALID in all Capstone architecture models, e.g.
		 * @c ARM_REG_INVALID, @c MIPS_REG_INVALID).
		 */
		virtual uint32_t getCapstoneRegister(llvm::GlobalVariable* gv) const = 0;
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
