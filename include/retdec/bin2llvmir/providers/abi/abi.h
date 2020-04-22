/**
 * @file include/retdec/bin2llvmir/providers/abi/abi.h
 * @brief ABI information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_ABI_ABI_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_ABI_ABI_H

#include <map>
#include <memory>
#include <set>
#include <vector>

#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

//#include "retdec/capstone2llvmir/x86/x86_defs.h"

namespace retdec {
namespace bin2llvmir {

class Abi
{
	// Constants.
	//
	public:
		static const uint32_t REG_INVALID;
		static const unsigned DEFAULT_ADDR_SPACE;

	// Ctors, dtors.
	//
	public:
		Abi(llvm::Module* m, Config* c);
		virtual ~Abi() = default;

	// Registers.
	//
	public:
		bool isRegister(const llvm::Value* val) const;
		bool isRegister(const llvm::Value* val, uint32_t r) const;
		bool isFlagRegister(const llvm::Value* val);
		bool isStackPointerRegister(const llvm::Value* val) const;
		bool isZeroRegister(const llvm::Value* val);
		virtual bool isGeneralPurposeRegister(const llvm::Value* val) const = 0;

		llvm::GlobalVariable* getRegister(uint32_t r, bool use = true) const;
		uint32_t getRegisterId(const llvm::Value* r) const;
		const std::vector<llvm::GlobalVariable*>& getRegisters() const;
		llvm::GlobalVariable* getStackPointerRegister() const;
		llvm::GlobalVariable* getZeroRegister() const;

		std::size_t getRegisterByteSize(uint32_t r) const;

		void addRegister(uint32_t id, llvm::GlobalVariable* reg);

		llvm::GlobalVariable* getSyscallIdRegister();
		llvm::GlobalVariable* getSyscallReturnRegister();
		llvm::GlobalVariable* getSyscallArgumentRegister(unsigned n);

	// Stacks.
	//
	public:
		bool isStackVariable(const llvm::Value* val) const;

	// Instructions.
	//
	public:
		bool isNopInstruction(AsmInstruction ai);
		virtual bool isNopInstruction(cs_insn* insn) = 0;

	// Types.
	//
	public:
		virtual std::size_t getTypeByteSize(llvm::Type* t) const;
		virtual std::size_t getTypeBitSize(llvm::Type* t) const;
		llvm::IntegerType* getDefaultType() const;
		llvm::PointerType* getDefaultPointerType() const;
		std::size_t getWordSize() const;

		static std::size_t getTypeByteSize(llvm::Module* m, llvm::Type* t);
		static std::size_t getTypeBitSize(llvm::Module* m, llvm::Type* t);
		static llvm::IntegerType* getDefaultType(llvm::Module* m);
		static llvm::Type* getDefaultFPType(llvm::Module* m);
		static llvm::PointerType* getDefaultPointerType(llvm::Module* m);
		static std::size_t getWordSize(llvm::Module* m);

	// Architectures.
	//
	public:
		bool isMips() const;
		bool isMips64() const;
		bool isArm() const;
		bool isArm64() const;
		bool isX86() const;
		bool isX64() const;
		bool isPowerPC() const;
		bool isPowerPC64() const;
		bool isPic32() const;

	// Calling conventions.
	//
	public:
		bool supportsCallingConvention(
				const CallingConvention::ID& cc);
		CallingConvention* getCallingConvention(
				const CallingConvention::ID& cc);
		CallingConvention* getDefaultCallingConvention();
		CallingConvention::ID getDefaultCallingConventionID() const;

	// Config.
	//
	public:
		Config* getConfig() const;

	// Private data - misc.
	//
	protected:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;

	// Private data - registers.
	//
	protected:
		/// Fast iteration over all registers.
		/// \c id2regs may contain \c nullptr values.
		std::vector<llvm::GlobalVariable*> _regs;
		/// Fast "capstone id -> LLVM value" search.
		std::vector<llvm::GlobalVariable*> _id2regs;
		/// Fast "is LLVM value a register?" check.
		/// Fast "LLVM value -> capstone id" search.
		std::map<const llvm::Value*, uint32_t> _regs2id;

		/// ID of stack pointer register.
		uint32_t _regStackPointerId = REG_INVALID;
		/// ID of register where function return values are stored.
		uint32_t _regFunctionReturnId = REG_INVALID;

		/// Ordered list of registers used in system calls.
		std::vector<uint32_t> _syscallRegs;
		/// Register used for returning values from system calls.
		uint32_t _regSyscallReturn = REG_INVALID;
		/// Register used to pass system call ID.
		uint32_t _regSyscallId = REG_INVALID;
		/// Register that is always equal to zero - not every arch have this.
		uint32_t _regZeroReg = REG_INVALID;

	// Private data - calling convention
	//
	protected:
		std::map<CallingConvention::ID, CallingConvention::Ptr> _id2cc;
		CallingConvention::ID _defcc;

};

class AbiProvider
{
	public:
		static Abi* addAbi(
				llvm::Module* m,
				Config* c);
		static Abi* getAbi(llvm::Module* m);
		static bool getAbi(llvm::Module* m, Abi*& abi);
		static void clear();

	private:
		static std::map<llvm::Module*, std::unique_ptr<Abi>> _module2abi;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
