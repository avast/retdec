/**
 * @file include/retdec/llvmir-emul/llvmir_emul.h
 * @brief LLVM IR emulator library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVMIR_EMUL_LLVMIR_EMUL_H
#define RETDEC_LLVMIR_EMUL_LLVMIR_EMUL_H

#include <list>
#include <map>
#include <set>

#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/IR/CallSite.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Module.h>

#include "retdec/llvmir-emul/exceptions.h"

namespace retdec {
namespace llvmir_emul {

/**
 * AllocaHolder - Object to track all of the blocks of memory allocated by
 * alloca.  When the function returns, this object is popped off the execution
 * stack, which causes the dtor to be run, which frees all the alloca'd memory.
 */
class AllocaHolder
{
	public:
		AllocaHolder()
		{

		}

		AllocaHolder(AllocaHolder &RHS) = default;
		AllocaHolder(AllocaHolder &&RHS) :
			Allocations(std::move(RHS.Allocations))
		{

		}

		AllocaHolder &operator=(AllocaHolder &RHS) = default;
		AllocaHolder &operator=(AllocaHolder &&RHS)
		{
			Allocations = std::move(RHS.Allocations);
			return *this;
		}

		~AllocaHolder()
		{
			for (void *Allocation : Allocations)
				free(Allocation);
		}

		void add(void *Mem)
		{
			Allocations.push_back(Mem);
		}

	private:
		std::vector<void *> Allocations;
};

class LocalExecutionContext;

/**
 * This is not ideal.
 * 1) Memory accesses are separated into global variable accesses and memory
 *    accesses using integer values. This is ok.
 * 2) Memory is not modeled byte-by-byte. Generic values of any size are mapped
 *    to every memory address. I.e. if 4 byte integer value is stored to 0x1000
 *    and 2 byte integer value is stored to 0x1002, right now these two values
 *    are both separate entries in the memory map and do not affect each other,
 *    even though they should.
 */
class GlobalExecutionContext
{
	public:
		GlobalExecutionContext(llvm::Module* m);
		llvm::Module* getModule() const;

		llvm::GenericValue getMemory(uint64_t addr, bool log = true);
		void setMemory(uint64_t addr, llvm::GenericValue val, bool log = true);

		llvm::GenericValue getGlobal(llvm::GlobalVariable* g, bool log = true);
		void setGlobal(
				llvm::GlobalVariable* g,
				llvm::GenericValue val,
				bool log = true);

		void setValue(llvm::Value* v, llvm::GenericValue val);
		llvm::GenericValue getOperandValue(
				llvm::Value* val,
				LocalExecutionContext& ec);

	public:
		llvm::Module* _module = nullptr;

		std::map<uint64_t, llvm::GenericValue> memory;
		std::list<uint64_t> memoryLoads;
		std::list<uint64_t> memoryStores;

		std::map<llvm::GlobalVariable*, llvm::GenericValue> globals;
		std::list<llvm::GlobalVariable*> globalsLoads;
		std::list<llvm::GlobalVariable*> globalsStores;

		/// LLVM values of all emulated objects.
		/// In the original LLVM's interpret implementation, this was in local
		/// context.
		/// However, we want to provide this information to the user of this
		/// library after emulation is done, so we need to preserve it for all
		/// emulated objects and not to thorw it away after local frame is left.
		std::map<llvm::Value*, llvm::GenericValue> values;
};

class LocalExecutionContext
{
	public:
		LocalExecutionContext();
		LocalExecutionContext(LocalExecutionContext& o) = default;
		LocalExecutionContext(LocalExecutionContext&& o);
		LocalExecutionContext &operator=(LocalExecutionContext&& o);
		LocalExecutionContext &operator=(LocalExecutionContext& o) = default;

		llvm::Module* getModule() const;

	public:
		/// The currently executing function
		llvm::Function* curFunction = nullptr;
		/// The currently executing BB
		llvm::BasicBlock* curBB = nullptr;
		/// The next instruction to execute
		llvm::BasicBlock::iterator curInst;
		/// Holds the call that called subframes.
		/// NULL if main func or debugger invoked fn
		llvm::CallSite caller;
		/// Track memory allocated by alloca
		AllocaHolder allocas;
};

class LlvmIrEmulator : public llvm::InstVisitor<LlvmIrEmulator>
{
	public:
		struct CallEntry
		{
			llvm::Value* calledValue;
			std::vector<llvm::GenericValue> calledArguments;
		};

	public:
		LlvmIrEmulator(llvm::Module* m);
		~LlvmIrEmulator();

		llvm::GenericValue runFunction(
				llvm::Function* f,
				const llvm::ArrayRef<llvm::GenericValue> argVals = {});

	// Emulation query methods.
	//
	public:
		const std::list<llvm::Instruction*>& getVisitedInstructions() const;
		const std::list<llvm::BasicBlock*>& getVisitedBasicBlocks() const;
		bool wasInstructionVisited(llvm::Instruction* i) const;
		bool wasBasicBlockVisited(llvm::BasicBlock* bb) const;

		llvm::GenericValue getExitValue() const;

		const std::list<CallEntry>& getCallEntries() const;
		std::list<llvm::Value*> getCalledValues() const;
		std::set<llvm::Value*> getCalledValuesSet() const;
		bool wasValueCalled(llvm::Value* v) const;
		const CallEntry* getCallEntry(llvm::Value* v, unsigned n = 0) const;

		bool wasGlobalVariableLoaded(llvm::GlobalVariable* gv);
		bool wasGlobalVariableStored(llvm::GlobalVariable* gv);
		std::list<llvm::GlobalVariable*> getLoadedGlobalVariables();
		std::set<llvm::GlobalVariable*> getLoadedGlobalVariablesSet();
		std::list<llvm::GlobalVariable*> getStoredGlobalVariables();
		std::set<llvm::GlobalVariable*> getStoredGlobalVariablesSet();
		llvm::GenericValue getGlobalVariableValue(llvm::GlobalVariable* gv);
		void setGlobalVariableValue(
				llvm::GlobalVariable* gv,
				llvm::GenericValue val);

		bool wasMemoryLoaded(uint64_t addr);
		bool wasMemoryStored(uint64_t addr);
		std::list<uint64_t> getLoadedMemory();
		std::set<uint64_t> getLoadedMemorySet();
		std::list<uint64_t> getStoredMemory();
		std::set<uint64_t> getStoredMemorySet();
		llvm::GenericValue getMemoryValue(uint64_t addr);
		void setMemoryValue(uint64_t addr, llvm::GenericValue val);

		llvm::GenericValue getValueValue(llvm::Value* val);

	// This needs to be public for LLVM instruction visitor.
	// However, users of this class SHOULD NOT call any of these.
	//
	public:
		void visitReturnInst(llvm::ReturnInst& I);
		void visitBranchInst(llvm::BranchInst& I);
		void visitSwitchInst(llvm::SwitchInst& I);
		void visitIndirectBrInst(llvm::IndirectBrInst& I);
		void visitBinaryOperator(llvm::BinaryOperator& I);
		void visitICmpInst(llvm::ICmpInst& I);
		void visitFCmpInst(llvm::FCmpInst& I);
		void visitAllocaInst(llvm::AllocaInst& I);
		void visitLoadInst(llvm::LoadInst& I);
		void visitStoreInst(llvm::StoreInst& I);
		void visitGetElementPtrInst(llvm::GetElementPtrInst& I);
		void visitPHINode(llvm::PHINode& PN);
		void visitTruncInst(llvm::TruncInst& I);
		void visitZExtInst(llvm::ZExtInst& I);
		void visitSExtInst(llvm::SExtInst& I);
		void visitFPTruncInst(llvm::FPTruncInst& I);
		void visitFPExtInst(llvm::FPExtInst& I);
		void visitUIToFPInst(llvm::UIToFPInst& I);
		void visitSIToFPInst(llvm::SIToFPInst& I);
		void visitFPToUIInst(llvm::FPToUIInst& I);
		void visitFPToSIInst(llvm::FPToSIInst& I);
		void visitPtrToIntInst(llvm::PtrToIntInst& I);
		void visitIntToPtrInst(llvm::IntToPtrInst& I);
		void visitBitCastInst(llvm::BitCastInst& I);
		void visitSelectInst(llvm::SelectInst& I);
		void visitCallInst(llvm::CallInst& I);
		void visitInvokeInst(llvm::InvokeInst& I);
		void visitUnreachableInst(llvm::UnreachableInst& I);
		void visitShl(llvm::BinaryOperator& I);
		void visitLShr(llvm::BinaryOperator& I);
		void visitAShr(llvm::BinaryOperator& I);
		void visitVAArgInst(llvm::VAArgInst& I);
		void visitExtractElementInst(llvm::ExtractElementInst& I);
		void visitInsertElementInst(llvm::InsertElementInst& I);
		void visitShuffleVectorInst(llvm::ShuffleVectorInst& I);
		void visitExtractValueInst(llvm::ExtractValueInst& I);
		void visitInsertValueInst(llvm::InsertValueInst& I);
		void visitInstruction(llvm::Instruction& I);

	private:
		void run();
		void callFunction(
				llvm::Function* f,
				llvm::ArrayRef<llvm::GenericValue> argVals);

		void logInstruction(llvm::Instruction* i);

		void popStackAndReturnValueToCaller(
				llvm::Type* retT,
				llvm::GenericValue res);

	public:
		std::vector<LocalExecutionContext> _ecStackRetired;

	private:
		llvm::IntrinsicLowering *IL = nullptr;
		llvm::Module* _module = nullptr;
		llvm::GenericValue _exitValue;
		std::vector<LocalExecutionContext> _ecStack;
		GlobalExecutionContext _globalEc;

		/// All visited instruction in order of their visitation.
		/// No cycling checks are performed at the moment -- one instruction
		/// might be visited multiple times.
		std::list<llvm::Instruction*> _visitedInsns;
		/// All visited basic blocks in order of their visitation.
		/// No cycling checks are performed at the moment -- one basic block
		/// might be visited multiple times.
		std::list<llvm::BasicBlock*> _visitedBbs;

		/// Intrinsic calls are lowered and not logged here.
		std::list<CallEntry> _calls;
};

} // llvmir_emul
} // retdec

#endif
