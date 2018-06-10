/**
* @file include/retdec/bin2llvmir/optimizations/decoder/decoder.h
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_H

#include <map>
#include <queue>
#include <sstream>

#include <llvm/IR/CFG.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/analyses/static_code/static_code.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder_debug.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder_ranges.h"
#include "retdec/bin2llvmir/optimizations/decoder/jump_targets.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/capstone2llvmir/capstone2llvmir.h"

namespace retdec {
namespace bin2llvmir {

class Decoder : public llvm::ModulePass
{
	public:
		static char ID;
		Decoder();
		~Decoder();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* o,
				DebugFormat* d,
				NameContainer* n,
				Abi* a);

	private:
		using ByteData = typename std::pair<const std::uint8_t*, std::size_t>;

	private:
		bool runCatcher();
		bool run();

	// Initializations.
	//
	private:
		void initTranslator();
		void initDryRunCsInstruction();
		void initEnvironment();
		void initEnvironmentAsm2LlvmMapping();
		void initEnvironmentPseudoFunctions();
		void initEnvironmentRegisters();
		void initRanges();
		void initAllowedRangesWithSegments();
		void initAllowedRangesWithConfig();
		void initJumpTargets();
		void initJumpTargetsConfig();
		void initJumpTargetsEntryPoint();
		void initJumpTargetsImports();
		void initJumpTargetsExports();
		void initJumpTargetsDebug();
		void initJumpTargetsSymbols();
		void initConfigFunctions();
		void initStaticCode();
		void initVtables();

	private:
		void decode();
		bool getJumpTarget(JumpTarget& jt);
		void decodeJumpTarget(const JumpTarget& jt);
		std::size_t decodeJumpTargetDryRun(
				const JumpTarget& jt,
				ByteData bytes,
				bool strict = false);
		cs_mode determineMode(cs_insn* insn, utils::Address& target);
		capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne
				translate(
						ByteData& bytes,
						utils::Address& addr,
						llvm::IRBuilder<>& irb);

		bool getJumpTargetsFromInstruction(
				utils::Address addr,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr,
				std::size_t& rangeSize);
		utils::Address getJumpTarget(
				utils::Address addr,
				llvm::CallInst* branchCall,
				llvm::Value* val);
		bool getJumpTargetSwitch(
				utils::Address addr,
				llvm::CallInst* branchCall,
				llvm::Value* val,
				SymbolicTree& st);
		bool instructionBreaksBasicBlock(
				utils::Address addr,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& tr);
		void handleDelaySlotTypical(
				utils::Address& addr,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& res,
				ByteData& bytes,
				llvm::IRBuilder<>& irb);
		void handleDelaySlotLikely(
				utils::Address& addr,
				capstone2llvmir::Capstone2LlvmIrTranslator::TranslationResultOne& res,
				ByteData& bytes,
				llvm::IRBuilder<>& irb);

		void resolvePseudoCalls();
		void finalizePseudoCalls();

	// Basic block related methods.
	//
	private:
		utils::Address getBasicBlockAddress(llvm::BasicBlock* b);
		utils::Address getBasicBlockEndAddress(llvm::BasicBlock* b);
		utils::Address getBasicBlockAddressAfter(utils::Address a);
		llvm::BasicBlock* getBasicBlockAtAddress(utils::Address a);
		llvm::BasicBlock* getBasicBlockBeforeAddress(utils::Address a);
		llvm::BasicBlock* getBasicBlockAfterAddress(utils::Address a);
		llvm::BasicBlock* getBasicBlockContainingAddress(utils::Address a);
		llvm::BasicBlock* createBasicBlock(
				utils::Address a,
				llvm::Function* f,
				llvm::BasicBlock* insertAfter = nullptr);
		void addBasicBlock(utils::Address a, llvm::BasicBlock* b);

		std::map<utils::Address, llvm::BasicBlock*> _addr2bb;
		std::map<llvm::BasicBlock*, utils::Address> _bb2addr;

	// Function related methods.
	//
	private:
		utils::Address getFunctionAddress(llvm::Function* f);
		utils::Address getFunctionEndAddress(llvm::Function* f);
		utils::Address getFunctionAddressAfter(utils::Address a);
		llvm::Function* getFunctionAtAddress(utils::Address a);
		llvm::Function* getFunctionBeforeAddress(utils::Address a);
		llvm::Function* getFunctionAfterAddress(utils::Address a);
		llvm::Function* getFunctionContainingAddress(utils::Address a);
		llvm::Function* createFunction(
				utils::Address a,
				bool declaration = false);
		void addFunction(utils::Address a, llvm::Function* f);
		void addFunctionSize(llvm::Function* f, utils::Maybe<std::size_t> sz);

		std::map<utils::Address, llvm::Function*> _addr2fnc;
		std::map<llvm::Function*, utils::Address> _fnc2addr;
		// Function sizes from debug info/symbol table/config/etc.
		// Used to prevent function splitting.
		//
		// TODO: Potential overlaps are not handled.
		// E.g. ack.arm.gnuarmgcc-4.4.1.O0.g.elf:
		// __floatundidf @ 0x1645c : size = 128
		// __floatdidf   @ 0x16470 : size = 108
		// It looks like there is one function in another.
		//
		std::map<llvm::Function*, std::size_t> _fnc2sz;

	// Pattern recognition methods.
	//
	private:
		bool patternsRecognize();
		bool patternTerminatingCalls();
		bool patternStaticallyLinked();

	// x86 specifix.
	//
	private:
		std::size_t decodeJumpTargetDryRun_x86(
				const JumpTarget& jt,
				ByteData bytes,
				bool strict = false);

	// ARM specific.
	//
	private:
		std::size_t decodeJumpTargetDryRun_arm(
				const JumpTarget& jt,
				ByteData bytes,
				bool strict = false);
		std::size_t decodeJumpTargetDryRun_arm(
				const JumpTarget& jt,
				ByteData bytes,
				cs_mode mode,
				std::size_t &decodedSz,
				bool strict = false);
		void patternsPseudoCall_arm(llvm::CallInst*& call, AsmInstruction& pAi);
		cs_mode determineMode_arm(cs_insn* insn, utils::Address& target);

	// MIPS specific.
	//
	private:
		bool disasm_mips(
				csh ce,
				cs_mode m,
				ByteData& bytes,
				uint64_t& a,
				cs_insn* i);
		std::size_t decodeJumpTargetDryRun_mips(
				const JumpTarget& jt,
				ByteData bytes,
				bool strict = false);
		void initializeGpReg_mips();

	// PowerPC specific.
	//
	private:
		std::size_t decodeJumpTargetDryRun_ppc(
				const JumpTarget& jt,
				ByteData bytes,
				bool strict = false);

	// IR modifications.
	//
	private:
		llvm::CallInst* transformToCall(
				llvm::CallInst* pseudo,
				llvm::Function* callee);
		llvm::CallInst* transformToCondCall(
				llvm::CallInst* pseudo,
				llvm::Value* cond,
				llvm::Function* callee,
				llvm::BasicBlock* falseBb);
		llvm::ReturnInst* transformToReturn(llvm::CallInst* pseudo);
		llvm::BranchInst* transformToBranch(
				llvm::CallInst* pseudo,
				llvm::BasicBlock* branchee);
		llvm::BranchInst* transformToCondBranch(
				llvm::CallInst* pseudo,
				llvm::Value* cond,
				llvm::BasicBlock* trueBb,
				llvm::BasicBlock* falseBb);
		llvm::SwitchInst* transformToSwitch(
				llvm::CallInst* pseudo,
				llvm::Value* val,
				llvm::BasicBlock* defaultBb,
				const std::vector<llvm::BasicBlock*>& cases);

		llvm::GlobalVariable* getCallReturnObject();

		void getOrCreateCallTarget(
				utils::Address addr,
				llvm::Function*& tFnc,
				llvm::BasicBlock*& tBb);
		void getOrCreateBranchTarget(
				utils::Address addr,
				llvm::BasicBlock*& tBb,
				llvm::Function*& tFnc,
				llvm::Instruction* from);

		bool canSplitFunctionOn(llvm::BasicBlock* bb);
		bool canSplitFunctionOn(
				utils::Address addr,
				llvm::BasicBlock* bb,
				std::set<llvm::BasicBlock*>& newFncStarts);
		llvm::Function* splitFunctionOn(utils::Address addr);
		llvm::Function* splitFunctionOn(utils::Address addr, llvm::BasicBlock* bb);

	// Data.
	//
	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _debug = nullptr;
		NameContainer* _names = nullptr;
		Llvm2CapstoneMap* _llvm2capstone = nullptr;
		Abi* _abi = nullptr;

		ReachingDefinitionsAnalysis _RDA;

		std::unique_ptr<capstone2llvmir::Capstone2LlvmIrTranslator> _c2l;
		cs_insn* _dryCsInsn = nullptr;

		llvm::IRBuilder<>* _irb;

		RangesToDecode _ranges;
		JumpTargets _jumpTargets;

		std::set<utils::Address> _imports;
		std::set<utils::Address> _exports;
		std::set<utils::Address> _symbols;
		std::map<utils::Address, const config::Function*> _debugFncs;
		std::set<utils::Address> _staticFncs;
		std::set<utils::Address> _vtableFncs;
		std::set<llvm::Function*> _terminatingFncs;
		llvm::Function* _entryPointFunction = nullptr;
		/// Start of all recognized jump tables.
		/// TODO: use this to check that one table does not use labels from
		/// another.
		/// TODO: maybe we should also remove/fix cond branches to default
		/// labels before switches (this was done in the original cfg
		/// implementation. However, if we do it too soon, it will cause
		/// diff problems when comparing to IDA cfg dumps). We could do it
		/// after.
		/// Btw, we already have diff problem because default label is added to
		/// switch -> it has one more succ then cond branch in IDA (if default
		/// label is not in jump table).
		std::map<utils::Address, std::set<llvm::SwitchInst*>> _switchTableStarts;

		std::map<llvm::CallInst*, llvm::Instruction*> _pseudoCalls;

		// We create helper BBs (without name and address) to handle MIPS
		// likely branches. For convenience, we map them to real BBs they will
		// eventually jump to.
		std::map<llvm::BasicBlock*, llvm::BasicBlock*> _likelyBb2Target;

		// TODO: remove, solve better.
		bool _switchGenerated = false;

		bool _somethingDecoded = false;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
