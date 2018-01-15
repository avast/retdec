/**
* @file include/retdec/bin2llvmir/optimizations/control_flow/control_flow.h
* @brief Reconstruct control flow.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CONTROL_FLOW_CONTROL_FLOW_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CONTROL_FLOW_CONTROL_FLOW_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

namespace retdec {
namespace bin2llvmir {

class ControlFlow : public llvm::ModulePass
{
	public:
		static char ID;
		ControlFlow();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* img);

	private:
		bool run();

		bool runX86();
		bool runX86Function(llvm::Function* f);
		bool runx86Return(AsmInstruction& ai);
		bool runx86Call(AsmInstruction& ai);
		bool runX86JmpNopNopPattern();

		bool runMips();
		bool runMipsFunction(llvm::Function* f);
		bool runMipsReturn(AsmInstruction& ai);
		bool runMipsCall(AsmInstruction& ai);
		bool runMipsDynamicStubPatter();

		bool runArm();
		bool runArmFunction(llvm::Function* f);
		bool runArmReturn(AsmInstruction& ai);
		bool runArmCall(AsmInstruction& ai);

		bool runPowerpc();
		bool runPowerpcFunction(llvm::Function* f);
		bool runPowerpcReturn(AsmInstruction& ai);
		bool runPowerpcCall(AsmInstruction& ai);

		bool runGeneric();
		bool runGenericFunction(llvm::Function* f);
		bool runGenericBr(AsmInstruction& ai, llvm::CallInst* call);
		bool runGenericCondBr(AsmInstruction& ai, llvm::CallInst* call);

		llvm::ReturnInst* transformToReturn(
				AsmInstruction& ai,
				llvm::CallInst* call = nullptr);
		llvm::Value* getOrMakeFunction(retdec::utils::Address addr);
		llvm::Value* makeFunction(retdec::utils::Address addr);
		llvm::CallInst* transformToCall(
				AsmInstruction& ai,
				llvm::CallInst* brCall,
				llvm::Value* called);

		llvm::GlobalVariable* getReturnObject();

		bool toReturn();
		bool toCall();
		bool toFunction();
		bool toBr();
		bool toCondBr();
		bool toSwitch();
		bool fixMain();

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		ReachingDefinitionsAnalysis _RDA;
		IrModifier _irmodif;

		struct SwitchEntry
		{
				llvm::CallInst* call = nullptr;
				AsmInstruction aiSource;
				llvm::Instruction* idx = nullptr;
				llvm::BasicBlock* defaultBb = nullptr;
				std::vector<std::pair<unsigned, AsmInstruction>> jmpTable;
		};

		std::set<AsmInstruction> _toFunctions;
		std::set<std::pair<AsmInstruction, llvm::CallInst*>> _toReturn;
		std::set<std::pair<llvm::CallInst*, retdec::utils::Address>> _toCall;
		std::set<std::pair<llvm::CallInst*, AsmInstruction>> _toBr;
		std::set<std::pair<llvm::CallInst*, AsmInstruction>> _toCondBr;
		std::list<SwitchEntry> _toSwitch;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
