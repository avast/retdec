/**
* @file include/retdec/bin2llvmir/optimizations/types_propagator/types_propagator.h
* @brief Data type propagation.
* @copyright (c) 2020 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_TYPES_PROPAGATOR_TYPES_PROPAGATOR_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_TYPES_PROPAGATOR_TYPES_PROPAGATOR_H

#include <list>
#include <unordered_map>
#include <unordered_set>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class TypesPropagator : public llvm::ModulePass
{
	public:
		static char ID;
		TypesPropagator();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Abi* abi);

	private:
		using EqSet = std::unordered_set<llvm::Value*>;
		using EqSets = std::list<EqSet>;

	private:
		bool run();
		void buildEquationSets();
		void processRoot(llvm::Value* val);
		void processValue(
				std::queue<llvm::Value*>& toProcess,
				EqSet& eqSet);
		void processUserInstruction(
				llvm::Value* val,
				llvm::Instruction* user,
				std::queue<llvm::Value*>& toProcess,
				EqSet& eqSet);

		bool skipRootProcessing(llvm::Value* val);
		EqSet* getEqSetForValue(llvm::Value* val);
		bool wasProcessed(llvm::Value* val);
		void addToProcessQueue(
				llvm::Value* val,
				std::queue<llvm::Value*>& toProcess);

	private:
		llvm::Module* _module = nullptr;
		Abi* _abi = nullptr;

	private:
		ReachingDefinitionsAnalysis _RDA;
		EqSets _eqSets;
		std::unordered_map<llvm::Value*, EqSet*> _val2eqSet;
};

} // namespace bin2llvmir
} // namespace retdec

#endif