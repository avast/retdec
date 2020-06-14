/**
* @file include/retdec/bin2llvmir/optimizations/param_return/collector/collector.h
* @brief Collects possible arguments and returns of functions.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_COLLECTOR_COLLECTOR_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_COLLECTOR_COLLECTOR_H

#include <map>
#include <vector>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/optimizations/param_return/data_entries.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class Collector
{
	public:
		typedef std::unique_ptr<Collector> Ptr;

	public:
		Collector(
			const Abi* abi,
			llvm::Module* m,
			const ReachingDefinitionsAnalysis* rda);

		virtual ~Collector() = default;

	public:
		virtual void collectCallArgs(CallEntry* ce) const;
		virtual void collectCallRets(CallEntry* ce) const;

		virtual void collectDefArgs(DataFlowEntry* de) const;
		virtual void collectDefRets(DataFlowEntry* de) const;

		virtual void collectCallSpecificTypes(CallEntry* ce) const;

	protected:

		void collectRetStores(ReturnEntry* re) const;

		void collectStoresBeforeInstruction(
			llvm::Instruction* i,
			std::vector<llvm::StoreInst*>& stores) const;

		void collectLoadsAfterInstruction(
			llvm::Instruction* i,
			std::vector<llvm::LoadInst*>& loads) const;

		bool collectLoadsAfterInstruction(
			llvm::Instruction* i,
			std::vector<llvm::LoadInst*>& loads,
			std::set<llvm::Value*>& excluded) const;

		void  collectStoresInSinglePredecessors(
			llvm::Instruction* i,
			std::vector<llvm::StoreInst*>& stores) const;

		void collectStoresRecursively(
			llvm::Instruction* i,
			std::vector<llvm::StoreInst*>& stores,
			std::map<llvm::BasicBlock*,
				std::set<llvm::Value*>>& seen) const;

		bool collectStoresInInstructionBlock(
			llvm::Instruction* i,
			std::set<llvm::Value*>& values,
			std::vector<llvm::StoreInst*>& stores) const;

	protected:
		bool extractFormatString(CallEntry* ce) const;

		bool storesString(llvm::StoreInst* si, std::string& str) const;
		llvm::Value* getRoot(llvm::Value* i) const;
		llvm::Value* _getRoot(llvm::Value* i, std::set<llvm::Value*>& seen) const;

	protected:
		const Abi* _abi;
		llvm::Module* _module;
		const ReachingDefinitionsAnalysis* _rda;
};

class CollectorProvider
{
	public:
		static Collector::Ptr createCollector(
				const Abi* abi,
				llvm::Module* m,
				const ReachingDefinitionsAnalysis* rda);
};

} // namespace bin2llvmir
} // namespace retdec

#endif
