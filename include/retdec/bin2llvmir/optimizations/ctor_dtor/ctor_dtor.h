/**
 * @file include/retdec/bin2llvmir/optimizations/ctor_dtor/ctor_dtor.h
 * @brief Constructor and destructor detection analysis.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CTOR_DTOR_CTOR_DTOR_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CTOR_DTOR_CTOR_DTOR_H

#include <map>
#include <set>

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/optimizations/vtable/vtable.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class CtorDtor : public llvm::ModulePass
{
	public:
		static char ID;
		CtorDtor();
		virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const override;
		virtual bool runOnModule(llvm::Module& M) override;

	public:
		class FunctionInfo
		{
			public:
				/// Super method calls in order.
				std::vector<const llvm::CallInst*> superMethods;
				/// Super method offsets in order.
				std::vector<int> superMethodOffsets;
				/// Virtual table stores in order.
				std::vector<std::pair<llvm::StoreInst*, Vtable*>> vftableStores;
				/// Virtual table offsets in order.
				std::vector<int> vftableOffsets;
				///
				bool ctor = false;
				bool dtor = false;
		};

	public:
		using FunctionSet    = std::set<llvm::Function*>;
		using FunctionToInfo = std::map<llvm::Function*, FunctionInfo>;
		using StoreToVtable  = std::map<llvm::StoreInst*, Vtable*>;

	public:
		FunctionToInfo& getResults();

	private:
		void findPossibleCtorsDtors();
		void analyseFunction(llvm::Function* fnc);
		FunctionInfo analyseFunctionForward(llvm::Function* fnc);
		FunctionInfo analyseFunctionBackward(llvm::Function* fnc);
		int getOffset(const llvm::Value* ecxStoreOp);
		const llvm::StoreInst* findPreviousStoreToECX(
				const llvm::Instruction* inst);
		void propagateCtorDtor();
		void replaceVtablesPointersInStores(
				llvm::StoreInst* store,
				Vtable* vtable);

		template<class T>
		FunctionInfo analyseFunctionCommon(T begin, T end);

	private:
		llvm::Module *module = nullptr;
		Config* config = nullptr;
		FunctionSet possibleCtorsDtors;
		StoreToVtable stores2vtables;
		FunctionToInfo function2info;
};

template<class T>
CtorDtor::FunctionInfo CtorDtor::analyseFunctionCommon(T begin, T end)
{
	enum
	{
		STEP_SUPER,
		STEP_VTABLES
	} step = STEP_SUPER;

	CtorDtor::FunctionInfo result;

	for (T it = begin; it != end; ++it)
	{
		llvm::Instruction *i = &(*it);
		if (step == STEP_SUPER)
		{
			if (llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(i))
			{
				if (possibleCtorsDtors.count(call->getCalledFunction()))
				{
					result.superMethods.push_back(call);
				}
			}
		}
		if (step == STEP_SUPER || step == STEP_VTABLES)
		{
			if (llvm::StoreInst *store = llvm::dyn_cast<llvm::StoreInst>(i))
			{
				auto fIt = stores2vtables.find(store);
				if (fIt != stores2vtables.end())
				{
					result.vftableStores.push_back( {store, fIt->second} );
					step = STEP_VTABLES;
				}
			}
		}
	}

	return result;
}

} // namespace bin2llvmir
} // namespace retdec

#endif
