/**
 * @file include/retdec/bin2llvmir/analyses/ctor_dtor.h
 * @brief Constructor and destructor detection analysis.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_CTOR_DTOR_H
#define RETDEC_BIN2LLVMIR_ANALYSES_CTOR_DTOR_H

#include <map>
#include <set>

#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class CtorDtor
{
	public:
		class FunctionInfo
		{
			public:
				/// Super method calls in order.
				std::vector<llvm::CallInst*> superMethods;
				/// Super method offsets in order.
				std::vector<int> superMethodOffsets;
				/// Virtual table stores in order.
				std::vector<std::pair<llvm::StoreInst*, const rtti_finder::Vtable*>> vftableStores;
				/// Virtual table offsets in order.
				std::vector<int> vftableOffsets;
				bool ctor = false;
				bool dtor = false;
		};

		using FunctionSet    = std::set<llvm::Function*>;
		using FunctionToInfo = std::map<llvm::Function*, FunctionInfo>;
		using StoreToVtable  = std::map<llvm::StoreInst*, const rtti_finder::Vtable*>;

	public:
		void runOnModule(llvm::Module* m, Config* c, FileImage* i);
		FunctionToInfo& getResults();

	private:
		void findPossibleCtorsDtors();
		void analyseFunction(llvm::Function* fnc);
		FunctionInfo analyseFunctionForward(llvm::Function* fnc);
		FunctionInfo analyseFunctionBackward(llvm::Function* fnc);
		int getOffset(llvm::Value* ecxStoreOp);
		llvm::StoreInst* findPreviousStoreToECX(llvm::Instruction* inst);
		void propagateCtorDtor();

		template<class T>
		FunctionInfo analyseFunctionCommon(T begin, T end);

	private:
		llvm::Module *module = nullptr;
		Config* config = nullptr;
		FileImage* image = nullptr;

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
