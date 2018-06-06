/**
* @file include/retdec/bin2llvmir/optimizations/param_return/param_return.h
* @brief Detect functions' parameters and returns.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_PARAM_RETURN_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_PARAM_RETURN_H

#include <map>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"

namespace retdec {
namespace bin2llvmir {

class CallEntry
{
	public:
		CallEntry(llvm::CallInst* c);

	public:
		void filterRegisters(Config* _config);
		void filterSort(Config* _config);
		void filterLeaveOnlyContinuousStackOffsets(Config* _config);
		void filterLeaveOnlyNeededStackOffsets(Config* _config);

		void extractFormatString(ReachingDefinitionsAnalysis& _RDA);

	public:
		llvm::CallInst* call = nullptr;
		std::vector<llvm::StoreInst*> possibleArgStores;
		std::vector<llvm::LoadInst*> possibleRetLoads;
		std::string formatStr;
};

class ReturnEntry
{
	public:
		ReturnEntry(llvm::ReturnInst* r);

	public:
		llvm::ReturnInst* ret = nullptr;
		std::vector<llvm::StoreInst*> possibleRetStores;
};

class DataFlowEntry
{
	public:
		DataFlowEntry(
				llvm::Module* m,
				ReachingDefinitionsAnalysis& rda,
				Config* c,
				Abi* abi,
				FileImage* img,
				DebugFormat* dbg,
				Lti* lti,
				llvm::Value* v);

		bool isFunctionEntry() const;
		bool isValueEntry() const;
		llvm::Value* getValue() const;
		llvm::Function* getFunction() const;
		void dump() const;

		void addCall(llvm::CallInst* call);

		void filter();

		void applyToIr();
		void applyToIrOrdinary();
		void applyToIrVariadic();
		void connectWrappers();

	private:
		void addArgLoads();
		void addRetStores();
		void addCallArgs(llvm::CallInst* call, CallEntry& ce);
		void addCallReturns(llvm::CallInst* call, CallEntry& ce);

		void callsFilterCommonRegisters();
		void callsFilterSameNumberOfStacks();

		void setTypeFromExtraInfo();
		void setTypeFromUseContext();
		void setReturnType();
		void setArgumentTypes();

		void filterRegistersArgLoads();
		void filterSortArgLoads();

		llvm::CallInst* isSimpleWrapper(llvm::Function* fnc);

	public:
		llvm::Module* _module = nullptr;
		ReachingDefinitionsAnalysis& _RDA;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		FileImage* _image = nullptr;
		Lti* _lti = nullptr;

		llvm::Value* called = nullptr;
		retdec::config::Function* configFnc = nullptr;
		retdec::config::Function* dbgFnc = nullptr;

		// In caller.
		//
		std::vector<CallEntry> calls;

		// In called function.
		//
		std::vector<llvm::LoadInst*> argLoads;
		std::vector<ReturnEntry> retStores;

		// Result.
		//
		bool typeSet = false;
		llvm::Type* retType = nullptr;
		std::vector<llvm::Type*> argTypes;
		std::map<std::size_t, llvm::Value*> specialArgStorage;
		bool isVarArg = false;
		llvm::CallInst* wrappedCall = nullptr;
		std::vector<std::string> argNames;
};

class ParamReturn : public llvm::ModulePass
{
	public:
		static char ID;
		ParamReturn();
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				Abi* abi,
				FileImage* img = nullptr,
				DebugFormat* dbgf = nullptr,
				Lti* lti = nullptr);
		virtual bool runOnModule(llvm::Module& m) override;

	private:
		bool run();
		void dumpInfo();

		void collectAllCalls();
		std::string extractFormatString(llvm::CallInst* call);

		void filterCalls();
		void filterSort(CallEntry& ce);
		void filterLeaveOnlyContinuousStackOffsets(CallEntry& ce);
		void filterLeaveOnlyNeededStackOffsets(CallEntry& ce);

		void applyToIr();

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _dbgf = nullptr;
		Lti* _lti = nullptr;

		std::map<llvm::Value*, DataFlowEntry> _fnc2calls;
		ReachingDefinitionsAnalysis _RDA;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
