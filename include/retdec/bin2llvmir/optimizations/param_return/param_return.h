/**
* @file include/retdec/bin2llvmir/optimizations/param_return/param_return.h
* @brief Detect functions' parameters and returns.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
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
#include "retdec/bin2llvmir/optimizations/param_return/collector/collector.h"
#include "retdec/bin2llvmir/optimizations/param_return/data_entries.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/providers/demangler.h"

namespace retdec {
namespace bin2llvmir {

class ParamReturn : public llvm::ModulePass
{
	public:
		static char ID;
		ParamReturn();
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				Abi* abi,
				Demangler* demangler,
				FileImage* img = nullptr,
				DebugFormat* dbgf = nullptr,
				Lti* lti = nullptr);
		virtual bool runOnModule(llvm::Module& m) override;

	private:
		bool run();
		void dumpInfo() const;
		void dumpInfo(const DataFlowEntry& de) const;
		void dumpInfo(const CallEntry& ce) const;
		void dumpInfo(const ReturnEntry& de) const;

	// Collection of functions.
	//
	private:
		void collectAllCalls();

		DataFlowEntry createDataFlowEntry(llvm::Value* calledValue) const;

	private:
		void collectExtraData(DataFlowEntry* de) const;
		void collectExtraData(CallEntry* ce) const;

		void collectCallSpecificTypes(CallEntry* ce) const;
		common::CallingConventionID toCallConv(const std::string &cc) const;

	// Collection of functions usage data.
	//
	private:
		void addDataFromCall(DataFlowEntry *dataflow, llvm::CallInst *call) const;

	// Optimizations.
	//
	private:
		llvm::CallInst* getWrapper(llvm::Function* fnc) const;
		llvm::Type* extractType(llvm::Value* from) const;

	// Filtration of collected functions arguments.
	//
	private:
		void filterCalls();
		void modifyType(DataFlowEntry& de) const;

	// Demangling informations.
	//
	private:
		void analyzeWithDemangler(DataFlowEntry& de) const;
		void modifyWithDemangledData(DataFlowEntry& de, Demangler::FunctionPair &funcPair) const;

	// Modification of functions in IR.
	//
	private:
		// Calls to dynamically-linked functions go through the procedure linkage
		// table (PLT).  RetDec turns a PLT entry into a function, say
		// malloc@plt, that appears to do nothing but call the external function,
		// say malloc (though the assembly code will do a jump rather than a
		// call). User code that logically wants to call malloc instead calls
		// malloc@plt (and sets up arguments as if calling malloc). The
		// malloc@plt code first jumps to the dynamic linker which modifies it so
		// that subsequent calls to malloc@plt will jump directly to malloc. We
		// say that malloc@plt wraps malloc.  The call to malloc in malloc@plt
		// will not have any arguments setup, so malloc will appear to have
		// no parameters or returns (unless that information is provided by
		// link-time-information, debug information, or name demangling), but it
		// needs to have the same parameter types and return type as
		// malloc@plt. The propagateWrapped methods copy the argument information
		// from the DataFlowEntry of the wrapping function to the wrapped
		// function. Then, when the calls to the wrapping function are inlined
		// (in connectWrappers), effectively the call to the wrapping function is
		// changed into a call to the wrapped function.
		// 
		// The motivation for this change is the programs that analyze the
		// output of RetDec (either the C code, or the LLVM code) want to
		// recognize library functions and treat them specially. This
		// change makes it so that the library function names are used
		// directly (rather than the plt version) and they are passed
		// their parameters correctly.

		void propagateWrapped();
		void propagateWrapped(DataFlowEntry& de);
		void applyToIr();
		void applyToIr(DataFlowEntry& de);
		void connectWrappers(const DataFlowEntry& de);

		std::map<llvm::CallInst*, std::vector<llvm::Value*>> fetchLoadsOfCalls(
						const std::vector<CallEntry>& calls) const;

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _dbgf = nullptr;
		Lti* _lti = nullptr;
		Demangler* _demangler = nullptr;

		std::map<llvm::Value*, DataFlowEntry> _fnc2calls;
		ReachingDefinitionsAnalysis _RDA;
		Collector::Ptr _collector;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
