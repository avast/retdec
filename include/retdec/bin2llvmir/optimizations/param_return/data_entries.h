/**
* @file include/retdec/bin2llvmir/optimizations/param_return/data_entries.h
* @brief Data entries for parameter analysis.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_DATA_ENTRIES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_DATA_ENTRIES_H

#include <vector>

#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>

namespace retdec {
namespace bin2llvmir {

class ReturnEntry
{
	public:
		ReturnEntry(llvm::ReturnInst* r);

	public:
		void addRetStore(llvm::StoreInst* st);

		void setRetStores(std::vector<llvm::StoreInst*>&& stores);
		void setRetStores(const std::vector<llvm::StoreInst*>& stores);
		void setRetValues(std::vector<llvm::Value*>&& values);

		void setRetValues(const std::vector<llvm::Value*>& values);

	public:
		llvm::ReturnInst* getRetInstruction() const;

		const std::vector<llvm::StoreInst*>& retStores() const;
		const std::vector<llvm::Value*>& retValues() const;

	protected:
		llvm::ReturnInst* _retInst = nullptr;

		std::vector<llvm::StoreInst*> _retStores;
		std::vector<llvm::Value*> _retValues;
};

class CallableEntry
{
	public:
		bool isVoidarg() const;

		void addArg(llvm::Value* arg);

		void setVoidarg(bool voidarg = true);
		void setArgTypes(
			std::vector<llvm::Type*>&& types,
			std::vector<std::string>&& names = {});

	public:
		const std::vector<llvm::Value*>& args() const;
		const std::vector<llvm::Type*>& argTypes() const;
		const std::vector<std::string>& argNames() const;

	protected:
		std::vector<llvm::Value*> _args;
		std::vector<llvm::Type*> _argTypes;
		std::vector<std::string> _argNames;

	protected:
		bool _voidarg = false;
};

class FunctionEntry : public CallableEntry
{
	public:
		bool isVariadic() const;
		bool isWrapper() const;

	public:
		void addRetEntry(const ReturnEntry& ret);
		ReturnEntry* createRetEntry(llvm::ReturnInst* ret);

		void setArgs(std::vector<llvm::Value*>&& args);
		void setVariadic(bool variadic = true);
		void setWrappedCall(llvm::CallInst* wrap);
		void setRetType(llvm::Type* type);
		void setRetValue(llvm::Value* val);
		void setCallingConvention(const CallingConvention::ID& cc);

	public:
		llvm::Value* getRetValue() const;
		llvm::Type* getRetType() const;
		llvm::CallInst* getWrappedCall() const;
		CallingConvention::ID getCallingConvention() const;

		const std::vector<ReturnEntry>& retEntries() const;
		std::vector<ReturnEntry>& retEntries();

	private:
		llvm::CallInst* _wrap = nullptr;
		llvm::Type* _retType = nullptr;
		llvm::Value* _retVal = nullptr;
		bool _variadic = false;
		CallingConvention::ID _callconv = CallingConvention::ID::CC_UNKNOWN;

		std::vector<ReturnEntry> _retEntries;
};

class CallEntry : public CallableEntry
{
	// Constructor.
	//
	public:
		CallEntry(
			llvm::CallInst* call,
			const FunctionEntry* base = nullptr);

	// Usage data.
	//
	public:
		void addRetLoad(llvm::LoadInst* load);

		void setFormatString(const std::string& fmt);
		void setArgStores(std::vector<llvm::StoreInst*>&& stores);
		void setArgs(std::vector<llvm::Value*>&& args);
		void setRetLoads(std::vector<llvm::LoadInst*>&& loads);
		void setRetValues(std::vector<llvm::Value*>&& values);

		llvm::CallInst* getCallInstruction() const;
		const FunctionEntry* getBaseFunction() const;
		std::string getFormatString() const;

	public:
		const std::vector<llvm::StoreInst*>& argStores() const;
		const std::vector<llvm::Value*>& retValues() const;
		const std::vector<llvm::LoadInst*>& retLoads() const;

	private:
		const FunctionEntry* _baseFunction;

		llvm::CallInst* _callInst = nullptr;
		std::string _fmtStr = "";

		std::vector<llvm::LoadInst*> _retLoads;
		std::vector<llvm::Value*> _retValues;
		std::vector<llvm::StoreInst*> _argStores;
};

class DataFlowEntry : public FunctionEntry
{
	// Constructor
	//
	public:
		DataFlowEntry(llvm::Value* called);

	// Type information
	//
	public:
		bool isFunction() const;
		bool isValue() const;
		bool hasDefinition() const;

		llvm::Function* getFunction() const;
		llvm::Value* getValue() const;

		void setCalledValue(llvm::Value* called);

		std::size_t numberOfCalls() const;
		bool hasBranches() const;
		bool storesOnRawStack(const Abi& abi) const;

		void setIsFullyDecoded(bool res = true);
		bool isFullyDecoded() const;

	// Usage data.
	//
	public:
		CallEntry* createCallEntry(llvm::CallInst *call);
		const std::vector<CallEntry>& callEntries() const;
		std::vector<CallEntry>& callEntries();

	private:
		llvm::Value* _calledValue = nullptr;

		std::vector<CallEntry> _calls;
		bool _decoded = true;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
