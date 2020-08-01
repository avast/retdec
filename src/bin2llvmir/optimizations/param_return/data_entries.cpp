/**
* @file src/bin2llvmir/optimizations/param_return/data_entries.cpp
* @brief Data entries for parameter analysis.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <set>

#include "retdec/bin2llvmir/optimizations/param_return/data_entries.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
// ReturnEntry
//=============================================================================
//

ReturnEntry::ReturnEntry(llvm::ReturnInst* r) :
		_retInst(r)
{
}

void ReturnEntry::addRetStore(llvm::StoreInst* st)
{
	_retStores.push_back(st);

	if (std::find(
		_retValues.begin(),
		_retValues.end(),
		st->getPointerOperand()) != _retValues.end())
	{
		_retValues.push_back(st->getPointerOperand());
	}
}

void ReturnEntry::setRetStores(std::vector<llvm::StoreInst*>&& stores)
{
	_retStores = std::move(stores);

	std::set<Value*> vals;
	for (auto& i: _retStores)
	{
		vals.insert(i->getPointerOperand());
	}

	_retValues.assign(vals.begin(), vals.end());
}

void ReturnEntry::setRetStores(const std::vector<llvm::StoreInst*>& stores)
{
	_retStores = stores;

	std::set<Value*> vals;
	for (auto& i: _retStores)
	{
		vals.insert(i->getPointerOperand());
	}

	_retValues.assign(vals.begin(), vals.end());
}

void ReturnEntry::setRetValues(std::vector<llvm::Value*>&& values)
{
	_retStores.erase(std::remove_if(
		_retStores.begin(),
		_retStores.end(),
		[values](StoreInst* st)
		{
			auto* op = st->getPointerOperand();
			return std::find(
				values.begin(),
				values.end(), op) == values.end();
		}),
	_retStores.end());

	_retValues = std::move(values);
}

void ReturnEntry::setRetValues(const std::vector<llvm::Value*>& values)
{
	_retStores.erase(std::remove_if(
		_retStores.begin(),
		_retStores.end(),
		[values](StoreInst* st)
		{
			auto* op = st->getPointerOperand();
			return std::find(
				values.begin(),
				values.end(), op) == values.end();
		}),
	_retStores.end());

	_retValues = values;
}

ReturnInst* ReturnEntry::getRetInstruction() const
{
	return _retInst;
}

const std::vector<llvm::StoreInst*>& ReturnEntry::retStores() const
{
	return _retStores;
}

const std::vector<llvm::Value*>& ReturnEntry::retValues() const
{
	return _retValues;
}

//
//=============================================================================
// CallableEntry
//=============================================================================
//

bool CallableEntry::isVoidarg() const
{
	return _voidarg;
}

void CallableEntry::addArg(llvm::Value* arg)
{
	_args.push_back(arg);
}

void CallableEntry::setVoidarg(bool voidarg)
{
	_voidarg = voidarg;
}

void CallableEntry::setArgTypes(
		std::vector<Type*>&& types,
		std::vector<std::string>&& names)
{
	_argTypes = std::move(types);
	_argNames = std::move(names);

	if (_argTypes.size() > _argNames.size())
	{
		_argNames.resize(_argTypes.size(), "");
	}
	else if (_argTypes.size() < _argNames.size())
	{
		_argTypes.resize(_argNames.size(), nullptr);
	}

	if (_argTypes.empty())
	{
		setVoidarg();
	}
}

const std::vector<llvm::Value*>& CallableEntry::args() const
{
	return _args;
}

const std::vector<llvm::Type*>& CallableEntry::argTypes() const
{
	return _argTypes;
}

const std::vector<std::string>& CallableEntry::argNames() const
{
	return _argNames;
}

//
//=============================================================================
//  FunctionEntry
//=============================================================================
//

bool FunctionEntry::isVariadic() const
{
	return _variadic;
}

bool FunctionEntry::isWrapper() const
{
	return _wrap != nullptr;
}

void FunctionEntry::addRetEntry(const ReturnEntry& ret)
{
	_retEntries.push_back(ret);
}

ReturnEntry* FunctionEntry::createRetEntry(llvm::ReturnInst* ret)
{
	_retEntries.push_back(ReturnEntry(ret));

	return &(_retEntries.back());
}

void FunctionEntry::setVariadic(bool variadic)
{
	_variadic = variadic;
}

void FunctionEntry::setArgs(std::vector<llvm::Value*>&& args)
{
	_args = std::move(args);
}

void FunctionEntry::setWrappedCall(llvm::CallInst* wrap)
{
	_wrap = wrap;
}

void FunctionEntry::setRetType(llvm::Type* type)
{
	_retType = type;
}

void FunctionEntry::setRetValue(llvm::Value* val)
{
	_retVal = val;
}

void FunctionEntry::setCallingConvention(const CallingConvention::ID& cc)
{
	if (cc == CallingConvention::ID::CC_VOIDARG)
	{
		setVoidarg();
	}
	else
	{
		_callconv = cc;
	}
}

llvm::Type* FunctionEntry::getRetType() const
{
	return _retType;
}

llvm::Value* FunctionEntry::getRetValue() const
{
	return _retVal;
}

llvm::CallInst* FunctionEntry::getWrappedCall() const
{
	return _wrap;
}

CallingConvention::ID FunctionEntry::getCallingConvention() const
{
	return _callconv;
}

const std::vector<ReturnEntry>& FunctionEntry::retEntries() const
{
	return _retEntries;
}

std::vector<ReturnEntry>& FunctionEntry::retEntries()
{
	return _retEntries;
}

//
//=============================================================================
//  CallEntry
//=============================================================================
//

CallEntry::CallEntry(CallInst* call, const FunctionEntry* base) :
	_baseFunction(base),
	_callInst(call)
{
}

void CallEntry::addRetLoad(LoadInst* load)
{
	_retLoads.push_back(load);
	_retValues.push_back(load->getPointerOperand());

	// TODO duplicity and pointer operand?
}

void CallEntry::setFormatString(const std::string &fmt)
{
	_fmtStr = fmt;
}

void CallEntry::setArgStores(std::vector<llvm::StoreInst*>&& stores)
{
	_argStores = std::move(stores);

	std::set<llvm::Value*> vals;
	for (auto& i : _argStores)
	{
		vals.insert(i->getPointerOperand());
	}

	_args.assign(vals.begin(), vals.end());
}

void CallEntry::setArgs(std::vector<Value*>&& args)
{
	_argStores.erase(
		std::remove_if(
			_argStores.begin(),
			_argStores.end(),
			[args](StoreInst* st)
			{
				auto* op = st->getPointerOperand();
				return std::find(
					args.begin(),
					args.end(), op) == args.end();
			}),
		_argStores.end());

	_args = std::move(args);
}

void CallEntry::setRetLoads(std::vector<LoadInst*>&& loads)
{
	_retLoads = std::move(loads);

	std::set<llvm::Value*> vals;
	for (auto& i: _retLoads)
	{
		vals.insert(i->getPointerOperand());
	}
	_retValues.assign(vals.begin(), vals.end());
}

void CallEntry::setRetValues(std::vector<llvm::Value*>&& values)
{
	_retLoads.erase(std::remove_if(
		_retLoads.begin(),
		_retLoads.end(),
		[values](llvm::LoadInst* st)
		{
			auto* op = st->getPointerOperand();
			return std::find(
				values.begin(),
				values.end(), op) == values.end();
		}),
	_retLoads.end());

	_retValues = std::move(values);
}

CallInst* CallEntry::getCallInstruction() const
{
	return _callInst;
}

const FunctionEntry* CallEntry::getBaseFunction() const
{
	return _baseFunction;
}

std::string CallEntry::getFormatString() const
{
	return _fmtStr;
}

const std::vector<llvm::StoreInst*>& CallEntry::argStores() const
{
	return _argStores;
}

const std::vector<Value*>& CallEntry::retValues() const
{
	return _retValues;
}

const std::vector<LoadInst*>& CallEntry::retLoads() const
{
	return _retLoads;
}

//
//=============================================================================
//  DataFlowEntry
//=============================================================================
//

DataFlowEntry::DataFlowEntry(Value* called):
	_calledValue(called)
{
}

bool DataFlowEntry::isFunction() const
{
	return getFunction() != nullptr;
}

bool DataFlowEntry::isValue() const
{
	return _calledValue && !isFunction();
}

void DataFlowEntry::setIsFullyDecoded(bool res)
{
	_decoded = res;
}

bool DataFlowEntry::isFullyDecoded() const
{
	return _decoded;
}

bool DataFlowEntry::hasDefinition() const
{
	return isFunction() && !getFunction()->empty();
}

Function* DataFlowEntry::getFunction() const
{
	return dyn_cast_or_null<Function>(_calledValue);
}

Value* DataFlowEntry::getValue() const
{
	return _calledValue;
}

void DataFlowEntry::setCalledValue(llvm::Value* called)
{
	_calledValue = called;
}

std::size_t DataFlowEntry::numberOfCalls() const
{
	auto fnc = getFunction();
	if (fnc == nullptr)
		return 0;

	std::size_t calls = 0;
	for (auto& bb: *fnc)
		for (auto& i: bb)
			if (auto call = dyn_cast<CallInst>(&i)) {
				auto* calledFnc = call->getCalledFunction();
				if (calledFnc && !calledFnc->isIntrinsic())
					calls++;
			}

	return calls;
}

bool DataFlowEntry::hasBranches() const
{
	auto fnc = getFunction();
	if (fnc == nullptr)
		return false;

	for (auto& bb: *fnc)
		for (auto& i: bb)
			if (isa<BranchInst>(i))
				return true;

	return false;
}

bool DataFlowEntry::storesOnRawStack(const Abi& abi) const
{
	auto fnc = getFunction();
	if (fnc == nullptr)
		return false;

	for (auto& bb: *fnc) {
		for (auto& i: bb) {
			if (auto store = dyn_cast<StoreInst>(&i)) {
				auto operand = store->getValueOperand();
				auto storage = store->getPointerOperand();
				if (abi.isStackPointerRegister(storage)) {
					if (auto* pi = dyn_cast<PtrToIntInst>(operand)) {
						if (abi.isStackVariable(pi->getPointerOperand()))
							continue;
					}

					return true;
				}
			}
		}
	}

	return false;
}

CallEntry* DataFlowEntry::createCallEntry(CallInst* call)
{
	_calls.push_back(CallEntry(call, this));
	return &(_calls.back());
}

const std::vector<CallEntry>& DataFlowEntry::callEntries() const
{
	return _calls;
}

std::vector<CallEntry>& DataFlowEntry::callEntries()
{
	return _calls;
}

}
}
