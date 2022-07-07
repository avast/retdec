/**
* @file src/bin2llvmir/optimizations/param_return/param_return.cpp
* @brief Detect functions' parameters and returns.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <limits>

#include <llvm/IR/CFG.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/container.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/param_return/filter/filter.h"
#include "retdec/bin2llvmir/optimizations/param_return/param_return.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  ParamReturn
//=============================================================================
//

char ParamReturn::ID = 0;

static RegisterPass<ParamReturn> X(
		"retdec-param-return",
		"Function parameters and returns optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ParamReturn::ParamReturn() :
		ModulePass(ID)
{

}

bool ParamReturn::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	_image = FileImageProvider::getFileImage(_module);
	_dbgf = DebugFormatProvider::getDebugFormat(_module);
	_lti = LtiProvider::getLti(_module);
	_demangler = DemanglerProvider::getDemangler(_module);
	_collector = CollectorProvider::createCollector(_abi, _module, &_RDA);

	return run();
}

bool ParamReturn::runOnModuleCustom(
		Module& m,
		Config* c,
		Abi* abi,
		Demangler* demangler,
		FileImage* img,
		DebugFormat* dbgf,
		Lti* lti)
{
	_module = &m;
	_config = c;
	_abi = abi;
	_image = img;
	_dbgf = dbgf;
	_lti = lti;
	_demangler = demangler;
	_collector = CollectorProvider::createCollector(_abi, _module, &_RDA);

	return run();
}

bool ParamReturn::run()
{
	if (_config == nullptr)
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	_RDA.runOnModule(*_module, _abi);

	collectAllCalls();
//	dumpInfo();
	filterCalls();
//	dumpInfo();
	propagateWrapped();
//	dumpInfo();
	applyToIr();

	_RDA.clear();

	return false;
}

/**
 * Collect possible arguments' stores for all calls we want to analyze.
 * At the moment, we analyze only indirect or declared function calls with no
 * arguments inside one basic block.
 */
void ParamReturn::collectAllCalls()
{
	for (auto& f : _module->getFunctionList())
	{
		if (f.isIntrinsic())
		{
			continue;
		}

		_fnc2calls.emplace(std::make_pair(
					&f,
					createDataFlowEntry(&f)));
	}

	for (auto& f : _module->getFunctionList())
	for (auto& b : f)
	for (auto& i : b)
	{
		auto* call = dyn_cast<CallInst>(&i);
		if (call == nullptr || call->getNumArgOperands() != 0)
		{
			continue;
		}

		auto* calledVal = call->getCalledValue();
		auto* calledFnc = call->getCalledFunction();

		if (calledFnc && calledFnc->isIntrinsic())
		{
			continue;
		}

		auto fIt = _fnc2calls.find(calledVal);
		if (fIt == _fnc2calls.end())
		{
			fIt = _fnc2calls.emplace(
				std::make_pair(
					calledVal,
					createDataFlowEntry(calledVal))).first;
		}

		addDataFromCall(&fIt->second, call);
	}
}

DataFlowEntry ParamReturn::createDataFlowEntry(Value* calledValue) const
{
	DataFlowEntry dataflow(calledValue);

	_collector->collectDefArgs(&dataflow);
	_collector->collectDefRets(&dataflow);

	collectExtraData(&dataflow);

	return dataflow;
}

common::CallingConventionID ParamReturn::toCallConv(const std::string &cc) const
{
	std::map<std::string, common::CallingConventionID> ccMap {
		{"cdecl", common::CallingConventionID::CC_CDECL},
		{"pascal", common::CallingConventionID::CC_PASCAL},
		{"thiscall", common::CallingConventionID::CC_THISCALL},
		{"stdcall", common::CallingConventionID::CC_STDCALL},
		{"fastcall", common::CallingConventionID::CC_FASTCALL},
		{"eabi", common::CallingConventionID::CC_ARM}
	};	// TODO add vectorcall and regcall

	return utils::mapGetValueOrDefault(ccMap, cc, common::CallingConventionID::CC_UNKNOWN);
}

void ParamReturn::collectExtraData(DataFlowEntry* dataflow) const
{
	auto* fnc = dataflow->getFunction();
	if (fnc == nullptr)
	{
		return;
	}

	auto& config = _config->getConfig();
	if (config.parameters.isSelectedDecodeOnly()) {
		auto rdFnc = _config->getFunctionAddress(fnc);
		auto isDecoded = config.parameters.selectedRanges.contains(rdFnc);
		dataflow->setIsFullyDecoded(isDecoded);
	}

	// LTI info.
	//
	auto* cf = _config->getConfigFunction(fnc);
	if (cf && (cf->isDynamicallyLinked() || cf->isStaticallyLinked()))
	{
		auto funcName = cf->getName();
		auto fp = _lti->getPairFunctionFree(funcName);
		if (fp.first)
		{
			std::vector<Type*> argTypes;
			std::vector<std::string> argNames;
			for (auto& a : fp.first->args())
			{
				if (!a.getType()->isSized())
				{
					continue;
				}
				argTypes.push_back(a.getType());
				argNames.push_back(a.getName());
			}
			dataflow->setArgTypes(
					std::move(argTypes),
					std::move(argNames));

			if (fp.first->isVarArg())
			{
				dataflow->setVariadic();
			}
			dataflow->setRetType(fp.first->getReturnType());

			std::string declr = fp.second->getDeclaration();
			if (!declr.empty())
			{
				cf->setDeclarationString(declr);
			}
			return;
		}

		auto demFuncPair = _demangler->getPairFunction(funcName);
		if (demFuncPair.first)
		{
			modifyWithDemangledData(*dataflow, demFuncPair);
			return;
		}
	}

	auto dbgFnc = _dbgf ? _dbgf->getFunction(
			_config->getFunctionAddress(fnc)) : nullptr;

	// Debug info.
	//
	if (dbgFnc)
	{
		std::vector<Type*> argTypes;
		std::vector<std::string> argNames;
		for (auto& a : dbgFnc->parameters)
		{
			auto* t = llvm_utils::stringToLlvmTypeDefault(
					_module, a.type.getLlvmIr());
			if (!t->isSized())
			{
				continue;
			}
			argTypes.push_back(t);
			argNames.push_back(a.getName());
		}
		dataflow->setArgTypes(
				std::move(argTypes),
				std::move(argNames));

		if (dbgFnc->isVariadic())
		{
			dataflow->setVariadic();
		}
		if (dbgFnc->returnType.isDefined())
		{
			dataflow->setRetType(
			llvm_utils::stringToLlvmTypeDefault(
				_module,
				dbgFnc->returnType.getLlvmIr()));
		}
		dataflow->setCallingConvention(dbgFnc->callingConvention.getID());

		// TODO: Maybe use demangled function name?
		// Would it be useful for names from debug info?
		return;
	}

	auto configFnc = _config->getConfigFunction(fnc);
	if (configFnc && configFnc->isUserDefined())
	{
		std::vector<Type*> argTypes;
		std::vector<std::string> argNames;
		for (auto& a : configFnc->parameters)
		{
			auto* t = llvm_utils::stringToLlvmTypeDefault(
					_module, a.type.getLlvmIr());
			if (!t->isSized())
			{
				continue;
			}
			argTypes.push_back(t);
			argNames.push_back(a.getName());
		}
		// If no parameters are found do not call setArgType method
		// as it will consider function to be without paprameters.
		if (configFnc->parameters.size())
			dataflow->setArgTypes(
				std::move(argTypes),
				std::move(argNames));

		if (configFnc->isVariadic())
		{
			dataflow->setVariadic();
		}
		if (configFnc->returnType.isDefined())
		{
			dataflow->setRetType(
				llvm_utils::stringToLlvmTypeDefault(
					_module,
					configFnc->returnType.getLlvmIr()));
		}
		dataflow->setCallingConvention(configFnc->callingConvention.getID());

		// TODO: Maybe use demangled function name?
		// Would it be useful for names from debug info?
	}
	else if (configFnc && configFnc->isDecompilerDefined())
	{
		// As decompiler is not good source of information,
		// we should use only names and other parameters that
		// we cannot guess by any heuristic.
		std::vector<Type*> argTypes;
		std::vector<std::string> argNames;
		for (auto& a : configFnc->parameters)
		{
			argTypes.push_back(_abi->getDefaultType());
			argNames.push_back(a.getName());
		}
		if (configFnc->parameters.size())
			dataflow->setArgTypes(
				std::move(argTypes),
				std::move(argNames));

		if (configFnc->isVariadic())
		{
			dataflow->setVariadic();
		}
		dataflow->setCallingConvention(configFnc->callingConvention.getID());
	}

	// Main
	//
	if (!dataflow->argNames().size() && fnc->getName().str() == "main")
	{
		auto charPointer = PointerType::get(
			Type::getInt8Ty(_module->getContext()), 0);

		dataflow->setArgTypes(
		{
			_abi->getDefaultType(),
			PointerType::get(charPointer, 0)
		},
		{
			"argc",
			"argv"
		});

		dataflow->setRetType(_abi->getDefaultType());
		return;
	}

	// Wrappers.
	//
	if (CallInst* wrappedCall = getWrapper(fnc))
	{
		dataflow->setWrappedCall(wrappedCall);
		auto* wf = wrappedCall->getCalledFunction();
		auto* ltiFnc = _lti->getLlvmFunctionFree(wf->getName());
		if (ltiFnc)
		{
			std::vector<Type*> argTypes;
			std::vector<std::string> argNames;
			for (auto& a : ltiFnc->args())
			{
				if (!a.getType()->isSized())
				{
					continue;
				}
				argTypes.push_back(a.getType());
				argNames.push_back(a.getName());
			}
			dataflow->setArgTypes(
					std::move(argTypes),
					std::move(argNames));

			if (ltiFnc->isVarArg())
			{
				dataflow->setVariadic();
			}
			dataflow->setRetType(ltiFnc->getReturnType());

			return;
		}

		auto demFuncPair = _demangler->getPairFunction(wf->getName());
		if (demFuncPair.first)
		{
			LOG << "wrapper: " << _demangler->demangleToString(wf->getName()) << std::endl;
			modifyWithDemangledData(*dataflow, demFuncPair);

			return;
		}
	}

	// try to get calling convention and return type if name is mangled
	auto fp = _demangler->getPairFunction(fnc->getName().str());
	if (fp.first)
	{
		dataflow->setCallingConvention(toCallConv(fp.second->getCallConvention()));
		if (!fp.second->getReturnType()->isUnknown())
		{
			dataflow->setRetType(fp.first->getReturnType());
		}
	}
}

CallInst* ParamReturn::getWrapper(Function* fnc) const
{
	auto ai = AsmInstruction(fnc);
	if (ai.isInvalid())
	{
		return nullptr;
	}

	bool single = true;
	auto next = ai.getNext();
	while (next.isValid())
	{
		if (!next.empty() && !next.front()->isTerminator())
		{
			single = false;
			break;
		}
		next = next.getNext();
	}

	// Pattern
	// .text:00008A38                 LDR     R0, =aCCc       ; "C::cc()"
	// .text:00008A3C                 B       puts
	// .text:00008A40 off_8A40        DCD aCCc
	// TODO: make better wrapper detection. In wrapper, wrapped function params
	// should not be set like in this example.
	//
	if (ai && next)
	{
		if (_image->getConstantDefault(next.getEndAddress()))
		{
			auto* l = ai.getInstructionFirst<LoadInst>();
			auto* s = ai.getInstructionFirst<StoreInst>();
			auto* c = next.getInstructionFirst<CallInst>();
			if (l && s && c && isa<GlobalVariable>(l->getPointerOperand())
					&& s->getPointerOperand()->getName() == "r0")
			{
				auto gvA = _config->getGlobalAddress(cast<GlobalVariable>(l->getPointerOperand()));
				if (gvA == next.getEndAddress())
				{
					return nullptr;
				}
			}
		}
	}

	if (single)
	{
		for (auto& i : ai)
		{
			if (auto* c = dyn_cast<CallInst>(&i))
			{
				auto* cf = c->getCalledFunction();
				if (cf && !cf->isIntrinsic()) // && cf->isDeclaration())
				{
					return c;
				}
			}
		}
	}

	unsigned aiNum = 0;
	bool isSmall = true;
	next = ai;
	while (next.isValid())
	{
		++aiNum;
		next = next.getNext();
		if (aiNum > 4)
		{
			isSmall = false;
			break;
		}
	}
	auto* s = _image->getImage()->getSegmentFromAddress(ai.getAddress());
	if ((s && s->getName() == ".plt") || isSmall)
	{
		for (inst_iterator it = inst_begin(fnc), rIt = inst_end(fnc);
				it != rIt; ++it)
		{
			if (auto* l = dyn_cast<LoadInst>(&*it))
			{
				std::string n = l->getPointerOperand()->getName();
				if (n == "lr" || n == "sp")
				{
					return nullptr;
				}
			}
			else if (auto* s = dyn_cast<StoreInst>(&*it))
			{
				std::string n = s->getPointerOperand()->getName();
				if (n == "lr" || n == "sp")
				{
					return nullptr;
				}
			}
			else if (auto* c = dyn_cast<CallInst>(&*it))
			{
				auto* cf = c->getCalledFunction();
				if (cf && !cf->isIntrinsic() && cf->isDeclaration())
				{
					return c;
				}
			}
		}
	}

	return nullptr;
}

void ParamReturn::addDataFromCall(DataFlowEntry *dataflow, CallInst *call) const
{
	CallEntry* ce = dataflow->createCallEntry(call);

	_collector->collectCallArgs(ce);

	// TODO: Use info from collecting return loads.
	//
	// At this moment info return loads is not used
	// as it is not reliable source of info
	// about return value. To enable this
	// collector must have redesigned and reimplemented
	// collection algorithm.
	//
	//_collector->collectCallRets(ce);

	collectExtraData(ce);
}

void ParamReturn::collectExtraData(CallEntry* ce) const
{
}

void ParamReturn::dumpInfo() const
{
	LOG << std::endl << "_fnc2calls:" << std::endl;

	for (auto& p : _fnc2calls)
	{
		dumpInfo(p.second);
	}
}

void ParamReturn::dumpInfo(const DataFlowEntry& de) const
{
	auto called = de.getValue();
	auto fnc = de.getFunction();
	auto configFnc = _config->getConfigFunction(fnc);
	auto dbgFnc = _dbgf ? _dbgf->getFunction(
			_config->getFunctionAddress(fnc)) : nullptr;
	auto wrappedCall = de.getWrappedCall();

	LOG << "\n\t>|" << called->getName().str() << std::endl;
	LOG << "\t>|&DataFlowEntry : " << &de << std::endl;
	LOG << "\t>|fnc call : " << de.isFunction() << std::endl;
	LOG << "\t>|val call : " << de.isValue() << std::endl;
	LOG << "\t>|variadic : " << de.isVariadic() << std::endl;
	LOG << "\t>|voidarg  : " << de.isVoidarg() << std::endl;
	LOG << "\t>|call conv: " << de.getCallingConvention() << std::endl;
	LOG << "\t>|config f : " << (configFnc != nullptr) << std::endl;
	LOG << "\t>|debug f  : " << (dbgFnc != nullptr) << std::endl;
	LOG << "\t>|wrapp c  : " << llvmObjToString(wrappedCall) << std::endl;
	LOG << "\t>|calls cnt: " << de.numberOfCalls() << std::endl;
	LOG << "\t>|sto stack: " << de.storesOnRawStack(*_abi) << std::endl;
	LOG << "\t>|is decode: " << de.isFullyDecoded() << std::endl;
	LOG << "\t>|type set : " << !de.argTypes().empty() << std::endl;
	LOG << "\t>|ret type : " << llvmObjToString(de.getRetType()) << std::endl;
	LOG << "\t>|ret value: " << llvmObjToString(de.getRetValue()) << std::endl;
	LOG << "\t>|arg types:" << std::endl;
	for (auto* t : de.argTypes())
	{
		LOG << "\t\t>|" << llvmObjToString(t) << std::endl;
	}
	LOG << "\t>|arg names:" << std::endl;
	for (auto& n : de.argNames())
	{
		LOG << "\t\t>|" << n << std::endl;
	}

	LOG << "\t>|calls:" << std::endl;
	for (auto& e : de.callEntries())
	{
		dumpInfo(e);
	}

	LOG << "\t>|arg loads:" << std::endl;
	for (auto* l : de.args())
	{
		LOG << "\t\t\t>|" << llvmObjToString(l) << std::endl;
	}

	LOG << "\t>|return stores:" << std::endl;
	for (auto& e : de.retEntries())
	{
		dumpInfo(e);
	}
}

void ParamReturn::dumpInfo(const CallEntry& ce) const
{
	LOG << "\t\t>|" << llvmObjToString(ce.getCallInstruction())
		<< std::endl;
	LOG << "\t\t\tvoidarg :" << ce.isVoidarg() << std::endl;
	LOG << "\t\t\targ values:" << std::endl;
	for (auto* s : ce.args())
	{
		LOG << "\t\t\t>|" << llvmObjToString(s) << std::endl;
	}
	LOG << "\t\t\targ stores:" << std::endl;
	for (auto* s : ce.argStores())
	{
		LOG << "\t\t\t>|" << llvmObjToString(s) << std::endl;
	}
	LOG << "\t\t\tret values:" << std::endl;
	for (auto* l : ce.retValues())
	{
		LOG << "\t\t\t>|" << llvmObjToString(l) << std::endl;
	}
	LOG << "\t\t\tret loads:" << std::endl;
	for (auto* l : ce.retLoads())
	{
		LOG << "\t\t\t>|" << llvmObjToString(l) << std::endl;
	}
	LOG << "\t\t\targ types:" << std::endl;
	for (auto* t : ce.getBaseFunction()->argTypes())
	{
		LOG << "\t\t\t>|" << llvmObjToString(t);
		LOG << " (size : " << _abi->getTypeByteSize(t) << "B)" << std::endl;
	}
	for (auto* t : ce.argTypes())
	{
		LOG << "\t\t\t>|" << llvmObjToString(t);
		LOG << " (size : " << _abi->getTypeByteSize(t) << "B)" << std::endl;
	}
	LOG << "\t\t\tformat string: " << ce.getFormatString() << std::endl;
}

void ParamReturn::dumpInfo(const ReturnEntry& re) const
{
	LOG << "\t\t>|" << llvmObjToString(re.getRetInstruction())
		<< std::endl;

	LOG << "\t\t\tret stores:" << std::endl;
	for (auto* s : re.retStores())
	{
		LOG << "\t\t\t>|" << llvmObjToString(s) << std::endl;
	}

	LOG << "\t\t\tret values:" << std::endl;
	for (auto* s : re.retValues())
	{
		LOG << "\t\t\t>|" << llvmObjToString(s) << std::endl;
	}
}

void ParamReturn::filterCalls()
{
	std::map<CallingConvention::ID, Filter::Ptr> filters;

	for (auto& p : _fnc2calls)
	{
		DataFlowEntry& de = p.second;
		auto cc = de.getCallingConvention();
		if (filters.find(cc) == filters.end())
		{
			filters[cc] = FilterProvider::createFilter(_abi, cc);
		}

		if (de.hasDefinition())
		{
			filters[cc]->filterDefinition(&de);
		}

		if (de.isVariadic())
		{
			filters[cc]->filterCallsVariadic(&de, _collector.get());
		}
		else
		{
			filters[cc]->filterCalls(&de);
		}

		filters[cc]->estimateRetValue(&de);

		if (_abi->supportsCallingConvention(cc))
		{
			de.setCallingConvention(cc);
		}
		else
		{
			de.setCallingConvention(_abi->getDefaultCallingConventionID());
		}
		modifyType(de);

		analyzeWithDemangler(de);
	}
}

void ParamReturn::analyzeWithDemangler(DataFlowEntry& de) const
{
	if (de.getFunction())
	{
		auto funcName = de.getFunction()->getName().str();
		auto demFuncPair = _demangler->getPairFunction(funcName);
		if (demFuncPair.first)	// demangling successful
		{
			modifyWithDemangledData(de, demFuncPair);
		}
	}
}

void ParamReturn::modifyWithDemangledData(DataFlowEntry &de, Demangler::FunctionPair &funcPair) const
{
	std::vector<Type*> argTypes;
	std::vector<std::string> argNames;

	auto detectedArgTypes = de.argTypes();
	const size_t detectedParamCount = detectedArgTypes.size();
	const size_t demanglerParamCount = funcPair.second->getParameterCount();

	if (detectedParamCount > demanglerParamCount +2) {
		return;		// param analysis was probably wrong, dont know what to do
	}

	const auto ptrSize = static_cast<unsigned>(Abi::getWordSize(_module)) * 8;
	bool retTypeSet = false;

	if (detectedParamCount == demanglerParamCount+2)
	{
		// add this param
		argTypes.emplace_back(PointerType::get(Type::getIntNTy(_module->getContext(), ptrSize), 0));
		argNames.emplace_back("this");

		// add result param
		argTypes.emplace_back(PointerType::get(Type::getIntNTy(_module->getContext(), ptrSize), 0));
		argNames.emplace_back("result");

		// set return type to result
		de.setRetType(funcPair.first->getReturnType());
		retTypeSet = true;
	}

	if (detectedParamCount == demanglerParamCount+1)
	{
		/*
		 * Adds pointer to result or this, cant be sure based on information we have.
		 * Parameter will be named "result"
		 */
		argTypes.emplace_back(PointerType::get(_abi->getDefaultType(), 0));
		argNames.emplace_back("result");
	}

	for (auto& demParam : funcPair.first->args())
	{
		if (demParam.getType()->isSized())
		{
			argTypes.push_back(demParam.getType());
			argNames.push_back(demParam.getName());
		}
	}

	de.setArgTypes(
		std::move(argTypes),
		std::move(argNames));

	if (funcPair.first->isVarArg())
	{
		de.setVariadic();
	}

	if (retTypeSet)
	{
		de.setRetType(funcPair.first->getReturnType());
	}

	auto callConv = funcPair.second->getCallConvention();
	de.setCallingConvention(toCallConv(callConv));
}

Type* ParamReturn::extractType(Value* from) const
{
	from = llvm_utils::skipCasts(from);

	if (from == nullptr)
	{
		return _abi->getDefaultType();
	}

	if (auto* p = dyn_cast<ArrayType>(from->getType()))
	{
		return p->getElementType();
	}

	if (auto* p = dyn_cast<PointerType>(from->getType()))
	{
		if (auto* a = dyn_cast<ArrayType>(p->getElementType()))
		{
			return PointerType::get(a->getElementType(), 0);
		}
	}

	return from->getType();
}

void ParamReturn::modifyType(DataFlowEntry& de) const
{
	// TODO
	// Based on large type we should do:
	//
	// If large type is encountered
	// and if cc passes large type by reference
	// just cast the reference
	//
	// else separate as much values as possible
	// and call function that will create new structure
	// and put this values in the elements of
	// the structure set this structure as parameter

	if (de.argTypes().empty())
	{
		for (auto& call : de.callEntries())
		{
			std::vector<Type*> types;
			for (auto& arg : call.args())
			{
				if (arg == nullptr)
				{
					types.push_back(_abi->getDefaultType());
					continue;
				}

				auto usage = std::find_if(
						call.argStores().begin(),
						call.argStores().end(),
						[arg](StoreInst* s)
						{
							return s->getPointerOperand()
								== arg;
						});

				if (usage == call.argStores().end())
				{

					if (auto* p = dyn_cast<PointerType>(arg->getType()))
					{
						types.push_back(p->getElementType());
					}
					else
					{
						types.push_back(arg->getType());
					}
				}
				else
				{
					types.push_back(extractType((*usage)->getValueOperand()));
				}
			}

			de.setArgTypes(std::move(types));
			break;
		}
	}

	if (de.argTypes().empty())
	{
		std::vector<Type*> types;
		std::vector<Value*> args;

		for (auto i : de.args())
		{
			if (i == nullptr)
			{
				types.push_back(_abi->getDefaultType());
			}
			else if (auto* p = dyn_cast<PointerType>(i->getType()))
			{
				types.push_back(p->getElementType());
			}
			else
			{
				types.push_back(i->getType());
			}
		}

		de.setArgTypes(std::move(types));
	}

	auto args = de.args();
	args.erase(
		std::remove_if(
			args.begin(),
			args.end(),
			[](Value* v){return v == nullptr;}),
		args.end());
	de.setArgs(std::move(args));
}

void ParamReturn::propagateWrapped() {
	for (auto& p : _fnc2calls)
	{
		propagateWrapped(p.second);
	}
}

void ParamReturn::propagateWrapped(DataFlowEntry& de) {
	auto* fnc = de.getFunction();
	auto* wrappedCall = de.getWrappedCall();
	if (fnc == nullptr || wrappedCall == nullptr)
	{
		return;
	}

	llvm::CallInst* wrappedCall2 = nullptr;
	for (inst_iterator I = inst_begin(fnc), E = inst_end(fnc); I != E; ++I)
	{
		if (auto* c = dyn_cast<CallInst>(&*I))
		{
			auto* cf = c->getCalledFunction();
			if (cf && !cf->isIntrinsic()) // && cf->isDeclaration())
			{
				wrappedCall2 = c;
				break;
			}
		}
	}

	if (wrappedCall != wrappedCall2) {
		// Something strange. Reset wrapped call and give up.
		de.setWrappedCall(nullptr);
		return;
	}
	auto* callee = wrappedCall->getCalledFunction();
	auto fIt = _fnc2calls.find(callee);
	assert (fIt != _fnc2calls.end());
	DataFlowEntry& wrapDe = fIt->second;
	// dumpInfo(de);
	// dumpInfo(wrapDe);

	if (!wrapDe.argTypes().empty()) {
		// Types have already been supplied.
		return;
	}

	wrapDe.setArgTypes(std::vector(de.argTypes()), std::vector(de.argNames()));
	wrapDe.setRetType(de.getRetType());
	// dumpInfo(wrapDe);
}

void ParamReturn::applyToIr()
{
	for (auto& p : _fnc2calls)
	{
		applyToIr(p.second);
	}

	for (auto& p : _fnc2calls)
	{

		connectWrappers(p.second);
	}
}

void ParamReturn::applyToIr(DataFlowEntry& de)
{
	Function* fnc = de.getFunction();

	if (fnc == nullptr)
	{
		auto loadsOfCalls = fetchLoadsOfCalls(de.callEntries());

		for (auto l : loadsOfCalls)
		{
			IrModifier::modifyCallInst(l.first, de.getRetType(), l.second);
		}

		return;
	}

	if (fnc->arg_size() > 0)
	{
		return;
	}

	auto loadsOfCalls = fetchLoadsOfCalls(de.callEntries());

	std::map<ReturnInst*, Value*> rets2vals;

	if (de.getRetValue())
	{
		if (de.getRetType() == nullptr)
		{
			if (auto* p = dyn_cast<PointerType>(de.getRetValue()->getType()))
			{
				de.setRetType(p->getElementType());
			}
			else
			{
				de.setRetType(de.getRetValue()->getType());
			}
		}

		for (auto& e : de.retEntries())
		{
			auto* l = new LoadInst(de.getRetValue(), "", e.getRetInstruction());
			rets2vals[e.getRetInstruction()] = l;
		}
	}
	else
	{
		de.setRetType(Type::getVoidTy(_module->getContext()));
	}

	std::vector<llvm::Value*> definitionArgs;
	for (auto& a : de.args())
	{
		if (a != nullptr)
		{
			definitionArgs.push_back(a);
		}
	}
	std::vector<llvm::Type*> definitionArgTypes;
	for (auto& t : de.argTypes())
	{
		definitionArgTypes.push_back(t != nullptr ? t : _abi->getDefaultType());
	}

	// Set used calling convention to config
	auto* cf = _config->getConfigFunction(fnc);
	if (cf)
	{
		cf->callingConvention = de.getCallingConvention();
	}

	IrModifier irm(_module, _config);
	auto* newFnc = irm.modifyFunction(
			fnc,
			de.getRetType(),
			definitionArgTypes,
			de.isVariadic(),
			rets2vals,
			loadsOfCalls,
			de.getRetValue(),
			definitionArgs,
			de.argNames()).first;

	de.setCalledValue(newFnc);
}

void ParamReturn::connectWrappers(const DataFlowEntry& de)
{
	auto* fnc = de.getFunction();
	auto* wrappedCall = de.getWrappedCall();
	if (fnc == nullptr || wrappedCall == nullptr)
	{
		return;
	}

	wrappedCall = nullptr;
	for (inst_iterator I = inst_begin(fnc), E = inst_end(fnc); I != E; ++I)
	{
		if (auto* c = dyn_cast<CallInst>(&*I))
		{
			auto* cf = c->getCalledFunction();
			if (cf && !cf->isIntrinsic()) // && cf->isDeclaration())
			{
				wrappedCall = c;
				break;
			}
		}
	}

	if (wrappedCall == nullptr)
	{
		return;
	}

	if (wrappedCall->getNumArgOperands() != fnc->arg_size())
	{
		// TODO: enable assert and inspect these cases.
		return;
	}
	assert(wrappedCall->getNumArgOperands() == fnc->arg_size());

	unsigned i = 0;
	for (auto& a : fnc->args())
	{
		auto iarg = wrappedCall->getArgOperand(i);
		bool shouldSkip = false;
		if (auto* load = dyn_cast<LoadInst>(llvm_utils::skipCasts(iarg))) {
			auto oldarg = load->getPointerOperand();

			std::vector<StoreInst*> users;
			for (const auto& U : oldarg->users())
			{
				if (auto* store = dyn_cast<StoreInst>(U)) {
					if (store->getFunction() == fnc)
						users.push_back(store);
				}
			}
			for (auto store: users) {
				if (llvm_utils::skipCasts(store->getValueOperand()) == &a)
					continue;

				shouldSkip = true;
			}
		}

		if (!shouldSkip) {
			auto* conv = IrModifier::convertValueToType(&a, wrappedCall->getArgOperand(i)->getType(), wrappedCall);
			wrappedCall->setArgOperand(i, conv);
		}
		i++;
	}

	//
	//
	std::set<CallInst*> calls;
	for (auto* u : fnc->users())
	{
		if (auto* c = dyn_cast<CallInst>(u))
		{
			// inline all wrapped functions
			// TODO: only really simple fncs, or from .plt, etc.?
//			if (fnc->isVarArg())
			{
				calls.insert(c);
			}
		}
	}

	auto* wrappedFnc = wrappedCall->getCalledFunction();
	assert(wrappedFnc);
	for (auto* c : calls)
	{
		// todo: should not happen?
		if (c->getType()->isVoidTy() && !wrappedFnc->getReturnType()->isVoidTy())
		{
			continue;
		}

		std::vector<Value*> args;
		unsigned numParams = wrappedFnc->getFunctionType()->getNumParams();
		unsigned i = 0;
		for (auto& a : c->arg_operands())
		{
			if (i >= numParams) // var args fncs
			{
				assert(wrappedFnc->isVarArg());
				args.push_back(a);
			}
			else
			{
				auto* conv = IrModifier::convertValueToType(a, wrappedFnc->getFunctionType()->getParamType(i++), c);
				args.push_back(conv);
			}
		}
		auto* nc = CallInst::Create(wrappedFnc, args, "", c);
		auto* resConv = IrModifier::convertValueToTypeAfter(nc, c->getType(), nc);
		c->replaceAllUsesWith(resConv);
		c->eraseFromParent();
	}
}

std::map<CallInst*, std::vector<Value*>> ParamReturn::fetchLoadsOfCalls(
						const std::vector<CallEntry>& calls) const
{
	std::map<CallInst*, std::vector<Value*>> loadsOfCalls;

	for (auto& e : calls)
	{
		std::vector<Value*> loads;
		auto* call = e.getCallInstruction();

		auto types = e.getBaseFunction()->argTypes();
		types.insert(
			types.end(),
			e.argTypes().begin(),
			e.argTypes().end());

		auto tIt = types.begin();
		auto aIt = e.args().begin();

		while (aIt != e.args().end())
		{
			if (*aIt == nullptr)
			{
				aIt++;
				continue;
			}

			Value* l = new LoadInst(*aIt, "", call);

			if (tIt != types.end())
			{
				auto t = *tIt != nullptr ? *tIt : _abi->getDefaultType();
				l = IrModifier::convertValueToType(l, t, call);
				tIt++;
			}
			else
			{
				l = IrModifier::convertValueToType(l, _abi->getDefaultType(), call);
			}

			loads.push_back(l);
			aIt++;
		}

		loadsOfCalls[call] = std::move(loads);
	}

	return loadsOfCalls;
}

}
}
