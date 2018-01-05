/**
* @file src/llvmir2hll/obtainer/call_info_obtainers/pessim_call_info_obtainer.cpp
* @brief Implementation of PessimCallInfoObtainer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer_factory.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainers/pessim_call_info_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("pessim", PESSIM_CALL_INFO_OBTAINER_ID, CallInfoObtainerFactory,
	PessimCallInfoObtainer::create);

/**
* @brief Constructs a new obtainer.
*
* See create() for the description of parameters.
*/
PessimCallInfoObtainer::PessimCallInfoObtainer() {}

bool PessimCallInfo::isNeverRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::mayBeRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimCallInfo::isAlwaysRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::isNeverModified(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::mayBeModified(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimCallInfo::isAlwaysModified(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::valueIsNeverChanged(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::isAlwaysModifiedBeforeRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

/**
* @brief Constructs a new pessimistic piece of information about the given
*        function.
*/
PessimFuncInfo::PessimFuncInfo(ShPtr<Function> func): FuncInfo(func) {}

bool PessimFuncInfo::isNeverRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::mayBeRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimFuncInfo::isAlwaysRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::isNeverModified(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::mayBeModified(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimFuncInfo::isAlwaysModified(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::valueIsNeverChanged(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::isAlwaysModifiedBeforeRead(ShPtr<Variable> var) const {
	// TODO Can this implementation be improved?
	return false;
}

/**
* @brief Constructs a new pessimistic piece of information about the given
*        function call.
*/
PessimCallInfo::PessimCallInfo(ShPtr<CallExpr> call): CallInfo(call) {}

/**
* @brief Creates a new obtainer.
*/
ShPtr<CallInfoObtainer> PessimCallInfoObtainer::create() {
	return ShPtr<CallInfoObtainer>(new PessimCallInfoObtainer());
}

std::string PessimCallInfoObtainer::getId() const {
	return PESSIM_CALL_INFO_OBTAINER_ID;
}

ShPtr<CallInfo> PessimCallInfoObtainer::getCallInfo(ShPtr<CallExpr> call,
		ShPtr<Function> caller) {
	PRECONDITION(module, "the obtainer has not been initialized");
	PRECONDITION(module->funcExists(caller),
		"function `" << caller->getName() << "` does not exist");

	ShPtr<PessimCallInfo> info(new PessimCallInfo(call));
	return info;
}

ShPtr<FuncInfo> PessimCallInfoObtainer::getFuncInfo(ShPtr<Function> func) {
	PRECONDITION(module, "the obtainer has not been initialized");
	PRECONDITION(module->funcExists(func),
		"function `" << func->getName() << "` does not exist");

	ShPtr<PessimFuncInfo> info(new PessimFuncInfo(func));

	// TODO

	return info;
}

} // namespace llvmir2hll
} // namespace retdec
