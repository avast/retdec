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

bool PessimCallInfo::isNeverRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::mayBeRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimCallInfo::isAlwaysRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::isNeverModified(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::mayBeModified(Variable* var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimCallInfo::isAlwaysModified(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::valueIsNeverChanged(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimCallInfo::isAlwaysModifiedBeforeRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

/**
* @brief Constructs a new pessimistic piece of information about the given
*        function.
*/
PessimFuncInfo::PessimFuncInfo(Function* func): FuncInfo(func) {}

bool PessimFuncInfo::isNeverRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::mayBeRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimFuncInfo::isAlwaysRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::isNeverModified(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::mayBeModified(Variable* var) const {
	// TODO Can this implementation be improved?
	return true;
}

bool PessimFuncInfo::isAlwaysModified(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::valueIsNeverChanged(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

bool PessimFuncInfo::isAlwaysModifiedBeforeRead(Variable* var) const {
	// TODO Can this implementation be improved?
	return false;
}

/**
* @brief Constructs a new pessimistic piece of information about the given
*        function call.
*/
PessimCallInfo::PessimCallInfo(CallExpr* call): CallInfo(call) {}

/**
* @brief Creates a new obtainer.
*/
CallInfoObtainer* PessimCallInfoObtainer::create() {
	return new PessimCallInfoObtainer();
}

std::string PessimCallInfoObtainer::getId() const {
	return PESSIM_CALL_INFO_OBTAINER_ID;
}

CallInfo* PessimCallInfoObtainer::getCallInfo(CallExpr* call,
		Function* caller) {
	PRECONDITION(module, "the obtainer has not been initialized");
	PRECONDITION(module->funcExists(caller),
		"function `" << caller->getName() << "` does not exist");

	PessimCallInfo* info(new PessimCallInfo(call));
	return info;
}

FuncInfo* PessimCallInfoObtainer::getFuncInfo(Function* func) {
	PRECONDITION(module, "the obtainer has not been initialized");
	PRECONDITION(module->funcExists(func),
		"function `" << func->getName() << "` does not exist");

	PessimFuncInfo* info(new PessimFuncInfo(func));

	// TODO

	return info;
}

} // namespace llvmir2hll
} // namespace retdec
