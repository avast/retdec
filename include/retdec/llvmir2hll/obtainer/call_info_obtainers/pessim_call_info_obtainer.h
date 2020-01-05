/**
* @file include/retdec/llvmir2hll/obtainer/call_info_obtainers/pessim_call_info_obtainer.h
* @brief Obtainer of information about functions and function calls that
*        assumes nothing.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINERS_PESSIM_CALL_INFO_OBTAINER_H
#define RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINERS_PESSIM_CALL_INFO_OBTAINER_H

#include <string>

#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Pessimistic information about a function call.
*
* Use PessimCallInfoObtainer to create instances.
*
* Instances of this class have reference object semantics.
*/
class PessimCallInfo: public CallInfo {
	friend class PessimCallInfoObtainer;

public:
	explicit PessimCallInfo(CallExpr* call);

	virtual bool isNeverRead(Variable* var) const override;
	virtual bool mayBeRead(Variable* var) const override;
	virtual bool isAlwaysRead(Variable* var) const override;

	virtual bool isNeverModified(Variable* var) const override;
	virtual bool mayBeModified(Variable* var) const override;
	virtual bool isAlwaysModified(Variable* var) const override;

	virtual bool valueIsNeverChanged(Variable* var) const override;
	virtual bool isAlwaysModifiedBeforeRead(Variable* var) const override;
};

/**
* @brief Pessimistic information about a function.
*
* Use PessimCallInfoObtainer to create instances.
*
* Instances of this class have reference object semantics.
*/
class PessimFuncInfo: public FuncInfo {
	friend class PessimCallInfoObtainer;

public:
	explicit PessimFuncInfo(Function* func);

	virtual bool isNeverRead(Variable* var) const override;
	virtual bool mayBeRead(Variable* var) const override;
	virtual bool isAlwaysRead(Variable* var) const override;

	virtual bool isNeverModified(Variable* var) const override;
	virtual bool mayBeModified(Variable* var) const override;
	virtual bool isAlwaysModified(Variable* var) const override;

	virtual bool valueIsNeverChanged(Variable* var) const override;
	virtual bool isAlwaysModifiedBeforeRead(Variable* var) const override;
};

/**
* @brief Obtainer of information about functions and function calls that
*        assumes nothing.
*
* Compare with OptimCallInfoObtainer.
*
* Use create() to create instances. Instances of this class have
* reference object semantics.
*/
class PessimCallInfoObtainer: public CallInfoObtainer {
public:
	static CallInfoObtainer* create();

	virtual std::string getId() const override;
	virtual CallInfo* getCallInfo(CallExpr* call,
		Function* caller) override;
	virtual FuncInfo* getFuncInfo(Function* func) override;

private:
	PessimCallInfoObtainer();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
