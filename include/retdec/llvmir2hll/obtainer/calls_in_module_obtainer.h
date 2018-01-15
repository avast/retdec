/**
* @file include/retdec/llvmir2hll/obtainer/calls_in_module_obtainer.h
* @brief An obtainer of information about function calls in a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OBTAINER_CALLS_IN_MODULE_OBTAINER_H
#define RETDEC_LLVMIR2HLL_OBTAINER_CALLS_IN_MODULE_OBTAINER_H

#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief An obtainer of information about function calls in a module.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class CallsInModuleObtainer: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	/// Information about a single call.
	struct CallInfo {
		/// The call itself.
		ShPtr<CallExpr> call;

		/// The statement in which the call appears.
		ShPtr<Statement> stmt;

		/// The function in which the call appears.
		ShPtr<Function> func;

		/// The module in which the function appears.
		ShPtr<Module> module;
	};

	/// A list of calls.
	using Calls = std::vector<CallInfo>;

public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~CallsInModuleObtainer() override;

	static Calls getCalls(ShPtr<Module> module);

private:
	CallsInModuleObtainer(ShPtr<Module> module);

	Calls getCallsImpl();
	void obtainCallsInGlobalVars();
	void obtainCallsInFuncs();
	void obtainCallsInFunc(ShPtr<Function> func);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	/// @}

private:
	/// Module in which the calls are searched.
	ShPtr<Module> module;

	/// The currently traversed function.
	ShPtr<Function> currFunc;

	/// Found function calls.
	Calls foundCalls;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
