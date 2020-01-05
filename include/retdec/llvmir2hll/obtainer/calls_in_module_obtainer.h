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
		CallExpr* call = nullptr;

		/// The statement in which the call appears.
		Statement* stmt = nullptr;

		/// The function in which the call appears.
		Function* func = nullptr;

		/// The module in which the function appears.
		Module* module = nullptr;
	};

	/// A list of calls.
	using Calls = std::vector<CallInfo>;

public:
	static Calls getCalls(Module* module);

private:
	CallsInModuleObtainer(Module* module);

	Calls getCallsImpl();
	void obtainCallsInGlobalVars();
	void obtainCallsInFuncs();
	void obtainCallsInFunc(Function* func);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(CallExpr* expr) override;
	/// @}

private:
	/// Module in which the calls are searched.
	Module* module = nullptr;

	/// The currently traversed function.
	Function* currFunc = nullptr;

	/// Found function calls.
	Calls foundCalls;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
