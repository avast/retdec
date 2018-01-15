/**
* @file include/retdec/llvmir2hll/obtainer/calls_obtainer.h
* @brief An obtainer of information about function calls.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OBTAINER_CALLS_OBTAINER_H
#define RETDEC_LLVMIR2HLL_OBTAINER_CALLS_OBTAINER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Value;

/**
* @brief An obtainer of information about function calls.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no instances can be created).
*/
class CallsObtainer: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~CallsObtainer() override;

	static CallVector getCalls(ShPtr<Value> value);
	static bool hasCalls(ShPtr<Value> value);

private:
	CallsObtainer();

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	/// @}

private:
	/// Found function calls.
	CallVector foundCalls;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
