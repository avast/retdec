/**
* @file include/retdec/llvmir2hll/support/variable_replacer.h
* @brief A replacer of variables in functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VARIABLE_REPLACER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VARIABLE_REPLACER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Function;
class Statement;
class Variable;

/**
* @brief A replacer of variables in functions.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class VariableReplacer: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~VariableReplacer() override;

	static void replaceVariable(ShPtr<Variable> oldVar, ShPtr<Variable> newVar,
		ShPtr<Function> func);

private:
	VariableReplacer(ShPtr<Variable> oldVar, ShPtr<Variable> newVar);

	void performReplace(ShPtr<Function> func);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Variable> var) override;
	/// @}

private:
	/// Old variable.
	ShPtr<Variable> oldVar;

	/// New variable.
	ShPtr<Variable> newVar;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
