/**
* @file include/retdec/llvmir2hll/optimizer/func_optimizer.h
* @brief A base class of all function optimizers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_FUNC_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_FUNC_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Function;
class Module;

/**
* @brief A base class of all function optimizers.
*
* Concrete optimizers should:
*  - subclass this class or a more specific subclass (if available)
*  - override the doInitialization() and doFinalization() functions from
*    Optimizer (if necessary; by default, they do nothing)
*  - override the runOnFunction() function (if necessary; by default, it just
*    calls @c func->accept(this))
*  - override the needed functions from OrderedAllVisitor (remember that
*    non-overridden functions have to brought to scope using the <tt>using
*    OrderedAllVisitor::visit;</tt> declaration; otherwise, they'll be hidden
*    by the overridden ones)
*  - add every accessed statement to the @c accessedStmts set to avoid looping
*    over the same statements. Also, when a statement is accessed, it should
*    check this set before accessing any of its "nested statements". For example,
*    an if statement should check whether its body has already been accessed or
*    not. visitStmt() takes care of that, so you can use it to visit statements
*    (blocks).
*
* The functions are not optimized in any particular order. Optimizations for a
* single function should not affect optimizations of other functions.
*
* Instances of this class have reference object semantics.
*/
class FuncOptimizer: public Optimizer {
public:
	virtual ~FuncOptimizer() override;

protected:
	FuncOptimizer(ShPtr<Module> module);

	virtual void doOptimization() override;
	virtual void runOnFunction(ShPtr<Function> func);

	/**
	* @brief Visits the given statement, its nested statements, and successor
	*        statements (depending on the settings of the visitor).
	*
	* This function is very handy in subclasses. Typical usage:
	* @code
	* void ForLoopOptimizer::visit(ShPtr<WhileLoopStmt> stmt) {
	*     visitNestedAndSuccessorStatements(stmt);
	*     tryConversionToForLoop(stmt);
	* }
	* @endcode
	*/
	template<typename T>
	void visitNestedAndSuccessorStatements(ShPtr<T> stmt) {
		// The qualification is needed to prevent infinite recursion when this
		// function is called from a subclass (typical usage).
		FuncOptimizer::visit(stmt);
	}

protected:
	/// Function that is currently being optimized.
	ShPtr<Function> currFunc;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
